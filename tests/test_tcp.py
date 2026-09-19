import struct

from sentinel.proto import tcp
from sentinel.proto.checksum import pseudo_header
from sentinel.proto.tcp import TcpOption, parse_tcp
from tools.gen_pcap import IP6_A, IP6_B, IP_A, IP_B, SYN_OPTIONS, tcp_segment

PAYLOAD = b"hello"


def make(flags: int = tcp.ACK, options: bytes = b"") -> bytes:
    return tcp_segment(IP_A, IP_B, 1234, 80, 100, 200, flags, options=options, payload=PAYLOAD)


def test_valid_hand_built() -> None:
    raw = bytes.fromhex("04d2005000000064000000c85018faf000000000") + PAYLOAD
    tcp_ = parse_tcp(raw)
    assert tcp_.error is None
    assert tcp_.anomalies == ()
    assert (tcp_.src_port, tcp_.dst_port, tcp_.seq, tcp_.ack) == (1234, 80, 100, 200)
    assert (tcp_.header_len, tcp_.window, tcp_.urgent) == (20, 0xFAF0, 0)
    assert tcp_.flags == tcp.PSH | tcp.ACK
    assert tcp_.options == ()
    assert tcp_.payload == PAYLOAD


def test_all_flags_including_ns() -> None:
    for bit in (tcp.FIN, tcp.SYN, tcp.RST, tcp.PSH, tcp.ACK, tcp.URG, tcp.ECE, tcp.CWR, tcp.NS):
        assert parse_tcp(make(bit)).flags == bit
    assert parse_tcp(make(0x1FF)).flags == 0x1FF


def test_options() -> None:
    parsed = parse_tcp(make(tcp.SYN, options=SYN_OPTIONS))
    assert parsed.error is None
    assert parsed.anomalies == ()
    assert parsed.header_len == 40
    assert parsed.options == (
        TcpOption(2, b"\x05\xb4"),
        TcpOption(4, b""),
        TcpOption(8, bytes.fromhex("000003e800000000")),
        TcpOption(1, b""),
        TcpOption(3, b"\x07"),
    )
    assert parsed.payload == PAYLOAD


def test_end_of_option_list_stops_parsing() -> None:
    parsed = parse_tcp(make(options=b"\x01\x00\x02\x04"))  # nop, eol, padding that looks like MSS
    assert parsed.options == (TcpOption(1, b""), TcpOption(0, b""))
    assert parsed.anomalies == ()


def test_valid_checksum_over_ipv4_and_ipv6() -> None:
    seg4 = make()
    assert parse_tcp(seg4, src=IP_A, dst=IP_B).anomalies == ()
    seg6 = tcp_segment(IP6_A, IP6_B, 1, 2, 3, 4, tcp.SYN)
    assert parse_tcp(seg6, src=IP6_A, dst=IP6_B).anomalies == ()


def test_checksum_matches_independent_computation() -> None:
    seg = make()
    data = IP_A.packed + IP_B.packed + struct.pack("!BBH", 0, 6, len(seg)) + seg
    data += b"\0" * (len(data) % 2)
    total = sum(data[i] << 8 | data[i + 1] for i in range(0, len(data), 2))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    assert total == 0xFFFF  # a valid segment sums to all-ones


def test_bad_checksum_reported_not_dropped() -> None:
    bad = bytearray(make())
    bad[-1] ^= 0xFF
    parsed = parse_tcp(bytes(bad), src=IP_A, dst=IP_B)
    assert parsed.error is None
    assert parsed.anomalies == ("bad tcp checksum",)
    assert parse_tcp(bytes(bad)).anomalies == ()  # not verified without addresses


def test_checksum_with_wrong_addresses_is_bad() -> None:
    assert parse_tcp(make(), src=IP_B, dst=IP_B).anomalies == ("bad tcp checksum",)


def test_truncated_header() -> None:
    raw = make()
    for n in range(20):
        parsed = parse_tcp(raw[:n])
        assert parsed.error is not None
        assert "truncated" in parsed.error


def test_truncated_options() -> None:
    raw = make(options=SYN_OPTIONS)
    for n in range(20, 40):
        parsed = parse_tcp(raw[:n])
        assert parsed.error is not None
        assert "truncated" in parsed.error
    assert parse_tcp(raw[:40]).error is None  # options present, payload cut off entirely


def test_data_offset_below_minimum() -> None:
    raw = bytearray(make())
    raw[12] = 0x40
    parsed = parse_tcp(bytes(raw))
    assert parsed.error == "invalid tcp data offset: header length 16"


def test_option_with_bad_length_is_an_anomaly() -> None:
    for opts in (
        b"\x02\x00\x00\x00",
        b"\x02\x01\x00\x00",
        b"\x02\x0a\x00\x00",
        b"\x01\x01\x01\x02",
    ):
        parsed = parse_tcp(make(options=opts))
        assert parsed.error is None
        assert any("tcp option 2" in a for a in parsed.anomalies), opts
        assert parsed.payload == PAYLOAD


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    for blob in blobs:
        parsed = parse_tcp(blob, src=IP_A, dst=IP_B)
        if len(blob) < 20:
            assert parsed.error is not None


def folded_sum(data: bytes) -> int:
    data += bytes(len(data) % 2)
    total = sum(data[i] << 8 | data[i + 1] for i in range(0, len(data), 2))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def with_checksum(seg: bytes, value: int) -> bytes:
    return seg[:16] + value.to_bytes(2, "big") + seg[18:]


def offloaded(seg: bytes, src: object, dst: object, length: int | None = None) -> bytes:
    """`seg` as a capture on the sending machine holds it: the checksum field is the sum of the
    pseudo-header alone (not complemented), which the network card then completes."""
    pseudo = pseudo_header(src, dst, 6, len(seg) if length is None else length)  # type: ignore[arg-type]
    return with_checksum(seg, folded_sum(pseudo))


def test_a_checksum_left_for_the_network_card_is_not_bad() -> None:
    for src, dst in ((IP_A, IP_B), (IP6_A, IP6_B)):
        for payload in (b"", PAYLOAD, b"odd length!"):
            seg = tcp_segment(src, dst, 1234, 80, 100, 200, tcp.ACK, payload=payload)
            assert parse_tcp(with_checksum(seg, 0), src=src, dst=dst).anomalies == (
                "bad tcp checksum",
            )
            parsed = parse_tcp(offloaded(seg, src, dst), src=src, dst=dst)
            assert parsed.anomalies == ()
            assert parsed.payload == payload


def test_only_the_exact_partial_checksum_is_accepted() -> None:
    seg = make()
    partial = folded_sum(pseudo_header(IP_A, IP_B, 6, len(seg)))
    for value in (partial + 1, partial - 1, partial ^ 0x8000, ~partial & 0xFFFF):
        bad = with_checksum(seg, value & 0xFFFF)
        assert parse_tcp(bad, src=IP_A, dst=IP_B).anomalies == ("bad tcp checksum",)
    other = pseudo_header(IP_A, IP_B, 6, len(seg) + 2)  # a pseudo-header with another length
    assert parse_tcp(with_checksum(seg, folded_sum(other)), src=IP_A, dst=IP_B).anomalies == (
        "bad tcp checksum",
    )
    wrong_addresses = pseudo_header(IP_B, IP_B, 6, len(seg))
    assert parse_tcp(
        with_checksum(seg, folded_sum(wrong_addresses)), src=IP_A, dst=IP_B
    ).anomalies == ("bad tcp checksum",)
