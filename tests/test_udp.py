import struct

from sentinel.proto.checksum import pseudo_header
from sentinel.proto.udp import parse_udp
from tools.gen_pcap import IP6_A, IP6_B, IP_A, IP_B, udp_datagram

PAYLOAD = b"hello"


def make() -> bytes:
    return udp_datagram(IP_A, IP_B, 5353, 53, PAYLOAD)


def set_field(raw: bytes, offset: int, value: int) -> bytes:
    return raw[:offset] + struct.pack("!H", value) + raw[offset + 2 :]


def test_valid_hand_built() -> None:
    raw = bytes.fromhex("14e90035000d0000") + PAYLOAD
    udp = parse_udp(raw)
    assert udp.error is None
    assert udp.anomalies == ()
    assert (udp.src_port, udp.dst_port, udp.length, udp.checksum) == (5353, 53, 13, 0)
    assert udp.payload == PAYLOAD


def test_valid_checksum_over_ipv4_and_ipv6() -> None:
    assert parse_udp(make(), src=IP_A, dst=IP_B).anomalies == ()
    assert parse_udp(udp_datagram(IP6_A, IP6_B, 1, 2, b"x"), src=IP6_A, dst=IP6_B).anomalies == ()


def test_ip_padding_is_trimmed() -> None:
    udp = parse_udp(make() + bytes(6), src=IP_A, dst=IP_B)
    assert udp.payload == PAYLOAD
    assert any("shorter than the 19 bytes" in a for a in udp.anomalies)


def test_bad_checksum_reported_not_dropped() -> None:
    bad = bytearray(make())
    bad[-1] ^= 0xFF
    udp = parse_udp(bytes(bad), src=IP_A, dst=IP_B)
    assert udp.error is None
    assert udp.anomalies == ("bad udp checksum",)


def test_zero_checksum_means_unchecked_over_ipv4() -> None:
    raw = set_field(make(), 6, 0)
    assert parse_udp(raw, src=IP_A, dst=IP_B).anomalies == ()


def test_zero_checksum_over_ipv6_is_an_anomaly() -> None:
    raw = set_field(udp_datagram(IP6_A, IP6_B, 1, 2, b"x"), 6, 0)
    assert parse_udp(raw, src=IP6_A, dst=IP6_B).anomalies == ("zero udp checksum over ipv6",)


def test_truncated_header() -> None:
    raw = make()
    for n in range(8):
        udp = parse_udp(raw[:n])
        assert udp.error is not None
        assert "truncated" in udp.error


def test_truncated_datagram_is_an_anomaly_and_skips_checksum() -> None:
    udp = parse_udp(make()[:10], src=IP_A, dst=IP_B)
    assert udp.error is None
    assert udp.payload == PAYLOAD[:2]
    assert [a for a in udp.anomalies if "bad udp checksum" in a] == []
    assert any("truncated udp datagram" in a for a in udp.anomalies)


def test_length_below_header_size() -> None:
    for length in (0, 7):
        assert parse_udp(set_field(make(), 4, length)).error == f"invalid udp length {length}"


def test_length_beyond_capture() -> None:
    udp = parse_udp(set_field(make(), 4, 60000))
    assert udp.error is None
    assert udp.payload == PAYLOAD
    assert any("truncated udp datagram" in a for a in udp.anomalies)


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    for blob in blobs:
        udp = parse_udp(blob, src=IP_A, dst=IP_B)
        if len(blob) < 8:
            assert udp.error is not None


def folded_sum(data: bytes) -> int:
    data += bytes(len(data) % 2)
    total = sum(data[i] << 8 | data[i + 1] for i in range(0, len(data), 2))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def test_a_checksum_left_for_the_network_card_is_not_bad() -> None:
    for src, dst in ((IP_A, IP_B), (IP6_A, IP6_B)):
        for payload in (b"", PAYLOAD, b"odd length!"):
            raw = udp_datagram(src, dst, 5353, 53, payload)
            partial = folded_sum(pseudo_header(src, dst, 17, len(raw)))
            offloaded = raw[:6] + partial.to_bytes(2, "big") + raw[8:]
            parsed = parse_udp(offloaded, src=src, dst=dst)
            assert parsed.anomalies == ()
            assert parsed.payload == payload


def test_only_the_exact_partial_udp_checksum_is_accepted() -> None:
    raw = make()
    partial = folded_sum(pseudo_header(IP_A, IP_B, 17, len(raw)))
    for value in (partial + 1, partial - 1, partial ^ 0x8000, ~partial & 0xFFFF):
        bad = raw[:6] + (value & 0xFFFF).to_bytes(2, "big") + raw[8:]
        assert parse_udp(bad, src=IP_A, dst=IP_B).anomalies == ("bad udp checksum",)
    other = folded_sum(pseudo_header(IP_A, IP_B, 17, len(raw) + 2))
    bad = raw[:6] + other.to_bytes(2, "big") + raw[8:]
    assert parse_udp(bad, src=IP_A, dst=IP_B).anomalies == ("bad udp checksum",)
