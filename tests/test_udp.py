import struct

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
