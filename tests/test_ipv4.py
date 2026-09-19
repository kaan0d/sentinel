from ipaddress import IPv4Address

from sentinel.proto.checksum import internet_checksum
from sentinel.proto.ipv4 import parse_ipv4
from tools.gen_pcap import IP_A, IP_B, ipv4_packet

PAYLOAD = b"0123456789"


def make(*, ident: int = 1, ttl: int = 64, flags_frag: int = 0x4000, options: bytes = b"") -> bytes:
    return ipv4_packet(
        IP_A, IP_B, 17, PAYLOAD, ident=ident, ttl=ttl, flags_frag=flags_frag, options=options
    )


def test_known_checksum_vector() -> None:
    # Header with a known-good checksum (0xb861), independent of our packet builders.
    header = bytes.fromhex("4500 0073 0000 4000 4011 b861 c0a8 0001 c0a8 00c7")
    assert internet_checksum(header) == 0
    ip = parse_ipv4(header + bytes(0x73 - 20))
    assert ip.error is None
    assert ip.anomalies == ()
    assert (ip.src, ip.dst) == (IPv4Address("192.168.0.1"), IPv4Address("192.168.0.199"))
    assert (ip.ttl, ip.proto, ip.total_length, ip.checksum) == (0x40, 17, 0x73, 0xB861)
    assert ip.dont_fragment
    assert not ip.more_fragments


def test_valid_fields() -> None:
    ip = parse_ipv4(make(ident=0x1234, ttl=7))
    assert ip.error is None
    assert ip.anomalies == ()
    assert (ip.header_len, ip.ident, ip.ttl, ip.proto) == (20, 0x1234, 7, 17)
    assert ip.payload == PAYLOAD
    assert ip.is_complete
    assert not ip.is_fragment


def test_ethernet_padding_is_trimmed() -> None:
    ip = parse_ipv4(make() + bytes(20))
    assert ip.payload == PAYLOAD
    assert ip.anomalies == ()
    assert ip.is_complete


def test_options() -> None:
    ip = parse_ipv4(make(options=b"\x01\x01\x01\x00"))
    assert ip.error is None
    assert ip.header_len == 24
    assert ip.options == b"\x01\x01\x01\x00"
    assert ip.payload == PAYLOAD


def test_fragment_fields() -> None:
    ip = parse_ipv4(make(flags_frag=0x2000 | 185))
    assert ip.more_fragments
    assert not ip.dont_fragment
    assert ip.frag_offset == 185 * 8
    assert ip.is_fragment


def test_truncated_header() -> None:
    raw = make()
    for n in range(20):
        ip = parse_ipv4(raw[:n])
        assert ip.error is not None
        assert "truncated" in ip.error


def test_truncated_options() -> None:
    raw = make(options=bytes(8))
    for n in range(20, 28):
        assert parse_ipv4(raw[:n]).error is not None
    assert parse_ipv4(raw[:28]).error is None


def test_truncated_payload_is_an_anomaly_not_an_error() -> None:
    ip = parse_ipv4(make()[:25])
    assert ip.error is None
    assert ip.payload == PAYLOAD[:5]
    assert not ip.is_complete
    assert any("truncated ipv4 packet" in a for a in ip.anomalies)


def test_bad_version() -> None:
    raw = bytearray(make())
    raw[0] = 0x65
    ip = parse_ipv4(bytes(raw))
    assert ip.error == "not ipv4: version 6"


def test_ihl_below_minimum() -> None:
    raw = bytearray(make())
    raw[0] = 0x44
    assert parse_ipv4(bytes(raw)).error == "invalid ipv4 header length 16"


def test_total_length_below_header_length() -> None:
    raw = bytearray(make())
    raw[2:4] = (19).to_bytes(2, "big")
    ip = parse_ipv4(bytes(raw))
    assert ip.error is not None
    assert "total length" in ip.error


def test_bad_header_checksum_is_reported_not_dropped() -> None:
    raw = bytearray(make())
    raw[8] ^= 0xFF  # ttl
    ip = parse_ipv4(bytes(raw))
    assert ip.error is None
    assert ip.anomalies == ("bad ipv4 header checksum",)
    assert ip.payload == PAYLOAD


def test_reserved_flag() -> None:
    ip = parse_ipv4(make(flags_frag=0x8000 | 0x4000))
    assert "ipv4 reserved flag set" in ip.anomalies


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    for blob in blobs:
        ip = parse_ipv4(blob)
        if len(blob) < 20:
            assert ip.error is not None
