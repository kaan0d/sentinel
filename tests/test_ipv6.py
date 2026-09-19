from ipaddress import IPv6Address

from sentinel.proto.ipv6 import parse_ipv6
from tools.gen_pcap import IP6_A, IP6_B, ipv6_packet

PAYLOAD = b"0123456789"


def test_valid_hand_built() -> None:
    raw = bytes.fromhex("6b8abcde000a1140")
    raw += IPv6Address("fe80::1").packed + IPv6Address("ff02::2").packed + PAYLOAD
    ip = parse_ipv6(raw)
    assert ip.error is None
    assert ip.anomalies == ()
    assert ip.traffic_class == 0xB8
    assert ip.flow_label == 0xABCDE
    assert (ip.payload_length, ip.next_header, ip.hop_limit) == (10, 17, 64)
    assert (ip.src, ip.dst) == (IPv6Address("fe80::1"), IPv6Address("ff02::2"))
    assert ip.payload == PAYLOAD
    assert ip.is_complete


def test_ethernet_padding_is_trimmed() -> None:
    ip = parse_ipv6(ipv6_packet(IP6_A, IP6_B, 17, PAYLOAD) + bytes(30))
    assert ip.payload == PAYLOAD
    assert ip.anomalies == ()


def test_truncated_header() -> None:
    raw = ipv6_packet(IP6_A, IP6_B, 17, PAYLOAD)
    for n in range(40):
        ip = parse_ipv6(raw[:n])
        assert ip.error is not None
        assert "truncated" in ip.error


def test_truncated_payload_is_an_anomaly() -> None:
    ip = parse_ipv6(ipv6_packet(IP6_A, IP6_B, 17, PAYLOAD)[:45])
    assert ip.error is None
    assert ip.payload == PAYLOAD[:5]
    assert not ip.is_complete
    assert any("truncated ipv6 packet" in a for a in ip.anomalies)


def test_bad_version() -> None:
    raw = bytearray(ipv6_packet(IP6_A, IP6_B, 17, PAYLOAD))
    raw[0] = 0x40
    assert parse_ipv6(bytes(raw)).error == "not ipv6: version 4"


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    for blob in blobs:
        ip = parse_ipv6(blob)
        if len(blob) < 40:
            assert ip.error is not None
