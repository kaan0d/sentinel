from ipaddress import IPv4Address

from sentinel.proto.arp import ARP_REPLY, ARP_REQUEST, parse_arp
from tools.gen_pcap import IP_A, IP_B, MAC_A, MAC_ZERO, arp_packet


def test_valid_request_hand_built() -> None:
    raw = bytes.fromhex("0001080006040001") + MAC_A + bytes([10, 0, 0, 1])
    raw += bytes(6) + bytes([10, 0, 0, 2])
    arp = parse_arp(raw)
    assert arp.error is None
    assert arp.anomalies == ()
    assert arp.op == ARP_REQUEST
    assert arp.sender_mac == MAC_A
    assert arp.sender_ip == IPv4Address("10.0.0.1")
    assert arp.target_mac == bytes(6)
    assert arp.target_ip == IPv4Address("10.0.0.2")


def test_valid_reply_with_ethernet_padding() -> None:
    arp = parse_arp(arp_packet(ARP_REPLY, MAC_A, IP_A, MAC_ZERO, IP_B) + bytes(18))
    assert arp.error is None
    assert arp.op == ARP_REPLY
    assert arp.sender_ip == IP_A


def test_truncated() -> None:
    raw = arp_packet(ARP_REQUEST, MAC_A, IP_A, MAC_ZERO, IP_B)
    for n in range(28):
        arp = parse_arp(raw[:n])
        assert arp.error is not None
        assert "truncated" in arp.error


def test_unsupported_address_types() -> None:
    good = arp_packet(ARP_REQUEST, MAC_A, IP_A, MAC_ZERO, IP_B)
    for offset, value in [(1, 6), (3, 0x86), (4, 8), (5, 16)]:  # htype, ptype, hlen, plen
        bad = bytearray(good)
        bad[offset] = value
        arp = parse_arp(bytes(bad))
        assert arp.error is not None
        assert "unsupported arp types" in arp.error


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    for blob in blobs:
        arp = parse_arp(blob)
        if len(blob) < 28:
            assert arp.error is not None
