import random

from sentinel.proto.arp import Arp
from sentinel.proto.decode import decode
from sentinel.proto.ethernet import Ethernet
from sentinel.proto.icmp import Icmp
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.ipv6 import IPv6
from sentinel.proto.tcp import Tcp
from sentinel.proto.udp import Udp
from sentinel.summary import describe
from tools.gen_pcap import (
    IP_A,
    IP_B,
    MAC_A,
    MAC_B,
    eth_frame,
    generate,
    ipv4_packet,
    tcp_segment,
    udp_datagram,
)

EXPECTED_LAYERS = [
    (Ethernet, Arp),
    (Ethernet, Arp),
    (Ethernet, IPv4, Icmp),
    (Ethernet, IPv4, Icmp),
    (Ethernet, IPv4, Icmp),
    (Ethernet, IPv4, Tcp),
    (Ethernet, IPv4, Tcp),
    (Ethernet, IPv4, Tcp),
    (Ethernet, IPv4, Tcp),
    (Ethernet, IPv4, Tcp),
    (Ethernet, IPv4, Udp),
    (Ethernet, IPv4, Udp),
    (Ethernet, IPv6, Tcp),
    (Ethernet, IPv6, Udp),
]


def test_generated_traffic_decodes_cleanly_and_covers_every_protocol() -> None:
    packets = generate()
    assert len(packets) == len(EXPECTED_LAYERS)
    for packet, expected in zip(packets, EXPECTED_LAYERS, strict=True):
        layers = decode(packet.data)
        assert tuple(type(layer) for layer in layers) == expected
        for layer in layers:
            assert layer.error is None
            assert layer.anomalies == ()
    eth = decode(packets[11].data)[0]
    assert isinstance(eth, Ethernet)
    assert eth.vlans == (100,)


def test_l4_checksum_skipped_when_capture_is_truncated() -> None:
    seg = tcp_segment(IP_A, IP_B, 1, 2, 3, 4, 0x18, payload=b"x" * 100)
    frame = eth_frame(MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 6, seg))[:80]
    layers = decode(frame)
    assert isinstance(layers[-1], Tcp)
    assert layers[-1].anomalies == ()  # no false "bad tcp checksum"
    assert any("truncated ipv4" in a for a in layers[1].anomalies)


def test_bad_checksums_are_reported_at_every_layer() -> None:
    seg = bytearray(udp_datagram(IP_A, IP_B, 1, 2, b"data"))
    seg[-1] ^= 0xFF
    pkt = bytearray(ipv4_packet(IP_A, IP_B, 17, bytes(seg)))
    pkt[8] ^= 0x01
    layers = decode(eth_frame(MAC_B, MAC_A, 0x0800, bytes(pkt)))
    assert layers[1].anomalies == ("bad ipv4 header checksum",)
    assert layers[2].anomalies == ("bad udp checksum",)


def test_fragments_are_not_decoded_further() -> None:
    frag = ipv4_packet(IP_A, IP_B, 17, b"x" * 30, flags_frag=0x2000 | 4)
    layers = decode(eth_frame(MAC_B, MAC_A, 0x0800, frag))
    assert tuple(type(layer) for layer in layers) == (Ethernet, IPv4)


def test_unknown_ethertype_stops_after_ethernet() -> None:
    layers = decode(eth_frame(MAC_B, MAC_A, 0x88CC, b"lldp"))
    assert len(layers) == 1
    assert layers[0].error is None


def test_error_in_a_layer_stops_decoding() -> None:
    frame = eth_frame(MAC_B, MAC_A, 0x0800, b"\x45" + bytes(9))  # cut-off IPv4 header
    layers = decode(frame[:24])
    assert len(layers) == 2
    assert layers[1].error is not None


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    for blob in blobs:
        describe(decode(blob), len(blob))
        for ethertype in (0x0800, 0x86DD, 0x0806, 0x8100):
            describe(decode(MAC_B + MAC_A + ethertype.to_bytes(2, "big") + blob), len(blob))


def test_every_truncation_of_every_packet_never_raises() -> None:
    for packet in generate():
        for n in range(len(packet.data) + 1):
            describe(decode(packet.data[:n]), packet.orig_len)


def test_byte_corruption_never_raises() -> None:
    rng = random.Random(99)
    for packet in generate():
        for i in range(len(packet.data)):
            for value in (0, 0xFF, rng.randrange(256), rng.randrange(256)):
                bad = bytearray(packet.data)
                bad[i] = value
                describe(decode(bytes(bad)), packet.orig_len)


def test_decode_is_deterministic() -> None:
    for packet in generate():
        assert decode(packet.data) == decode(packet.data)
