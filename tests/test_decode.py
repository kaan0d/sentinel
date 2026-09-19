import random

from sentinel.proto.arp import Arp
from sentinel.proto.decode import decode
from sentinel.proto.dns import Dns
from sentinel.proto.ethernet import Ethernet
from sentinel.proto.http import Http
from sentinel.proto.icmp import Icmp
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.ipv6 import IPv6
from sentinel.proto.tcp import Tcp
from sentinel.proto.tls import TlsClientHello
from sentinel.proto.udp import Udp
from sentinel.summary import describe
from tools.gen_pcap import (
    CLIENT_HELLO,
    IP_A,
    IP_B,
    MAC_A,
    MAC_B,
    client_hello,
    dns_query,
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
    (Ethernet, IPv4, Tcp, Http),
    (Ethernet, IPv4, Tcp),
    (Ethernet, IPv4, Udp, Dns),
    (Ethernet, IPv4, Udp, Dns),
    (Ethernet, IPv6, Tcp),
    (Ethernet, IPv6, Udp, Dns),
    (Ethernet, IPv4, Udp, Dns),
    (Ethernet, IPv4, Udp, Dns),
    (Ethernet, IPv4, Tcp, Dns),
    (Ethernet, IPv4, Tcp, Http),
    (Ethernet, IPv4, Tcp, TlsClientHello),
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


def test_later_fragments_are_not_decoded_further() -> None:
    for flags_frag in (0x2000 | 4, 4):  # a middle fragment and the last one
        frag = ipv4_packet(IP_A, IP_B, 17, b"x" * 30, flags_frag=flags_frag)
        layers = decode(eth_frame(MAC_B, MAC_A, 0x0800, frag))
        assert tuple(type(layer) for layer in layers) == (Ethernet, IPv4)


def test_a_first_fragment_is_decoded_but_its_checksum_is_not_verified() -> None:
    datagram = bytearray(udp_datagram(IP_A, IP_B, 5000, 6000, b"payload"))
    datagram[-1] ^= 0xFF  # the checksum is now wrong
    whole = ipv4_packet(IP_A, IP_B, 17, bytes(datagram))
    first = ipv4_packet(IP_A, IP_B, 17, bytes(datagram), flags_frag=0x2000)
    assert decode(eth_frame(MAC_B, MAC_A, 0x0800, whole))[2].anomalies == ("bad udp checksum",)
    layers = decode(eth_frame(MAC_B, MAC_A, 0x0800, first))
    assert tuple(type(layer) for layer in layers) == (Ethernet, IPv4, Udp)
    udp = layers[2]
    assert isinstance(udp, Udp)
    assert (udp.src_port, udp.dst_port) == (5000, 6000)
    assert udp.anomalies == ()  # the message is not whole, so nothing to verify


def test_a_first_fragment_of_a_longer_message_is_decoded_with_its_own_anomaly() -> None:
    datagram = udp_datagram(IP_A, IP_B, 5000, 53, b"x" * 40)
    first = ipv4_packet(IP_A, IP_B, 17, datagram[:20], flags_frag=0x2000)
    udp = decode(eth_frame(MAC_B, MAC_A, 0x0800, first))[2]
    assert isinstance(udp, Udp)
    assert udp.anomalies == ("truncated udp datagram: length 48, captured 20",)


def test_a_frame_with_a_length_instead_of_an_ethertype_stops_after_ethernet() -> None:
    for length in (0x0026, 0x05FF):  # 802.3 with an LLC header behind it
        layers = decode(eth_frame(MAC_B, MAC_A, length, b"llc payload"))
        assert len(layers) == 1
        assert isinstance(layers[0], Ethernet)
        assert layers[0].error is None
        assert layers[0].ethertype == length


def test_the_summary_says_802_3_below_0x0600_and_an_ethertype_from_there_on() -> None:
    below = describe(decode(eth_frame(MAC_B, MAC_A, 0x05FF, b"x" * 20)), 60)
    assert below.endswith(", 802.3, length 60")
    assert "ethertype" not in below
    from_there = describe(decode(eth_frame(MAC_B, MAC_A, 0x0600, b"x" * 20)), 60)
    assert from_there.endswith(", ethertype 0x0600, length 60")
    tagged = describe(decode(eth_frame(MAC_B, MAC_A, 0x0026, b"x" * 20, vlan=5)), 64)
    assert tagged.startswith("vlan 5, ")
    assert tagged.endswith(", 802.3, length 64")


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


def tcp_frame(sport: int, dport: int, payload: bytes) -> bytes:
    seg = tcp_segment(IP_A, IP_B, sport, dport, 1, 1, 0x18, payload=payload)
    return eth_frame(MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 6, seg))


def test_http_and_tls_are_found_by_content_not_port() -> None:
    http = decode(tcp_frame(50000, 8080, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert isinstance(http[-1], Http)
    tls = decode(tcp_frame(50000, 8443, CLIENT_HELLO))
    assert isinstance(tls[-1], TlsClientHello)


def test_other_tcp_payloads_get_no_application_layer() -> None:
    layers = decode(tcp_frame(50000, 8080, b"\x00\x01binary"))
    assert tuple(type(layer) for layer in layers) == (Ethernet, IPv4, Tcp)


def test_tcp_dns_split_across_segments_is_left_alone() -> None:
    query = dns_query(7, "example.com")
    prefixed = len(query).to_bytes(2) + query
    whole = decode(tcp_frame(50000, 53, prefixed))
    dns = whole[-1]
    assert isinstance(dns, Dns)
    assert dns.questions[0].name == "example.com"
    for cut in (1, 2, 10, len(prefixed) - 1):  # needs stream reassembly (stage 3)
        assert isinstance(decode(tcp_frame(50000, 53, prefixed[:cut]))[-1], Tcp)


def test_application_errors_and_anomalies_show_up_in_the_summary() -> None:
    frame = eth_frame(
        MAC_B,
        MAC_A,
        0x0800,
        ipv4_packet(IP_A, IP_B, 17, udp_datagram(IP_A, IP_B, 5000, 53, b"xyz")),
    )
    line = describe(decode(frame), len(frame))
    assert line.endswith("[error: truncated dns header: 3 of 12 bytes]")
    cut = decode(tcp_frame(50000, 443, CLIENT_HELLO)[:120])
    assert "[truncated client hello:" in describe(cut, 200)


def test_snaplen_cut_client_hello_gives_no_false_checksum_anomaly() -> None:
    layers = decode(tcp_frame(50000, 443, CLIENT_HELLO)[:120])
    assert [a for layer in layers for a in layer.anomalies if "checksum" in a] == []


def test_summary_never_prints_control_characters() -> None:
    payload = b"GET /a\x1b[2J HTTP/1.1\r\nHost: \x07\x1b]0;pwned\x07\r\n\r\n"
    frame = tcp_frame(50000, 80, payload)
    line = describe(decode(frame), len(frame))
    assert line.isprintable()
    assert "\\x1b" in line
    hello = client_hello("a\x1b[31m.test", [0x0304], [0x1301])
    assert describe(decode(tcp_frame(50000, 443, hello)), 300).isprintable()
