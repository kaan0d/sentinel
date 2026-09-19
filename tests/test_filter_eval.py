"""The evaluator against hand-written predicates on a corpus of decoded packets.

Each predicate below is written straight from the meaning of the filter word, on the decoded
layers, without using the filter code. Random combinations (and, or, not) of these primitives are
compared with Python's own `and`, `or`, `not` over the same predicates."""

import random
from collections.abc import Callable, Sequence
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

import pytest

from sentinel.filter import parse_filter
from sentinel.proto.arp import Arp
from sentinel.proto.decode import decode
from sentinel.proto.dns import Dns
from sentinel.proto.ethernet import Ethernet
from sentinel.proto.http import Http
from sentinel.proto.icmp import Icmp
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.ipv6 import IPv6
from sentinel.proto.layer import Layer
from sentinel.proto.tcp import Tcp
from sentinel.proto.tls import TlsClientHello
from sentinel.proto.udp import Udp
from tools.gen_pcap import (
    IP6_A,
    IP6_B,
    IP_A,
    IP_B,
    MAC_A,
    MAC_B,
    eth_frame,
    generate,
    generate_streams,
    ipv4_packet,
    ipv6_packet,
    tcp_segment,
    udp_datagram,
)

Address = IPv4Address | IPv6Address
Layers = Sequence[Layer]
Predicate = Callable[[Layers], bool]


def extra_frames() -> list[bytes]:
    syn = tcp_segment(IP_A, IP_B, 4000, 8080, 1, 0, 2)
    tcp_v4 = ipv4_packet(IP_A, IP_B, 6, syn)
    double_tag = (MAC_B + MAC_A + bytes.fromhex("88a80064810000070800") + tcp_v4).ljust(60, b"\0")
    return [
        eth_frame(MAC_B, MAC_A, 0x0800, tcp_v4)[: 14 + 20 + 10],  # a TCP header cut short: an error
        eth_frame(MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 6, syn, flags_frag=0x2000)),
        eth_frame(MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 6, syn, flags_frag=0x0008)),
        eth_frame(MAC_B, MAC_A, 0x0800, tcp_v4, vlan=7),
        double_tag,
        eth_frame(
            MAC_B,
            MAC_A,
            0x86DD,
            ipv6_packet(IP6_B, IP6_A, 17, udp_datagram(IP6_B, IP6_A, 9, 5060, b"x")),
        ),
        b"junk",
        bytes(60),
        eth_frame(MAC_B, MAC_A, 0x0800, b"\x45" + bytes(9)),  # IPv4 header cut short
    ]


def corpus() -> list[Layers]:
    frames = [p.data for p in generate()] + [p.data for p in generate_streams()] + extra_frames()
    rng = random.Random(3)
    frames += [rng.randbytes(rng.randint(0, 120)) for _ in range(20)]
    return [decode(f) for f in frames]


CORPUS = corpus()


def has(layers: Layers, *kinds: type[Layer]) -> bool:
    return any(isinstance(layer, kinds) for layer in layers)


def addrs(layers: Layers) -> tuple[Address, Address] | None:
    for layer in layers:
        if isinstance(layer, IPv4 | IPv6) and layer.error is None:
            return layer.src, layer.dst
        if isinstance(layer, Arp) and layer.error is None:
            return layer.sender_ip, layer.target_ip
    return None


def ports(layers: Layers) -> tuple[int, int] | None:
    for layer in layers:
        if isinstance(layer, Tcp | Udp) and layer.error is None:
            return layer.src_port, layer.dst_port
    return None


def vlans(layers: Layers) -> tuple[int, ...]:
    eth = layers[0]
    return eth.vlans if isinstance(eth, Ethernet) and eth.error is None else ()


def host_pred(direction: str | None, text: str) -> Predicate:
    want = ip_address(text)

    def pred(layers: Layers) -> bool:
        pair = addrs(layers)
        if pair is None:
            return False
        src, dst = pair
        if direction == "src":
            return src == want
        if direction == "dst":
            return dst == want
        return want in (src, dst)

    return pred


def net_pred(direction: str | None, text: str) -> Predicate:
    net = ip_network(text)

    def inside(a: Address) -> bool:
        return a.version == net.version and int(a) & int(net.netmask) == int(net.network_address)

    def pred(layers: Layers) -> bool:
        pair = addrs(layers)
        if pair is None:
            return False
        if direction == "src":
            return inside(pair[0])
        if direction == "dst":
            return inside(pair[1])
        return inside(pair[0]) or inside(pair[1])

    return pred


def port_pred(direction: str | None, lo: int, hi: int) -> Predicate:
    def pred(layers: Layers) -> bool:
        pair = ports(layers)
        if pair is None:
            return False
        if direction == "src":
            return lo <= pair[0] <= hi
        if direction == "dst":
            return lo <= pair[1] <= hi
        return lo <= pair[0] <= hi or lo <= pair[1] <= hi

    return pred


PRIMITIVES: list[tuple[str, Predicate]] = [
    ("ip", lambda L: has(L, IPv4)),
    ("ip6", lambda L: has(L, IPv6)),
    ("arp", lambda L: has(L, Arp)),
    ("tcp", lambda L: has(L, Tcp)),
    ("udp", lambda L: has(L, Udp)),
    ("icmp", lambda L: has(L, Icmp)),
    ("dns", lambda L: has(L, Dns)),
    ("http", lambda L: has(L, Http)),
    ("tls", lambda L: has(L, TlsClientHello)),
    ("vlan", lambda L: bool(vlans(L))),
    ("vlan 100", lambda L: 100 in vlans(L)),
    ("vlan 7", lambda L: 7 in vlans(L)),
    ("host 10.0.0.1", host_pred(None, "10.0.0.1")),
    ("src host 10.0.0.1", host_pred("src", "10.0.0.1")),
    ("dst host 10.0.0.1", host_pred("dst", "10.0.0.1")),
    ("host 10.0.0.2", host_pred(None, "10.0.0.2")),
    ("dst host 10.0.0.2", host_pred("dst", "10.0.0.2")),
    ("host 2001:db8::1", host_pred(None, "2001:db8::1")),
    ("src host 2001:db8::2", host_pred("src", "2001:db8::2")),
    ("net 10.0.0.0/24", net_pred(None, "10.0.0.0/24")),
    ("src net 10.0.0.0/30", net_pred("src", "10.0.0.0/30")),
    ("dst net 10.0.0.2/32", net_pred("dst", "10.0.0.2/32")),
    ("net 192.168.0.0/16", net_pred(None, "192.168.0.0/16")),
    ("net 2001:db8::/32", net_pred(None, "2001:db8::/32")),
    ("dst net 2001:db8::/126", net_pred("dst", "2001:db8::/126")),
    ("net 0.0.0.0/0", net_pred(None, "0.0.0.0/0")),
    ("port 80", port_pred(None, 80, 80)),
    ("src port 80", port_pred("src", 80, 80)),
    ("dst port 53", port_pred("dst", 53, 53)),
    ("port 443", port_pred(None, 443, 443)),
    ("portrange 40000-50000", port_pred(None, 40000, 50000)),
    ("src portrange 53000-53004", port_pred("src", 53000, 53004)),
    ("dst portrange 1-100", port_pred("dst", 1, 100)),
    ("src port 53", port_pred("src", 53, 53)),
]


@pytest.mark.parametrize(("text", "predicate"), PRIMITIVES, ids=[t for t, _ in PRIMITIVES])
def test_each_primitive_matches_its_predicate_on_the_corpus(
    text: str, predicate: Predicate
) -> None:
    flt = parse_filter(text)
    assert flt.error is None
    for layers in CORPUS:
        assert flt.matches(layers) == predicate(layers), (text, [type(x).__name__ for x in layers])


def test_the_primitives_are_not_all_trivially_true_or_false() -> None:
    for text, predicate in PRIMITIVES:
        hits = sum(predicate(layers) for layers in CORPUS)
        assert 0 < hits < len(CORPUS) or text in ("net 0.0.0.0/0", "net 192.168.0.0/16"), text


def test_implicit_and_forms_match_the_written_out_forms() -> None:
    pairs = [
        ("tcp port 80", "tcp and port 80"),
        ("udp dst port 53", "udp and dst port 53"),
        ("ip host 10.0.0.1", "ip and host 10.0.0.1"),
        ("ip6 host 2001:db8::1", "ip6 and host 2001:db8::1"),
    ]
    for short, long in pairs:
        a, b = parse_filter(short), parse_filter(long)
        assert [a.matches(x) for x in CORPUS] == [b.matches(x) for x in CORPUS]


def test_precedence_matches_python() -> None:
    def tcp(L: Layers) -> bool:
        return has(L, Tcp)

    def udp(L: Layers) -> bool:
        return has(L, Udp)

    def p53(L: Layers) -> bool:
        return port_pred(None, 53, 53)(L)

    def p80(L: Layers) -> bool:
        return port_pred(None, 80, 80)(L)

    cases: list[tuple[str, Predicate]] = [
        ("tcp or udp and port 53", lambda L: tcp(L) or (udp(L) and p53(L))),
        ("tcp and port 80 or udp", lambda L: (tcp(L) and p80(L)) or udp(L)),
        ("not tcp and port 53", lambda L: (not tcp(L)) and p53(L)),
        ("not (tcp and port 53)", lambda L: not (tcp(L) and p53(L))),
        ("!tcp || !udp", lambda L: (not tcp(L)) or (not udp(L))),
        (
            "(tcp or udp) and (port 53 or port 80)",
            lambda L: (tcp(L) or udp(L)) and (p53(L) or p80(L)),
        ),
        ("!!tcp", tcp),
    ]
    for text, predicate in cases:
        flt = parse_filter(text)
        assert flt.error is None, text
        assert [flt.matches(x) for x in CORPUS] == [predicate(x) for x in CORPUS], text


def random_combination(rng: random.Random, depth: int = 0) -> tuple[str, Predicate]:
    roll = rng.random()
    if depth >= 3 or roll < 0.3:
        return rng.choice(PRIMITIVES)
    if roll < 0.45:
        text, pred = random_combination(rng, depth + 1)
        return f"not ({text})", lambda L, p=pred: not p(L)
    parts = [random_combination(rng, depth + 1) for _ in range(rng.randint(2, 4))]
    joined = [f"({t})" for t, _ in parts]
    preds = [p for _, p in parts]
    if roll < 0.75:
        return " and ".join(joined), lambda L, ps=preds: all(p(L) for p in ps)
    return " or ".join(joined), lambda L, ps=preds: any(p(L) for p in ps)


def test_random_combinations_match_python_logic_on_the_corpus() -> None:
    rng = random.Random(4242)
    for _ in range(400):
        text, predicate = random_combination(rng)
        flt = parse_filter(text)
        assert flt.error is None, text
        for layers in CORPUS:
            assert flt.matches(layers) == predicate(layers), text


def test_known_counts_on_the_default_demo_capture() -> None:
    demo = [decode(p.data) for p in generate()]

    def count(text: str) -> int:
        flt = parse_filter(text)
        assert flt.error is None
        return sum(flt.matches(layers) for layers in demo)

    assert len(demo) == 19
    assert {t: count(t) for t in ["arp", "icmp", "ip6", "vlan", "vlan 100", "vlan 5"]} == {
        "arp": 2,
        "icmp": 3,
        "ip6": 2,
        "vlan": 1,
        "vlan 100": 1,
        "vlan 5": 0,
    }
    assert (count("ip"), count("tcp"), count("udp")) == (15, 9, 5)
    assert (count("dns"), count("http"), count("tls")) == (6, 2, 1)
    assert (count("port 80"), count("src port 80"), count("port 53"), count("port 443")) == (
        6,
        2,
        6,
        2,
    )
    assert count("host 10.0.0.1") == 17  # 15 IPv4 packets and the 2 ARP packets
    assert count("host 2001:db8::1") == 2
    assert count("tcp and (port 80 or port 443) and not src host 10.0.0.1") == 3


def test_errors_in_a_layer_are_handled_as_documented() -> None:
    cut_tcp = decode(extra_frames()[0])
    assert isinstance(cut_tcp[-1], Tcp)
    assert cut_tcp[-1].error is not None
    assert parse_filter("tcp").matches(cut_tcp)  # still a TCP packet
    assert not parse_filter("port 4000").matches(cut_tcp)  # but its ports cannot be trusted
    assert not parse_filter("port 0").matches(cut_tcp)  # not even the zeros left in their place
    assert parse_filter("host 10.0.0.1").matches(cut_tcp)  # the IP header is fine
    cut_ip = decode(extra_frames()[-1])
    assert parse_filter("ip").matches(cut_ip)
    assert not parse_filter("host 10.0.0.1").matches(cut_ip)
    assert not parse_filter("host 0.0.0.0").matches(cut_ip)  # nor the zero address left behind
    assert not parse_filter("net 0.0.0.0/0").matches(cut_ip)


def test_ip_fragments_match_ip_but_not_tcp() -> None:
    # decode() does not look past the IP header of a fragment, first or later.
    for frame in (extra_frames()[1], extra_frames()[2]):
        layers = decode(frame)
        assert parse_filter("ip").matches(layers)
        assert not parse_filter("tcp").matches(layers)
        assert parse_filter("host 10.0.0.1").matches(layers)
        assert not parse_filter("port 4000").matches(layers)


def test_any_vlan_tag_counts() -> None:
    double = decode(extra_frames()[4])
    assert parse_filter("vlan 100").matches(double)
    assert parse_filter("vlan 7").matches(double)
    assert parse_filter("vlan").matches(double)
    assert not parse_filter("vlan 8").matches(double)


def test_address_families_never_match_each_other() -> None:
    v4, v6 = decode(generate()[5].data), decode(generate()[12].data)
    assert not parse_filter("net ::/0").matches(v4)
    assert not parse_filter("net 0.0.0.0/0").matches(v6)
    assert parse_filter("net ::/0").matches(v6)


def test_matching_never_raises_on_random_frames() -> None:
    rng = random.Random(5)
    filters = [parse_filter(t) for t, _ in PRIMITIVES]
    for _ in range(300):
        layers = decode(rng.randbytes(rng.randint(0, 200)))
        for flt in filters:
            flt.matches(layers)
