import random
from ipaddress import IPv4Address, IPv6Address, ip_network

import pytest

from sentinel.filter import parse_filter
from sentinel.filter.nodes import (
    And,
    Direction,
    Expr,
    FilterError,
    Host,
    Net,
    Not,
    Or,
    Port,
    Proto,
    Vlan,
    format_expr,
)
from sentinel.filter.parser import MAX_DEPTH, parse

TCP, UDP, ICMP, ARP = Proto("tcp"), Proto("udp"), Proto("icmp"), Proto("arp")


def tree(text: str) -> Expr:
    result = parse(text)
    assert not isinstance(result, FilterError), (text, result)
    return result


def error(text: str) -> FilterError:
    result = parse(text)
    assert isinstance(result, FilterError), (text, result)
    return result


def test_the_documented_example() -> None:
    assert tree("tcp and (port 80 or port 443) and not src host 10.0.0.1") == And(
        (
            TCP,
            Or((Port(None, 80, 80), Port(None, 443, 443))),
            Not(Host("src", IPv4Address("10.0.0.1"))),
        )
    )


def test_or_binds_looser_than_and_and_not_binds_tighter() -> None:
    assert tree("tcp or udp and icmp") == Or((TCP, And((UDP, ICMP))))
    assert tree("tcp and udp or icmp") == Or((And((TCP, UDP)), ICMP))
    assert tree("not tcp and udp") == And((Not(TCP), UDP))
    assert tree("not (tcp and udp)") == Not(And((TCP, UDP)))
    assert tree("!!tcp") == Not(Not(TCP))


def test_parentheses_group_and_nested_same_operators_are_flattened() -> None:
    assert tree("(tcp or udp) and icmp") == And((Or((TCP, UDP)), ICMP))
    assert tree("(tcp and udp) and icmp") == And((TCP, UDP, ICMP))
    assert tree("tcp and (udp and icmp) and arp") == And((TCP, UDP, ICMP, ARP))
    assert tree("tcp or (udp or icmp)") == Or((TCP, UDP, ICMP))
    assert tree("((tcp))") == TCP


def test_symbol_operators_and_case() -> None:
    assert tree("TCP && !UDP || icmp") == Or((And((TCP, Not(UDP))), ICMP))
    assert tree("HOST 10.0.0.1") == Host(None, IPv4Address("10.0.0.1"))


def test_protocol_followed_by_a_qualifier_is_an_implicit_and() -> None:
    assert tree("tcp port 80") == And((TCP, Port(None, 80, 80)))
    assert tree("udp dst port 53") == And((UDP, Port("dst", 53, 53)))
    assert tree("ip host 10.0.0.1") == And((Proto("ip"), Host(None, IPv4Address("10.0.0.1"))))
    assert tree("ip6 src net 2001:db8::/32") == And(
        (Proto("ip6"), Net("src", ip_network("2001:db8::/32")))
    )
    assert tree("tcp portrange 1-2 or udp") == Or((And((TCP, Port(None, 1, 2))), UDP))


def test_qualifiers() -> None:
    assert tree("src host ::1") == Host("src", IPv6Address("::1"))
    assert tree("dst host 192.0.2.7") == Host("dst", IPv4Address("192.0.2.7"))
    assert tree("net 10.0.0.0/8") == Net(None, ip_network("10.0.0.0/8"))
    assert tree("dst net 10.1.0.0/16") == Net("dst", ip_network("10.1.0.0/16"))
    assert tree("src port 80") == Port("src", 80, 80)
    assert tree("dst portrange 5000-6000") == Port("dst", 5000, 6000)
    assert tree("portrange 80-80") == Port(None, 80, 80) == tree("port 80")


def test_networks_may_have_host_bits_set() -> None:
    assert tree("net 10.1.2.3/8") == Net(None, ip_network("10.0.0.0/8"))
    assert tree("net 10.0.0.1") == Net(None, ip_network("10.0.0.1/32"))


def test_vlan() -> None:
    assert tree("vlan") == Vlan(None)
    assert tree("vlan 100") == Vlan(100)
    assert tree("vlan and tcp") == And((Vlan(None), TCP))
    assert tree("vlan 0 or vlan 4095") == Or((Vlan(0), Vlan(4095)))


def test_number_limits() -> None:
    assert tree("port 0") == Port(None, 0, 0)
    assert tree("port 65535") == Port(None, 65535, 65535)
    assert error("port 65536").message == "expected a port number (0-65535), got '65536'"
    assert error("vlan 4096").message == "expected a VLAN id (0-4095), got '4096'"
    assert error("portrange 90-80").message == "invalid port range '90-80'"
    assert error("portrange 1-65536").message == "invalid port range '1-65536'"


@pytest.mark.parametrize(
    ("text", "message", "position"),
    [
        ("", "empty filter", 0),
        ("   ", "empty filter", 0),
        ("tcp and", "unexpected end of filter, expected a filter primitive or '('", 7),
        ("and tcp", "unexpected 'and', expected a filter primitive or '('", 0),
        ("tcp udp", "unexpected 'udp', expected 'and', 'or' or end of filter", 4),
        ("(tcp", "expected ')'", 4),
        ("(tcp udp)", "expected ')'", 5),
        ("tcp )", "unexpected ')', expected 'and', 'or' or end of filter", 4),
        ("()", "unexpected ')', expected a filter primitive or '('", 1),
        ("tcp and and udp", "unexpected 'and', expected a filter primitive or '('", 8),
        ("not", "unexpected end of filter, expected a filter primitive or '('", 3),
        ("src", "unexpected end of filter, expected host, net, port or portrange", 3),
        ("src tcp", "expected host, net, port or portrange, got 'tcp'", 4),
        ("src src host 1.2.3.4", "expected host, net, port or portrange, got 'src'", 4),
        ("host", "unexpected end of filter, expected an IP address", 4),
        ("host example.com", "expected an IP address, got 'example.com'", 5),
        ("host 10.0.0.256", "expected an IP address, got '10.0.0.256'", 5),
        ("host 10.0.0.0/8", "expected an IP address, got '10.0.0.0/8'", 5),
        ("net 10.0.0.0/33", "expected a network like 10.0.0.0/8, got '10.0.0.0/33'", 4),
        ("net bogus", "expected a network like 10.0.0.0/8, got 'bogus'", 4),
        ("port", "unexpected end of filter, expected a port number", 4),
        ("tcp and port http", "expected a port number (0-65535), got 'http'", 13),
        ("port -1", "expected a port number (0-65535), got '-1'", 5),
        ("portrange 80", "expected a port range like 80-90, got '80'", 10),
        ("portrange 80-", "expected a port range like 80-90, got '80-'", 10),
        ("portrange a-b", "expected a port range like 80-90, got 'a-b'", 10),
        ("portrange 1-2-3", "expected a port range like 80-90, got '1-2-3'", 10),
        ("banana", "unknown filter word 'banana'", 0),
        ("tcp or bananas and udp", "unknown filter word 'bananas'", 7),
        ("tcp @", "unexpected character '@'", 4),
        ("tcp & udp", "unexpected '&', did you mean '&&'?", 4),
    ],
)
def test_error_messages_and_positions(text: str, message: str, position: int) -> None:
    assert error(text) == FilterError(message, position)


def test_nesting_depth_is_limited() -> None:
    assert isinstance(parse("(" * (MAX_DEPTH - 1) + "tcp" + ")" * (MAX_DEPTH - 1)), Proto)
    too_deep = "(" * (MAX_DEPTH + 1) + "tcp" + ")" * (MAX_DEPTH + 1)
    assert "nested more than 100 levels" in error(too_deep).message
    assert "nested more than 100 levels" in error("not " * (MAX_DEPTH + 1) + "tcp").message
    assert isinstance(parse("not " * (MAX_DEPTH - 1) + "tcp"), Not)


def test_a_long_flat_chain_is_one_node() -> None:
    chain = tree(" and ".join(["tcp"] * 400))
    assert isinstance(chain, And)
    assert len(chain.operands) == 400


def test_huge_tokens_do_not_break_or_flood_messages() -> None:
    huge = "9" * 20000
    for text in (
        f"port {huge}",
        f"portrange {huge}-1",
        f"vlan {huge}",
        f"host {huge}",
        f"net {huge}",
    ):
        result = error(text)
        assert len(result.message) < 120
    assert len(error("bad" + "x" * 5000).message) < 120


def test_filter_object() -> None:
    good = parse_filter("tcp   and (port 80 or port 443)")
    assert good.error is None
    assert str(good) == "tcp and (port 80 or port 443)"
    bad = parse_filter("tcp and port http")
    assert bad.error == "expected a port number (0-65535), got 'http'"
    assert bad.position == 13
    assert bad.describe_error() == [bad.error, "  tcp and port http", "  " + " " * 13 + "^"]
    assert bad.matches(()) is False
    assert str(bad) == "tcp and port http"


def rand_expr(rng: random.Random, depth: int = 0) -> Expr:
    roll = rng.random()
    if depth >= 4 or roll < 0.35:
        return rand_primitive(rng)
    if roll < 0.5:
        return Not(rand_expr(rng, depth + 1))
    kind = And if roll < 0.75 else Or
    items: list[Expr] = []
    for _ in range(rng.randint(2, 4)):
        item = rand_expr(rng, depth + 1)
        items += item.operands if isinstance(item, kind) else [item]
    return kind(tuple(items))


def rand_primitive(rng: random.Random) -> Expr:
    direction: Direction = rng.choice([None, "src", "dst"])
    kind = rng.randrange(6)
    if kind == 0:
        return Proto(rng.choice(["ip", "ip6", "arp", "tcp", "udp", "icmp", "dns", "http", "tls"]))
    if kind == 1:
        return Vlan(rng.choice([None, 0, 7, 4095]))
    if kind == 2:
        options: list[IPv4Address | IPv6Address] = [
            IPv4Address(rng.getrandbits(32)),
            IPv6Address(rng.getrandbits(128)),
        ]
        return Host(direction, rng.choice(options))
    if kind == 3:
        v6 = rng.random() < 0.5
        bits = 128 if v6 else 32
        raw = rng.getrandbits(bits)
        prefix = rng.randint(0, bits)
        base = IPv6Address(raw) if v6 else IPv4Address(raw)
        return Net(direction, ip_network((base, prefix), strict=False))
    lo = rng.randrange(65536)
    hi = lo if kind == 4 else rng.randint(lo, 65535)
    return Port(direction, lo, hi)


def test_printing_a_tree_and_parsing_it_back_gives_the_same_tree() -> None:
    rng = random.Random(77)
    for _ in range(1500):
        expr = rand_expr(rng)
        assert tree(format_expr(expr)) == expr, format_expr(expr)


def test_parsing_is_stable_under_reprinting() -> None:
    rng = random.Random(78)
    words = [
        "tcp",
        "udp",
        "and",
        "or",
        "not",
        "(",
        ")",
        "!",
        "&&",
        "||",
        "port",
        "80",
        "host",
        "1.2.3.4",
    ]
    words += ["src", "dst", "net", "10.0.0.0/8", "portrange", "1-9", "vlan", "5", "arp", "icmp"]
    parsed = 0
    for _ in range(20000):
        text = " ".join(rng.choice(words) for _ in range(rng.randint(1, 6)))
        result = parse(text)
        if isinstance(result, FilterError):
            assert 0 <= result.position <= len(text)
            continue
        parsed += 1
        assert tree(format_expr(result)) == result, text
    assert parsed > 300  # the soup is not all errors


def test_random_text_never_raises() -> None:
    rng = random.Random(79)
    for _ in range(3000):
        text = "".join(chr(rng.randrange(0x300)) for _ in range(rng.randint(0, 60)))
        result = parse(text)
        if isinstance(result, FilterError):
            assert 0 <= result.position <= max(len(text), 0)
