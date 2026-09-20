"""The SSH brute force and ICMP tunnel detectors (stage 10)."""

import random
from ipaddress import IPv4Address, IPv6Address

import pytest

from sentinel.ids import Engine, parse_rules
from sentinel.ids.detectors import DETECTORS, Detection, Detector, IcmpTunnel, SshBruteForce
from sentinel.ids.view import make_view
from sentinel.pcap import Packet
from sentinel.proto import tcp
from sentinel.proto.decode import decode
from sentinel.proto.icmp import Icmp
from sentinel.proto.ipv4 import IPv4
from tools.gen_pcap import (
    IP6_A,
    IP6_B,
    MAC_A,
    MAC_B,
    Timeline,
    eth_frame,
    generate_attacks,
    generate_benign,
    icmp_message,
    ipv4_packet,
    ipv6_packet,
    tcp_segment,
)

CLIENT = IPv4Address("10.0.2.9")
OTHER = IPv4Address("10.0.2.10")
SERVER = IPv4Address("10.0.0.31")
OTHER_SERVER = IPv4Address("10.0.0.32")


def feed(detector: Detector, packets: list[Packet]) -> list[Detection]:
    out: list[Detection] = []
    for p in packets:
        out += detector.on_packet(make_view(p.ts_ns, decode(p.data)))
    return out


# ---- SSH brute force -------------------------------------------------------------------------


def ssh(**config: float) -> SshBruteForce:
    detector = SshBruteForce.create(config)
    assert isinstance(detector, SshBruteForce)
    return detector


def connections(
    n: int,
    *,
    gap: float = 0.1,
    start: float = 0.0,
    client: IPv4Address = CLIENT,
    server: IPv4Address = SERVER,
    port: int = 22,
    first_port: int = 50000,
) -> list[Packet]:
    t = Timeline()
    for i in range(n):
        t.handshake(start + i * gap, client, first_port + i, server, port)
    return t.packets()


def test_the_defaults() -> None:
    assert SshBruteForce.name == "ssh_brute_force"
    assert DETECTORS["ssh_brute_force"] is SshBruteForce
    assert SshBruteForce.severity == "medium"
    defaults = {p.name: p.default for p in SshBruteForce.params}
    assert defaults == {"port": 22, "connections": 10, "window_seconds": 60.0}


def test_it_fires_exactly_at_the_threshold() -> None:
    assert feed(ssh(), connections(9)) == []
    packets = connections(10)
    (found,) = feed(ssh(), packets)
    assert found.ts_ns == packets[-1].ts_ns  # at the ACK that completes the tenth
    assert found.message == "10.0.2.9 made 10 connections to the SSH port of 10.0.0.31 in 0.9s"
    assert (found.src, found.dst) == ("10.0.2.9", "10.0.0.31")
    assert found.evidence == {"connections": 10, "port": 22, "seconds": 0.9}


def test_the_number_of_connections_is_a_parameter() -> None:
    assert feed(ssh(connections=3), connections(2)) == []
    (found,) = feed(ssh(connections=3), connections(3))
    assert found.evidence["connections"] == 3
    assert len(feed(ssh(connections=1), connections(1))) == 1


def test_connections_that_do_not_complete_are_not_counted() -> None:
    t = Timeline()
    for i in range(50):  # SYNs that are never answered
        t.tcp(i * 0.01, CLIENT, 50000 + i, SERVER, 22, 1000, 0, tcp.SYN)
    assert feed(ssh(), t.packets()) == []
    t = Timeline()
    for i in range(50):  # SYNs that are refused
        t.tcp(i * 0.01, CLIENT, 50000 + i, SERVER, 22, 1000, 0, tcp.SYN)
        t.tcp(i * 0.01 + 0.001, SERVER, 22, CLIENT, 50000 + i, 0, 1001, tcp.RST | tcp.ACK)
        t.tcp(i * 0.01 + 0.002, CLIENT, 50000 + i, SERVER, 22, 1001, 0, tcp.RST)
    assert feed(ssh(), t.packets()) == []


def test_only_the_ack_that_completes_the_handshake_counts() -> None:
    t = Timeline()
    for i in range(9):
        t.handshake(i * 0.1, CLIENT, 50000 + i, SERVER, 22)
        for k in range(5):  # data and acknowledgements on the same connection
            t.tcp(i * 0.1 + 0.01 * (k + 1), CLIENT, 50000 + i, SERVER, 22, 1001, 5001, tcp.ACK)
    assert feed(ssh(), t.packets()) == []
    t = Timeline()
    for i in range(20):  # ACKs of connections whose start was not captured
        t.tcp(i * 0.01, CLIENT, 50000 + i, SERVER, 22, 1001, 5001, tcp.ACK)
    assert feed(ssh(), t.packets()) == []


def test_a_retransmitted_syn_is_one_connection() -> None:
    t = Timeline()
    for i in range(9):
        t.tcp(i * 0.1, CLIENT, 50000 + i, SERVER, 22, 1000, 0, tcp.SYN)
        t.tcp(i * 0.1 + 0.05, CLIENT, 50000 + i, SERVER, 22, 1000, 0, tcp.SYN)  # again
        t.tcp(i * 0.1 + 0.06, CLIENT, 50000 + i, SERVER, 22, 1001, 5001, tcp.ACK)
    assert feed(ssh(), t.packets()) == []


def test_other_ports_are_ignored_and_the_port_is_a_parameter() -> None:
    assert feed(ssh(), connections(30, port=2222)) == []
    assert feed(ssh(), connections(30, port=80)) == []
    (found,) = feed(ssh(port=2222), connections(10, port=2222))
    assert found.evidence["port"] == 2222
    assert feed(ssh(port=2222), connections(30, port=22)) == []


def test_the_window_edge() -> None:
    # Ten connections, one second apart, span 9 seconds: inside a window of 9 seconds, and
    # (1.001 seconds apart, 9.009 in all) outside it.
    assert len(feed(ssh(window_seconds=9), connections(10, gap=1.0))) == 1
    assert feed(ssh(window_seconds=9), connections(10, gap=1.001)) == []


def test_slow_guessing_is_not_seen() -> None:
    assert feed(ssh(), connections(100, gap=10.0)) == []  # 6 or 7 per minute, for 1,000 seconds


def test_clients_and_servers_are_counted_separately() -> None:
    both = connections(6, client=CLIENT) + connections(6, client=OTHER, first_port=51000)
    assert feed(ssh(), sorted(both, key=lambda p: p.ts_ns)) == []
    split = connections(5, server=SERVER) + connections(5, server=OTHER_SERVER, first_port=51000)
    assert feed(ssh(), sorted(split, key=lambda p: p.ts_ns)) == []
    two = connections(10, client=CLIENT) + connections(10, client=OTHER, first_port=51000)
    found = feed(ssh(), sorted(two, key=lambda p: p.ts_ns))
    assert sorted(d.src or "" for d in found) == ["10.0.2.10", "10.0.2.9"]


def test_one_burst_is_one_alert_until_the_window_has_passed() -> None:
    detector = ssh()
    assert len(feed(detector, connections(40))) == 1
    assert len(feed(detector, connections(12, start=200.0, first_port=52000))) == 1


def test_ipv6_is_watched_too() -> None:
    def v6(seconds: float, sport: int, flags: int, ack: int = 0) -> Packet:
        segment = tcp_segment(IP6_A, IP6_B, sport, 22, 1000, ack, flags)
        frame = eth_frame(MAC_B, MAC_A, 0x86DD, ipv6_packet(IP6_A, IP6_B, 6, segment))
        return Packet(round(seconds * 1e9), len(frame), frame)

    packets = []
    for i in range(10):
        packets += [v6(i * 0.1, 50000 + i, tcp.SYN), v6(i * 0.1 + 0.002, 50000 + i, tcp.ACK, 5001)]
    (found,) = feed(ssh(), packets)
    assert found.src == str(IPv6Address(IP6_A))
    assert found.dst == str(IPv6Address(IP6_B))


def test_the_half_open_table_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sentinel.ids.detectors.MAX_KEYS", 3)
    detector = ssh(connections=1)
    t = Timeline()
    for i in range(5):  # five SYNs, and only the newest three are remembered
        t.tcp(i * 0.01, CLIENT, 50000 + i, SERVER, 22, 1000, 0, tcp.SYN)
    feed(detector, t.packets())
    assert len(detector._pending) == 3
    t = Timeline()
    t.tcp(1.0, CLIENT, 50000, SERVER, 22, 1001, 5001, tcp.ACK)  # the oldest one is forgotten
    assert feed(detector, t.packets()) == []
    t = Timeline()
    t.tcp(1.1, CLIENT, 50004, SERVER, 22, 1001, 5001, tcp.ACK)  # the newest is not
    assert len(feed(detector, t.packets())) == 1


def test_the_table_of_pairs_is_bounded_and_forgets_idle_pairs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sentinel.ids.detectors.MAX_KEYS", 2)
    detector = ssh(connections=5)
    clients = [IPv4Address("10.0.2.20") + i for i in range(3)]
    packets: list[Packet] = []
    for i, client in enumerate(clients):
        packets += connections(1, client=client, start=i * 0.1, first_port=50000 + i)
    feed(detector, packets)
    assert len(detector._done) == 2
    assert detector.dropped == 1
    late = connections(1, client=clients[2], start=500.0, first_port=53000)
    feed(detector, late)  # everything before has been idle for longer than the window
    assert len(detector._done) == 1
    assert detector.dropped == 1


def test_the_rule_can_be_limited_with_a_filter() -> None:
    text = """
[[rule]]
id = "ssh"
detector = "ssh_brute_force"
filter = "not src host 10.0.2.9"
"""
    rules = parse_rules(text, "t")
    assert rules.errors == ()
    engine = Engine(rules.rules)
    for packet in connections(30):  # the excluded host
        engine.process(packet)
    assert engine.finish() == []
    engine = Engine(rules.rules)
    for packet in connections(30, client=OTHER):
        engine.process(packet)
    assert [a.rule for a in engine.finish()] == ["ssh"]


# ---- ICMP tunnel -----------------------------------------------------------------------------


def icmp(**config: float) -> IcmpTunnel:
    detector = IcmpTunnel.create(config)
    assert isinstance(detector, IcmpTunnel)
    return detector


def echoes(
    n: int,
    size: int,
    *,
    gap: float = 0.1,
    start: float = 0.0,
    src: IPv4Address = CLIENT,
    dst: IPv4Address = SERVER,
    ident: int = 7,
    first_seq: int = 0,
    reply: bool = False,
) -> list[Packet]:
    t = Timeline()
    for i in range(n):
        t.icmp_echo(start + i * gap, src, dst, ident, first_seq + i, bytes([i % 256]) * size, reply)
    return t.packets()


def exchange(
    n: int,
    size: int,
    *,
    changed: int = 0,
    start: float = 0.0,
    gap: float = 0.1,
    src: IPv4Address = CLIENT,
    dst: IPv4Address = SERVER,
    ident: int = 7,
) -> list[Packet]:
    """`n` requests, each answered; the first `changed` replies carry other data."""
    t = Timeline()
    for i in range(n):
        data = bytes([i % 256]) * size
        t.icmp_echo(start + i * gap, src, dst, ident, i, data)
        answer = bytes([(i + 1) % 256]) * size if i < changed else data
        t.icmp_echo(start + i * gap + 0.001, dst, src, ident, i, answer, reply=True)
    return t.packets()


def test_the_icmp_defaults() -> None:
    assert IcmpTunnel.name == "icmp_tunnel"
    assert DETECTORS["icmp_tunnel"] is IcmpTunnel
    assert IcmpTunnel.severity == "medium"
    defaults = {p.name: p.default for p in IcmpTunnel.params}
    assert defaults == {
        "min_payload_bytes": 512,
        "large_requests": 10,
        "changed_replies": 5,
        "window_seconds": 60.0,
    }


def test_large_requests_fire_exactly_at_the_threshold() -> None:
    assert feed(icmp(), echoes(9, 512)) == []
    packets = echoes(10, 512)
    (found,) = feed(icmp(), packets)
    assert found.ts_ns == packets[-1].ts_ns
    assert found.message == (
        "10.0.2.9 sent 10 echo requests of 512 bytes or more to 10.0.0.31 in 0.9s"
    )
    assert (found.src, found.dst) == ("10.0.2.9", "10.0.0.31")
    assert found.evidence == {"signal": "large_echo", "requests": 10, "bytes": 512, "seconds": 0.9}


def test_the_size_that_makes_a_request_large_is_a_parameter() -> None:
    assert feed(icmp(), echoes(30, 511)) == []  # one byte short
    assert len(feed(icmp(min_payload_bytes=100), echoes(10, 100))) == 1
    assert feed(icmp(min_payload_bytes=100), echoes(30, 99)) == []
    assert len(feed(icmp(large_requests=3), echoes(3, 600))) == 1
    assert feed(icmp(large_requests=3), echoes(2, 600)) == []


def test_only_requests_count_as_large() -> None:
    assert feed(icmp(), echoes(30, 900, reply=True)) == []


def test_large_requests_can_be_turned_off() -> None:
    assert feed(icmp(min_payload_bytes=0), echoes(30, 900)) == []


def test_normal_pings_are_left_alone() -> None:
    assert feed(icmp(), exchange(200, 56)) == []  # 56 bytes, the usual size
    assert feed(icmp(), exchange(9, 1400)) == []  # nine MTU tests, each answered as it should be


def test_the_window_edge_for_large_requests() -> None:
    assert len(feed(icmp(window_seconds=9), echoes(10, 600, gap=1.0))) == 1
    assert feed(icmp(window_seconds=9), echoes(10, 600, gap=1.001)) == []


def test_changed_replies_fire_exactly_at_the_threshold() -> None:
    assert feed(icmp(), exchange(30, 56, changed=4)) == []
    packets = exchange(30, 56, changed=5)
    (found,) = feed(icmp(), packets)
    assert found.ts_ns == packets[9].ts_ns  # the fifth changed reply, the tenth packet
    assert found.message == (
        "10.0.2.9 got 5 echo replies from 10.0.0.31 that do not repeat the data it sent, in 0.4s"
    )
    assert (found.src, found.dst) == ("10.0.2.9", "10.0.0.31")
    assert found.evidence == {"signal": "changed_reply", "replies": 5, "seconds": 0.4}


def test_the_number_of_changed_replies_is_a_parameter_and_can_be_turned_off() -> None:
    assert len(feed(icmp(changed_replies=2), exchange(5, 56, changed=2))) == 1
    assert feed(icmp(changed_replies=2), exchange(5, 56, changed=1)) == []
    off = icmp(changed_replies=0)
    assert feed(off, exchange(30, 56, changed=30)) == []
    assert off._requests == {}  # and it does not keep what the requests carried


def test_one_changed_byte_is_a_change() -> None:
    t = Timeline()
    for i in range(5):
        data = bytes(range(256)) * 3
        t.icmp_echo(i * 0.1, CLIENT, SERVER, 1, i, data)
        t.icmp_echo(i * 0.1 + 0.001, SERVER, CLIENT, 1, i, data[:-1] + b"\x00", reply=True)
    assert len(feed(icmp(), t.packets())) == 1


def test_empty_data_is_data_too() -> None:
    t = Timeline()
    for i in range(5):
        t.icmp_echo(i * 0.1, CLIENT, SERVER, 1, i, b"")
        t.icmp_echo(i * 0.1 + 0.001, SERVER, CLIENT, 1, i, b"x", reply=True)
    assert len(feed(icmp(), t.packets())) == 1
    same = Timeline()
    for i in range(20):
        same.icmp_echo(i * 0.1, CLIENT, SERVER, 1, i, b"")
        same.icmp_echo(i * 0.1 + 0.001, SERVER, CLIENT, 1, i, b"", reply=True)
    assert feed(icmp(), same.packets()) == []


def test_a_reply_is_compared_only_with_its_own_request() -> None:
    t = Timeline()
    for i in range(10):
        t.icmp_echo(i * 0.1, CLIENT, SERVER, 1, i, b"a" * 10)
    for i in range(10):  # replies to other sequence numbers, other identifiers, other hosts
        t.icmp_echo(2.0 + i * 0.1, SERVER, CLIENT, 1, 100 + i, b"b" * 10, reply=True)
        t.icmp_echo(3.0 + i * 0.1, SERVER, CLIENT, 2, i, b"b" * 10, reply=True)
        t.icmp_echo(4.0 + i * 0.1, OTHER_SERVER, CLIENT, 1, i, b"b" * 10, reply=True)
        t.icmp_echo(5.0 + i * 0.1, SERVER, OTHER, 1, i, b"b" * 10, reply=True)
    assert feed(icmp(), t.packets()) == []


def test_a_request_is_answered_once() -> None:
    t = Timeline()
    for i in range(5):
        t.icmp_echo(i * 0.1, CLIENT, SERVER, 1, i, b"a" * 10)
        t.icmp_echo(i * 0.1 + 0.001, SERVER, CLIENT, 1, i, b"a" * 10, reply=True)  # as it should
        t.icmp_echo(i * 0.1 + 0.002, SERVER, CLIENT, 1, i, b"b" * 10, reply=True)  # a stray one
    assert feed(icmp(), t.packets()) == []


def test_the_same_sequence_number_sent_again_replaces_the_request() -> None:
    t = Timeline()
    for i in range(5):
        t.icmp_echo(i * 0.2, CLIENT, SERVER, 1, i, b"a" * 10)
        t.icmp_echo(i * 0.2 + 0.05, CLIENT, SERVER, 1, i, b"b" * 10)  # sent again, other data
        t.icmp_echo(i * 0.2 + 0.06, SERVER, CLIENT, 1, i, b"b" * 10, reply=True)
    assert feed(icmp(), t.packets()) == []


def test_hosts_are_counted_separately() -> None:
    half = exchange(3, 56, changed=3) + exchange(3, 56, changed=3, src=OTHER, ident=8)
    assert feed(icmp(), sorted(half, key=lambda p: p.ts_ns)) == []
    large = echoes(6, 700) + echoes(6, 700, src=OTHER, dst=OTHER_SERVER)
    assert feed(icmp(), sorted(large, key=lambda p: p.ts_ns)) == []


def test_both_signals_are_reported_and_each_once_per_window() -> None:
    detector = icmp()
    found = feed(detector, exchange(40, 800, changed=40))
    assert sorted(d.evidence["signal"] for d in found) == ["changed_reply", "large_echo"]
    later = exchange(12, 800, changed=12, start=200.0, ident=9)
    assert sorted(d.evidence["signal"] for d in feed(detector, later)) == [
        "changed_reply",
        "large_echo",
    ]


def test_other_icmp_messages_are_ignored() -> None:
    t = Timeline()
    for i in range(30):
        for kind, code in ((3, 0), (11, 0), (5, 0), (8, 1), (0, 1)):
            message = icmp_message(kind, code, 1 << 16 | i, b"z" * 800)
            frame = eth_frame(MAC_B, MAC_A, 0x0800, ipv4_packet(CLIENT, SERVER, 1, message))
            t.add(i * 0.01, frame)
    assert feed(icmp(), t.packets()) == []


def test_messages_that_were_not_captured_whole_are_ignored() -> None:
    packets = echoes(30, 900)
    cut = [Packet(p.ts_ns, len(p.data), p.data[:700]) for p in packets]  # a short snap length
    assert feed(icmp(), cut) == []
    assert len(feed(icmp(), packets)) == 1


def test_icmpv6_is_not_looked_at() -> None:
    t = Timeline()
    for i in range(30):
        message = icmp_message(128, 0, i, b"z" * 800)
        frame = eth_frame(MAC_B, MAC_A, 0x86DD, ipv6_packet(IP6_A, IP6_B, 58, message))
        t.add(i * 0.01, frame)
    assert feed(icmp(), t.packets()) == []


def test_the_request_table_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sentinel.ids.detectors.MAX_KEYS", 3)
    detector = icmp(changed_replies=1)
    feed(detector, echoes(5, 20))
    assert len(detector._requests) == 3
    t = Timeline()
    t.icmp_echo(1.0, SERVER, CLIENT, 7, 0, b"other", reply=True)  # the oldest request is forgotten
    assert feed(detector, t.packets()) == []
    t = Timeline()
    t.icmp_echo(1.1, SERVER, CLIENT, 7, 4, b"other", reply=True)  # the newest is not
    assert len(feed(detector, t.packets())) == 1


def test_the_tables_of_pairs_are_bounded_and_forget_idle_pairs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sentinel.ids.detectors.MAX_KEYS", 2)
    detector = icmp(large_requests=5, changed_replies=5)
    hosts = [IPv4Address("10.0.2.20") + i for i in range(3)]
    packets: list[Packet] = []
    for i, host in enumerate(hosts):
        packets += exchange(1, 800, changed=1, start=i * 0.1, src=host)
    feed(detector, sorted(packets, key=lambda p: p.ts_ns))
    assert len(detector._large) == 2
    assert len(detector._changed) == 2
    assert detector.dropped == 2  # the third host, in each of the two tables
    feed(detector, exchange(1, 800, changed=1, start=500.0, src=hosts[2]))
    assert len(detector._large) == 1
    assert len(detector._changed) == 1


# ---- what the packet view shows, and the rules -----------------------------------------------


def test_the_view_has_the_icmp_layer_when_it_is_intact() -> None:
    (packet,) = echoes(1, 20)
    view = make_view(packet.ts_ns, decode(packet.data))
    assert isinstance(view.icmp, Icmp)
    assert (view.icmp.icmp_type, view.icmp.ident, view.icmp.seq) == (8, 7, 0)
    cut = packet.data[: 14 + 20 + 5]  # an ICMP header cut short
    assert make_view(0, decode(cut)).icmp is None
    assert make_view(0, decode(b"junk")).icmp is None


def test_the_timeline_makes_echo_requests_and_replies() -> None:
    t = Timeline()
    t.icmp_echo(0.0, CLIENT, SERVER, 0x1234, 0x0056, b"data")
    t.icmp_echo(0.5, SERVER, CLIENT, 0x1234, 0x0056, b"data", reply=True)
    request, reply = (decode(p.data) for p in t.packets())
    request_ip, request_icmp = request[1], request[2]
    reply_ip, reply_icmp = reply[1], reply[2]
    assert isinstance(request_ip, IPv4)
    assert isinstance(reply_ip, IPv4)
    assert isinstance(request_icmp, Icmp)
    assert isinstance(reply_icmp, Icmp)
    assert (request_icmp.icmp_type, reply_icmp.icmp_type) == (8, 0)
    assert (request_icmp.ident, request_icmp.seq, request_icmp.payload) == (0x1234, 0x56, b"data")
    assert request_icmp.anomalies == ()
    assert reply_icmp.anomalies == ()
    assert (str(request_ip.src), str(request_ip.dst)) == ("10.0.2.9", "10.0.0.31")
    assert (str(reply_ip.src), str(reply_ip.dst)) == ("10.0.0.31", "10.0.2.9")


@pytest.mark.parametrize(
    ("detector", "key", "bad"),
    [
        ("ssh_brute_force", "port", 0),
        ("ssh_brute_force", "port", 65536),
        ("ssh_brute_force", "connections", 0),
        ("ssh_brute_force", "window_seconds", 0),
        ("icmp_tunnel", "min_payload_bytes", -1),
        ("icmp_tunnel", "min_payload_bytes", 65536),
        ("icmp_tunnel", "large_requests", 0),
        ("icmp_tunnel", "changed_replies", -1),
        ("icmp_tunnel", "window_seconds", 0),
    ],
)
def test_the_parameters_are_range_checked(detector: str, key: str, bad: int) -> None:
    text = f'[[rule]]\nid = "x"\ndetector = "{detector}"\n{key} = {bad}\n'
    result = parse_rules(text, "t")
    assert len(result.errors) == 1
    assert f"'{key}' must be between" in result.errors[0]
    ok = parse_rules(f'[[rule]]\nid = "x"\ndetector = "{detector}"\n', "t")
    assert ok.errors == ()


def test_the_edges_of_the_ranges_are_accepted() -> None:
    for line in (
        'detector = "ssh_brute_force"\nport = 1\nconnections = 1',
        'detector = "ssh_brute_force"\nport = 65535',
        'detector = "icmp_tunnel"\nmin_payload_bytes = 0\nchanged_replies = 0',
        'detector = "icmp_tunnel"\nmin_payload_bytes = 65535\nlarge_requests = 1',
    ):
        assert parse_rules(f'[[rule]]\nid = "x"\n{line}\n', "t").errors == ()


# ---- the generated captures ------------------------------------------------------------------


def alerts_of(rules_toml: str, packets: list[Packet]) -> list[str]:
    rules = parse_rules(rules_toml, "t")
    assert rules.errors == ()
    engine = Engine(rules.rules)
    for packet in packets:
        engine.process(packet)
    return [a.message for a in engine.finish()]


def test_the_benign_capture_sits_just_below_the_new_thresholds() -> None:
    packets = generate_benign()
    ssh_rule = '[[rule]]\nid = "s"\ndetector = "ssh_brute_force"\n'
    assert alerts_of(ssh_rule, packets) == []
    assert len(alerts_of(ssh_rule + "connections = 9\n", packets)) == 1  # nine connections, no more
    large = '[[rule]]\nid = "i"\ndetector = "icmp_tunnel"\nchanged_replies = 0\n'
    assert alerts_of(large, packets) == []
    assert len(alerts_of(large + "large_requests = 9\n", packets)) == 1  # nine large pings
    changed = '[[rule]]\nid = "i"\ndetector = "icmp_tunnel"\nmin_payload_bytes = 0\n'
    assert alerts_of(changed, packets) == []
    assert len(alerts_of(changed.replace("0\n", "0\nchanged_replies = 4\n"), packets)) == 1


def test_the_attack_capture_raises_the_three_alerts_and_only_them_for_these_detectors() -> None:
    both = (
        '[[rule]]\nid = "s"\ndetector = "ssh_brute_force"\n'
        '[[rule]]\nid = "i"\ndetector = "icmp_tunnel"\n'
    )
    assert alerts_of(both, generate_attacks()) == [
        "10.9.9.6 made 10 connections to the SSH port of 10.0.0.31 in 0.9s",
        "10.0.8.8 got 5 echo replies from 10.0.0.40 that do not repeat the data it sent, in 0.8s",
        "10.0.8.8 sent 10 echo requests of 512 bytes or more to 10.0.0.40 in 1.8s",
    ]


def test_random_traffic_never_raises_from_the_new_detectors() -> None:
    rng = random.Random(11)
    detectors = [ssh(connections=1), icmp(min_payload_bytes=1, large_requests=1, changed_replies=1)]
    for _ in range(300):
        frame = rng.randbytes(rng.randint(0, 200))
        for detector in detectors:
            detector.on_packet(make_view(0, decode(frame)))
    ping = eth_frame(MAC_B, MAC_A, 0x0800, ipv4_packet(CLIENT, SERVER, 1, rng.randbytes(50)))
    for detector in detectors:
        for cut in range(len(ping) + 1):
            detector.on_packet(make_view(0, decode(ping[:cut])))


# ---- more edges of the SSH detector ------------------------------------------------------------


def test_a_reset_or_a_syn_ack_does_not_complete_a_handshake() -> None:
    t = Timeline()
    for i in range(20):
        t.tcp(i * 0.01, CLIENT, 50000 + i, SERVER, 22, 1000, 0, tcp.SYN)
        t.tcp(i * 0.01 + 0.001, CLIENT, 50000 + i, SERVER, 22, 1001, 5001, tcp.RST | tcp.ACK)
    assert feed(ssh(), t.packets()) == []
    t = Timeline()
    for i in range(20):
        t.tcp(i * 0.01, CLIENT, 50000 + i, SERVER, 22, 1000, 0, tcp.SYN)
        t.tcp(i * 0.01 + 0.001, CLIENT, 50000 + i, SERVER, 22, 1001, 5001, tcp.SYN | tcp.ACK)
    assert feed(ssh(), t.packets()) == []
    t = Timeline()
    for i in range(20):  # a SYN with the ACK flag is not the start of a connection either
        t.tcp(i * 0.01, CLIENT, 50000 + i, SERVER, 22, 1000, 0, tcp.SYN | tcp.ACK)
        t.tcp(i * 0.01 + 0.001, CLIENT, 50000 + i, SERVER, 22, 1001, 5001, tcp.ACK)
    assert feed(ssh(), t.packets()) == []


def test_the_count_and_the_time_in_an_alert_are_those_of_its_own_window() -> None:
    # The window holds at most one more than the threshold (its size is bounded), so a burst
    # that goes on is reported again, once the alert window has passed, with 11.
    found = feed(ssh(window_seconds=1.0), connections(40, gap=0.05))
    assert [(d.evidence["connections"], d.evidence["seconds"]) for d in found] == [
        (10, 0.45),
        (11, 0.5),
    ]
    assert [d.message.rsplit(" in ", 1)[1] for d in found] == ["0.5s", "0.5s"]
    assert [d.message.split(" made ")[1].split(" ")[0] for d in found] == ["10", "11"]
    (single,) = feed(ssh(), connections(10, gap=0.0123))
    assert single.evidence["seconds"] == 0.111  # three decimals in the evidence,
    assert single.message.endswith(" in 0.1s")  # one in the message


# ---- more edges of the ICMP detector -----------------------------------------------------------


def test_two_servers_of_one_client_are_two_alerts() -> None:
    both = echoes(10, 700) + echoes(10, 700, dst=OTHER_SERVER)
    found = feed(icmp(), sorted(both, key=lambda p: p.ts_ns))
    assert sorted(d.dst or "" for d in found) == ["10.0.0.31", "10.0.0.32"]
    both = exchange(5, 56, changed=5) + exchange(5, 56, changed=5, dst=OTHER_SERVER, ident=8)
    found = feed(icmp(), sorted(both, key=lambda p: p.ts_ns))
    assert sorted(d.dst or "" for d in found) == ["10.0.0.31", "10.0.0.32"]
    two_clients = exchange(5, 56, changed=5) + exchange(5, 56, changed=5, src=OTHER, ident=8)
    found = feed(icmp(), sorted(two_clients, key=lambda p: p.ts_ns))
    assert sorted(d.src or "" for d in found) == ["10.0.2.10", "10.0.2.9"]


def test_a_later_icmp_alert_reports_its_own_window() -> None:
    found = feed(icmp(window_seconds=1.0), echoes(40, 700, gap=0.05))
    assert [d.evidence["requests"] for d in found] == [10, 11]  # the window is bounded, see above
    found = feed(icmp(window_seconds=1.0), exchange(40, 56, changed=40, gap=0.05))
    assert [d.evidence["replies"] for d in found] == [5, 6]
