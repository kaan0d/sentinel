import base64
import random
from ipaddress import IPv4Address

import pytest

from sentinel.ids.detectors import (
    DETECTORS,
    Detection,
    Detector,
    SynFlood,
    entropy,
    is_scan_probe,
)
from sentinel.ids.view import make_view
from sentinel.pcap import Packet
from sentinel.proto import tcp
from sentinel.proto.decode import decode
from sentinel.proto.ethernet import ETHERTYPE_IPV4
from tools.gen_pcap import (
    GATEWAY_MAC,
    IP6_A,
    IP6_B,
    MAC_A,
    MAC_B,
    MAC_ZERO,
    Timeline,
    dns_response,
    eth_frame,
    ipv4_packet,
    ipv6_packet,
    tcp_segment,
    udp_datagram,
)

ATTACKER = IPv4Address("10.9.9.1")
TARGET = IPv4Address("10.0.0.30")
RESOLVER = IPv4Address("10.0.0.53")
CLIENT = IPv4Address("10.0.3.3")
EVIL_MAC = bytes.fromhex("02ee00000666")


def feed(detector: Detector, packets: list[Packet]) -> list[Detection]:
    out: list[Detection] = []
    for p in packets:
        out += detector.on_packet(make_view(p.ts_ns, decode(p.data)))
    return out


def probes(n: int, *, flags: int = tcp.SYN, gap: float = 0.01, start: float = 0.0) -> list[Packet]:
    t = Timeline()
    for i in range(n):
        t.tcp(start + i * gap, ATTACKER, 50000, TARGET, 1 + i, 7000, 0, flags)
    return t.packets()


def sample(name: str, **overrides: float | bool) -> Detector:
    return DETECTORS[name].create(overrides)


# ---- port scan ------------------------------------------------------------------------------


def test_scan_probe_flags() -> None:
    yes = [tcp.SYN, 0, tcp.FIN, tcp.FIN | tcp.PSH | tcp.URG, tcp.SYN | tcp.ECE | tcp.CWR]
    no = [
        tcp.SYN | tcp.ACK,
        tcp.ACK,
        tcp.PSH | tcp.ACK,
        tcp.RST,
        tcp.RST | tcp.ACK,
        tcp.FIN | tcp.ACK,
    ]
    assert all(is_scan_probe(f) for f in yes)
    assert not any(is_scan_probe(f) for f in no)


def test_port_scan_fires_exactly_at_the_threshold() -> None:
    assert feed(sample("port_scan"), probes(14)) == []
    found = feed(sample("port_scan"), probes(15))
    assert len(found) == 1
    d = found[0]
    assert (d.src, d.dst) == ("10.9.9.1", "10.0.0.30")
    assert d.message == "10.9.9.1 probed 15 ports on 10.0.0.30 in 0.1s"
    assert d.evidence == {"ports": 15, "seconds": 0.14, "sample": list(range(1, 11))}
    assert d.ts_ns == probes(15)[-1].ts_ns  # raised by the 15th distinct port


def test_a_scan_needs_different_ports_not_many_packets() -> None:
    t = Timeline()
    for i in range(200):
        t.tcp(i * 0.01, ATTACKER, 50000, TARGET, 80, 7000, 0, tcp.SYN)
    assert feed(sample("port_scan"), t.packets()) == []


def test_a_slow_scan_falls_out_of_the_window() -> None:
    assert len(feed(sample("port_scan"), probes(15, gap=0.7))) == 1  # 9.8 s: all 15 fit
    assert feed(sample("port_scan"), probes(15, gap=0.72)) == []  # 10.08 s: the first is gone
    assert feed(sample("port_scan", window_seconds=1.0), probes(15, gap=0.5)) == []


@pytest.mark.parametrize("flags", [0, tcp.FIN, tcp.FIN | tcp.PSH | tcp.URG])
def test_stealth_scans_count(flags: int) -> None:
    assert len(feed(sample("port_scan"), probes(15, flags=flags))) == 1


@pytest.mark.parametrize(
    "flags", [tcp.ACK, tcp.SYN | tcp.ACK, tcp.PSH | tcp.ACK, tcp.RST | tcp.ACK, tcp.FIN | tcp.ACK]
)
def test_packets_of_real_connections_do_not_count(flags: int) -> None:
    assert feed(sample("port_scan"), probes(60, flags=flags)) == []


def test_udp_is_not_counted() -> None:
    t = Timeline()
    for i in range(50):
        datagram = udp_datagram(ATTACKER, TARGET, 5000, 1000 + i, b"x")
        t.add(
            i * 0.01,
            eth_frame(MAC_B, MAC_A, ETHERTYPE_IPV4, ipv4_packet(ATTACKER, TARGET, 17, datagram)),
        )
    assert feed(sample("port_scan"), t.packets()) == []


def test_host_sweep_fires_at_the_threshold() -> None:
    def sweep(n: int) -> list[Packet]:
        t = Timeline()
        for i in range(n):
            t.tcp(i * 0.01, ATTACKER, 52000, IPv4Address("10.0.4.0") + i + 1, 22, 7000, 0, tcp.SYN)
        return t.packets()

    assert feed(sample("port_scan"), sweep(29)) == []
    found = feed(sample("port_scan"), sweep(30))
    assert len(found) == 1
    assert found[0].message == "10.9.9.1 probed port 22 on 30 hosts in 0.3s"
    assert found[0].dst is None
    assert found[0].evidence == {"hosts": 30, "port": 22, "seconds": 0.29}


def test_each_check_can_be_turned_off() -> None:
    assert feed(sample("port_scan", distinct_ports=0), probes(50)) == []
    t = Timeline()
    for i in range(40):
        t.tcp(i * 0.01, ATTACKER, 52000, IPv4Address("10.0.4.0") + i + 1, 22, 7000, 0, tcp.SYN)
    assert feed(sample("port_scan", distinct_hosts=0), t.packets()) == []


def test_one_scan_is_one_alert_until_the_window_has_passed() -> None:
    packets = probes(200, gap=0.01)  # 2 s of scanning
    assert len(feed(sample("port_scan"), packets)) == 1
    long_scan = probes(600, gap=0.05)  # 30 s: the alert may come back every 10 s
    assert len(feed(sample("port_scan"), long_scan)) == 3


def test_sources_are_tracked_separately() -> None:
    t = Timeline()
    for i in range(10):  # two scanners with 10 ports each: neither reaches 15
        t.tcp(i * 0.01, IPv4Address("10.9.9.1"), 50000, TARGET, 1 + i, 7000, 0, tcp.SYN)
        t.tcp(i * 0.01, IPv4Address("10.9.9.2"), 50000, TARGET, 100 + i, 7000, 0, tcp.SYN)
    assert feed(sample("port_scan"), t.packets()) == []


def test_ipv6_scans_are_found_too() -> None:
    packets = []
    for i in range(15):
        segment = tcp_segment(IP6_A, IP6_B, 50000, 1 + i, 1, 0, tcp.SYN)
        frame = eth_frame(MAC_B, MAC_A, 0x86DD, ipv6_packet(IP6_A, IP6_B, 6, segment))
        packets.append(Packet(i * 10_000_000, len(frame), frame))
    (found,) = feed(sample("port_scan"), packets)
    assert (found.src, found.dst) == ("2001:db8::1", "2001:db8::2")


def test_state_limits_are_reported_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sentinel.ids.detectors.MAX_KEYS", 3)
    detector = sample("port_scan")
    t = Timeline()
    for i in range(10):  # ten different sources: only three can be followed
        t.tcp(i * 0.01, IPv4Address("10.9.9.0") + i + 1, 50000, TARGET, 80, 7000, 0, tcp.SYN)
    feed(detector, t.packets())
    assert detector.dropped > 0


# ---- syn flood ------------------------------------------------------------------------------


def flood(syns: int, completed: int, *, gap: float = 0.001) -> list[Packet]:
    """`syns` SYNs from different sources to 10.0.0.2:80; the first `completed` also ACK."""
    t = Timeline()
    for i in range(syns):
        src = IPv4Address("10.20.0.0") + i + 1
        t.tcp(i * gap, src, 1024 + i, IPv4Address("10.0.0.2"), 80, 9000, 0, tcp.SYN)
        if i < completed:
            t.tcp(
                i * gap + gap / 2, src, 1024 + i, IPv4Address("10.0.0.2"), 80, 9001, 5001, tcp.ACK
            )
    return t.packets()


def test_syn_flood_fires_at_the_threshold() -> None:
    assert feed(sample("syn_flood"), flood(99, 0)) == []
    (found,) = feed(sample("syn_flood"), flood(100, 0))
    assert found.dst == "10.0.0.2"
    assert found.src is None
    assert found.message == "100 SYNs to 10.0.0.2:80 in 0.1s from 100 sources, 0 completed"
    assert found.evidence == {
        "syns": 100,
        "completed": 0,
        "sources": 100,
        "port": 80,
        "seconds": 0.099,
    }


def test_a_busy_server_whose_handshakes_complete_is_not_flooded() -> None:
    assert feed(sample("syn_flood"), flood(300, 300)) == []


def test_the_completed_ratio_boundary() -> None:
    def alerts(completed: int) -> int:
        packets = flood(100, completed)
        # The ACKs of the first `completed` connections come right after their own SYN, so by
        # the 100th SYN all of them have been seen.
        return len(feed(sample("syn_flood"), packets))

    assert alerts(30) == 1  # 30% completed: at the limit, still a flood
    assert alerts(31) == 0


def test_a_slow_trickle_of_syns_is_not_a_flood() -> None:
    assert feed(sample("syn_flood"), flood(100, 0, gap=0.02)) == []  # 2 s for 100


def test_services_are_counted_separately() -> None:
    t = Timeline()
    for i in range(60):
        t.tcp(
            i * 0.001,
            IPv4Address("10.20.0.0") + i + 1,
            1024,
            IPv4Address("10.0.0.2"),
            80,
            9000,
            0,
            tcp.SYN,
        )
        t.tcp(
            i * 0.001,
            IPv4Address("10.20.1.0") + i + 1,
            1024,
            IPv4Address("10.0.0.2"),
            443,
            9000,
            0,
            tcp.SYN,
        )
    assert feed(sample("syn_flood"), t.packets()) == []


def test_only_plain_syns_and_real_acks_are_counted() -> None:
    t = Timeline()
    for i in range(300):
        src = IPv4Address("10.20.0.0") + i + 1
        t.tcp(i * 0.001, src, 1024, IPv4Address("10.0.0.2"), 80, 9000, 0, tcp.SYN | tcp.ACK)
        t.tcp(i * 0.001, src, 1025, IPv4Address("10.0.0.2"), 80, 9000, 0, tcp.RST)
    assert feed(sample("syn_flood"), t.packets()) == []
    # ACKs from connections that never sent a SYN complete nothing
    t2 = Timeline()
    for i in range(100):
        src = IPv4Address("10.77.0.0") + i + 1
        t2.tcp(0.0005 + i * 0.001, src, 1024, IPv4Address("10.0.0.2"), 80, 1, 1, tcp.ACK)
    mixed = sorted(flood(100, 0) + t2.packets(), key=lambda p: p.ts_ns)
    assert len(feed(sample("syn_flood"), mixed)) == 1


def test_one_flood_is_one_alert() -> None:
    assert len(feed(sample("syn_flood"), flood(400, 0))) == 1


def test_the_pending_table_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sentinel.ids.detectors.MAX_KEYS", 5)
    detector = sample("syn_flood", syns=1000)
    feed(detector, flood(50, 0))  # must not raise or grow without limit
    assert isinstance(detector, SynFlood)
    assert len(detector._pending) <= 5


# ---- arp spoofing -----------------------------------------------------------------------------


def arp_packets(*claims: tuple[bytes, str, bytes | None]) -> list[Packet]:
    """ARP replies from 10.0.0.77's point of view: (sender mac, sender ip, ethernet source)."""
    t = Timeline()
    for i, (mac, ip, eth_src) in enumerate(claims):
        t.arp(float(i), 2, mac, ip, MAC_A, "10.0.0.77", eth_src=eth_src)
    return t.packets()


def test_a_stable_binding_raises_nothing() -> None:
    packets = arp_packets(*[(GATEWAY_MAC, "10.0.0.1", None)] * 5)
    assert feed(sample("arp_spoof"), packets) == []


def test_an_address_that_changes_mac_is_reported_once() -> None:
    packets = arp_packets(
        (GATEWAY_MAC, "10.0.0.1", None),
        (EVIL_MAC, "10.0.0.1", None),
        (EVIL_MAC, "10.0.0.1", None),  # the same claim again: nothing new
    )
    (found,) = feed(sample("arp_spoof"), packets)
    assert found.message == "10.0.0.1 moved from 02:aa:00:00:00:01 to 02:ee:00:00:06:66"
    assert (found.src, found.dst) == ("02:ee:00:00:06:66", "10.0.0.1")
    assert found.evidence == {
        "ip": "10.0.0.1",
        "old_mac": "02:aa:00:00:00:01",
        "new_mac": "02:ee:00:00:06:66",
        "op": 2,
    }


def test_the_same_change_is_not_reported_again_and_again() -> None:
    flip_flop = arp_packets(
        (GATEWAY_MAC, "10.0.0.1", None),
        (EVIL_MAC, "10.0.0.1", None),
        (GATEWAY_MAC, "10.0.0.1", None),
        (EVIL_MAC, "10.0.0.1", None),
        (GATEWAY_MAC, "10.0.0.1", None),
        (EVIL_MAC, "10.0.0.1", None),
    )
    found = feed(sample("arp_spoof"), flip_flop)
    assert [d.evidence["new_mac"] for d in found] == ["02:ee:00:00:06:66", "02:aa:00:00:00:01"]
    forged = arp_packets(*[(GATEWAY_MAC, "10.0.0.1", EVIL_MAC)] * 4)
    assert len(feed(sample("arp_spoof"), forged)) == 1


def test_requests_teach_bindings_too() -> None:
    t = Timeline()
    t.arp(0.0, 1, GATEWAY_MAC, "10.0.0.1", MAC_ZERO, "10.0.0.77")  # a request from the gateway
    t.arp(1.0, 2, EVIL_MAC, "10.0.0.1", MAC_A, "10.0.0.77")  # a reply from someone else
    assert len(feed(sample("arp_spoof"), t.packets())) == 1


def test_a_sender_mac_that_differs_from_the_ethernet_source() -> None:
    packets = arp_packets((GATEWAY_MAC, "10.0.0.1", EVIL_MAC))
    (found,) = feed(sample("arp_spoof"), packets)
    assert found.message == (
        "ARP says 10.0.0.1 is at 02:aa:00:00:00:01, but the frame came from 02:ee:00:00:06:66"
    )
    assert feed(sample("arp_spoof", check_ethernet_mismatch=False), packets) == []


def test_address_probes_and_repeated_announcements_are_normal() -> None:
    t = Timeline()
    for i in range(3):
        t.arp(i * 0.2, 1, MAC_A, "0.0.0.0", MAC_ZERO, "10.0.0.77")
        t.arp(i * 0.2, 1, MAC_B, "0.0.0.0", MAC_ZERO, "10.0.0.77")  # two hosts probing the same one
    for i in range(3):
        t.arp(2 + i, 2, MAC_A, "10.0.0.77", MAC_A, "10.0.0.77")
    assert feed(sample("arp_spoof"), t.packets()) == []


def test_arp_with_errors_is_ignored() -> None:
    frame = eth_frame(MAC_B, MAC_A, 0x0806, bytes(10))[:24]
    assert feed(sample("arp_spoof"), [Packet(0, len(frame), frame)]) == []


def test_the_binding_table_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sentinel.ids.detectors.MAX_KEYS", 2)
    detector = sample("arp_spoof")
    feed(detector, arp_packets(*[(GATEWAY_MAC, f"10.0.1.{i}", None) for i in range(1, 6)]))
    assert detector.dropped == 3


# ---- dns tunneling ----------------------------------------------------------------------------


def queries(names: list[str], *, gap: float = 0.1, client: IPv4Address = CLIENT) -> list[Packet]:
    t = Timeline()
    for i, name in enumerate(names):
        t.dns(i * gap, client, RESOLVER, 100 + i, name)
    return t.packets()


def random_label(rng: random.Random, n_bytes: int = 30) -> str:
    return base64.b32encode(rng.randbytes(n_bytes)).decode().lower().rstrip("=")


def test_entropy() -> None:
    assert entropy("") == 0.0
    assert entropy("aaaa") == 0.0
    assert entropy("abcd") == pytest.approx(2.0)
    assert entropy("aabb") == pytest.approx(1.0)


def test_a_very_long_name() -> None:
    long_name = "a" * 30 + "." + "b" * 30 + "." + "c" * 30 + ".example.org"  # 104 characters
    (found,) = feed(sample("dns_tunnel"), queries([long_name]))
    assert found.evidence["signal"] == "long_name"
    assert found.message == "10.0.3.3 asked for a very long name under example.org (104 characters)"
    assert len(feed(sample("dns_tunnel"), queries([long_name[:100]]))) == 1  # the limit itself
    assert feed(sample("dns_tunnel"), queries([long_name[:99]])) == []  # one less
    assert feed(sample("dns_tunnel", max_name_length=0), queries([long_name])) == []


def test_a_very_long_label() -> None:
    (found,) = feed(sample("dns_tunnel"), queries(["x" * 50 + ".example.org"]))
    assert found.evidence["signal"] == "long_name"
    assert feed(sample("dns_tunnel"), queries(["x" * 49 + ".example.org"])) == []
    assert (
        feed(sample("dns_tunnel", max_label_length=0), queries(["x" * 50 + ".example.org"])) == []
    )


def test_a_random_looking_subdomain() -> None:
    label = random_label(random.Random(1), 30)  # 48 characters of base32
    (found,) = feed(sample("dns_tunnel"), queries([f"{label}.t.evil.test"]))
    assert found.evidence["signal"] == "high_entropy"
    assert found.message == "10.0.3.3 asked for a random-looking name under evil.test"
    assert found.evidence["length"] == 49
    assert feed(sample("dns_tunnel", entropy_threshold=0), queries([f"{label}.t.evil.test"])) == []


def test_readable_and_short_names_are_not_random_looking() -> None:
    readable = [
        "reporting-service-internal-metrics-collector.eu-west.prod.example.org",
        "mail-relay-outbound-03.datacenter-frankfurt.example.com",
        "www.example.com",
        "a.b",
        ".",
        "localhost",
    ]
    assert feed(sample("dns_tunnel"), queries(readable)) == []
    short_random = random_label(random.Random(2), 15)  # 24 characters: too short to judge
    assert feed(sample("dns_tunnel"), queries([f"{short_random}.evil.test"])) == []
    all_different = "abcdefghijklmnopqrstuvwx"  # 24 characters, 4.58 bits: high, but too short
    assert entropy(all_different) > 4.2
    assert feed(sample("dns_tunnel"), queries([f"{all_different}.evil.test"])) == []
    longer = "abcdefghijklmnopqrstuvwxyz0123456789abcd"  # 40 characters, judged
    assert len(feed(sample("dns_tunnel"), queries([f"{longer}.evil.test"]))) == 1


def test_many_subdomains_of_one_domain() -> None:
    def names(n: int) -> list[str]:
        return [f"host-{i}.example.net" for i in range(n)]

    assert feed(sample("dns_tunnel"), queries(names(49))) == []
    (found,) = feed(sample("dns_tunnel"), queries(names(50)))
    assert found.evidence == {
        "signal": "many_subdomains",
        "name": "host-49.example.net",
        "subdomains": 50,
        "domain": "example.net",
    }
    assert feed(sample("dns_tunnel"), queries(["same.example.net"] * 200)) == []  # one subdomain
    assert feed(sample("dns_tunnel", unique_subdomains=0), queries(names(80))) == []


def test_subdomains_are_counted_per_client_and_per_domain() -> None:
    a = queries([f"host-{i}.example.net" for i in range(30)], client=IPv4Address("10.0.3.1"))
    b = queries([f"host-{i}.example.net" for i in range(30)], client=IPv4Address("10.0.3.2"))
    c = queries([f"host-{i}.example.org" for i in range(30)], client=IPv4Address("10.0.3.1"))
    assert feed(sample("dns_tunnel"), sorted(a + b + c, key=lambda p: p.ts_ns)) == []


def test_slow_lookups_fall_out_of_the_window() -> None:
    slow = queries([f"host-{i}.example.net" for i in range(50)], gap=2.0)  # 100 s for 50 names
    assert feed(sample("dns_tunnel"), slow) == []


def nxdomains(n: int, client: str = "10.0.6.6", *, rcode_ok: bool = False) -> list[Packet]:
    t = Timeline()
    for i in range(n):
        reply = dns_response(i, f"x{i}.example.com", rcode=0 if rcode_ok else 3)
        datagram = udp_datagram(RESOLVER, IPv4Address(client), 53, 50000, reply)
        t.add(
            i * 0.05,
            eth_frame(
                MAC_A,
                MAC_B,
                ETHERTYPE_IPV4,
                ipv4_packet(RESOLVER, IPv4Address(client), 17, datagram),
            ),
        )
    return t.packets()


def test_nxdomain_answers() -> None:
    assert feed(sample("dns_tunnel"), nxdomains(19)) == []
    (found,) = feed(sample("dns_tunnel"), nxdomains(20))
    assert found.message == "10.0.6.6 received 20 'no such name' answers in 0.9s"
    assert (found.src, found.dst) == (None, "10.0.6.6")
    assert feed(sample("dns_tunnel"), nxdomains(100, rcode_ok=True)) == []
    assert feed(sample("dns_tunnel", nxdomain_count=0), nxdomains(100)) == []


def test_one_signal_is_one_alert_per_window() -> None:
    label = random_label(random.Random(3), 30)
    names = [f"{random_label(random.Random(i), 30)}.t.evil.test" for i in range(1, 20)]
    found = feed(sample("dns_tunnel"), queries([f"{label}.t.evil.test", *names]))
    assert [d.evidence["signal"] for d in found] == ["high_entropy"]


def test_dns_responses_are_not_queries() -> None:
    label = random_label(random.Random(4), 30)
    packets = nxdomains(1)  # just to have a response; the query names are checked separately
    detector = sample("dns_tunnel")
    assert feed(detector, packets) == []
    reply = dns_response(1, f"{label}.t.evil.test")
    datagram = udp_datagram(RESOLVER, CLIENT, 53, 50000, reply)
    frame = eth_frame(MAC_A, MAC_B, ETHERTYPE_IPV4, ipv4_packet(RESOLVER, CLIENT, 17, datagram))
    assert feed(detector, [Packet(0, len(frame), frame)]) == []


def test_every_detector_ignores_packets_that_are_not_theirs() -> None:
    frames = [b"", b"junk", bytes(60), eth_frame(MAC_B, MAC_A, 0x88CC, b"lldp")]
    for name in ("port_scan", "syn_flood", "arp_spoof", "dns_tunnel"):
        detector = sample(name)
        assert feed(detector, [Packet(i, len(f), f) for i, f in enumerate(frames)]) == []
