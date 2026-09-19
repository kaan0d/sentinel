import json
import random

import pytest

from sentinel.ids import Alert, Engine, default_rules, parse_rules, to_json
from sentinel.pcap import Packet
from sentinel.proto.decode import decode
from tools.gen_pcap import generate, generate_attacks, generate_benign, generate_streams


def run(packets: list[Packet], rules_toml: str | None = None) -> list[Alert]:
    rules = default_rules() if rules_toml is None else parse_rules(rules_toml, "test")
    assert rules.errors == ()
    engine = Engine(rules.rules)
    for packet in packets:
        engine.process(packet)
    return engine.finish()


def test_harmless_traffic_raises_no_alert() -> None:
    assert run(generate_benign()) == []
    assert run(generate()) == []
    assert run(generate_streams()) == []


ATTACK_ALERTS = [
    ("port-scan", "10.9.9.1 probed 15 ports on 10.0.0.30 in 0.1s"),
    ("port-scan", "10.9.9.2 probed 15 ports on 10.0.0.30 in 0.7s"),
    ("port-scan", "10.9.9.3 probed 15 ports on 10.0.0.30 in 0.7s"),
    ("port-scan", "10.9.9.4 probed 15 ports on 10.0.0.30 in 0.7s"),
    ("port-scan", "10.9.9.5 probed port 22 on 30 hosts in 1.2s"),
    ("syn-flood", "100 SYNs to 10.0.0.2:80 in 0.1s from 100 sources, 20 completed"),
    ("arp-spoof", "10.0.0.1 moved from 02:aa:00:00:00:01 to 02:ee:00:00:06:66"),
    (
        "arp-spoof",
        "ARP says 10.0.0.1 is at 02:aa:00:00:00:01, but the frame came from 02:ee:00:00:06:66",
    ),
    ("arp-spoof", "10.0.0.1 moved from 02:ee:00:00:06:66 to 02:aa:00:00:00:01"),
    ("dns-tunnel", "10.0.5.5 asked for a random-looking name under evil-cdn.test"),
    ("dns-tunnel", "10.0.5.5 asked for 50 different subdomains of evil-cdn.test in 2.5s"),
    ("dns-tunnel", "10.0.5.6 asked for a very long name under example.org (124 characters)"),
    ("dns-tunnel", "10.0.6.6 received 20 'no such name' answers in 0.9s"),
]


def test_each_attack_raises_its_alert_and_nothing_else() -> None:
    alerts = run(generate_attacks())
    assert [(a.rule, a.message) for a in alerts] == ATTACK_ALERTS
    assert [a.severity for a in alerts] == ["medium"] * 5 + ["high"] * 4 + ["medium"] * 4
    assert [a.ts_ns for a in alerts] == sorted(a.ts_ns for a in alerts)


def test_the_same_capture_gives_the_same_output() -> None:
    def lines() -> list[str]:
        return [to_json(a) for a in run(generate_attacks())]

    first = lines()
    assert first == lines()
    for line in first:
        parsed = json.loads(line)
        assert set(parsed) == {
            "ts",
            "ts_ns",
            "rule",
            "detector",
            "severity",
            "src",
            "dst",
            "message",
            "evidence",
        }


def test_precomputed_layers_give_the_same_alerts() -> None:
    rules = default_rules()
    with_layers, without = Engine(rules.rules), Engine(rules.rules)
    for p in generate_attacks():
        with_layers.process(p, decode(p.data))
        without.process(p)
    assert with_layers.finish() == without.finish()


def test_a_rule_filter_limits_what_the_detector_sees() -> None:
    only_ssh = """
    [[rule]]
    id = "ssh"
    detector = "port_scan"
    filter = "dst port 22"
    """
    (alert,) = run(generate_attacks(), only_ssh)
    assert alert.src == "10.9.9.5"  # the sweep of port 22; the other scans never reach the rule
    from_scanner = """
    [[rule]]
    id = "one-scanner"
    detector = "port_scan"
    filter = "src host 10.9.9.1"
    """
    (alert,) = run(generate_attacks(), from_scanner)
    assert alert.src == "10.9.9.1"


def test_disabled_rules_do_nothing() -> None:
    rules = """
    [[rule]]
    id = "off"
    detector = "port_scan"
    enabled = false
    [[rule]]
    id = "on"
    detector = "syn_flood"
    """
    assert [a.rule for a in run(generate_attacks(), rules)] == ["on"]


def test_rules_may_change_thresholds_and_severity() -> None:
    rules = """
    [[rule]]
    id = "picky"
    detector = "port_scan"
    severity = "critical"
    distinct_ports = 100
    distinct_hosts = 0
    """
    alerts = run(generate_attacks(), rules)
    assert [(a.rule, a.severity, a.src) for a in alerts] == [("picky", "critical", "10.9.9.1")]


def test_two_rules_of_one_detector_are_independent_and_ordered() -> None:
    rules = """
    [[rule]]
    id = "sensitive"
    detector = "port_scan"
    severity = "low"
    distinct_ports = 5
    distinct_hosts = 0
    [[rule]]
    id = "normal"
    detector = "port_scan"
    distinct_hosts = 0
    """
    alerts = run(generate_attacks(), rules)
    scanner1 = [a for a in alerts if a.src == "10.9.9.1"]
    assert [a.rule for a in scanner1] == ["sensitive", "normal"]  # the 5th port comes first
    assert scanner1[0].ts_ns < scanner1[1].ts_ns
    assert len(alerts) == 8  # four scanners, two rules each


def test_alerts_at_the_same_time_keep_the_rule_order() -> None:
    rules = """
    [[rule]]
    id = "z-first"
    detector = "port_scan"
    distinct_ports = 15
    [[rule]]
    id = "a-second"
    detector = "port_scan"
    distinct_ports = 15
    """
    alerts = run(generate_attacks()[:200], rules)
    assert [a.rule for a in alerts[:2]] == ["z-first", "a-second"]
    assert alerts[0].ts_ns == alerts[1].ts_ns


def test_a_detector_that_hits_its_state_limit_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sentinel.ids.detectors.MAX_KEYS", 3)
    alerts = run(generate_attacks())
    limit = [a for a in alerts if "state limit" in a.message]
    assert limit
    assert all(a.severity == "low" and a.evidence["packets"] for a in limit)
    assert alerts[-1].ts_ns == max(a.ts_ns for a in alerts)


def test_the_engine_never_raises_on_broken_packets(blobs: list[bytes]) -> None:
    engine = Engine(default_rules().rules)
    for i, blob in enumerate(blobs):
        engine.process(Packet(i, len(blob), blob))
    rng = random.Random(9)
    for packet in generate_attacks()[::25] + generate():
        for n in range(0, len(packet.data) + 1, 3):
            engine.process(Packet(packet.ts_ns, n, packet.data[:n]))
        for _ in range(3):
            bad = bytearray(packet.data)
            bad[rng.randrange(len(bad))] = rng.randrange(256)
            engine.process(Packet(packet.ts_ns, len(bad), bytes(bad)))
    engine.finish()


def test_scrambled_timestamps_do_not_break_the_detectors() -> None:
    rng = random.Random(10)
    packets = generate_attacks()
    shuffled = [Packet(rng.randrange(10**12), p.orig_len, p.data) for p in packets]
    run(shuffled)  # the alerts do not matter, only that nothing raises
