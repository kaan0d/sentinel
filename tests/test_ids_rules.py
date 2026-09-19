from pathlib import Path

import pytest

from sentinel.ids import default_rules, load_rules, parse_rules
from sentinel.ids.detectors import DETECTORS
from sentinel.ids.rules import MAX_FILE_BYTES

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def test_a_full_rule() -> None:
    result = parse_rules(
        """
        [[rule]]
        id = "ssh-scan"
        detector = "port_scan"
        severity = "high"
        enabled = false
        filter = "dst port 22"
        distinct_ports = 3
        window_seconds = 30
        """,
        "x.toml",
    )
    assert result.errors == ()
    (rule,) = result.rules
    assert (rule.id, rule.detector, rule.severity, rule.enabled) == (
        "ssh-scan",
        "port_scan",
        "high",
        False,
    )
    assert rule.filter is not None
    assert str(rule.filter) == "dst port 22"
    assert rule.config == {"distinct_ports": 3, "distinct_hosts": 30, "window_seconds": 30.0}
    assert isinstance(rule.config["window_seconds"], float)  # an integer is accepted for a float


def test_defaults_are_filled_in() -> None:
    (rule,) = parse_rules('[[rule]]\nid = "a"\ndetector = "syn_flood"\n', "x").rules
    assert rule.severity == "high"  # the detector's own default
    assert rule.enabled is True
    assert rule.filter is None
    assert rule.config == {"syns": 100, "window_seconds": 1.0, "max_completed_ratio": 0.3}


def test_several_rules_of_one_detector() -> None:
    result = parse_rules(
        '[[rule]]\nid = "a"\ndetector = "port_scan"\n[[rule]]\nid = "b"\ndetector = "port_scan"\n'
        "distinct_ports = 5\n",
        "x",
    )
    assert [r.id for r in result.rules] == ["a", "b"]
    assert result.rules[1].config["distinct_ports"] == 5


@pytest.mark.parametrize(
    ("toml", "message"),
    [
        ("", None),
        (
            "[[rule]]\ndetector = 'port_scan'\n",
            "rule 1: 'id' must be 1-64 characters: a-z, 0-9, '-' and '_'",
        ),
        (
            "[[rule]]\nid = 'Bad Id'\ndetector = 'port_scan'\n",
            "rule 1: 'id' must be 1-64 characters",
        ),
        (
            "[[rule]]\nid = 'ok id'\ndetector = 'port_scan'\n",
            "rule 1: 'id' must be 1-64 characters",
        ),
        (
            "[[rule]]\nid = '" + "a" * 65 + "'\ndetector = 'port_scan'\n",
            "rule 1: 'id' must be 1-64 characters",
        ),
        (
            "[[rule]]\nid = 'a'\n",
            "rule 1 (a): missing 'detector' (known: arp_spoof, dns_tunnel, port_scan, syn_flood)",
        ),
        ("[[rule]]\nid = 'a'\ndetector = 'nope'\n", "rule 1 (a): unknown detector 'nope' (known:"),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\nseverity = 'urgent'\n",
            "rule 1 (a): 'severity' must be one of low, medium, high, critical",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\nenabled = 'yes'\n",
            "rule 1 (a): 'enabled' must be true or false",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\nfilter = 5\n",
            "rule 1 (a): 'filter' must be a string",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\nfilter = 'tcp and port http'\n",
            "rule 1 (a): bad filter: expected a port number (0-65535), got 'http' (at position 13)",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\nports = 3\n",
            "rule 1 (a): unknown parameter 'ports' for port_scan "
            "(allowed: distinct_hosts, distinct_ports, window_seconds)",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\ndistinct_ports = 'many'\n",
            "rule 1 (a): 'distinct_ports' must be a number",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\ndistinct_ports = 2.5\n",
            "rule 1 (a): 'distinct_ports' must be a whole number",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\ndistinct_ports = true\n",
            "rule 1 (a): 'distinct_ports' must be a number",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\ndistinct_ports = -1\n",
            "rule 1 (a): 'distinct_ports' must be between 0 and 65535",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\ndistinct_ports = 70000\n",
            "rule 1 (a): 'distinct_ports' must be between 0 and 65535",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\nwindow_seconds = 0\n",
            "rule 1 (a): 'window_seconds' must be between 0.001 and 86400",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'port_scan'\nwindow_seconds = nan\n",
            "rule 1 (a): 'window_seconds' must be between",
        ),
        (
            "[[rule]]\nid = 'a'\ndetector = 'arp_spoof'\ncheck_ethernet_mismatch = 1\n",
            "rule 1 (a): 'check_ethernet_mismatch' must be true or false",
        ),
        ("rule = 5\n", "'rule' must be written as [[rule]] tables"),
        ("rule = [1]\n", "rule 1: must be a table"),
        ("colour = 'red'\n", "unknown top-level key 'colour'"),
        ("[[rule]\n", "not valid TOML"),
    ],
)
def test_error_messages(toml: str, message: str | None) -> None:
    result = parse_rules(toml, "x.toml")
    if message is None:
        assert result.errors == ()
        return
    assert result.errors, toml
    assert any(e.startswith("x.toml: ") and message in e for e in result.errors), result.errors


def test_all_the_problems_in_a_file_are_reported_at_once() -> None:
    result = parse_rules(
        "[[rule]]\nid = 'a'\ndetector = 'nope'\nseverity = 'x'\n"
        "[[rule]]\nid = 'b'\ndetector = 'port_scan'\nports = 1\n",
        "x",
    )
    assert len(result.errors) == 3
    assert result.rules == ()


def test_a_good_rule_next_to_a_bad_one_still_loads() -> None:
    result = parse_rules(
        "[[rule]]\nid = 'good'\ndetector = 'port_scan'\n[[rule]]\nid = 'bad'\ndetector = 'nope'\n",
        "x",
    )
    assert [r.id for r in result.rules] == ["good"]
    assert len(result.errors) == 1


def test_loading_a_directory_reads_files_in_name_order(tmp_path: Path) -> None:
    (tmp_path / "b.toml").write_text('[[rule]]\nid = "second"\ndetector = "syn_flood"\n')
    (tmp_path / "a.toml").write_text('[[rule]]\nid = "first"\ndetector = "port_scan"\n')
    (tmp_path / "notes.txt").write_text("not a rule file")
    result = load_rules(tmp_path)
    assert result.errors == ()
    assert [r.id for r in result.rules] == ["first", "second"]
    assert result.rules[0].source == str(tmp_path / "a.toml")


def test_loading_a_single_file(tmp_path: Path) -> None:
    path = tmp_path / "only.toml"
    path.write_text('[[rule]]\nid = "x"\ndetector = "arp_spoof"\n')
    assert [r.id for r in load_rules(path).rules] == ["x"]


def test_duplicate_ids_across_files(tmp_path: Path) -> None:
    (tmp_path / "a.toml").write_text('[[rule]]\nid = "same"\ndetector = "port_scan"\n')
    (tmp_path / "b.toml").write_text('[[rule]]\nid = "same"\ndetector = "syn_flood"\n')
    result = load_rules(tmp_path)
    assert [r.detector for r in result.rules] == ["port_scan"]
    assert len(result.errors) == 1
    assert "duplicate id" in result.errors[0]
    assert str(tmp_path / "a.toml") in result.errors[0]


def test_problems_with_the_files_themselves(tmp_path: Path) -> None:
    missing = load_rules(tmp_path / "nope.toml")
    assert missing.rules == ()
    assert len(missing.errors) == 1
    assert missing.errors[0].startswith(str(tmp_path / "nope.toml"))
    assert load_rules(tmp_path).errors == (f"{tmp_path}: no .toml rule files found",)
    (tmp_path / "bad.toml").write_bytes(b"\xff\xfe\x00 not utf-8")
    assert load_rules(tmp_path).errors  # reported, not raised
    (tmp_path / "bad.toml").write_text("x" * 10)
    assert "not valid TOML" in load_rules(tmp_path).errors[0]


def test_files_over_the_size_limit_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sentinel.ids.rules.MAX_FILE_BYTES", 50)
    path = tmp_path / "big.toml"
    path.write_text("# " + "x" * 100 + "\n")
    assert load_rules(path).errors == (f"{path}: larger than 50 bytes",)
    assert MAX_FILE_BYTES == 1 << 20


def test_the_built_in_defaults() -> None:
    result = default_rules()
    assert result.errors == ()
    assert [r.id for r in result.rules] == ["port-scan", "syn-flood", "arp-spoof", "dns-tunnel"]
    assert {r.detector for r in result.rules} == set(DETECTORS)


def test_the_rule_files_in_the_repository_equal_the_built_in_defaults() -> None:
    loaded = load_rules(RULES_DIR)
    assert loaded.errors == ()
    built_in = default_rules().rules
    assert [(r.id, r.detector, r.severity, r.enabled, r.config) for r in loaded.rules] == [
        (r.id, r.detector, r.severity, r.enabled, r.config) for r in built_in
    ]
    assert all(r.filter is None for r in loaded.rules)
