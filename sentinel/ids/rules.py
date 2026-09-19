"""Rule configuration, in TOML files (the standard library reads TOML, so no dependency).

    [[rule]]
    id = "ssh-scan"              # required, unique across all files: a-z 0-9 - _
    detector = "port_scan"       # required: port_scan, syn_flood, arp_spoof or dns_tunnel
    severity = "high"            # optional: low, medium, high or critical
    enabled = true               # optional
    filter = "dst port 22"       # optional: only packets that match are shown to the detector
    distinct_ports = 3           # the rest are the detector's own parameters
    window_seconds = 30

Loading never raises: every problem comes back as a message that names the file and the rule."""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from sentinel.filter import Filter, parse_filter
from sentinel.ids.alert import SEVERITIES
from sentinel.ids.detectors import DETECTORS
from sentinel.ids.params import Value, check_param

MAX_FILE_BYTES = 1 << 20

_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_COMMON_KEYS = ("id", "detector", "severity", "enabled", "filter")


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    detector: str
    severity: str
    enabled: bool
    filter: Filter | None
    config: dict[str, Value]  # every parameter of the detector, defaults filled in
    source: str  # where the rule came from, for messages


@dataclass(frozen=True, slots=True)
class RuleSet:
    rules: tuple[Rule, ...]
    errors: tuple[str, ...]


def _rule(table: object, index: int, source: str) -> tuple[Rule | None, list[str]]:
    where = f"{source}: rule {index + 1}"
    if not isinstance(table, dict):
        return None, [f"{where}: must be a table"]
    errors: list[str] = []
    rule_id = table.get("id")
    if isinstance(rule_id, str) and _ID.fullmatch(rule_id):
        where += f" ({rule_id})"
    else:
        errors.append(f"{where}: 'id' must be 1-64 characters: a-z, 0-9, '-' and '_'")
    name = table.get("detector")
    cls = DETECTORS.get(name) if isinstance(name, str) else None
    if cls is None:
        known = ", ".join(sorted(DETECTORS))
        problem = "missing 'detector'" if name is None else f"unknown detector {name!r}"
        errors.append(f"{where}: {problem} (known: {known})")

    severity = table.get("severity", cls.severity if cls else "medium")
    if severity not in SEVERITIES:
        errors.append(f"{where}: 'severity' must be one of {', '.join(SEVERITIES)}")
    enabled = table.get("enabled", True)
    if not isinstance(enabled, bool):
        errors.append(f"{where}: 'enabled' must be true or false")
    flt: Filter | None = None
    if "filter" in table:
        text = table["filter"]
        flt = parse_filter(text) if isinstance(text, str) else None
        if flt is None:
            errors.append(f"{where}: 'filter' must be a string")
        elif flt.error is not None:
            errors.append(f"{where}: bad filter: {flt.error} (at position {flt.position})")

    config: dict[str, Value] = {}
    if cls is not None:
        config = {p.name: p.default for p in cls.params}
        by_name = {p.name: p for p in cls.params}
        for key, value in table.items():
            if key in _COMMON_KEYS:
                continue
            param = by_name.get(key)
            if param is None:
                allowed = ", ".join(sorted(by_name))
                errors.append(
                    f"{where}: unknown parameter {key!r} for {cls.name} (allowed: {allowed})"
                )
                continue
            checked, bad = check_param(param, value)
            if bad:
                errors.append(f"{where}: {bad}")
            elif checked is not None:
                config[key] = checked
    if errors or cls is None or not isinstance(rule_id, str):
        return None, errors
    return Rule(rule_id, cls.name, str(severity), bool(enabled), flt, config, source), []


def parse_rules(text: str, source: str) -> RuleSet:
    """The rules in TOML `text`. `source` names it in messages."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return RuleSet((), (f"{source}: not valid TOML: {e}",))
    errors = [
        f"{source}: unknown top-level key {key!r} (only [[rule]] tables are allowed)"
        for key in data
        if key != "rule"
    ]
    tables = data.get("rule", [])
    if not isinstance(tables, list):
        return RuleSet((), (*errors, f"{source}: 'rule' must be written as [[rule]] tables"))
    rules: list[Rule] = []
    for i, table in enumerate(tables):
        rule, problems = _rule(table, i, source)
        errors += problems
        if rule is not None:
            rules.append(rule)
    return RuleSet(tuple(rules), tuple(errors))


def _read(path: Path) -> tuple[str | None, str | None]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None, f"{path}: larger than {MAX_FILE_BYTES} bytes"
        return path.read_text(encoding="utf-8"), None
    except (OSError, UnicodeDecodeError) as e:
        return None, f"{path}: {e}"


def load_rules(path: Path) -> RuleSet:
    """Rules from one TOML file, or from every `*.toml` file in a directory (sorted by name)."""
    try:
        files = sorted(path.glob("*.toml")) if path.is_dir() else [path]
    except OSError as e:
        return RuleSet((), (f"{path}: {e}",))
    if not files:
        return RuleSet((), (f"{path}: no .toml rule files found",))
    rules: list[Rule] = []
    errors: list[str] = []
    seen: dict[str, str] = {}
    for file in files:
        text, problem = _read(file)
        if text is None:
            errors.append(problem or f"{file}: unreadable")
            continue
        loaded = parse_rules(text, str(file))
        errors += loaded.errors
        for rule in loaded.rules:
            if rule.id in seen:
                errors.append(
                    f"{file}: rule ({rule.id}): duplicate id, first defined in {seen[rule.id]}"
                )
                continue
            seen[rule.id] = str(file)
            rules.append(rule)
    return RuleSet(tuple(rules), tuple(errors))


def default_rules() -> RuleSet:
    """One rule per detector, with the detector's own defaults. `rules/default.toml` in the
    repository spells out the same thing, and a test keeps them equal."""
    rules = tuple(
        Rule(
            cls.name.replace("_", "-"),
            cls.name,
            cls.severity,
            True,
            None,
            {p.name: p.default for p in cls.params},
            "built-in defaults",
        )
        for cls in DETECTORS.values()
    )
    return RuleSet(rules, ())
