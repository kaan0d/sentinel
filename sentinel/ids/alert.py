"""What an alert is, and how it is printed. Both formats are deterministic: the same alerts
always give the same text."""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

SEVERITIES = ("low", "medium", "high", "critical")

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# Evidence values are plain data, so an alert can be printed as JSON.
type Evidence = dict[str, int | float | str | list[str] | list[int]]


@dataclass(frozen=True, slots=True)
class Alert:
    ts_ns: int  # timestamp of the packet that triggered it
    rule: str  # the rule id from the configuration
    detector: str
    severity: str
    src: str | None
    dst: str | None
    message: str
    evidence: Evidence = field(default_factory=dict)


def _iso(ts_ns: int) -> str:
    sec, ns = divmod(ts_ns, 1_000_000_000)
    return f"{(_EPOCH + timedelta(seconds=sec)):%Y-%m-%dT%H:%M:%S}.{ns // 1000:06d}Z"


def to_json(alert: Alert) -> str:
    """One JSON object on one line, keys sorted, ASCII only."""
    return json.dumps(
        {
            "ts": _iso(alert.ts_ns),
            "ts_ns": alert.ts_ns,
            "rule": alert.rule,
            "detector": alert.detector,
            "severity": alert.severity,
            "src": alert.src,
            "dst": alert.dst,
            "message": alert.message,
            "evidence": alert.evidence,
        },
        sort_keys=True,
        ensure_ascii=True,
    )


def to_text(alert: Alert) -> str:
    return f"{_iso(alert.ts_ns)} [{alert.severity}] {alert.rule}: {alert.message}"
