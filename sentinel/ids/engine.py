"""Feeds packets to the enabled rules and collects alerts, in a deterministic order."""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from sentinel.ids.alert import Alert
from sentinel.ids.detectors import DETECTORS, Detection, Detector
from sentinel.ids.rules import Rule
from sentinel.ids.view import make_view
from sentinel.pcap import Packet
from sentinel.proto.decode import decode
from sentinel.proto.layer import Layer


@dataclass(slots=True)
class _Active:
    rule: Rule
    detector: Detector


class Engine:
    """`process()` every packet in capture order, then `finish()` for the alerts.

    Alerts are sorted by the timestamp of the packet that raised them, then by the position of
    the rule in the configuration, so the same capture and rules always give the same output."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._active = [
            _Active(rule, DETECTORS[rule.detector](rule.config)) for rule in rules if rule.enabled
        ]
        self._alerts: list[tuple[int, Alert]] = []  # (rule position, alert)
        self._last_ts = 0

    def process(self, packet: Packet, layers: Sequence[Layer] | None = None) -> None:
        """Show one packet to every rule whose filter (if any) accepts it."""
        layers = decode(packet.data) if layers is None else layers
        self._last_ts = max(self._last_ts, packet.ts_ns)
        view = make_view(packet.ts_ns, layers)
        for position, active in enumerate(self._active):
            flt = active.rule.filter
            if flt is not None and not flt.matches(layers):
                continue
            self._collect(position, active, active.detector.on_packet(view))

    def _collect(self, position: int, active: _Active, detections: Iterable[Detection]) -> None:
        rule = active.rule
        for d in detections:
            alert = Alert(
                d.ts_ns, rule.id, rule.detector, rule.severity, d.src, d.dst, d.message, d.evidence
            )
            self._alerts.append((position, alert))

    def pop_alerts(self) -> list[Alert]:
        """The alerts raised since the last call, in the usual order, removed from the engine.
        A live run calls this after every packet, so alerts are printed as they happen and the
        engine does not keep them all until the end."""
        self._alerts.sort(key=lambda item: (item[1].ts_ns, item[0]))
        alerts = [alert for _, alert in self._alerts]
        self._alerts = []
        return alerts

    def finish(self) -> list[Alert]:
        for position, active in enumerate(self._active):
            self._collect(position, active, active.detector.finish())
            if active.detector.dropped:
                n = active.detector.dropped
                self._alerts.append(
                    (
                        position,
                        Alert(
                            self._last_ts,
                            active.rule.id,
                            active.rule.detector,
                            "low",
                            None,
                            None,
                            f"{n} packets were not tracked: the detector's state limit was reached",
                            {"packets": n},
                        ),
                    )
                )
                active.detector.dropped = 0
        self._alerts.sort(key=lambda item: (item[1].ts_ns, item[0]))  # stable: ties keep order
        alerts = [alert for _, alert in self._alerts]
        return alerts
