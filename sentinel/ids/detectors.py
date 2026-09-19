"""The detectors. Each one is fed decoded packets in capture order and returns detections.

Every detector keeps bounded state (see MAX_KEYS and SlidingWindow) and reports when it had to
ignore packets because of it. A detector never raises on a packet: it only sees intact layers
(see PacketView)."""

import math
from collections import OrderedDict
from collections.abc import Hashable, Mapping
from dataclasses import dataclass, field
from typing import ClassVar

from sentinel.ids.alert import Evidence
from sentinel.ids.params import Param, Value
from sentinel.ids.view import PacketView
from sentinel.ids.window import SlidingWindow
from sentinel.proto import tcp as tcpflags

MAX_KEYS = 100_000  # tracked sources, targets, pairs or bindings per detector


@dataclass(frozen=True, slots=True)
class Detection:
    ts_ns: int
    message: str
    src: str | None = None
    dst: str | None = None
    evidence: Evidence = field(default_factory=dict)


class Detector:
    name: ClassVar[str]
    severity: ClassVar[str]  # default, a rule may override it
    params: ClassVar[tuple[Param, ...]]

    def __init__(self, config: Mapping[str, Value]) -> None:
        self.dropped = 0  # packets ignored because a state limit was reached
        self._alerted: dict[Hashable, int] = {}

    @classmethod
    def create(cls, overrides: Mapping[str, Value] | None = None) -> "Detector":
        """A detector with the defaults, plus any overrides (which are not checked here)."""
        config: dict[str, Value] = {p.name: p.default for p in cls.params}
        config.update(overrides or {})
        return cls(config)

    def on_packet(self, view: PacketView) -> list[Detection]:
        raise NotImplementedError

    def finish(self) -> list[Detection]:
        return []

    def _first(self, key: Hashable, ts_ns: int, window_ns: int) -> bool:
        """True at most once per `window_ns` for each key, so one attack is one alert."""
        until = self._alerted.pop(key, None)
        if until is not None and ts_ns < until:
            self._alerted[key] = until
            return False
        if len(self._alerted) >= MAX_KEYS:
            del self._alerted[next(iter(self._alerted))]
        self._alerted[key] = ts_ns + window_ns
        return True

    def _table_window[K: Hashable](
        self,
        table: OrderedDict[K, SlidingWindow],
        key: K,
        window_ns: int,
        max_events: int,
        ts_ns: int,
    ) -> SlidingWindow | None:
        """The window of `key`, made if needed. The table is kept in order of last use, and a
        key that has been idle for longer than the window is forgotten (its window would be
        empty anyway), so a long run does not fill the table with sources that are long gone."""
        window = table.get(key)
        if window is not None:
            table.move_to_end(key)
            return window
        while table:
            oldest = table[next(iter(table))].newest_ns
            if oldest is not None and ts_ns - oldest <= window_ns:
                break
            table.popitem(last=False)
        if len(table) >= MAX_KEYS:
            self.dropped += 1
            return None
        window = table[key] = SlidingWindow(window_ns, max_events)
        return window


def _window_ns(config: Mapping[str, Value]) -> int:
    return int(float(config["window_seconds"]) * 1_000_000_000)


def _sample(keys: list[Hashable], limit: int = 10) -> list[int]:
    return sorted(k for k in keys if isinstance(k, int))[:limit]


_FLAGS = tcpflags.SYN | tcpflags.ACK | tcpflags.RST | tcpflags.FIN | tcpflags.PSH | tcpflags.URG


def is_scan_probe(flags: int) -> bool:
    """A TCP packet that starts no real connection: a SYN scan, or one of the stealth scans
    (no flags at all, FIN only, or FIN+PSH+URG)."""
    f = flags & _FLAGS
    return f in (tcpflags.SYN, 0, tcpflags.FIN, tcpflags.FIN | tcpflags.PSH | tcpflags.URG)


class PortScan(Detector):
    """One source probing many ports on one host, or one port on many hosts."""

    name = "port_scan"
    severity = "medium"
    params = (
        Param("distinct_ports", int, 15, 0, 65535, "ports on one host that make a scan (0: off)"),
        Param(
            "distinct_hosts", int, 30, 0, 1_000_000, "hosts on one port that make a sweep (0: off)"
        ),
        Param("window_seconds", float, 10.0, 0.001, 86_400, "how long the probes may take"),
    )

    def __init__(self, config: Mapping[str, Value]) -> None:
        super().__init__(config)
        self._ports_needed = int(config["distinct_ports"])
        self._hosts_needed = int(config["distinct_hosts"])
        self._window = _window_ns(config)
        self._by_target: OrderedDict[tuple[str, str], SlidingWindow] = OrderedDict()
        self._by_port: OrderedDict[tuple[str, int], SlidingWindow] = OrderedDict()

    def on_packet(self, view: PacketView) -> list[Detection]:
        tcp, src, dst = view.tcp, view.src_ip, view.dst_ip
        if tcp is None or src is None or dst is None or not is_scan_probe(tcp.flags):
            return []
        s, d, out = str(src), str(dst), []
        dropped_before = self.dropped
        if self._ports_needed:
            w = self._window_for(self._by_target, (s, d), self._ports_needed, view.ts_ns)
            if w is not None:
                w.add(view.ts_ns, tcp.dst_port)
                if w.distinct >= self._ports_needed and self._first(
                    ("ports", s, d), view.ts_ns, self._window
                ):
                    out.append(
                        Detection(
                            view.ts_ns,
                            f"{s} probed {w.distinct} ports on {d} in {w.span_ns / 1e9:.1f}s",
                            s,
                            d,
                            {
                                "ports": w.distinct,
                                "seconds": round(w.span_ns / 1e9, 3),
                                "sample": _sample(w.keys),
                            },
                        )
                    )
        if self._hosts_needed:
            w = self._window_for(self._by_port, (s, tcp.dst_port), self._hosts_needed, view.ts_ns)
            if w is not None:
                w.add(view.ts_ns, d)
                key = ("hosts", s, tcp.dst_port)
                if w.distinct >= self._hosts_needed and self._first(key, view.ts_ns, self._window):
                    out.append(
                        Detection(
                            view.ts_ns,
                            f"{s} probed port {tcp.dst_port} on {w.distinct} hosts "
                            f"in {w.span_ns / 1e9:.1f}s",
                            s,
                            None,
                            {
                                "hosts": w.distinct,
                                "port": tcp.dst_port,
                                "seconds": round(w.span_ns / 1e9, 3),
                            },
                        )
                    )
        if self.dropped - dropped_before > 1:  # one packet, however many tables refused it
            self.dropped = dropped_before + 1
        return out

    def _window_for[K: Hashable](
        self, table: OrderedDict[K, SlidingWindow], key: K, needed: int, ts_ns: int
    ) -> SlidingWindow | None:
        # Enough room to see `needed` different keys, whatever repeats in between.
        return self._table_window(table, key, self._window, max(needed * 4, 64), ts_ns)


class SynFlood(Detector):
    """Many SYNs to one service, and almost none of them followed by the handshake's ACK."""

    name = "syn_flood"
    severity = "high"
    params = (
        Param("syns", int, 100, 1, 10_000_000, "SYNs to one service within the window"),
        Param("window_seconds", float, 1.0, 0.001, 86_400, "the window"),
        Param("max_completed_ratio", float, 0.3, 0, 1, "at most this share may be completed"),
    )

    def __init__(self, config: Mapping[str, Value]) -> None:
        super().__init__(config)
        self._needed = int(config["syns"])
        self._max_ratio = float(config["max_completed_ratio"])
        self._window = _window_ns(config)
        self._syns: OrderedDict[tuple[str, int], SlidingWindow] = OrderedDict()
        self._done: OrderedDict[tuple[str, int], SlidingWindow] = OrderedDict()
        self._pending: dict[tuple[str, int, str, int], None] = {}  # connections awaiting the ACK

    def on_packet(self, view: PacketView) -> list[Detection]:
        tcp, src, dst = view.tcp, view.src_ip, view.dst_ip
        if tcp is None or src is None or dst is None:
            return []
        s, d = str(src), str(dst)
        target = (d, tcp.dst_port)
        conn = (s, tcp.src_port, d, tcp.dst_port)
        if tcp.flags & tcpflags.SYN and not tcp.flags & tcpflags.ACK:
            w = self._table_window(self._syns, target, self._window, self._needed + 1, view.ts_ns)
            if w is None:
                return []
            w.add(view.ts_ns, s)
            self._pending.pop(conn, None)
            if len(self._pending) >= MAX_KEYS:
                del self._pending[next(iter(self._pending))]  # forget the oldest half-open one
            self._pending[conn] = None
            done = self._done.get(target)
            completed = done.count if done is not None else 0
            if (
                w.count >= self._needed
                and completed / w.count <= self._max_ratio
                and self._first(target, view.ts_ns, self._window)
            ):
                return [
                    Detection(
                        view.ts_ns,
                        f"{w.count} SYNs to {d}:{tcp.dst_port} in {w.span_ns / 1e9:.1f}s from "
                        f"{w.distinct} sources, {completed} completed",
                        None,
                        d,
                        {
                            "syns": w.count,
                            "completed": completed,
                            "sources": w.distinct,
                            "port": tcp.dst_port,
                            "seconds": round(w.span_ns / 1e9, 3),
                        },
                    )
                ]
        elif tcp.flags & tcpflags.ACK and not tcp.flags & (tcpflags.SYN | tcpflags.RST):
            if conn in self._pending:  # the third packet of a handshake
                del self._pending[conn]
                done_window = self._table_window(
                    self._done, target, self._window, self._needed + 1, view.ts_ns
                )
                if done_window is not None:
                    done_window.add(view.ts_ns)
        return []


class ArpSpoof(Detector):
    """An IP address that suddenly belongs to another MAC address, or an ARP packet whose
    sender address differs from the Ethernet source it arrived from."""

    name = "arp_spoof"
    severity = "high"
    params = (Param("check_ethernet_mismatch", bool, True, doc="compare with the Ethernet source"),)

    def __init__(self, config: Mapping[str, Value]) -> None:
        super().__init__(config)
        self._check_mismatch = bool(config["check_ethernet_mismatch"])
        self._bindings: dict[str, str] = {}
        self._seen: set[tuple[str, str, str]] = set()

    def on_packet(self, view: PacketView) -> list[Detection]:
        arp = view.arp
        if arp is None:
            return []
        ip, mac, out = str(arp.sender_ip), arp.sender_mac.hex(":"), []
        if self._check_mismatch and view.eth is not None and arp.sender_mac != view.eth.src:
            eth_src = view.eth.src.hex(":")
            if self._new(("mismatch", mac, eth_src)):
                out.append(
                    Detection(
                        view.ts_ns,
                        f"ARP says {ip} is at {mac}, but the frame came from {eth_src}",
                        eth_src,
                        ip,
                        {"ip": ip, "arp_mac": mac, "ethernet_source": eth_src, "op": arp.op},
                    )
                )
        if ip == "0.0.0.0":  # an address probe: nobody claims anything yet
            return out
        old = self._bindings.get(ip)
        if old is None:
            if len(self._bindings) < MAX_KEYS:
                self._bindings[ip] = mac
            else:
                self.dropped += 1
        elif old != mac:
            self._bindings[ip] = mac
            if self._new(("moved", ip, f"{old}>{mac}")):
                out.append(
                    Detection(
                        view.ts_ns,
                        f"{ip} moved from {old} to {mac}",
                        mac,
                        ip,
                        {"ip": ip, "old_mac": old, "new_mac": mac, "op": arp.op},
                    )
                )
        return out

    def _new(self, key: tuple[str, str, str]) -> bool:
        if key in self._seen or len(self._seen) >= MAX_KEYS:
            return False
        self._seen.add(key)
        return True


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


class DnsTunnel(Detector):
    """Signs of data hidden in DNS names, and of a client asking for names that do not exist.

    Names are split into the registered-looking part (the last two labels) and the rest."""

    name = "dns_tunnel"
    severity = "medium"
    params = (
        Param("max_name_length", int, 100, 0, 255, "a name at least this long (0: off)"),
        Param("max_label_length", int, 50, 0, 63, "a label at least this long (0: off)"),
        Param(
            "entropy_threshold", float, 4.2, 0, 8, "bits per character of the subdomain (0: off)"
        ),
        Param(
            "min_entropy_length", int, 40, 1, 253, "shortest subdomain the entropy test looks at"
        ),
        Param(
            "unique_subdomains",
            int,
            50,
            0,
            1_000_000,
            "different subdomains of one domain (0: off)",
        ),
        Param(
            "nxdomain_count", int, 20, 0, 1_000_000, "'no such name' answers to one client (0: off)"
        ),
        Param("window_seconds", float, 60.0, 0.001, 86_400, "window for the two counts"),
    )

    def __init__(self, config: Mapping[str, Value]) -> None:
        super().__init__(config)
        self._max_name = int(config["max_name_length"])
        self._max_label = int(config["max_label_length"])
        self._entropy = float(config["entropy_threshold"])
        self._min_entropy_len = int(config["min_entropy_length"])
        self._unique = int(config["unique_subdomains"])
        self._nx = int(config["nxdomain_count"])
        self._window = _window_ns(config)
        self._subdomains: OrderedDict[tuple[str, str], SlidingWindow] = OrderedDict()
        self._nxdomains: OrderedDict[str, SlidingWindow] = OrderedDict()

    def on_packet(self, view: PacketView) -> list[Detection]:
        dns = view.dns
        if dns is None:
            return []
        if dns.is_response:
            return self._nxdomain(view) if dns.rcode == 3 and self._nx else []
        src = view.src_ip
        if src is None:
            return []
        out: list[Detection] = []
        client = str(src)
        for question in dns.questions:
            out += self._query(view.ts_ns, client, question.name)
        return out

    def _query(self, ts_ns: int, client: str, name: str) -> list[Detection]:
        labels = [] if name == "." else name.split(".")
        base = ".".join(labels[-2:])
        sub = ".".join(labels[:-2])
        shown = name if len(name) <= 80 else name[:77] + "..."
        out: list[Detection] = []

        def alert(signal: str, message: str, evidence: Evidence) -> None:
            if self._first((signal, client, base), ts_ns, self._window):
                evidence = {"signal": signal, "name": shown, **evidence}
                out.append(Detection(ts_ns, f"{client} {message}", client, None, evidence))

        longest = max((len(x) for x in labels), default=0)
        if (self._max_name and len(name) >= self._max_name) or (
            self._max_label and longest >= self._max_label
        ):
            alert(
                "long_name",
                f"asked for a very long name under {base} ({len(name)} characters)",
                {"length": len(name), "longest_label": longest},
            )
        flat = sub.replace(".", "")
        if self._entropy and len(flat) >= self._min_entropy_len and entropy(flat) >= self._entropy:
            alert(
                "high_entropy",
                f"asked for a random-looking name under {base}",
                {"entropy": round(entropy(flat), 3), "length": len(flat)},
            )
        if self._unique and sub:
            w = self._table_window(
                self._subdomains, (client, base), self._window, self._unique * 2 + 1, ts_ns
            )
            if w is not None:
                w.add(ts_ns, sub)
                if w.distinct >= self._unique:
                    alert(
                        "many_subdomains",
                        f"asked for {w.distinct} different subdomains of {base} "
                        f"in {w.span_ns / 1e9:.1f}s",
                        {"subdomains": w.distinct, "domain": base},
                    )
        return out

    def _nxdomain(self, view: PacketView) -> list[Detection]:
        dst = view.dst_ip
        if dst is None:
            return []
        client = str(dst)
        w = self._table_window(self._nxdomains, client, self._window, self._nx + 1, view.ts_ns)
        if w is None:
            return []
        w.add(view.ts_ns)
        if w.count >= self._nx and self._first(("nxdomain", client), view.ts_ns, self._window):
            return [
                Detection(
                    view.ts_ns,
                    f"{client} received {w.count} 'no such name' answers in {w.span_ns / 1e9:.1f}s",
                    None,
                    client,
                    {"signal": "nxdomain", "answers": w.count},
                )
            ]
        return []


DETECTORS: dict[str, type[Detector]] = {
    cls.name: cls for cls in (PortScan, SynFlood, ArpSpoof, DnsTunnel)
}
