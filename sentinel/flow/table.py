"""Groups packets into bidirectional TCP and UDP flows and keeps per-flow statistics.

A flow is identified by its protocol and the two (address, port) endpoints, in either direction.
A new flow starts when the same endpoints are used again after the old flow ended (a new SYN after
FIN or RST, or a SYN with a different initial sequence number) or after it sat idle too long.
ICMP, ARP, IP fragments and packets that failed to parse are not flows; they are only counted.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from sentinel.flow.app import DNS_PORT, AppItem, analyze_stream
from sentinel.flow.stream import DEFAULT_MAX_BYTES, Budget, TcpStream
from sentinel.pcap import Packet
from sentinel.proto import tcp
from sentinel.proto.decode import decode
from sentinel.proto.dns import Dns
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.ipv6 import IPv6
from sentinel.proto.layer import Layer
from sentinel.proto.tcp import Tcp
from sentinel.proto.udp import Udp

MAX_UDP_MESSAGES = 8

Address = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class Endpoint:
    addr: Address
    port: int

    def __str__(self) -> str:
        return (
            f"[{self.addr}]:{self.port}"
            if isinstance(self.addr, IPv6Address)
            else f"{self.addr}:{self.port}"
        )


FlowKey = tuple[str, Address, int, Address, int]


def _s(n: int) -> str:
    return "" if n == 1 else "s"


def _key(proto: str, a: Endpoint, b: Endpoint) -> FlowKey:
    """The same key for both directions: the smaller endpoint goes first."""
    if (int(a.addr), a.port) > (int(b.addr), b.port):
        a, b = b, a
    return (proto, a.addr, a.port, b.addr, b.port)


class Flow:
    """Direction 0 is client to server. For TCP the client is whoever sent the SYN; without one
    (the capture started mid-connection) it is whoever was seen first."""

    def __init__(self, proto: str, client: Endpoint, server: Endpoint, ts_ns: int) -> None:
        self.proto = proto
        self.client = client
        self.server = server
        self.first_ts_ns = ts_ns
        self.last_ts_ns = ts_ns
        self.packets = [0, 0]
        self.payload_bytes = [0, 0]  # TCP/UDP payload bytes seen, retransmissions included
        self.anomaly_packets = 0
        self.streams: list[TcpStream | None] = [None, None]
        self.udp_messages: list[AppItem] = []
        self.client_syn_seq: int | None = None
        self._syn = False
        self._synack = False
        self._fin = [False, False]
        self._rst = False
        self._app: tuple[AppItem, ...] | None = None

    @property
    def duration_ns(self) -> int:
        return max(0, self.last_ts_ns - self.first_ts_ns)

    @property
    def state(self) -> str:
        """TCP only: what the packets seen so far say about the connection."""
        if self.proto != "tcp":
            return ""
        if self._rst:
            return "reset"
        if all(self._fin):
            return "closed"
        if any(self._fin):
            return "closing"
        if self._synack:
            return "established"
        if self._syn:
            return "syn-sent"
        return "midstream"

    @property
    def is_finished(self) -> bool:
        return self.state in ("closed", "reset")

    def app(self) -> tuple[AppItem, ...]:
        """DNS, HTTP and TLS ClientHello messages found in the flow (parsed once, then cached)."""
        if self._app is None:
            items = list(self.udp_messages)
            dns = DNS_PORT in (self.client.port, self.server.port)
            for direction, stream in enumerate(self.streams):
                if stream is not None:
                    items += analyze_stream(direction, stream.data(), dns)
            self._app = tuple(items)
        return self._app

    def notes(self) -> list[str]:
        """Things worth a second look, as short phrases."""
        out: list[str] = []
        who = ("client", "server")
        for direction, stream in enumerate(self.streams):
            if stream is None:
                continue
            if stream.stored_bytes and not stream.has_start:
                out.append(f"{who[direction]} stream start not captured")
            if stream.retransmitted_segments:
                n = stream.retransmitted_segments
                out.append(f"{n} retransmitted {who[direction]} segment{_s(n)}")
            if stream.out_of_order_segments:
                n = stream.out_of_order_segments
                out.append(f"{n} out-of-order {who[direction]} segment{_s(n)}")
            if stream.missing_bytes:
                n = stream.missing_bytes
                out.append(f"{n} {who[direction]} byte{_s(n)} missing")
            if stream.overlap_conflicts:
                n = stream.overlap_conflicts
                out.append(f"{n} conflicting {who[direction]} overlap{_s(n)}")
            if stream.dropped_bytes:
                n = stream.dropped_bytes
                out.append(f"{n} {who[direction]} byte{_s(n)} not buffered")
            if stream.conflicting_syns:
                out.append(f"conflicting {who[direction]} syn")
        if self.anomaly_packets:
            out.append(f"{self.anomaly_packets} packet{_s(self.anomaly_packets)} with anomalies")
        return out

    def _wants_new_flow(self, l4: Tcp) -> bool:
        """A SYN that cannot belong to this flow: it ended, or the initial sequence differs."""
        if not (l4.flags & tcp.SYN) or l4.flags & tcp.ACK:
            return False
        return self.is_finished or (
            self.client_syn_seq is not None and self.client_syn_seq != l4.seq
        )

    def _update_tcp(self, direction: int, l4: Tcp, budget: Budget, max_bytes: int) -> None:
        stream = self.streams[direction]
        if stream is None and (l4.payload or l4.flags & (tcp.SYN | tcp.FIN)):
            stream = self.streams[direction] = TcpStream(max_bytes, budget)
        if l4.flags & tcp.RST:
            self._rst = True
        if l4.flags & tcp.SYN:
            if l4.flags & tcp.ACK:
                self._synack = True
            else:
                self._syn = True
                if direction == 0:
                    self.client_syn_seq = l4.seq
            assert stream is not None
            stream.add_syn(l4.seq)
        if l4.payload:
            assert stream is not None
            stream.add_segment(l4.seq, l4.payload)
        if l4.flags & tcp.FIN:
            self._fin[direction] = True
            assert stream is not None
            stream.add_fin(l4.seq + len(l4.payload))


class FlowTable:
    def __init__(
        self,
        *,
        tcp_idle_s: int = 3600,
        udp_idle_s: int = 120,
        max_flows: int = 200_000,
        max_stream_bytes: int = DEFAULT_MAX_BYTES,
        max_buffered_bytes: int = 256 << 20,
    ) -> None:
        self._idle_ns = {"tcp": tcp_idle_s * 1_000_000_000, "udp": udp_idle_s * 1_000_000_000}
        self._max_flows = max_flows
        self._max_stream_bytes = max_stream_bytes
        self._budget = Budget(max_buffered_bytes)
        self._active: dict[FlowKey, Flow] = {}
        self.flows: list[Flow] = []  # in the order they started
        self.skipped_packets = 0  # not TCP/UDP, a fragment, or unparsable
        self.untracked_packets = 0  # packets that would start a flow beyond `max_flows`

    def add(self, packet: Packet, layers: Sequence[Layer] | None = None) -> None:
        """Add a packet. Pass `layers` if the packet was already decoded."""
        layers = decode(packet.data) if layers is None else layers
        ip = layers[1] if len(layers) > 1 else None
        l4 = layers[2] if len(layers) > 2 else None
        if not isinstance(ip, IPv4 | IPv6) or ip.error or not isinstance(l4, Tcp | Udp) or l4.error:
            self.skipped_packets += 1
            return
        proto = "tcp" if isinstance(l4, Tcp) else "udp"
        src, dst = Endpoint(ip.src, l4.src_port), Endpoint(ip.dst, l4.dst_port)
        key = _key(proto, src, dst)
        flow = self._active.get(key)
        if flow is not None and (
            packet.ts_ns - flow.last_ts_ns > self._idle_ns[proto]
            or (isinstance(l4, Tcp) and flow._wants_new_flow(l4))
        ):
            flow = None  # the old flow stays in `flows`; this packet starts a new one
        if flow is None:
            if len(self.flows) >= self._max_flows:
                self.untracked_packets += 1
                return
            flow = self._start_flow(proto, src, dst, l4, packet.ts_ns)
            self._active[key] = flow
            self.flows.append(flow)
        direction = 0 if src == flow.client else 1
        flow.last_ts_ns = max(flow.last_ts_ns, packet.ts_ns)
        flow.packets[direction] += 1
        flow.payload_bytes[direction] += len(l4.payload)
        # Only Ethernet, IP and TCP/UDP: a message split across segments is judged on the stream.
        if any(layer.error or layer.anomalies for layer in layers[:3]):
            flow.anomaly_packets += 1
        if isinstance(l4, Tcp):
            flow._update_tcp(direction, l4, self._budget, self._max_stream_bytes)
        elif (
            len(layers) > 3
            and isinstance(layers[3], Dns)
            and len(flow.udp_messages) < MAX_UDP_MESSAGES
        ):
            flow.udp_messages.append(AppItem(direction, layers[3]))

    @staticmethod
    def _start_flow(proto: str, src: Endpoint, dst: Endpoint, l4: Tcp | Udp, ts_ns: int) -> Flow:
        if isinstance(l4, Tcp) and l4.flags & tcp.SYN and l4.flags & tcp.ACK:
            return Flow(proto, dst, src, ts_ns)  # a SYN-ACK came first: the sender is the server
        return Flow(proto, src, dst, ts_ns)
