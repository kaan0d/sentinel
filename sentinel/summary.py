"""tcpdump-style one-line packet summaries. Timestamps are UTC with microsecond precision."""

import struct
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sentinel.pcap import Packet
from sentinel.proto import tcp
from sentinel.proto.arp import ARP_REPLY, ARP_REQUEST, Arp
from sentinel.proto.decode import decode
from sentinel.proto.ethernet import Ethernet
from sentinel.proto.icmp import ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, Icmp
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.ipv6 import IPv6
from sentinel.proto.layer import Layer
from sentinel.proto.tcp import Tcp, TcpOption
from sentinel.proto.udp import Udp

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ICMP_NAMES = {3: "destination unreachable", 5: "redirect", 11: "time exceeded"}
# tcpdump's flag letters, in its print order; ACK is shown as ".".
_FLAG_LETTERS = (
    (tcp.FIN, "F"),
    (tcp.SYN, "S"),
    (tcp.RST, "R"),
    (tcp.PSH, "P"),
    (tcp.ACK, "."),
    (tcp.URG, "U"),
    (tcp.ECE, "E"),
    (tcp.CWR, "W"),
    (tcp.NS, "N"),
)


def _timestamp(ts_ns: int) -> str:
    sec, ns = divmod(ts_ns, 1_000_000_000)
    when = _EPOCH + timedelta(seconds=sec)
    return f"{when:%Y-%m-%d %H:%M:%S}.{ns // 1000:06d}"


def _tcp_option(opt: TcpOption) -> str:
    d = opt.data
    if opt.kind == 0:
        return "eol"
    if opt.kind == 1:
        return "nop"
    if opt.kind == 2 and len(d) == 2:
        return f"mss {int.from_bytes(d)}"
    if opt.kind == 3 and len(d) == 1:
        return f"wscale {d[0]}"
    if opt.kind == 4 and not d:
        return "sackOK"
    if opt.kind == 5 and d and len(d) % 8 == 0:
        return "sack " + "".join(f"{{{a}:{b}}}" for a, b in struct.iter_unpack("!II", d))
    if opt.kind == 8 and len(d) == 8:
        return f"TS val {int.from_bytes(d[:4])} ecr {int.from_bytes(d[4:])}"
    return f"opt-{opt.kind}"


def _tcp(t: Tcp) -> str:
    flags = "".join(letter for bit, letter in _FLAG_LETTERS if t.flags & bit) or "none"
    parts = [f"Flags [{flags}]", f"seq {t.seq}"]
    if t.flags & tcp.ACK:
        parts.append(f"ack {t.ack}")
    parts.append(f"win {t.window}")
    if t.flags & tcp.URG:
        parts.append(f"urg {t.urgent}")
    if t.options:
        parts.append("options [" + ",".join(_tcp_option(o) for o in t.options) + "]")
    parts.append(f"length {len(t.payload)}")
    return ", ".join(parts)


def _icmp(i: Icmp) -> str:
    length = 8 + len(i.payload)
    if i.icmp_type in (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST):
        kind = "echo reply" if i.icmp_type == ICMP_ECHO_REPLY else "echo request"
        return f"ICMP {kind}, id {i.ident}, seq {i.seq}, length {length}"
    name = _ICMP_NAMES.get(i.icmp_type, f"type {i.icmp_type}")
    return f"ICMP {name}, code {i.code}, length {length}"


def _arp(a: Arp) -> str:
    if a.error:
        return "ARP"
    if a.op == ARP_REQUEST:
        return f"ARP, Request who-has {a.target_ip} tell {a.sender_ip}, length 28"
    if a.op == ARP_REPLY:
        return f"ARP, Reply {a.sender_ip} is-at {a.sender_mac.hex(':')}, length 28"
    return f"ARP, op {a.op}, length 28"


def _ip(ip: IPv4 | IPv6, l4: Layer | None) -> str:
    name = "IP" if isinstance(ip, IPv4) else "IP6"
    if ip.error:
        return name
    src, dst = str(ip.src), str(ip.dst)
    if isinstance(l4, Tcp | Udp) and not l4.error:
        src, dst = f"{src}.{l4.src_port}", f"{dst}.{l4.dst_port}"
    head = f"{name} {src} > {dst}: "
    if l4 is None:
        proto = ip.proto if isinstance(ip, IPv4) else ip.next_header
        return f"{head}ip-proto-{proto}, length {len(ip.payload)}"
    if l4.error:
        return head + type(l4).__name__.upper()
    if isinstance(l4, Tcp):
        return head + _tcp(l4)
    if isinstance(l4, Udp):
        return f"{head}UDP, length {len(l4.payload)}"
    assert isinstance(l4, Icmp)
    return head + _icmp(l4)


def _body(layers: Sequence[Layer], wire_len: int) -> str:
    eth = layers[0]
    if not isinstance(eth, Ethernet) or eth.error:
        return f"ethernet, length {wire_len}"
    vlan = "".join(f"vlan {v}, " for v in eth.vlans)
    l3 = layers[1] if len(layers) > 1 else None
    if isinstance(l3, Arp):
        return vlan + _arp(l3)
    if isinstance(l3, IPv4 | IPv6):
        return vlan + _ip(l3, layers[2] if len(layers) > 2 else None)
    return (
        f"{vlan}{eth.src.hex(':')} > {eth.dst.hex(':')}, "
        f"ethertype {eth.ethertype:#06x}, length {wire_len}"
    )


def describe(layers: Sequence[Layer], wire_len: int) -> str:
    """Summary of decoded layers, with every anomaly and error appended as `[...]`."""
    notes = [a for layer in layers for a in layer.anomalies]
    notes += [f"error: {layer.error}" for layer in layers if layer.error]
    return _body(layers, wire_len) + "".join(f" [{n}]" for n in notes)


def summarize(packet: Packet) -> str:
    return f"{_timestamp(packet.ts_ns)} {describe(decode(packet.data), packet.orig_len)}"
