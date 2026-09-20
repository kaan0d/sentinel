"""tcpdump-style one-line packet summaries. Timestamps are UTC with microsecond precision."""

import struct
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sentinel.pcap import Packet
from sentinel.proto import tcp
from sentinel.proto.arp import ARP_REPLY, ARP_REQUEST, Arp
from sentinel.proto.decode import decode
from sentinel.proto.dns import RCODE_NAMES, RTYPE_NAMES, Dns, DnsRecord
from sentinel.proto.ethernet import MIN_ETHERTYPE, Ethernet
from sentinel.proto.http import Http
from sentinel.proto.icmp import ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, Icmp
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.ipv6 import IPv6
from sentinel.proto.layer import Layer
from sentinel.proto.tcp import Tcp, TcpOption
from sentinel.proto.tls import CIPHER_NAMES, VERSION_NAMES, TlsClientHello, is_grease
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


_DNS_TEXT_TYPES = {1, 2, 5, 12, 15, 16, 28}


def _dns_type(rtype: int) -> str:
    return RTYPE_NAMES.get(rtype, f"TYPE{rtype}")


def _dns_record(r: DnsRecord) -> str:
    if r.rtype not in _DNS_TEXT_TYPES:
        return _dns_type(r.rtype)
    text = r.text if len(r.text) <= 60 else r.text[:57] + "..."
    return f"{_dns_type(r.rtype)} {text}"


def _dns(d: Dns) -> str:
    head = f"DNS {'response' if d.is_response else 'query'} {d.ident}"
    if d.is_response:
        head += " " + RCODE_NAMES.get(d.rcode, f"rcode {d.rcode}")
    parts = [head] + [f"{_dns_type(q.qtype)}? {q.name}" for q in d.questions]
    if d.answers:
        shown = [_dns_record(r) for r in d.answers[:4]]
        parts.append("answers [" + ", ".join(shown + ["..."] * (len(d.answers) > 4)) + "]")
    return ", ".join(parts)


def _http(h: Http) -> str:
    if not h.is_request:
        return f"HTTP: {h.version} {h.status} {h.reason}".rstrip()
    host = h.header("host")
    return f"HTTP: {h.method} {h.target} {h.version}" + (f", host {host}" if host else "")


def _version(v: int) -> str:
    return VERSION_NAMES.get(v, f"{v:#06x}")


def _tls(t: TlsClientHello) -> str:
    versions = [v for v in t.supported_versions if not is_grease(v)] or [t.client_version]
    suites = [c for c in t.cipher_suites if not is_grease(c)]
    names = [CIPHER_NAMES.get(c, f"{c:#06x}") for c in suites[:3]]
    more = [f"+{len(suites) - 3} more"] if len(suites) > 3 else []
    parts = ["TLS ClientHello"]
    if t.server_name is not None:
        parts.append(f"sni {t.server_name}")
    parts.append("versions [" + ", ".join(_version(v) for v in versions) + "]")
    parts.append(f"ciphers ({len(suites)}) [" + ", ".join(names + more) + "]")
    if t.ja3 is not None:
        parts.append(f"ja3 {t.ja3}")
    return ", ".join(parts)


def describe_app(app: Layer) -> str:
    if isinstance(app, Dns):
        return _dns(app)
    if isinstance(app, Http):
        return _http(app)
    assert isinstance(app, TlsClientHello)
    return _tls(app)


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


def _ip(ip: IPv4 | IPv6, l4: Layer | None, app: Layer | None) -> str:
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
    if isinstance(l4, Icmp):
        return head + _icmp(l4)
    text = _tcp(l4) if isinstance(l4, Tcp) else f"UDP, length {len(l4.payload)}"
    if app is not None and not app.error:
        text += ": " + describe_app(app)
    return head + text


def _body(layers: Sequence[Layer], wire_len: int) -> str:
    eth = layers[0]
    if not isinstance(eth, Ethernet) or eth.error:
        return f"ethernet, length {wire_len}"
    vlan = "".join(f"vlan {v}, " for v in eth.vlans)
    l3 = layers[1] if len(layers) > 1 else None
    if isinstance(l3, Arp):
        return vlan + _arp(l3)
    if isinstance(l3, IPv4 | IPv6):
        l4 = layers[2] if len(layers) > 2 else None
        return vlan + _ip(l3, l4, layers[3] if len(layers) > 3 else None)
    kind = "802.3" if eth.ethertype < MIN_ETHERTYPE else f"ethertype {eth.ethertype:#06x}"
    return f"{vlan}{eth.src.hex(':')} > {eth.dst.hex(':')}, {kind}, length {wire_len}"


def describe(layers: Sequence[Layer], wire_len: int) -> str:
    """Summary of decoded layers, with every anomaly and error appended as `[...]`."""
    notes = [a for layer in layers for a in layer.anomalies]
    notes += [f"error: {layer.error}" for layer in layers if layer.error]
    return _body(layers, wire_len) + "".join(f" [{n}]" for n in notes)


def summarize(packet: Packet, layers: Sequence[Layer] | None = None) -> str:
    """The line for one packet. Pass `layers` if the packet was already decoded."""
    layers = decode(packet.data) if layers is None else layers
    return f"{_timestamp(packet.ts_ns)} {describe(layers, packet.orig_len)}"
