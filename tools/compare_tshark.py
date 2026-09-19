"""Compare Sentinel's decoding of a capture with tshark's, packet by packet and field by field.

    python -m tools.compare_tshark capture.pcap [more captures...] [--tshark PATH]

tshark is the reference: it is written by other people, and it has read far more traffic than the
generator of this project ever made. Every field both programs report must be equal. A field that
only one of them reports is listed separately. The exit code is 1 if anything differs.

tshark is run with reassembly, sequence analysis and defragmentation switched off, because
`read` looks at one packet at a time and so does this comparison. Checksums are verified.
Nothing here is needed at run time: this is a development tool, and tshark is not a dependency.
"""

import argparse
import ipaddress
import os
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from sentinel.flow import FlowTable
from sentinel.flow.table import Endpoint
from sentinel.pcap import Packet, PcapError, open_reader
from sentinel.proto.arp import Arp
from sentinel.proto.decode import decode
from sentinel.proto.dns import Dns
from sentinel.proto.ethernet import MIN_ETHERTYPE, Ethernet
from sentinel.proto.http import Http
from sentinel.proto.icmp import Icmp
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.ipv6 import IPv6
from sentinel.proto.layer import Layer
from sentinel.proto.tcp import Tcp
from sentinel.proto.tls import TlsClientHello
from sentinel.proto.udp import Udp

Value = int | bool | str | list[int] | list[str]

WINDOWS_TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
SEPARATOR = "\t"
AGGREGATOR = "|"

# Options that make tshark look at one packet at a time, like `read`, and verify checksums.
OPTIONS = [
    "tcp.desegment_tcp_streams:FALSE",
    "tcp.analyze_sequence_numbers:FALSE",
    "tcp.check_checksum:TRUE",
    "udp.check_checksum:TRUE",
    "ip.check_checksum:TRUE",
    "tcp.no_subdissector_on_error:FALSE",
    "ip.defragment:FALSE",
    "ipv6.defragment:FALSE",
    "http.desegment_headers:FALSE",
    "http.desegment_body:FALSE",
    "tls.desegment_ssl_records:FALSE",
    "tls.desegment_ssl_application_data:FALSE",
    "dns.desegment_dns_messages:FALSE",
]

# (name, tshark field, kind). Kinds: int (decimal or 0x), bool, str, mac, ip, and list of these
# ("[int]", "[str]", "[ip]"), which tshark prints joined with AGGREGATOR.
SCALARS: list[tuple[str, str, str]] = [
    ("frame.len", "frame.len", "int"),
    ("frame.cap_len", "frame.cap_len", "int"),
    ("eth.dst", "eth.dst", "mac"),
    ("eth.src", "eth.src", "mac"),
    ("arp.op", "arp.opcode", "int"),
    ("arp.sender_mac", "arp.src.hw_mac", "mac"),
    ("arp.sender_ip", "arp.src.proto_ipv4", "ip"),
    ("arp.target_mac", "arp.dst.hw_mac", "mac"),
    ("arp.target_ip", "arp.dst.proto_ipv4", "ip"),
    ("ip.src", "ip.src", "ip"),
    ("ip.dst", "ip.dst", "ip"),
    ("ip.proto", "ip.proto", "int"),
    ("ip.ttl", "ip.ttl", "int"),
    ("ip.id", "ip.id", "int"),
    ("ip.len", "ip.len", "int"),
    ("ip.hdr_len", "ip.hdr_len", "int"),
    ("ip.tos", "ip.dsfield", "int"),
    ("ip.df", "ip.flags.df", "bool"),
    ("ip.mf", "ip.flags.mf", "bool"),
    ("ip.frag_offset", "ip.frag_offset", "int"),
    ("ip.checksum_status", "ip.checksum.status", "int"),
    ("ipv6.src", "ipv6.src", "ip"),
    ("ipv6.dst", "ipv6.dst", "ip"),
    ("ipv6.next_header", "ipv6.nxt", "int"),
    ("ipv6.hop_limit", "ipv6.hlim", "int"),
    ("ipv6.payload_length", "ipv6.plen", "int"),
    ("ipv6.traffic_class", "ipv6.tclass", "int"),
    ("ipv6.flow_label", "ipv6.flow", "int"),
    ("tcp.srcport", "tcp.srcport", "int"),
    ("tcp.dstport", "tcp.dstport", "int"),
    ("tcp.seq", "tcp.seq_raw", "int"),
    ("tcp.ack", "tcp.ack_raw", "int"),
    ("tcp.hdr_len", "tcp.hdr_len", "int"),
    ("tcp.flags", "tcp.flags", "int"),
    ("tcp.window", "tcp.window_size_value", "int"),
    ("tcp.urgent", "tcp.urgent_pointer", "int"),
    ("tcp.len", "tcp.len", "int"),
    ("tcp.checksum_status", "tcp.checksum.status", "int"),
    ("udp.srcport", "udp.srcport", "int"),
    ("udp.dstport", "udp.dstport", "int"),
    ("udp.length", "udp.length", "int"),
    ("udp.checksum_status", "udp.checksum.status", "int"),
    ("icmp.type", "icmp.type", "int"),
    ("icmp.code", "icmp.code", "int"),
    ("icmp.checksum_status", "icmp.checksum.status", "int"),
    ("dns.id", "dns.id", "int"),
    ("dns.response", "dns.flags.response", "bool"),
    ("dns.opcode", "dns.flags.opcode", "int"),
    ("dns.aa", "dns.flags.authoritative", "bool"),
    ("dns.tc", "dns.flags.truncated", "bool"),
    ("dns.rd", "dns.flags.recdesired", "bool"),
    ("dns.ra", "dns.flags.recavail", "bool"),
    ("dns.rcode", "dns.flags.rcode", "int"),
    ("dns.count_queries", "dns.count.queries", "int"),
    ("dns.count_answers", "dns.count.answers", "int"),
    ("dns.count_authority", "dns.count.auth_rr", "int"),
    ("dns.count_additional", "dns.count.add_rr", "int"),
    ("http.method", "http.request.method", "str"),
    ("http.target", "http.request.uri", "str"),
    ("http.version", "http.request.version", "str"),
    ("http.status", "http.response.code", "int"),
    ("http.reason", "http.response.phrase", "str"),
    ("http.host", "http.host", "str"),
    ("tls.record_version", "tls.record.version", "int"),
    ("tls.client_version", "tls.handshake.version", "int"),
    ("tls.server_name", "tls.handshake.extensions_server_name", "str"),
]
# tshark reports eth.type (the outer type: 0x8100 for a VLAN tag) and vlan.etype (the type
# after each tag), and Sentinel reports the inner type once, so those are combined below.
LISTS: list[tuple[str, str, str]] = [
    ("vlan.id", "vlan.id", "[int]"),
    ("dns.question_names", "dns.qry.name", "[str]"),
    ("dns.question_types", "dns.qry.type", "[int]"),
    ("dns.question_classes", "dns.qry.class", "[int]"),
    ("dns.record_names", "dns.resp.name", "[str]"),
    ("dns.record_types", "dns.resp.type", "[int]"),
    ("dns.record_ttls", "dns.resp.ttl", "[int]"),
    ("dns.a", "dns.a", "[ip]"),
    ("dns.aaaa", "dns.aaaa", "[ip]"),
    ("dns.cname", "dns.cname", "[str]"),
    ("tcp.option_kinds", "tcp.option_kind", "[int]"),
    ("tcp.mss", "tcp.options.mss_val", "[int]"),
    ("tcp.wscale", "tcp.options.wscale.shift", "[int]"),
    ("tcp.tsval", "tcp.options.timestamp.tsval", "[int]"),
    ("tcp.tsecr", "tcp.options.timestamp.tsecr", "[int]"),
    ("tls.ciphers", "tls.handshake.ciphersuite", "[int]"),
    ("tls.versions", "tls.handshake.extensions.supported_version", "[int]"),
    ("tls.extensions", "tls.handshake.extension.type", "[int]"),
]
EXTRA = [("eth.type", "eth.type", "int"), ("vlan.etype", "vlan.etype", "[int]")]
KINDS = {key: kind for key, _field, kind in SCALARS + LISTS + EXTRA}

# tshark's checksum status: 0 bad, 1 good, 2 unverified, 3 not present, 4 illegal.
CHECKSUM_BAD = 0
# The bits of tcp.flags that Sentinel keeps (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN).
TCP_FLAG_BITS = 0x1FF


class TsharkError(Exception):
    """tshark is missing or refused to read the file."""


def find_tshark(explicit: str | None = None) -> str:
    for candidate in (explicit, os.environ.get("TSHARK"), shutil.which("tshark")):
        if candidate:
            return candidate
    if WINDOWS_TSHARK.exists():
        return str(WINDOWS_TSHARK)
    raise TsharkError("tshark was not found: install Wireshark, or pass --tshark PATH")


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def normalize(kind: str, raw: str) -> Value:
    """A value as tshark printed it, in the form Sentinel's fields have."""
    if kind == "[int]":
        return [int(part, 0) for part in raw.split(AGGREGATOR)]
    if kind.startswith("["):
        return [str(_scalar(kind[1:-1], part)) for part in raw.split(AGGREGATOR)]
    return _scalar(kind, raw)


def _scalar(kind: str, raw: str) -> int | bool | str:
    if kind == "int":
        return int(raw, 0)
    if kind == "bool":
        return raw in ("1", "True", "true")
    if kind == "mac":
        return raw.lower()
    if kind == "ip":
        return str(ipaddress.ip_address(raw))
    return raw


def theirs(scalars: Mapping[str, str], lists: Mapping[str, str]) -> dict[str, Value]:
    """One tshark row (the fields it printed, by name) as Sentinel-style fields. A field tshark
    left empty is not in the result."""
    out: dict[str, Value] = {}
    for name, field, kind in SCALARS:
        if scalars.get(field):
            out[name] = normalize(kind, scalars[field])
    for name, field, kind in LISTS:
        if lists.get(field):
            out[name] = normalize(kind, lists[field])
    if lists.get("vlan.etype"):
        out["ethertype"] = int(lists["vlan.etype"].split(AGGREGATOR)[-1], 0)
    elif scalars.get("eth.type") and not lists.get("vlan.id"):
        out["ethertype"] = int(scalars["eth.type"], 0)
    flags, offset = out.get("tcp.flags"), out.get("ip.frag_offset")
    if isinstance(flags, int):
        out["tcp.flags"] = flags & TCP_FLAG_BITS
    if isinstance(offset, int):
        out["ip.frag_offset"] = offset * 8  # tshark counts in units of 8 bytes, Sentinel in bytes
    for proto in ("ip", "tcp", "udp", "icmp"):
        status = out.pop(f"{proto}.checksum_status", None)
        if status is not None:
            out[f"{proto}.checksum_bad"] = status == CHECKSUM_BAD
    return out


def _layer(layers: Sequence[Layer], kind: type[Layer]) -> Layer | None:
    layer = next((x for x in layers if isinstance(x, kind)), None)
    return None if layer is None or layer.error else layer


def ours(packet: Packet, layers: Sequence[Layer]) -> dict[str, Value]:
    """The same fields, from Sentinel's decoding of one packet. Layers that came back with an
    error mean nothing, so they give no fields."""
    r: dict[str, Value] = {"frame.len": packet.orig_len, "frame.cap_len": len(packet.data)}
    eth = _layer(layers, Ethernet)
    if isinstance(eth, Ethernet):
        r["eth.dst"], r["eth.src"] = _mac(eth.dst), _mac(eth.src)
        if eth.ethertype >= MIN_ETHERTYPE:  # below that it is a length, and tshark has no type
            r["ethertype"] = eth.ethertype
        if eth.vlans:
            r["vlan.id"] = list(eth.vlans)
    arp = _layer(layers, Arp)
    if isinstance(arp, Arp):
        r["arp.op"] = arp.op
        r["arp.sender_mac"], r["arp.sender_ip"] = _mac(arp.sender_mac), str(arp.sender_ip)
        r["arp.target_mac"], r["arp.target_ip"] = _mac(arp.target_mac), str(arp.target_ip)
    ip4 = _layer(layers, IPv4)
    if isinstance(ip4, IPv4):
        r["ip.src"], r["ip.dst"] = str(ip4.src), str(ip4.dst)
        r["ip.proto"], r["ip.ttl"], r["ip.id"] = ip4.proto, ip4.ttl, ip4.ident
        r["ip.len"], r["ip.hdr_len"], r["ip.tos"] = ip4.total_length, ip4.header_len, ip4.tos
        r["ip.df"], r["ip.mf"], r["ip.frag_offset"] = (
            ip4.dont_fragment,
            ip4.more_fragments,
            ip4.frag_offset,
        )
        r["ip.checksum_bad"] = "bad ipv4 header checksum" in ip4.anomalies
    ip6 = _layer(layers, IPv6)
    if isinstance(ip6, IPv6):
        r["ipv6.src"], r["ipv6.dst"] = str(ip6.src), str(ip6.dst)
        r["ipv6.next_header"], r["ipv6.hop_limit"] = ip6.next_header, ip6.hop_limit
        r["ipv6.payload_length"] = ip6.payload_length
        r["ipv6.traffic_class"], r["ipv6.flow_label"] = ip6.traffic_class, ip6.flow_label
    tcp = _layer(layers, Tcp)
    if isinstance(tcp, Tcp):
        r["tcp.srcport"], r["tcp.dstport"] = tcp.src_port, tcp.dst_port
        r["tcp.seq"], r["tcp.ack"] = tcp.seq, tcp.ack
        r["tcp.hdr_len"], r["tcp.flags"], r["tcp.window"] = tcp.header_len, tcp.flags, tcp.window
        r["tcp.urgent"], r["tcp.len"] = tcp.urgent, len(tcp.payload)
        r["tcp.checksum_bad"] = "bad tcp checksum" in tcp.anomalies
        if tcp.options:
            r["tcp.option_kinds"] = [o.kind for o in tcp.options]
        for o in tcp.options:
            if o.kind == 2 and len(o.data) == 2:
                r["tcp.mss"] = [int.from_bytes(o.data)]
            elif o.kind == 3 and len(o.data) == 1:
                r["tcp.wscale"] = [o.data[0]]
            elif o.kind == 8 and len(o.data) == 8:
                r["tcp.tsval"] = [int.from_bytes(o.data[:4])]
                r["tcp.tsecr"] = [int.from_bytes(o.data[4:])]
    udp = _layer(layers, Udp)
    if isinstance(udp, Udp):
        r["udp.srcport"], r["udp.dstport"], r["udp.length"] = udp.src_port, udp.dst_port, udp.length
        r["udp.checksum_bad"] = "bad udp checksum" in udp.anomalies
    icmp = _layer(layers, Icmp)
    if isinstance(icmp, Icmp):
        r["icmp.type"], r["icmp.code"] = icmp.icmp_type, icmp.code
        r["icmp.checksum_bad"] = "bad icmp checksum" in icmp.anomalies
    dns = _layer(layers, Dns)
    if isinstance(dns, Dns):
        r["dns.id"], r["dns.response"], r["dns.opcode"] = dns.ident, dns.is_response, dns.opcode
        r["dns.aa"], r["dns.tc"] = dns.authoritative, dns.truncated
        r["dns.rd"], r["dns.ra"], r["dns.rcode"] = (
            dns.recursion_desired,
            dns.recursion_available,
            dns.rcode,
        )
        counts = dns.counts
        r["dns.count_queries"], r["dns.count_answers"] = counts[0], counts[1]
        r["dns.count_authority"], r["dns.count_additional"] = counts[2], counts[3]
        if dns.questions:
            r["dns.question_names"] = [q.name for q in dns.questions]
            r["dns.question_types"] = [q.qtype for q in dns.questions]
            r["dns.question_classes"] = [q.qclass for q in dns.questions]
        records = dns.answers + dns.authorities + dns.additionals
        if records:
            r["dns.record_names"] = [x.name for x in records]
            r["dns.record_types"] = [x.rtype for x in records]
            r["dns.record_ttls"] = [x.ttl for x in records]
        for key, rtype in (("dns.a", 1), ("dns.aaaa", 28), ("dns.cname", 5)):
            texts = [x.text for x in records if x.rtype == rtype]
            if texts:
                r[key] = texts
    http = _layer(layers, Http)
    if isinstance(http, Http):
        if http.is_request:
            r["http.method"], r["http.target"], r["http.version"] = (
                http.method,
                http.target,
                http.version,
            )
        else:
            r["http.status"], r["http.reason"] = http.status, http.reason
        host = next((v for k, v in http.headers if k.lower() == "host"), None)
        if host is not None:
            r["http.host"] = host
    tls = _layer(layers, TlsClientHello)
    if isinstance(tls, TlsClientHello):
        r["tls.record_version"], r["tls.client_version"] = tls.record_version, tls.client_version
        if tls.server_name is not None:
            r["tls.server_name"] = tls.server_name
        if tls.cipher_suites:
            r["tls.ciphers"] = list(tls.cipher_suites)
        if tls.supported_versions:
            r["tls.versions"] = list(tls.supported_versions)
        if tls.extensions:
            r["tls.extensions"] = list(tls.extensions)
    return r


@dataclass(frozen=True, slots=True)
class Difference:
    file: str
    frame: int  # 1-based, like tshark's frame.number
    field: str
    kind: str  # "differs", "only sentinel" or "only tshark"
    sentinel: Value | None
    tshark: Value | None
    reason: str | None = None  # set when the difference is explained, see explain()


ICMP_ERRORS = (3, 4, 5, 11, 12)  # these quote the header of the packet that caused them
ICMPV6 = 58


def explain(
    layers: Sequence[Layer], a: Mapping[str, Value], b: Mapping[str, Value]
) -> list[tuple[str, str, str]]:
    """Differences that are not a disagreement: (field prefix, kind, why). Each one is a way in
    which tshark reports something else than a field of this packet, or a limit of `read` that
    is documented. They are counted and shown with their reason, never dropped silently."""
    rules = []
    if a.get("dns.response") is False:
        for field in ("dns.aa", "dns.ra", "dns.rcode"):
            rules.append((field, "only sentinel", "tshark shows these flags only in responses"))
    if "http.status" in b:
        for field in ("http.method", "http.target", "http.version"):
            rules.append((field, "only tshark", "tshark shows the request that a response answers"))
    quoting = a.get("icmp.type") in ICMP_ERRORS or a.get("ipv6.next_header") == ICMPV6
    if quoting:  # ICMP errors quote the start of the packet that caused them; ICMPv6 is not parsed
        for prefix in ("tcp.", "udp.", "dns.", "http.", "tls."):
            rules.append(
                (prefix, "only tshark", "tshark reads the packet quoted inside an ICMP error")
            )
    eth = _layer(layers, Ethernet)
    if isinstance(eth, Ethernet) and eth.ethertype < MIN_ETHERTYPE:
        rules.append(
            ("", "only tshark", "an 802.3 frame with an LLC header: not decoded above Ethernet")
        )
    tcp = _layer(layers, Tcp)
    if isinstance(tcp, Tcp) and 53 in (tcp.src_port, tcp.dst_port) and tcp.payload:
        size = int.from_bytes(tcp.payload[:2])
        if len(tcp.payload) < 2 + size:
            rules.append(
                (
                    "dns.",
                    "only tshark",
                    "a DNS message that is not whole in this segment (flows reads it)",
                )
            )
    tls = _layer(layers, TlsClientHello)
    if isinstance(tls, TlsClientHello) and any("truncated" in x for x in tls.anomalies):
        rules.append(
            ("tls.", "only sentinel", "a ClientHello that is cut short: tshark reads none of it")
        )
    return rules


def compare(
    file: str, frame: int, a: Mapping[str, Value], b: Mapping[str, Value]
) -> list[Difference]:
    """Sentinel's fields `a` against tshark's `b` for one packet."""
    found = []
    for field in sorted(a.keys() | b.keys()):
        if field not in b:
            found.append(Difference(file, frame, field, "only sentinel", a[field], None))
        elif field not in a:
            found.append(Difference(file, frame, field, "only tshark", None, b[field]))
        elif a[field] != b[field]:
            found.append(Difference(file, frame, field, "differs", a[field], b[field]))
    return found


def run_tshark(
    tshark: str, path: Path, fields: Sequence[str], occurrence: str
) -> list[dict[str, str]]:
    """One row per packet: the requested fields, by name. `occurrence` is "f" for the first
    occurrence of a field in the packet (the outer header, for ICMP errors that quote one) or
    "a" for all of them."""
    command = [tshark, "-r", str(path), "-n", "-T", "fields"]
    for option in OPTIONS:
        command += ["-o", option]
    for field in fields:
        command += ["-e", field]
    command += [
        "-E",
        "separator=/t",
        "-E",
        f"occurrence={occurrence}",
        "-E",
        f"aggregator={AGGREGATOR}",
    ]
    done = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=False)
    if done.returncode != 0:
        raise TsharkError(f"tshark failed on {path}: {done.stderr.strip() or done.returncode}")
    rows = []
    for line in done.stdout.split("\n"):
        if line == "" and not fields:
            continue
        cells = line.rstrip("\r").split(SEPARATOR)
        if len(cells) == len(fields):
            rows.append(dict(zip(fields, cells, strict=True)))
    return rows


def tshark_rows(tshark: str, path: Path) -> list[dict[str, dict[str, str]]]:
    scalar_fields = [f for _n, f, _k in SCALARS + EXTRA[:1]]
    list_fields = [f for _n, f, _k in LISTS + EXTRA[1:]]
    first = run_tshark(tshark, path, scalar_fields, "f")
    every = run_tshark(tshark, path, list_fields, "a")
    if len(first) != len(every):
        raise TsharkError(f"tshark gave {len(first)} and {len(every)} rows for {path}")
    return [{"scalars": a, "lists": b} for a, b in zip(first, every, strict=True)]


def sentinel_packets(path: Path) -> list[tuple[Packet, Sequence[Layer]]]:
    with path.open("rb") as fp:
        return [(p, decode(p.data)) for p in open_reader(fp)]


FLOW_FIELDS = [
    "frame.protocols",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "udp.srcport",
    "udp.dstport",
    "udp.stream",
]
FlowSummary = Counter[tuple[str, frozenset[str], int]]  # (protocol, both ends, packets)


def tshark_flows(rows: Sequence[Mapping[str, str]]) -> FlowSummary:
    """The TCP and UDP conversations tshark numbers (`tcp.stream`, `udp.stream`), as
    (protocol, both ends, packets). The header an ICMP error quotes is not a conversation."""
    counts: dict[tuple[str, str], int] = {}
    ends: dict[tuple[str, str], frozenset[str]] = {}
    for row in rows:
        chain = row["frame.protocols"].split(":")
        proto = next((x for x in chain if x in ("tcp", "udp", "icmp", "icmpv6")), "")
        stream = row[f"{proto}.stream"] if proto in ("tcp", "udp") else ""
        if not stream:
            continue
        src = row["ip.src"] or row["ipv6.src"]
        dst = row["ip.dst"] or row["ipv6.dst"]
        a = Endpoint(ipaddress.ip_address(src), int(row[f"{proto}.srcport"]))
        b = Endpoint(ipaddress.ip_address(dst), int(row[f"{proto}.dstport"]))
        counts[(proto, stream)] = counts.get((proto, stream), 0) + 1
        ends[(proto, stream)] = frozenset((str(a), str(b)))
    return Counter((proto, ends[(proto, s)], n) for (proto, s), n in counts.items())


def sentinel_flows(packets: Sequence[tuple[Packet, Sequence[Layer]]]) -> FlowSummary:
    """The same summary from Sentinel's flow table, with no idle timeout: tshark has none."""
    table = FlowTable(tcp_idle_s=10**9, udp_idle_s=10**9)
    for packet, layers in packets:
        table.add(packet, layers)
    return Counter(
        (f.proto, frozenset((str(f.client), str(f.server))), sum(f.packets)) for f in table.flows
    )


def compare_flows(file: str, a: FlowSummary, b: FlowSummary) -> list[Difference]:
    found = []
    for (proto, ends, n), count in sorted((a - b).items(), key=str):
        name = f"{proto} flow {' <-> '.join(sorted(ends))}"
        found += [Difference(file, 0, name, "only sentinel", n, None)] * count
    for (proto, ends, n), count in sorted((b - a).items(), key=str):
        name = f"{proto} flow {' <-> '.join(sorted(ends))}"
        found += [Difference(file, 0, name, "only tshark", None, n)] * count
    return found


@dataclass(frozen=True, slots=True)
class FileReport:
    file: str
    packets: int
    fields: int  # how many field values were compared
    differences: tuple[Difference, ...]  # the ones that are not explained
    explained: tuple[Difference, ...] = ()


def compare_file(
    path: Path,
    tshark: str,
    read: Callable[[Path], Sequence[Mapping[str, Mapping[str, str]]]] | None = None,
    read_flows: Callable[[Path], list[dict[str, str]]] | None = None,
) -> FileReport:
    ours_all = sentinel_packets(path)
    rows = (read or (lambda p: tshark_rows(tshark, p)))(path)
    differences: list[Difference] = []
    explained: list[Difference] = []
    compared = 0
    for i, (packet, layers) in enumerate(ours_all):
        if i >= len(rows):
            break
        a = ours(packet, layers)
        b = theirs(rows[i]["scalars"], rows[i]["lists"])
        compared += len(a.keys() & b.keys())
        rules = explain(layers, a, b)
        for d in compare(path.name, i + 1, a, b):
            why = next((r for p, k, r in rules if k == d.kind and d.field.startswith(p)), None)
            if why is None:
                differences.append(d)
            else:
                explained.append(replace(d, reason=why))
    if len(rows) != len(ours_all):
        differences.append(
            Difference(path.name, 0, "packet count", "differs", len(ours_all), len(rows))
        )
    flow_rows = (read_flows or (lambda p: run_tshark(tshark, p, FLOW_FIELDS, "f")))(path)
    flows_ours, flows_theirs = sentinel_flows(ours_all), tshark_flows(flow_rows)
    compared += len(flows_ours & flows_theirs)
    differences += compare_flows(path.name, flows_ours, flows_theirs)
    return FileReport(path.name, len(ours_all), compared, tuple(differences), tuple(explained))


def render(reports: Sequence[FileReport], show: int) -> list[str]:
    lines = []
    for report in reports:
        by_kind = Counter((d.field, d.kind) for d in report.differences)
        lines.append(
            f"{report.file}: {report.packets} packets, {report.fields} field values compared, "
            f"{len(report.differences)} differences, {len(report.explained)} explained"
        )
        for (field, kind), count in sorted(by_kind.items()):
            lines.append(f"  {field} ({kind}): {count}")
            shown = [d for d in report.differences if (d.field, d.kind) == (field, kind)][:show]
            for d in shown:
                lines.append(f"    frame {d.frame}: sentinel {d.sentinel!r}, tshark {d.tshark!r}")
        by_reason = Counter(d.reason for d in report.explained)
        for reason, count in sorted(by_reason.items(), key=lambda item: str(item[0])):
            lines.append(f"  explained, {count} x: {reason}")
    return lines


def _positive(text: str) -> int:
    if not text.isdecimal() or int(text) < 1:
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive whole number")
    return int(text)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare Sentinel's decoding with tshark's")
    parser.add_argument("files", nargs="+", type=Path, help="pcap or pcapng files")
    parser.add_argument(
        "--tshark", metavar="PATH", help="the tshark program (default: look for it)"
    )
    parser.add_argument("--show", type=_positive, default=3, help="examples per kind of difference")
    args = parser.parse_args(argv)
    try:
        tshark = find_tshark(args.tshark)
        reports = [compare_file(path, tshark) for path in args.files]
    except (TsharkError, OSError, PcapError) as e:
        print(f"compare_tshark: {e}", file=sys.stderr)
        return 2
    for line in render(reports, args.show):
        print(line)
    return 1 if any(r.differences for r in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
