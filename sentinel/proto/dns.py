"""DNS message parser (RFC 1035). Names may use compression pointers: every pointer is
bounds-checked, must point backward, and the number of jumps is capped."""

import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from sentinel.proto.layer import Layer

RTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

_HEADER_LEN = 12
_MAX_NAME = 255
_MAX_JUMPS = 32


class _Malformed(Exception):
    """Internal: a record or name is broken. Always caught inside this module."""


@dataclass(frozen=True, slots=True)
class DnsQuestion:
    name: str
    qtype: int
    qclass: int


@dataclass(frozen=True, slots=True)
class DnsRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes  # raw, as on the wire (names inside may be compressed)
    text: str  # presentation form for A, AAAA, NS, CNAME, PTR, MX, TXT; hex otherwise


@dataclass(frozen=True, slots=True, kw_only=True)
class Dns(Layer):
    """`counts` is what the header declares; the tuples hold what was actually parsed."""

    ident: int = 0
    is_response: bool = False
    opcode: int = 0
    authoritative: bool = False
    truncated: bool = False  # the TC flag
    recursion_desired: bool = False
    recursion_available: bool = False
    rcode: int = 0
    counts: tuple[int, int, int, int] = (0, 0, 0, 0)
    questions: tuple[DnsQuestion, ...] = ()
    answers: tuple[DnsRecord, ...] = ()
    authorities: tuple[DnsRecord, ...] = ()
    additionals: tuple[DnsRecord, ...] = ()


def _label_text(label: bytes) -> str:
    """Presentation format (RFC 4343): bytes outside printable ASCII, '.' and '\\' are escaped,
    so a name is always safe to print."""
    return "".join(
        chr(b) if 0x20 < b < 0x7F and b not in (0x2E, 0x5C) else f"\\{b:03d}" for b in label
    )


def _read_name(data: bytes, pos: int) -> tuple[str, int]:
    """Returns the name and the offset just after it (after the first pointer, if any)."""
    labels: list[str] = []
    end = -1
    jumps = 0
    total = 0
    while True:
        if pos >= len(data):
            raise _Malformed("name runs past the end of the message")
        n = data[pos]
        if n == 0:
            pos += 1
            break
        kind = n & 0xC0
        if kind == 0xC0:
            if pos + 1 >= len(data):
                raise _Malformed("truncated compression pointer")
            target = ((n & 0x3F) << 8) | data[pos + 1]
            if end < 0:
                end = pos + 2
            jumps += 1
            if jumps > _MAX_JUMPS:
                raise _Malformed("too many compression pointers")
            if not _HEADER_LEN <= target < pos:
                raise _Malformed("compression pointer does not point backward into the message")
            pos = target
            continue
        if kind != 0:
            raise _Malformed("reserved label type")
        if pos + 1 + n > len(data):
            raise _Malformed("label runs past the end of the message")
        total += n + 1
        if total > _MAX_NAME:
            raise _Malformed("name longer than 255 bytes")
        labels.append(_label_text(data[pos + 1 : pos + 1 + n]))
        pos += 1 + n
    return ".".join(labels) or ".", end if end >= 0 else pos


def _rdata_text(rtype: int, data: bytes, start: int, length: int) -> str:
    end = start + length
    raw = data[start:end]
    if rtype == 1 and length == 4:
        return str(IPv4Address(raw))
    if rtype == 28 and length == 16:
        return str(IPv6Address(raw))
    if rtype in (2, 5, 12):
        name, after = _read_name(data, start)
        if after > end:
            raise _Malformed("name in rdata runs past the record")
        return name
    if rtype == 15 and length >= 3:
        name, after = _read_name(data, start + 2)
        if after > end:
            raise _Malformed("name in rdata runs past the record")
        return f"{int.from_bytes(raw[:2])} {name}"
    if rtype == 16:
        strings: list[str] = []
        i = 0
        while i < length:
            n = raw[i]
            if i + 1 + n > length:
                raise _Malformed("txt string runs past the record")
            strings.append('"' + _label_text(raw[i + 1 : i + 1 + n]) + '"')
            i += 1 + n
        return " ".join(strings)
    return raw.hex()


def _read_question(data: bytes, pos: int) -> tuple[DnsQuestion, int]:
    name, pos = _read_name(data, pos)
    if pos + 4 > len(data):
        raise _Malformed("truncated question")
    qtype, qclass = struct.unpack_from("!HH", data, pos)
    return DnsQuestion(name, qtype, qclass), pos + 4


def _read_record(data: bytes, pos: int) -> tuple[DnsRecord, int]:
    name, pos = _read_name(data, pos)
    if pos + 10 > len(data):
        raise _Malformed("truncated record header")
    rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, pos)
    pos += 10
    if pos + rdlen > len(data):
        raise _Malformed("truncated rdata")
    text = _rdata_text(rtype, data, pos, rdlen)
    return DnsRecord(name, rtype, rclass, ttl, data[pos : pos + rdlen], text), pos + rdlen


def parse_dns(data: bytes) -> Dns:
    """`data` is one whole DNS message (for TCP, without the 2-byte length prefix). Only a
    header that cannot be read is an error; a broken or missing record ends parsing and is
    reported as an anomaly, keeping everything parsed before it."""
    if len(data) < _HEADER_LEN:
        return Dns(error=f"truncated dns header: {len(data)} of {_HEADER_LEN} bytes")
    ident, flags, qd, an, ns, ar = struct.unpack_from("!6H", data)
    questions: list[DnsQuestion] = []
    records: dict[str, list[DnsRecord]] = {"answer": [], "authority": [], "additional": []}
    problem: str | None = None
    pos = _HEADER_LEN
    for kind, count in (("question", qd), ("answer", an), ("authority", ns), ("additional", ar)):
        for i in range(count):
            if pos >= len(data):
                problem = f"truncated dns message: {kind} {i + 1} of {count} is missing"
                break
            try:
                if kind == "question":
                    question, pos = _read_question(data, pos)
                    questions.append(question)
                else:
                    record, pos = _read_record(data, pos)
                    records[kind].append(record)
            except _Malformed as e:
                problem = f"malformed dns {kind} {i + 1}: {e}"
                break
        if problem:
            break
    anomalies: list[str] = []
    if problem:
        anomalies.append(problem)
    elif pos < len(data):
        anomalies.append(f"{len(data) - pos} trailing bytes after the dns message")
    return Dns(
        ident=ident,
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0xF,
        authoritative=bool(flags & 0x0400),
        truncated=bool(flags & 0x0200),
        recursion_desired=bool(flags & 0x0100),
        recursion_available=bool(flags & 0x0080),
        rcode=flags & 0xF,
        counts=(qd, an, ns, ar),
        questions=tuple(questions),
        answers=tuple(records["answer"]),
        authorities=tuple(records["authority"]),
        additionals=tuple(records["additional"]),
        anomalies=tuple(anomalies),
    )
