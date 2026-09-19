import struct
from ipaddress import IPv4Address

from sentinel.proto.dns import DnsQuestion, parse_dns
from tools.gen_pcap import dns_cname_response, dns_name, dns_query

HEADER = bytes.fromhex("beef01000001000000000000")
QUESTION = dns_name("a.test") + struct.pack("!HH", 1, 1)


def message(*records: bytes, answers: int | None = None) -> bytes:
    """A response with one question and the given raw answer records."""
    header = struct.pack(
        "!6H", 0x1111, 0x8180, 1, len(records) if answers is None else answers, 0, 0
    )
    return header + QUESTION + b"".join(records)


def record(name: bytes, rtype: int, rdata: bytes, rdlen: int | None = None) -> bytes:
    length = len(rdata) if rdlen is None else rdlen
    return name + struct.pack("!HHIH", rtype, 1, 60, length) + rdata


def test_valid_query_hand_built() -> None:
    raw = HEADER + b"\x07example\x03com\x00" + bytes.fromhex("00010001")
    dns = parse_dns(raw)
    assert dns.error is None
    assert dns.anomalies == ()
    assert (dns.ident, dns.is_response, dns.recursion_desired, dns.rcode) == (
        0xBEEF,
        False,
        True,
        0,
    )
    assert dns.counts == (1, 0, 0, 0)
    assert dns.questions == (DnsQuestion("example.com", 1, 1),)
    assert dns.answers == ()


def test_response_flags() -> None:
    dns = parse_dns(dns_cname_response())
    assert dns.is_response
    assert dns.recursion_desired
    assert dns.recursion_available
    assert not dns.authoritative
    assert not dns.truncated
    assert (dns.opcode, dns.rcode) == (0, 0)


def test_compression_pointers_in_names_and_rdata() -> None:
    dns = parse_dns(dns_cname_response())
    assert dns.error is None
    assert dns.anomalies == ()
    assert dns.questions == (DnsQuestion("www.example.com", 1, 1),)
    cname, a = dns.answers
    assert (cname.name, cname.rtype, cname.text, cname.ttl) == (
        "www.example.com",
        5,
        "example.com",
        300,
    )
    assert (a.name, a.rtype, a.text) == ("example.com", 1, "192.0.2.1")
    assert a.rdata == IPv4Address("192.0.2.1").packed


def test_record_types_as_text() -> None:
    aaaa = record(b"\xc0\x0c", 28, bytes(15) + b"\x01")
    mx = record(b"\xc0\x0c", 15, struct.pack("!H", 10) + dns_name("mail.test"))
    txt = record(b"\xc0\x0c", 16, b"\x05hello\x03a b")
    ptr = record(b"\xc0\x0c", 12, dns_name("host.test"))
    odd = record(b"\xc0\x0c", 99, b"\x01\x02")
    dns = parse_dns(message(aaaa, mx, txt, ptr, odd))
    assert dns.anomalies == ()
    assert [r.text for r in dns.answers] == [
        "::1",
        "10 mail.test",
        '"hello" "a\\032b"',
        "host.test",
        "0102",
    ]


def test_names_are_escaped_so_they_print_safely() -> None:
    label = b"\x05a.b\x1bc"  # a dot and an escape character inside one label
    dns = parse_dns(HEADER + label + b"\x00" + struct.pack("!HH", 1, 1))
    assert dns.questions[0].name == "a\\046b\\027c"


def test_root_name() -> None:
    dns = parse_dns(HEADER + b"\x00" + struct.pack("!HH", 2, 1))
    assert dns.questions == (DnsQuestion(".", 2, 1),)


def test_truncated_header() -> None:
    raw = dns_cname_response()
    for n in range(12):
        dns = parse_dns(raw[:n])
        assert dns.error is not None
        assert "truncated" in dns.error


def test_every_truncation_after_the_header_is_an_anomaly() -> None:
    raw = dns_cname_response()
    for n in range(12, len(raw)):
        dns = parse_dns(raw[:n])
        assert dns.error is None
        assert len(dns.anomalies) == 1, n
    assert parse_dns(raw).anomalies == ()


def test_earlier_records_survive_a_later_broken_one() -> None:
    raw = dns_cname_response()
    dns = parse_dns(raw[:-2])  # the A record's rdata is cut
    assert len(dns.answers) == 1
    assert dns.answers[0].rtype == 5
    assert "malformed dns answer 2" in dns.anomalies[0]


def test_malformed_names_are_anomalies() -> None:
    cases = {
        "loop to itself": (b"\xc0\x0c", "does not point backward"),
        "forward pointer": (b"\xc0\x40", "does not point backward"),
        "pointer into the header": (b"\xc0\x02", "does not point backward"),
        "reserved label type": (b"\x40abc\x00", "reserved label type"),
        "label past the end": (b"\x3fabc", "label runs past"),
        "no terminator": (b"\x01a", "name runs past"),
        "half a pointer": (b"\xc0", "truncated compression pointer"),
        "name over 255 bytes": ((b"\x3f" + b"a" * 63) * 5 + b"\x00", "longer than 255"),
    }
    for why, (name, expected) in cases.items():
        dns = parse_dns(HEADER + name)
        assert dns.error is None, why
        assert dns.questions == (), why
        assert dns.anomalies[0].startswith("malformed dns question 1"), why
        assert expected in dns.anomalies[0], why


def test_pointer_chain_is_capped() -> None:
    # 40 backward pointers in a row: each points at the previous one.
    chain = b"".join(struct.pack("!H", 0xC000 | (12 + 2 * i)) for i in range(40)) + b"\x00"
    dns = parse_dns(HEADER + b"\x01a\x00" + b"\xc0\x0c" + chain[2:])
    assert dns.error is None
    assert dns.anomalies  # never loops; ends with an anomaly or a clean parse


def test_lying_counts_do_not_hang_or_crash() -> None:
    raw = struct.pack("!6H", 1, 0, 65535, 65535, 65535, 65535)
    dns = parse_dns(raw)
    assert dns.error is None
    assert dns.counts == (65535, 65535, 65535, 65535)
    assert "truncated dns message" in dns.anomalies[0]


def test_rdata_longer_than_the_message() -> None:
    dns = parse_dns(message(record(b"\xc0\x0c", 1, b"\x01\x02\x03\x04", rdlen=500)))
    assert dns.answers == ()
    assert "truncated rdata" in dns.anomalies[0]


def test_name_inside_rdata_must_not_leave_the_record() -> None:
    # CNAME whose rdlen is 1 but whose name needs more bytes.
    dns = parse_dns(message(record(b"\xc0\x0c", 5, b"\x03abc\x00", rdlen=1)))
    assert "runs past the record" in dns.anomalies[0]


def test_trailing_bytes_are_reported() -> None:
    dns = parse_dns(dns_query(1, "a.test") + b"junk")
    assert dns.anomalies == ("4 trailing bytes after the dns message",)


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    with_question = bytes.fromhex("000081800001000200000000")
    for blob in blobs:
        dns = parse_dns(blob)
        if len(blob) < 12:
            assert dns.error is not None
        parse_dns(with_question + blob)
        parse_dns(with_question + QUESTION + blob)
