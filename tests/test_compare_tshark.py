"""The tshark comparison tool. Most tests use rows written by hand in the form tshark prints
them; the last ones run the real tshark, and are skipped where it is not installed."""

import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from sentinel.pcap import Packet, PcapWriter
from sentinel.proto.decode import decode
from sentinel.proto.layer import Layer
from tools import compare_tshark as ct
from tools.gen_pcap import (
    IP_A,
    IP_B,
    MAC_A,
    MAC_B,
    eth_frame,
    generate,
    generate_attacks,
    generate_benign,
    generate_streams,
    icmp_message,
    ipv4_packet,
    pcapng_bytes,
    tcp_segment,
    udp_datagram,
)

PACKETS = generate()


def fields(index: int) -> dict[str, ct.Value]:
    packet = PACKETS[index]
    return ct.ours(packet, decode(packet.data))


# ---- reading what tshark prints --------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [
        ("int", "80", 80),
        ("int", "0x0800", 2048),
        ("int", "0", 0),
        ("bool", "1", True),
        ("bool", "True", True),
        ("bool", "true", True),
        ("bool", "0", False),
        ("bool", "False", False),
        ("mac", "02:AA:00:00:00:01", "02:aa:00:00:00:01"),
        ("ip", "10.0.0.1", "10.0.0.1"),
        ("ip", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("str", "Example.COM", "Example.COM"),
        ("[int]", "1|2|0x0304", [1, 2, 772]),
        ("[int]", "7", [7]),
        ("[str]", "a.b|c", ["a.b", "c"]),
        ("[ip]", "192.0.2.1|10.0.0.9", ["192.0.2.1", "10.0.0.9"]),
    ],
)
def test_normalize(kind: str, raw: str, expected: ct.Value) -> None:
    assert ct.normalize(kind, raw) == expected


def test_a_field_tshark_left_empty_is_not_in_the_result() -> None:
    assert ct.theirs({"ip.src": "", "ip.ttl": "64"}, {"dns.qry.name": ""}) == {"ip.ttl": 64}
    assert ct.theirs({}, {}) == {}


def test_theirs_reads_scalars_and_lists() -> None:
    got = ct.theirs(
        {"ip.src": "10.0.0.1", "tcp.srcport": "40000", "ip.flags.df": "True"},
        {"dns.qry.name": "a.example|b.example", "tcp.options.mss_val": "1460"},
    )
    assert got == {
        "ip.src": "10.0.0.1",
        "tcp.srcport": 40000,
        "ip.df": True,
        "dns.question_names": ["a.example", "b.example"],
        "tcp.mss": [1460],
    }


def test_checksum_status_becomes_bad_or_not() -> None:
    for proto, field in (
        ("ip", "ip.checksum.status"),
        ("tcp", "tcp.checksum.status"),
        ("udp", "udp.checksum.status"),
        ("icmp", "icmp.checksum.status"),
    ):
        # 0 is bad; good, unverified, not present and illegal are not a checksum that is wrong
        for status, bad in (("0", True), ("1", False), ("2", False), ("3", False), ("4", False)):
            assert ct.theirs({field: status}, {}) == {f"{proto}.checksum_bad": bad}


def test_tcp_flags_keep_only_the_nine_bits_sentinel_has() -> None:
    assert ct.theirs({"tcp.flags": "0x0002"}, {})["tcp.flags"] == 2
    assert ct.theirs({"tcp.flags": "0x0e12"}, {})["tcp.flags"] == 0x012  # reserved bits dropped
    assert ct.theirs({"tcp.flags": "0x01ff"}, {})["tcp.flags"] == 0x1FF
    assert ct.theirs({"tcp.flags": "0x0200"}, {})["tcp.flags"] == 0


def test_the_fragment_offset_is_in_bytes() -> None:
    assert ct.theirs({"ip.frag_offset": "185"}, {})["ip.frag_offset"] == 1480
    assert ct.theirs({"ip.frag_offset": "0"}, {})["ip.frag_offset"] == 0


def test_ethertype_is_the_inner_one() -> None:
    assert ct.theirs({"eth.type": "0x0800"}, {})["ethertype"] == 0x0800
    tagged = ct.theirs({"eth.type": "0x8100"}, {"vlan.id": "5", "vlan.etype": "0x0800"})
    assert tagged["ethertype"] == 0x0800
    double = ct.theirs({"eth.type": "0x88a8"}, {"vlan.id": "5|6", "vlan.etype": "0x8100|0x86dd"})
    assert double["ethertype"] == 0x86DD
    # an LLC frame has a length where the type would be, and tshark reports no type
    assert "ethertype" not in ct.theirs({"eth.type": "0x8100"}, {"vlan.id": "5"})
    assert "ethertype" not in ct.theirs({}, {})


# ---- what Sentinel reports -------------------------------------------------------------------


def test_sentinel_fields_of_an_arp_request() -> None:
    assert fields(0) == {
        "frame.len": 60,
        "frame.cap_len": 60,
        "eth.dst": "ff:ff:ff:ff:ff:ff",
        "eth.src": "02:00:00:00:00:01",
        "ethertype": 0x0806,
        "arp.op": 1,
        "arp.sender_mac": "02:00:00:00:00:01",
        "arp.sender_ip": "10.0.0.1",
        "arp.target_mac": "00:00:00:00:00:00",
        "arp.target_ip": "10.0.0.2",
    }


def test_sentinel_fields_of_a_syn() -> None:
    got = fields(5)
    assert got["ip.src"] == "10.0.0.1"
    assert (got["ip.ttl"], got["ip.id"], got["ip.len"], got["ip.hdr_len"]) == (64, 1, 60, 20)
    assert (got["ip.df"], got["ip.mf"], got["ip.frag_offset"]) == (True, False, 0)
    assert (got["tcp.srcport"], got["tcp.dstport"], got["tcp.seq"], got["tcp.ack"]) == (
        40000,
        80,
        1000,
        0,
    )
    assert (got["tcp.hdr_len"], got["tcp.flags"], got["tcp.window"], got["tcp.len"]) == (
        40,
        0x02,
        64240,
        0,
    )
    assert got["tcp.option_kinds"] == [2, 4, 8, 1, 3]
    assert (got["tcp.mss"], got["tcp.wscale"]) == ([1460], [7])
    assert (got["tcp.tsval"], got["tcp.tsecr"]) == ([1000], [0])
    assert got["ip.checksum_bad"] is False
    assert got["tcp.checksum_bad"] is False
    assert not any(key.startswith(("udp.", "dns.", "http.", "tls.")) for key in got)


def test_sentinel_fields_of_http_dns_and_tls() -> None:
    http = fields(8)
    assert (http["http.method"], http["http.target"], http["http.version"]) == (
        "GET",
        "/",
        "HTTP/1.1",
    )
    assert http["http.host"] == "example.test"
    response = fields(17)
    assert (response["http.status"], response["http.reason"]) == (200, "OK")
    assert "http.method" not in response
    query = fields(10)
    assert query["dns.question_names"] == ["example.com"]
    assert (query["dns.response"], query["dns.rd"], query["dns.count_queries"]) == (False, True, 1)
    answer = fields(15)
    assert answer["dns.record_names"] == ["www.example.com", "example.com"]
    assert (answer["dns.record_types"], answer["dns.record_ttls"]) == ([5, 1], [300, 300])
    assert (answer["dns.a"], answer["dns.cname"]) == (["192.0.2.1"], ["example.com"])
    hello = fields(18)
    assert hello["tls.server_name"] == "example.com"
    assert (hello["tls.record_version"], hello["tls.client_version"]) == (0x0301, 0x0303)
    assert hello["tls.versions"] == [0x2A2A, 0x0304, 0x0303]
    assert hello["tls.extensions"] == [0x1A1A, 0, 10, 43]
    assert hello["tls.groups"] == [29, 23, 24]
    assert hello["tls.ja3"] == "61279becc80ab0e3aca57f5913c3e1a0"
    assert "tls.point_formats" not in hello
    assert list(hello["tls.ciphers"])[:3] == [0x0A0A, 0x1301, 0x1302]  # type: ignore[arg-type]


def test_sentinel_fields_of_icmp_ipv6_and_vlan() -> None:
    icmp = fields(2)
    assert (icmp["icmp.type"], icmp["icmp.code"], icmp["icmp.checksum_bad"]) == (8, 0, False)
    ipv6 = fields(12)
    assert ipv6["ipv6.src"] == "2001:db8::1"
    assert (ipv6["ipv6.next_header"], ipv6["ipv6.hop_limit"]) == (6, 64)
    assert (ipv6["ipv6.payload_length"], ipv6["ipv6.traffic_class"]) == (20, 0)
    assert ipv6["ipv6.flow_label"] == 0
    tagged = fields(11)
    assert tagged["vlan.id"] == [100]
    assert tagged["ethertype"] == 0x0800


def test_a_broken_layer_gives_no_fields() -> None:
    cut = PACKETS[5].data[: 14 + 20 + 10]  # a TCP header cut short
    got = ct.ours(Packet(0, len(cut), cut), decode(cut))
    assert "ip.src" in got
    assert not any(key.startswith("tcp.") for key in got)
    none = ct.ours(Packet(0, 3, b"abc"), decode(b"abc"))
    assert none == {"frame.len": 3, "frame.cap_len": 3}


def test_checksum_fields_report_the_anomalies() -> None:
    bad = bytearray(PACKETS[5].data)
    bad[24] ^= 0xFF  # the IPv4 header checksum
    assert ct.ours(Packet(0, 74, bytes(bad)), decode(bytes(bad)))["ip.checksum_bad"] is True
    bad = bytearray(PACKETS[5].data)
    bad[-1] ^= 0xFF  # inside the TCP options, so the TCP checksum
    assert ct.ours(Packet(0, 74, bytes(bad)), decode(bytes(bad)))["tcp.checksum_bad"] is True
    bad = bytearray(PACKETS[10].data)
    bad[-1] ^= 0xFF
    assert ct.ours(Packet(0, len(bad), bytes(bad)), decode(bytes(bad)))["udp.checksum_bad"] is True
    bad = bytearray(PACKETS[2].data)
    bad[-1] ^= 0xFF
    assert ct.ours(Packet(0, len(bad), bytes(bad)), decode(bytes(bad)))["icmp.checksum_bad"] is True


def test_a_length_instead_of_an_ethertype_is_not_reported_as_one() -> None:
    frame = eth_frame(MAC_B, MAC_A, 0x0026, b"llc" * 10)
    assert "ethertype" not in ct.ours(Packet(0, len(frame), frame), decode(frame))
    frame = eth_frame(MAC_B, MAC_A, 0x0600, b"x" * 30)
    assert ct.ours(Packet(0, len(frame), frame), decode(frame))["ethertype"] == 0x0600


# ---- comparing -------------------------------------------------------------------------------


def test_compare_finds_the_three_kinds_of_difference() -> None:
    a: dict[str, ct.Value] = {"same": 1, "differs": 1, "only sentinel": 2, "list": [1, 2]}
    b: dict[str, ct.Value] = {"same": 1, "differs": 2, "only tshark": 3, "list": [1, 2]}
    found = ct.compare("f.pcap", 7, a, b)
    assert found == [
        ct.Difference("f.pcap", 7, "differs", "differs", 1, 2),
        ct.Difference("f.pcap", 7, "only sentinel", "only sentinel", 2, None),
        ct.Difference("f.pcap", 7, "only tshark", "only tshark", None, 3),
    ]
    assert ct.compare("f.pcap", 1, a, a) == []
    assert ct.compare("f.pcap", 1, {"x": [1, 2]}, {"x": [2, 1]})[0].kind == "differs"
    assert ct.compare("f.pcap", 1, {"x": True}, {"x": False})[0].kind == "differs"


def test_zero_and_false_are_values_like_any_other() -> None:
    assert ct.compare("f", 1, {"x": 0}, {"x": 0}) == []
    assert ct.compare("f", 1, {"x": 0}, {})[0].kind == "only sentinel"
    assert ct.compare("f", 1, {}, {"x": False})[0].kind == "only tshark"


def layers_of(frame: bytes) -> tuple[Layer, ...]:
    return tuple(decode(frame))


def test_explain_query_flags() -> None:
    query, response = fields(10), fields(15)
    rules = ct.explain(layers_of(PACKETS[10].data), query, {})
    assert {(p, k) for p, k, _ in rules} >= {
        (f, "only sentinel") for f in ("dns.aa", "dns.ra", "dns.rcode")
    }
    assert not any(
        p.startswith("dns.") for p, _k, _r in ct.explain(layers_of(PACKETS[15].data), response, {})
    )


def test_explain_the_request_a_response_answers() -> None:
    rules = ct.explain(layers_of(PACKETS[17].data), fields(17), {"http.status": 200})
    assert {p for p, k, _ in rules if k == "only tshark"} == {
        "http.method",
        "http.target",
        "http.version",
    }
    assert not ct.explain(layers_of(PACKETS[8].data), fields(8), {"http.method": "GET"})
    # the reason is tshark's: Sentinel having a status and tshark not is nothing to explain
    assert not any(p.startswith("http.") for p, _k, _r in ct.explain((), {"http.status": 200}, {}))


def test_explain_a_header_quoted_inside_an_icmp_error() -> None:
    for index in (4,):  # destination unreachable
        rules = ct.explain(layers_of(PACKETS[index].data), fields(index), {})
        assert {"tcp.", "udp.", "dns.", "http.", "tls."} <= {
            p for p, k, _ in rules if k == "only tshark"
        }
    assert not any(
        p == "udp." for p, _k, _r in ct.explain(layers_of(PACKETS[2].data), fields(2), {})
    )  # an echo
    for icmp_type in range(20):  # only the error types quote a packet
        frame = eth_frame(
            MAC_B,
            MAC_A,
            0x0800,
            ipv4_packet(IP_A, IP_B, 1, icmp_message(icmp_type, 0, 0, b"quoted")),
        )
        got = ct.ours(Packet(0, len(frame), frame), decode(frame))
        rules = ct.explain(layers_of(frame), got, {})
        assert any(p == "udp." for p, _k, _r in rules) == (icmp_type in (3, 4, 5, 11, 12))
    v6 = {"ipv6.next_header": 58}
    assert any(p == "udp." for p, _k, _r in ct.explain((), v6, {}))
    assert not any(p == "udp." for p, _k, _r in ct.explain((), {"ipv6.next_header": 6}, {}))


def test_explain_an_802_3_frame() -> None:
    frame = eth_frame(MAC_B, MAC_A, 0x0026, b"llc" * 10)
    rules = ct.explain(layers_of(frame), {}, {})
    assert ("", "only tshark") in {(p, k) for p, k, _ in rules}
    assert not ct.explain(layers_of(PACKETS[5].data), fields(5), {})
    for ethertype, explained in ((0x05FF, True), (0x0600, False), (0x0800, False)):
        frame = eth_frame(MAC_B, MAC_A, ethertype, b"x" * 30)
        rules = ct.explain(layers_of(frame), {}, {})
        assert (("", "only tshark") in {(p, k) for p, k, _ in rules}) == explained


def test_explain_a_dns_message_that_is_not_whole_in_its_segment() -> None:
    streams = generate_streams()
    split = decode(
        streams[19].data
    )  # the first half of a DNS query, length prefix 29, 20 bytes here
    rules = ct.explain(split, {}, {})
    assert ("dns.", "only tshark") in {(p, k) for p, k, _ in rules}
    whole = decode(streams[20].data) if False else decode(PACKETS[16].data)  # one whole message
    assert not any(p == "dns." for p, _k, _r in ct.explain(whole, {}, {}))


def test_explain_a_client_hello_that_is_cut_short() -> None:
    cut = decode(generate_streams()[15].data)
    assert ("tls.", "only sentinel") in {(p, k) for p, k, _ in ct.explain(cut, {}, {})}
    assert not ct.explain(decode(PACKETS[18].data), {}, {})


# ---- flows -----------------------------------------------------------------------------------


def flow_row(chain: str, src: str, sport: str, dst: str, dport: str, stream: str) -> dict[str, str]:
    proto = "tcp" if "tcp" in chain else "udp"
    v6 = ":" in src
    row = dict.fromkeys(ct.FLOW_FIELDS, "")
    row.update({"frame.protocols": chain, "ipv6.src" if v6 else "ip.src": src})
    row.update({"ipv6.dst" if v6 else "ip.dst": dst})
    row.update({f"{proto}.srcport": sport, f"{proto}.dstport": dport, f"{proto}.stream": stream})
    return row


def test_tshark_flows_are_counted_per_stream() -> None:
    rows = [
        flow_row("eth:ethertype:ip:tcp", "10.0.0.1", "1000", "10.0.0.2", "80", "0"),
        flow_row("eth:ethertype:ip:tcp:http", "10.0.0.2", "80", "10.0.0.1", "1000", "0"),
        flow_row("eth:ethertype:ip:udp:dns", "10.0.0.1", "5", "10.0.0.2", "53", "0"),
        flow_row("eth:ethertype:ipv6:tcp", "2001:db8::1", "7", "2001:db8::2", "443", "1"),
        flow_row("eth:ethertype:ip:tcp", "10.0.0.1", "1000", "10.0.0.2", "80", "2"),
    ]
    got = ct.tshark_flows(rows)
    assert got == Counter(
        {
            ("tcp", frozenset({"10.0.0.1:1000", "10.0.0.2:80"}), 2): 1,
            ("udp", frozenset({"10.0.0.1:5", "10.0.0.2:53"}), 1): 1,
            ("tcp", frozenset({"[2001:db8::1]:7", "[2001:db8::2]:443"}), 1): 1,
            ("tcp", frozenset({"10.0.0.1:1000", "10.0.0.2:80"}), 1): 1,
        }
    )


def test_a_header_quoted_in_an_icmp_error_is_not_a_conversation() -> None:
    quoted = flow_row("eth:ethertype:ip:icmp:ip:udp:data", "10.0.0.1", "5", "10.0.0.2", "9", "3")
    quoted["udp.stream"] = "3"  # tshark numbers it, but ICMP came first
    assert ct.tshark_flows([quoted]) == Counter()
    assert ct.tshark_flows([flow_row("eth:ethertype:ip:arp", "", "", "", "", "")]) == Counter()
    v6 = flow_row("eth:ethertype:ipv6:icmpv6:ipv6:udp", "2001:db8::1", "5", "2001:db8::2", "9", "3")
    assert ct.tshark_flows([v6]) == Counter()


def test_sentinel_flows_have_no_idle_timeout() -> None:
    def datagram(ts_s: int) -> tuple[Packet, tuple[Layer, ...]]:
        frame = eth_frame(
            MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 17, udp_datagram(IP_A, IP_B, 5, 9, b"x"))
        )
        return Packet(ts_s * 10**9, len(frame), frame), tuple(decode(frame))

    got = ct.sentinel_flows([datagram(0), datagram(5000), datagram(10000)])  # far apart, one flow
    assert got == Counter({("udp", frozenset({"10.0.0.1:5", "10.0.0.2:9"}), 3): 1})

    def segment(ts_s: int) -> tuple[Packet, tuple[Layer, ...]]:
        frame = eth_frame(
            MAC_B,
            MAC_A,
            0x0800,
            ipv4_packet(IP_A, IP_B, 6, tcp_segment(IP_A, IP_B, 5, 9, 1, 1, 0x10)),
        )
        return Packet(ts_s * 10**9, len(frame), frame), tuple(decode(frame))

    got = ct.sentinel_flows([segment(0), segment(100_000), segment(200_000)])
    assert got == Counter({("tcp", frozenset({"10.0.0.1:5", "10.0.0.2:9"}), 3): 1})


def test_compare_flows() -> None:
    both = ("tcp", frozenset({"a:1", "b:2"}), 4)
    a = Counter({both: 1, ("udp", frozenset({"a:5", "b:6"}), 2): 1})
    b = Counter({both: 1, ("udp", frozenset({"a:5", "b:6"}), 3): 1})
    found = ct.compare_flows("f", a, b)
    assert [(d.kind, d.sentinel, d.tshark, d.field) for d in found] == [
        ("only sentinel", 2, None, "udp flow a:5 <-> b:6"),
        ("only tshark", None, 3, "udp flow a:5 <-> b:6"),
    ]
    assert ct.compare_flows("f", a, a) == []
    twice = ct.compare_flows("f", Counter({both: 2}), Counter())
    assert len(twice) == 2  # two flows that tshark does not have
    assert [d.kind for d in ct.compare_flows("f", Counter(), Counter({both: 3}))] == [
        "only tshark"
    ] * 3


# ---- a whole file ----------------------------------------------------------------------------


def write_pcap(path: Path, packets: list[Packet]) -> Path:
    with path.open("wb") as fp:
        writer = PcapWriter(fp)
        for packet in packets:
            writer.write(packet)
    return path


def rows_like_tshark(packets: list[Packet]) -> list[dict[str, dict[str, str]]]:
    """What tshark would print for these packets, taken from Sentinel's own fields and turned back
    into text. It checks the plumbing, not the decoding."""
    out: list[dict[str, dict[str, str]]] = []
    for packet in packets:
        scalars: dict[str, str] = {}
        lists: dict[str, str] = {}
        for name, value in ct.ours(packet, decode(packet.data)).items():
            if name == "ethertype":
                if "vlan.id" in ct.ours(packet, decode(packet.data)):
                    lists["vlan.etype"] = str(value)
                else:
                    scalars["eth.type"] = str(value)
                continue
            if name == "ip.frag_offset":
                scalars["ip.frag_offset"] = str(int(value) // 8)  # type: ignore[arg-type]
                continue
            if name.endswith("checksum_bad"):
                scalars[name.replace("checksum_bad", "checksum.status")] = "0" if value else "1"
                continue
            field = next((f for n, f, _k in ct.SCALARS + ct.LISTS if n == name), None)
            if field is None:
                continue
            if isinstance(value, list):
                lists[field] = ct.AGGREGATOR.join(str(v) for v in value)
            elif isinstance(value, bool):
                scalars[field] = "True" if value else "False"
            else:
                scalars[field] = str(value)
        out.append({"scalars": scalars, "lists": lists})
    return out


def test_a_file_that_agrees(tmp_path: Path) -> None:
    packets = PACKETS[:5]  # ARP and ICMP: no flows, so tshark's empty flow rows agree
    path = write_pcap(tmp_path / "a.pcap", packets)
    report = ct.compare_file(path, "unused", lambda p: rows_like_tshark(packets), lambda p: [])
    assert report.file == "a.pcap"
    assert report.packets == 5
    assert report.differences == ()
    assert report.fields == sum(len(ct.ours(p, decode(p.data))) for p in packets)


def test_a_field_that_differs_is_reported_with_its_frame(tmp_path: Path) -> None:
    packets = PACKETS[:6]
    path = write_pcap(tmp_path / "a.pcap", packets)
    rows = rows_like_tshark(packets)
    rows[3] = {"scalars": {**rows[3]["scalars"], "ip.ttl": "63"}, "lists": rows[3]["lists"]}
    report = ct.compare_file(path, "unused", lambda p: rows, lambda p: [])
    ttl = [d for d in report.differences if d.field == "ip.ttl"]
    assert [(d.frame, d.kind, d.sentinel, d.tshark) for d in ttl] == [(4, "differs", 64, 63)]


def test_a_different_packet_count_is_reported(tmp_path: Path) -> None:
    packets = PACKETS[:4]
    path = write_pcap(tmp_path / "a.pcap", packets)
    rows = rows_like_tshark(packets)[:3]
    report = ct.compare_file(path, "unused", lambda p: rows, lambda p: [])
    count = [d for d in report.differences if d.field == "packet count"]
    assert [(d.sentinel, d.tshark) for d in count] == [(4, 3)]
    more = rows_like_tshark(packets) + rows_like_tshark(packets[:2])
    report = ct.compare_file(path, "unused", lambda p: more, lambda p: [])
    count = [d for d in report.differences if d.field == "packet count"]
    assert [(d.sentinel, d.tshark) for d in count] == [(4, 6)]


def test_explained_differences_are_kept_apart_with_their_reason(tmp_path: Path) -> None:
    packets = [PACKETS[10]]  # a DNS query: tshark leaves the response-only flags out
    path = write_pcap(tmp_path / "q.pcap", packets)
    rows = rows_like_tshark(packets)
    for field in ("dns.flags.authoritative", "dns.flags.recavail", "dns.flags.rcode"):
        del rows[0]["scalars"][field]
    report = ct.compare_file(path, "unused", lambda p: rows, lambda p: [])
    assert {d.field for d in report.explained} == {"dns.aa", "dns.ra", "dns.rcode"}
    assert all(d.reason for d in report.explained)
    assert not [d for d in report.differences if d.field.startswith("dns.")]
    ours_count = len(ct.ours(packets[0], decode(packets[0].data)))
    assert report.fields == ours_count - 3  # only what both sides report is compared


def test_a_difference_is_explained_only_if_it_is_of_the_kind_the_reason_covers(
    tmp_path: Path,
) -> None:
    packets = [PACKETS[10]]  # a query, so "only sentinel" for the flag dns.aa is explained
    path = write_pcap(tmp_path / "q.pcap", packets)
    rows = rows_like_tshark(packets)
    rows[0]["scalars"]["dns.flags.authoritative"] = "True"  # but here tshark says something else
    report = ct.compare_file(path, "unused", lambda p: rows, lambda p: [])
    dns = [(d.field, d.kind) for d in report.differences if d.field.startswith("dns.")]
    assert dns == [("dns.aa", "differs")]
    assert "dns.aa" not in {d.field for d in report.explained}
    other = rows_like_tshark(packets)
    other[0]["scalars"]["dns.flags.authoritative"] = "True"
    other[0]["scalars"]["dns.flags.recavail"] = ""
    report = ct.compare_file(path, "unused", lambda p: other, lambda p: [])
    assert {d.field for d in report.explained} == {"dns.ra"}


def test_render_lists_counts_examples_and_reasons() -> None:
    d = ct.Difference("f.pcap", 4, "ip.ttl", "differs", 64, 63)
    e = ct.Difference("f.pcap", 9, "dns.aa", "only sentinel", False, None, "because")
    report = ct.FileReport("f.pcap", 10, 200, (d, d, d), (e, e))
    lines = ct.render([report], show=2)
    assert lines[0] == "f.pcap: 10 packets, 200 field values compared, 3 differences, 2 explained"
    assert "  ip.ttl (differs): 3" in lines
    assert lines.count("    frame 4: sentinel 64, tshark 63") == 2  # only the first `show`
    assert "  explained, 2 x: because" in lines
    clean = ct.render([ct.FileReport("g.pcap", 1, 5, ())], show=3)
    assert clean == ["g.pcap: 1 packets, 5 field values compared, 0 differences, 0 explained"]


# ---- running tshark --------------------------------------------------------------------------


class FakeRun:
    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        return self.result


def test_run_tshark_builds_the_command_and_reads_the_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRun("1\t10.0.0.1\n2\t\n")
    monkeypatch.setattr(subprocess, "run", fake)
    rows = ct.run_tshark("tshark", Path("x.pcap"), ["frame.number", "ip.src"], "a")
    assert rows == [
        {"frame.number": "1", "ip.src": "10.0.0.1"},
        {"frame.number": "2", "ip.src": ""},
    ]
    command = fake.commands[0]
    assert command[:6] == ["tshark", "-r", "x.pcap", "-n", "-T", "fields"]
    for option in ct.OPTIONS:
        assert ["-o", option] == command[command.index(option) - 1 : command.index(option) + 1]
    assert [command[i + 1] for i, x in enumerate(command) if x == "-e"] == [
        "frame.number",
        "ip.src",
    ]
    assert "separator=/t" in command
    assert "occurrence=a" in command
    assert f"aggregator={ct.AGGREGATOR}" in command


def test_run_tshark_reports_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", FakeRun("", 2, "tshark: bad file\n"))
    with pytest.raises(ct.TsharkError, match="bad file"):
        ct.run_tshark("tshark", Path("x.pcap"), ["ip.src"], "f")
    monkeypatch.setattr(subprocess, "run", FakeRun("", 3, ""))
    with pytest.raises(ct.TsharkError, match=r"failed on x\.pcap: 3"):
        ct.run_tshark("tshark", Path("x.pcap"), ["ip.src"], "f")


def test_run_tshark_skips_lines_that_are_not_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", FakeRun("a\tb\nonly one\r\nx\ty\tz\r\nc\td\r\n\n"))
    assert ct.run_tshark("tshark", Path("x"), ["f1", "f2"], "f") == [
        {"f1": "a", "f2": "b"},
        {"f1": "c", "f2": "d"},
    ]


def test_tshark_rows_runs_twice_and_pairs_the_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake(tshark: str, path: Path, names: list[str], occurrence: str) -> list[dict[str, str]]:
        calls.append(occurrence)
        return [dict.fromkeys(names, occurrence)] * 2

    monkeypatch.setattr(ct, "run_tshark", fake)
    rows = ct.tshark_rows("tshark", Path("x"))
    assert calls == ["f", "a"]
    assert len(rows) == 2
    assert rows[0]["scalars"]["ip.src"] == "f"
    assert rows[0]["lists"]["dns.qry.name"] == "a"
    monkeypatch.setattr(ct, "run_tshark", lambda t, p, n, o: [{}] * (2 if o == "f" else 3))
    with pytest.raises(ct.TsharkError, match="2 and 3 rows"):
        ct.tshark_rows("tshark", Path("x"))


def test_find_tshark(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("TSHARK", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(ct, "WINDOWS_TSHARK", tmp_path / "missing.exe")
    with pytest.raises(ct.TsharkError, match="not found"):
        ct.find_tshark()
    installed = tmp_path / "tshark.exe"
    installed.write_bytes(b"")
    monkeypatch.setattr(ct, "WINDOWS_TSHARK", installed)
    assert ct.find_tshark() == str(installed)
    monkeypatch.setattr(shutil, "which", lambda name: "on-path")
    assert ct.find_tshark() == "on-path"
    monkeypatch.setenv("TSHARK", "from-env")
    assert ct.find_tshark() == "from-env"
    assert ct.find_tshark("explicit") == "explicit"


def test_the_command_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_pcap(tmp_path / "a.pcap", PACKETS[:2])
    monkeypatch.setattr(ct, "find_tshark", lambda explicit=None: "tshark")
    clean = ct.FileReport("a.pcap", 2, 30, ())
    monkeypatch.setattr(ct, "compare_file", lambda p, t: clean)
    assert ct.main([str(path)]) == 0
    assert (
        capsys.readouterr().out
        == "a.pcap: 2 packets, 30 field values compared, 0 differences, 0 explained\n"
    )
    dirty = ct.FileReport("a.pcap", 2, 30, (ct.Difference("a.pcap", 1, "ip.ttl", "differs", 1, 2),))
    monkeypatch.setattr(ct, "compare_file", lambda p, t: dirty)
    assert ct.main([str(path), "--show", "1"]) == 1
    assert "frame 1: sentinel 1, tshark 2" in capsys.readouterr().out
    explained = ct.FileReport(
        "a.pcap", 2, 30, (), (ct.Difference("a.pcap", 1, "x", "differs", 1, 2, "why"),)
    )
    monkeypatch.setattr(ct, "compare_file", lambda p, t: explained)
    assert ct.main([str(path)]) == 0  # an explained difference is not a failure


def test_the_command_line_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing(explicit: str | None = None) -> str:
        raise ct.TsharkError("tshark was not found")

    monkeypatch.setattr(ct, "find_tshark", missing)
    assert ct.main([str(tmp_path / "a.pcap")]) == 2
    assert "compare_tshark: tshark was not found" in capsys.readouterr().err
    monkeypatch.setattr(ct, "find_tshark", lambda explicit=None: "tshark")
    assert ct.main([str(tmp_path / "nope.pcap")]) == 2
    assert "nope.pcap" in capsys.readouterr().err
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"not a capture")
    assert ct.main([str(junk)]) == 2
    with pytest.raises(SystemExit):
        ct.main([str(junk), "--show", "0"])


# ---- the real tshark -------------------------------------------------------------------------


def real_tshark() -> str | None:
    try:
        tshark = ct.find_tshark()
        done = subprocess.run([tshark, "--version"], capture_output=True, check=False)
    except (ct.TsharkError, OSError):
        return None
    return tshark if done.returncode == 0 else None


TSHARK = real_tshark()
needs_tshark = pytest.mark.skipif(TSHARK is None, reason="tshark is not installed")


@needs_tshark
@pytest.mark.parametrize(
    "make",
    [generate, generate_streams, generate_benign, generate_attacks],
    ids=lambda f: f.__name__,
)
def test_sentinel_agrees_with_tshark_on_the_generated_captures(
    tmp_path: Path, make: object
) -> None:
    assert TSHARK is not None
    packets = make()  # type: ignore[operator]
    for name, path in (
        ("pcap", write_pcap(tmp_path / "x.pcap", packets)),
        ("pcapng", tmp_path / "x.pcapng"),
    ):
        if name == "pcapng":
            path.write_bytes(pcapng_bytes(packets))
        report = ct.compare_file(path, TSHARK)
        assert report.packets == len(packets)
        assert report.differences == ()
        assert report.fields > 10 * len(packets)


@needs_tshark
def test_the_comparison_notices_a_wrong_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert TSHARK is not None
    path = write_pcap(tmp_path / "x.pcap", PACKETS)
    real = ct.ours

    def wrong(packet: Packet, layers: object) -> dict[str, ct.Value]:
        got = real(packet, layers)  # type: ignore[arg-type]
        if "tcp.window" in got:
            got["tcp.window"] = 1
        return got

    monkeypatch.setattr(ct, "ours", wrong)
    report = ct.compare_file(path, TSHARK)
    assert {d.field for d in report.differences} == {"tcp.window"}
    assert len(report.differences) == 9  # the nine TCP segments of the demo capture


@needs_tshark
def test_the_first_fragment_and_an_offloaded_checksum_agree_with_tshark(tmp_path: Path) -> None:
    assert TSHARK is not None
    datagram = udp_datagram(IP_A, IP_B, 5000, 6000, b"payload" * 5)
    first = eth_frame(
        MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 17, datagram[:20], flags_frag=0x2000)
    )
    later = eth_frame(
        MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 17, datagram[20:], flags_frag=0x0003)
    )
    echo = eth_frame(
        MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 1, icmp_message(8, 0, 1, b"ping"))
    )
    packets = [Packet(i, len(f), f) for i, f in enumerate((first, later, echo))]
    report = ct.compare_file(write_pcap(tmp_path / "f.pcap", packets), TSHARK)
    assert report.differences == ()
    assert report.fields > 40
