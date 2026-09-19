import random
from itertools import pairwise

import pytest

from sentinel.flow import FlowTable
from sentinel.flow.report import format_flow, format_footer
from sentinel.pcap import Packet
from sentinel.proto import tcp
from tools.gen_pcap import (
    IP6_A,
    IP6_B,
    IP_A,
    IP_B,
    MAC_A,
    MAC_B,
    dns_cname_response,
    dns_query,
    eth_frame,
    generate,
    generate_streams,
    icmp_message,
    ipv4_packet,
    ipv6_packet,
    tcp_segment,
    udp_datagram,
)

SEC = 1_000_000_000
PSH_ACK = tcp.PSH | tcp.ACK


def tcp4(
    ts: int,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    *,
    reverse: bool = False,
    vlan: int | None = None,
) -> Packet:
    """A TCP packet from 10.0.0.1 to 10.0.0.2, or the other way round with reverse=True."""
    src, dst = (IP_B, IP_A) if reverse else (IP_A, IP_B)
    a, b = (dport, sport) if reverse else (sport, dport)
    seg = tcp_segment(src, dst, a, b, seq, ack, flags, payload=payload)
    frame = eth_frame(MAC_A, MAC_B, 0x0800, ipv4_packet(src, dst, 6, seg), vlan=vlan)
    return Packet(ts, len(frame), frame)


def table_of(*packets: Packet, **kw: int) -> FlowTable:
    table = FlowTable(**kw)
    for p in packets:
        table.add(p)
    return table


def test_both_directions_are_one_flow() -> None:
    table = table_of(
        tcp4(0, 4000, 80, 100, 0, tcp.SYN),
        tcp4(1, 4000, 80, 500, 101, tcp.SYN | tcp.ACK, reverse=True),
        tcp4(2, 4000, 80, 101, 501, PSH_ACK, b"hello"),
        tcp4(3, 4000, 80, 501, 106, PSH_ACK, b"hi!", reverse=True),
    )
    assert len(table.flows) == 1
    flow = table.flows[0]
    assert (str(flow.client), str(flow.server)) == ("10.0.0.1:4000", "10.0.0.2:80")
    assert flow.packets == [2, 2]
    assert flow.payload_bytes == [5, 3]
    assert flow.duration_ns == 3
    assert flow.state == "established"


def test_the_client_is_the_syn_sender_or_the_first_packet_seen() -> None:
    synack_first = table_of(tcp4(0, 4000, 80, 500, 101, tcp.SYN | tcp.ACK, reverse=True))
    assert str(synack_first.flows[0].client) == "10.0.0.1:4000"  # the SYN-ACK sender is the server
    midstream = table_of(tcp4(0, 4000, 80, 900, 1, PSH_ACK, b"x", reverse=True))
    assert str(midstream.flows[0].client) == "10.0.0.2:80"
    assert midstream.flows[0].state == "midstream"


@pytest.mark.parametrize(
    ("flags", "reverse", "expected"),
    [
        ([tcp.SYN], [False], "syn-sent"),
        ([tcp.SYN, tcp.SYN | tcp.ACK], [False, True], "established"),
        ([tcp.SYN, tcp.SYN | tcp.ACK, tcp.FIN | tcp.ACK], [False, True, False], "closing"),
        (
            [tcp.SYN, tcp.SYN | tcp.ACK, tcp.FIN | tcp.ACK, tcp.FIN | tcp.ACK],
            [False, True, False, True],
            "closed",
        ),
        ([tcp.SYN, tcp.RST | tcp.ACK], [False, True], "reset"),
        ([tcp.ACK], [False], "midstream"),
    ],
)
def test_tcp_states(flags: list[int], reverse: list[bool], expected: str) -> None:
    packets = [
        tcp4(i, 4000, 80, 100 + i, 1, f, reverse=r)
        for i, (f, r) in enumerate(zip(flags, reverse, strict=True))
    ]
    assert table_of(*packets).flows[0].state == expected


def test_a_syn_after_the_connection_ended_starts_a_new_flow() -> None:
    table = table_of(
        tcp4(0, 4000, 80, 100, 0, tcp.SYN),
        tcp4(1, 4000, 80, 200, 101, tcp.RST | tcp.ACK, reverse=True),
        tcp4(2, 4000, 80, 900, 0, tcp.SYN),  # same ports, used again
    )
    assert [f.state for f in table.flows] == ["reset", "syn-sent"]


def test_a_syn_after_the_end_is_a_new_flow_even_with_the_same_sequence_number() -> None:
    table = table_of(
        tcp4(0, 4000, 80, 100, 0, tcp.SYN),
        tcp4(1, 4000, 80, 200, 101, tcp.RST | tcp.ACK, reverse=True),
        tcp4(2, 4000, 80, 100, 0, tcp.SYN),  # the same initial number, but the flow is over
    )
    assert [f.state for f in table.flows] == ["reset", "syn-sent"]


def test_a_syn_with_a_new_initial_sequence_number_starts_a_new_flow() -> None:
    table = table_of(
        tcp4(0, 4000, 80, 100, 0, tcp.SYN),
        tcp4(1, 4000, 80, 100, 0, tcp.SYN),  # a retransmitted SYN: same flow
        tcp4(2, 4000, 80, 9000, 0, tcp.SYN),
    )
    assert len(table.flows) == 2
    assert table.flows[0].packets == [2, 0]


def test_idle_flows_expire() -> None:
    quiet = table_of(
        tcp4(0, 4000, 80, 1, 1, PSH_ACK, b"a"),
        tcp4(3599 * SEC, 4000, 80, 2, 1, PSH_ACK, b"b"),
        tcp4(3599 * SEC + 3601 * SEC, 4000, 80, 3, 1, PSH_ACK, b"c"),
    )
    assert len(quiet.flows) == 2
    assert quiet.flows[0].packets == [2, 0]


def test_flows_are_kept_in_the_order_they_started() -> None:
    table = table_of(
        tcp4(0, 4001, 80, 1, 0, tcp.SYN),
        tcp4(1, 4002, 80, 1, 0, tcp.SYN),
        tcp4(2, 4001, 80, 2, 0, tcp.ACK),
    )
    assert [f.client.port for f in table.flows] == [4001, 4002]


def test_udp_flow_with_dns_messages() -> None:
    query = udp_datagram(IP_A, IP_B, 5353, 53, dns_query(0x1234, "www.example.com"))
    answer = udp_datagram(IP_B, IP_A, 53, 5353, dns_cname_response())
    frames = [
        eth_frame(MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 17, query)),
        eth_frame(MAC_A, MAC_B, 0x0800, ipv4_packet(IP_B, IP_A, 17, answer)),
    ]
    table = table_of(*(Packet(i, len(f), f) for i, f in enumerate(frames)))
    (flow,) = table.flows
    assert flow.proto == "udp"
    assert flow.state == ""
    assert [item.direction for item in flow.app()] == [0, 1]
    line = format_flow(flow)
    assert line.startswith("udp 10.0.0.1:5353 > 10.0.0.2:53: pkts 1/1, bytes 33/63, ")
    assert "-> DNS query 4660" in line
    assert "<- DNS response 4660 NOERROR" in line


def test_ipv6_and_vlan() -> None:
    seg = tcp_segment(IP6_A, IP6_B, 41000, 443, 1, 0, tcp.SYN)
    v6 = eth_frame(MAC_B, MAC_A, 0x86DD, ipv6_packet(IP6_A, IP6_B, 6, seg))
    table = table_of(Packet(0, len(v6), v6))
    assert str(table.flows[0].client) == "[2001:db8::1]:41000"
    assert "tcp [2001:db8::1]:41000 > [2001:db8::2]:443: syn-sent" in format_flow(table.flows[0])
    tagged = table_of(tcp4(0, 4000, 80, 1, 0, tcp.SYN), tcp4(1, 4000, 80, 2, 0, tcp.ACK, vlan=7))
    assert len(tagged.flows) == 1  # VLAN tags are not part of the flow identity


def test_packets_that_are_not_flows_are_only_counted() -> None:
    echo = eth_frame(MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 1, icmp_message(8, 0, 1, b"x")))
    fragment = eth_frame(
        MAC_B, MAC_A, 0x0800, ipv4_packet(IP_A, IP_B, 17, b"x" * 30, flags_frag=0x2000)
    )
    arp = eth_frame(MAC_B, MAC_A, 0x0806, bytes(28))
    table = table_of(*(Packet(0, len(f), f) for f in (echo, fragment, arp, b"junk", bytes(60))))
    assert table.flows == []
    assert table.skipped_packets == 5
    assert format_footer(table) == "# 0 flows, 0 packets in flows, 5 not in a flow"


def test_the_flow_limit() -> None:
    table = table_of(*(tcp4(i, 4000 + i, 80, 1, 0, tcp.SYN) for i in range(10)), max_flows=3)
    assert len(table.flows) == 3
    assert table.untracked_packets == 7
    assert "7 packets not tracked (flow limit)" in format_footer(table)
    table.add(tcp4(99, 4000, 80, 2, 0, tcp.ACK))  # existing flows still work
    assert table.flows[0].packets == [2, 0]


def test_the_buffer_limit_shows_up_in_the_notes() -> None:
    table = table_of(
        tcp4(0, 4000, 80, 100, 0, tcp.SYN),
        tcp4(1, 4000, 80, 101, 0, PSH_ACK, b"x" * 100),
        max_buffered_bytes=40,
    )
    assert "100 client bytes not buffered" in table.flows[0].notes()


def test_reassembly_through_the_table_survives_shuffling_and_duplicates() -> None:
    rng = random.Random(11)
    for _ in range(25):
        payload = rng.randbytes(rng.randint(1, 4000))
        cuts = sorted({0, len(payload), *(rng.randrange(len(payload)) for _ in range(8))})
        pieces = [(a, payload[a:b]) for a, b in pairwise(cuts)]
        pieces += rng.sample(pieces, k=min(3, len(pieces)))
        rng.shuffle(pieces)
        packets = [tcp4(0, 4000, 80, 700, 0, tcp.SYN)]
        packets += [
            tcp4(i + 1, 4000, 80, 701 + off, 1, PSH_ACK, c) for i, (off, c) in enumerate(pieces)
        ]
        stream = table_of(*packets).flows[0].streams[0]
        assert stream is not None
        assert stream.data() == payload


def test_notes_for_the_streams_demo() -> None:
    table = table_of(*generate_streams())
    notes = {f.client.port: f.notes() for f in table.flows}
    assert notes[44000] == ["1 retransmitted client segment", "1 out-of-order client segment"]
    assert notes[45000] == ["1 out-of-order client segment"]
    assert notes[46000] == []
    assert notes[47000] == ["100 client bytes missing"]
    assert notes[48000] == []
    assert table.skipped_packets == 1


def test_a_capture_that_starts_mid_connection_is_flagged() -> None:
    table = table_of(tcp4(0, 4000, 80, 5000, 1, PSH_ACK, b"middle of things"))
    assert "client stream start not captured" in table.flows[0].notes()


def test_conflicting_overlaps_are_reported() -> None:
    table = table_of(
        tcp4(0, 4000, 80, 100, 0, tcp.SYN),
        tcp4(1, 4000, 80, 101, 1, PSH_ACK, b"AAAA"),
        tcp4(2, 4000, 80, 103, 1, PSH_ACK, b"BBBB"),
    )
    assert "1 conflicting client overlap" in table.flows[0].notes()


def test_network_level_anomalies_are_counted_but_split_messages_are_not() -> None:
    bad = bytearray(tcp4(0, 4000, 80, 1, 1, PSH_ACK, b"x").data)
    bad[14 + 8] ^= 0xFF  # ttl: breaks the ipv4 checksum
    table = table_of(Packet(0, len(bad), bytes(bad)))
    assert table.flows[0].notes() == [
        "client stream start not captured",
        "1 packet with anomalies",
    ]
    split = table_of(*generate_streams())
    assert all("anomalies" not in n for f in split.flows for n in f.notes())


def test_same_packets_give_the_same_output() -> None:
    def run() -> list[str]:
        table = table_of(*generate_streams(), *generate())
        return [format_flow(f) for f in table.flows] + [format_footer(table)]

    assert run() == run()


def test_the_table_never_raises_on_broken_packets(blobs: list[bytes]) -> None:
    table = FlowTable()
    for i, blob in enumerate(blobs):
        table.add(Packet(i, len(blob), blob))
    rng = random.Random(3)
    for packet in [*generate(), *generate_streams()]:
        for n in range(len(packet.data) + 1):
            table.add(Packet(1000 + n, n, packet.data[:n]))
        for _ in range(3):
            bad = bytearray(packet.data)
            bad[rng.randrange(len(bad))] = rng.randrange(256)
            table.add(Packet(2000, len(bad), bytes(bad)))
    for flow in table.flows:
        format_flow(flow)
    format_footer(table)
