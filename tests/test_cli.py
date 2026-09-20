import subprocess
import sys
from pathlib import Path

import pytest

from sentinel.cli import main
from sentinel.pcap import Packet, PcapWriter
from tools import gen_pcap

GOLDEN = """\
2023-11-14 22:13:20.000000 ARP, Request who-has 10.0.0.2 tell 10.0.0.1, length 28
2023-11-14 22:13:20.001000 ARP, Reply 10.0.0.2 is-at 02:00:00:00:00:02, length 28
2023-11-14 22:13:20.002000 IP 10.0.0.1 > 10.0.0.2: ICMP echo request, id 1, seq 1, length 40
2023-11-14 22:13:20.003000 IP 10.0.0.2 > 10.0.0.1: ICMP echo reply, id 1, seq 1, length 40
2023-11-14 22:13:20.004000 IP 10.0.0.2 > 10.0.0.1: ICMP destination unreachable, code 3, length 36
2023-11-14 22:13:20.005000 IP 10.0.0.1.40000 > 10.0.0.2.80: Flags [S], seq 1000, win 64240, options [mss 1460,sackOK,TS val 1000 ecr 0,nop,wscale 7], length 0
2023-11-14 22:13:20.006000 IP 10.0.0.2.80 > 10.0.0.1.40000: Flags [S.], seq 5000, ack 1001, win 64240, options [mss 1460,sackOK,TS val 1000 ecr 0,nop,wscale 7], length 0
2023-11-14 22:13:20.007000 IP 10.0.0.1.40000 > 10.0.0.2.80: Flags [.], seq 1001, ack 5001, win 64240, length 0
2023-11-14 22:13:20.008000 IP 10.0.0.1.40000 > 10.0.0.2.80: Flags [P.], seq 1001, ack 5001, win 64240, length 38: HTTP: GET / HTTP/1.1, host example.test
2023-11-14 22:13:20.009000 IP 10.0.0.1.40000 > 10.0.0.2.80: Flags [F.], seq 1039, ack 5001, win 64240, length 0
2023-11-14 22:13:20.010000 IP 10.0.0.1.53000 > 10.0.0.2.53: UDP, length 29: DNS query 48879, A? example.com
2023-11-14 22:13:20.011000 vlan 100, IP 10.0.0.1.53001 > 10.0.0.2.53: UDP, length 29: DNS query 48879, A? example.com
2023-11-14 22:13:20.012000 IP6 2001:db8::1.41000 > 2001:db8::2.443: Flags [S], seq 1, win 65535, length 0
2023-11-14 22:13:20.013000 IP6 2001:db8::1.53002 > 2001:db8::2.53: UDP, length 29: DNS query 48879, A? example.com
2023-11-14 22:13:20.014000 IP 10.0.0.1.53003 > 10.0.0.2.53: UDP, length 33: DNS query 4660, A? www.example.com
2023-11-14 22:13:20.015000 IP 10.0.0.2.53 > 10.0.0.1.53003: UDP, length 63: DNS response 4660 NOERROR, A? www.example.com, answers [CNAME example.com, A 192.0.2.1]
2023-11-14 22:13:20.016000 IP 10.0.0.1.42000 > 10.0.0.2.53: Flags [P.], seq 1, ack 1, win 64240, length 31: DNS query 17185, AAAA? example.com
2023-11-14 22:13:20.017000 IP 10.0.0.2.80 > 10.0.0.1.40000: Flags [P.], seq 5001, ack 1039, win 64240, length 77: HTTP: HTTP/1.1 200 OK
2023-11-14 22:13:20.018000 IP 10.0.0.1.43000 > 10.0.0.2.443: Flags [P.], seq 1, ack 1, win 64240, length 161: TLS ClientHello, sni example.com, versions [TLS 1.3, TLS 1.2], ciphers (15) [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, +12 more], ja3 61279becc80ab0e3aca57f5913c3e1a0
"""


SAMPLE_FLOWS = """\
tcp 10.0.0.1:40000 > 10.0.0.2:80: closing, pkts 4/2, bytes 38/77, 0.012000s | -> HTTP: GET / HTTP/1.1, host example.test | <- HTTP: HTTP/1.1 200 OK
udp 10.0.0.1:53000 > 10.0.0.2:53: pkts 1/0, bytes 29/0, 0.000000s | -> DNS query 48879, A? example.com
udp 10.0.0.1:53001 > 10.0.0.2:53: pkts 1/0, bytes 29/0, 0.000000s | -> DNS query 48879, A? example.com
tcp [2001:db8::1]:41000 > [2001:db8::2]:443: syn-sent, pkts 1/0, bytes 0/0, 0.000000s
udp [2001:db8::1]:53002 > [2001:db8::2]:53: pkts 1/0, bytes 29/0, 0.000000s | -> DNS query 48879, A? example.com
udp 10.0.0.1:53003 > 10.0.0.2:53: pkts 1/1, bytes 33/63, 0.001000s | -> DNS query 4660, A? www.example.com | <- DNS response 4660 NOERROR, A? www.example.com, answers [CNAME example.com, A 192.0.2.1]
tcp 10.0.0.1:42000 > 10.0.0.2:53: midstream, pkts 1/0, bytes 31/0, 0.000000s [client stream start not captured] | -> DNS query 17185, AAAA? example.com
tcp 10.0.0.1:43000 > 10.0.0.2:443: midstream, pkts 1/0, bytes 161/0, 0.000000s [client stream start not captured] | -> TLS ClientHello, sni example.com, versions [TLS 1.3, TLS 1.2], ciphers (15) [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, +12 more], ja3 61279becc80ab0e3aca57f5913c3e1a0
# 8 flows, 14 packets in flows, 5 not in a flow
"""

STREAM_FLOWS = """\
tcp 10.0.0.1:44000 > 10.0.0.2:8080: closed, pkts 8/3, bytes 129/40, 0.010000s [1 retransmitted client segment] [1 out-of-order client segment] | -> HTTP: POST /upload HTTP/1.1, host files.test | <- HTTP: HTTP/1.1 200 OK
tcp 10.0.0.1:45000 > 10.0.0.2:8443: established, pkts 4/1, bytes 161/0, 0.004000s [1 out-of-order client segment] | -> TLS ClientHello, sni example.com, versions [TLS 1.3, TLS 1.2], ciphers (15) [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, +12 more], ja3 61279becc80ab0e3aca57f5913c3e1a0
tcp 10.0.0.1:46000 > 10.0.0.2:53: established, pkts 4/1, bytes 66/0, 0.004000s | -> DNS query 1, A? example.com | -> DNS query 2, AAAA? www.example.com
tcp 10.0.0.1:47000 > 10.0.0.2:80: closing, pkts 5/1, bytes 160/0, 0.005000s [100 client bytes missing]
tcp 10.0.0.1:48000 > 10.0.0.2:22: reset, pkts 1/1, bytes 0/0, 0.001000s
udp 10.0.0.1:53004 > 10.0.0.2:53: pkts 1/1, bytes 33/63, 0.001000s | -> DNS query 4660, A? www.example.com | <- DNS response 4660 NOERROR, A? www.example.com, answers [CNAME example.com, A 192.0.2.1]
# 6 flows, 31 packets in flows, 1 not in a flow
"""


ATTACK_ALERTS_JSON = """\
{"detector": "port_scan", "dst": "10.0.0.30", "evidence": {"ports": 15, "sample": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], "seconds": 0.14}, "message": "10.9.9.1 probed 15 ports on 10.0.0.30 in 0.1s", "rule": "port-scan", "severity": "medium", "src": "10.9.9.1", "ts": "2023-11-14T22:13:20.140000Z", "ts_ns": 1700000000140000000}
{"detector": "port_scan", "dst": "10.0.0.30", "evidence": {"ports": 15, "sample": [21, 22, 23, 24, 25, 26, 27, 28, 29, 30], "seconds": 0.7}, "message": "10.9.9.2 probed 15 ports on 10.0.0.30 in 0.7s", "rule": "port-scan", "severity": "medium", "src": "10.9.9.2", "ts": "2023-11-14T22:13:23.700000Z", "ts_ns": 1700000003700000000}
{"detector": "port_scan", "dst": "10.0.0.30", "evidence": {"ports": 15, "sample": [21, 22, 23, 24, 25, 26, 27, 28, 29, 30], "seconds": 0.7}, "message": "10.9.9.3 probed 15 ports on 10.0.0.30 in 0.7s", "rule": "port-scan", "severity": "medium", "src": "10.9.9.3", "ts": "2023-11-14T22:13:24.700000Z", "ts_ns": 1700000004700000000}
{"detector": "port_scan", "dst": "10.0.0.30", "evidence": {"ports": 15, "sample": [21, 22, 23, 24, 25, 26, 27, 28, 29, 30], "seconds": 0.7}, "message": "10.9.9.4 probed 15 ports on 10.0.0.30 in 0.7s", "rule": "port-scan", "severity": "medium", "src": "10.9.9.4", "ts": "2023-11-14T22:13:25.700000Z", "ts_ns": 1700000005700000000}
{"detector": "port_scan", "dst": null, "evidence": {"hosts": 30, "port": 22, "seconds": 1.16}, "message": "10.9.9.5 probed port 22 on 30 hosts in 1.2s", "rule": "port-scan", "severity": "medium", "src": "10.9.9.5", "ts": "2023-11-14T22:13:29.160000Z", "ts_ns": 1700000009160000000}
{"detector": "syn_flood", "dst": "10.0.0.2", "evidence": {"completed": 20, "port": 80, "seconds": 0.099, "sources": 100, "syns": 100}, "message": "100 SYNs to 10.0.0.2:80 in 0.1s from 100 sources, 20 completed", "rule": "syn-flood", "severity": "high", "src": null, "ts": "2023-11-14T22:13:32.099000Z", "ts_ns": 1700000012099000000}
{"detector": "arp_spoof", "dst": "10.0.0.1", "evidence": {"ip": "10.0.0.1", "new_mac": "02:ee:00:00:06:66", "old_mac": "02:aa:00:00:00:01", "op": 2}, "message": "10.0.0.1 moved from 02:aa:00:00:00:01 to 02:ee:00:00:06:66", "rule": "arp-spoof", "severity": "high", "src": "02:ee:00:00:06:66", "ts": "2023-11-14T22:13:41.000000Z", "ts_ns": 1700000021000000000}
{"detector": "arp_spoof", "dst": "10.0.0.1", "evidence": {"arp_mac": "02:aa:00:00:00:01", "ethernet_source": "02:ee:00:00:06:66", "ip": "10.0.0.1", "op": 2}, "message": "ARP says 10.0.0.1 is at 02:aa:00:00:00:01, but the frame came from 02:ee:00:00:06:66", "rule": "arp-spoof", "severity": "high", "src": "02:ee:00:00:06:66", "ts": "2023-11-14T22:13:42.000000Z", "ts_ns": 1700000022000000000}
{"detector": "arp_spoof", "dst": "10.0.0.1", "evidence": {"ip": "10.0.0.1", "new_mac": "02:aa:00:00:00:01", "old_mac": "02:ee:00:00:06:66", "op": 2}, "message": "10.0.0.1 moved from 02:ee:00:00:06:66 to 02:aa:00:00:00:01", "rule": "arp-spoof", "severity": "high", "src": "02:aa:00:00:00:01", "ts": "2023-11-14T22:13:42.000000Z", "ts_ns": 1700000022000000000}
{"detector": "dns_tunnel", "dst": null, "evidence": {"entropy": 4.594, "length": 49, "name": "thrbeobwung4fkxetkxyw2zxfyegdafb3is63n64ok3qvcp4.t.evil-cdn.test", "signal": "high_entropy"}, "message": "10.0.5.5 asked for a random-looking name under evil-cdn.test", "rule": "dns-tunnel", "severity": "medium", "src": "10.0.5.5", "ts": "2023-11-14T22:13:50.000000Z", "ts_ns": 1700000030000000000}
{"detector": "dns_tunnel", "dst": null, "evidence": {"domain": "evil-cdn.test", "name": "f2bnefn35c7je47372ve3rjtbgehkvyx3lfanxi7ldzb7j4b.t.evil-cdn.test", "signal": "many_subdomains", "subdomains": 50}, "message": "10.0.5.5 asked for 50 different subdomains of evil-cdn.test in 2.5s", "rule": "dns-tunnel", "severity": "medium", "src": "10.0.5.5", "ts": "2023-11-14T22:13:52.450000Z", "ts_ns": 1700000032450000000}
{"detector": "dns_tunnel", "dst": null, "evidence": {"length": 124, "longest_label": 45, "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb...", "signal": "long_name"}, "message": "10.0.5.6 asked for a very long name under example.org (124 characters)", "rule": "dns-tunnel", "severity": "medium", "src": "10.0.5.6", "ts": "2023-11-14T22:13:55.000000Z", "ts_ns": 1700000035000000000}
{"detector": "dns_tunnel", "dst": "10.0.6.6", "evidence": {"answers": 20, "signal": "nxdomain"}, "message": "10.0.6.6 received 20 'no such name' answers in 0.9s", "rule": "dns-tunnel", "severity": "medium", "src": null, "ts": "2023-11-14T22:13:56.951000Z", "ts_ns": 1700000036951000000}
{"detector": "ssh_brute_force", "dst": "10.0.0.31", "evidence": {"connections": 10, "port": 22, "seconds": 0.9}, "message": "10.9.9.6 made 10 connections to the SSH port of 10.0.0.31 in 0.9s", "rule": "ssh-brute-force", "severity": "medium", "src": "10.9.9.6", "ts": "2023-11-14T22:14:00.902000Z", "ts_ns": 1700000040902000000}
{"detector": "icmp_tunnel", "dst": "10.0.0.40", "evidence": {"replies": 5, "seconds": 0.8, "signal": "changed_reply"}, "message": "10.0.8.8 got 5 echo replies from 10.0.0.40 that do not repeat the data it sent, in 0.8s", "rule": "icmp-tunnel", "severity": "medium", "src": "10.0.8.8", "ts": "2023-11-14T22:14:05.850000Z", "ts_ns": 1700000045850000000}
{"detector": "icmp_tunnel", "dst": "10.0.0.40", "evidence": {"bytes": 800, "requests": 10, "seconds": 1.8, "signal": "large_echo"}, "message": "10.0.8.8 sent 10 echo requests of 512 bytes or more to 10.0.0.40 in 1.8s", "rule": "icmp-tunnel", "severity": "medium", "src": "10.0.8.8", "ts": "2023-11-14T22:14:06.800000Z", "ts_ns": 1700000046800000000}
"""

ATTACK_ALERTS_TEXT = """\
2023-11-14T22:13:20.140000Z [medium] port-scan: 10.9.9.1 probed 15 ports on 10.0.0.30 in 0.1s
2023-11-14T22:13:23.700000Z [medium] port-scan: 10.9.9.2 probed 15 ports on 10.0.0.30 in 0.7s
2023-11-14T22:13:24.700000Z [medium] port-scan: 10.9.9.3 probed 15 ports on 10.0.0.30 in 0.7s
2023-11-14T22:13:25.700000Z [medium] port-scan: 10.9.9.4 probed 15 ports on 10.0.0.30 in 0.7s
2023-11-14T22:13:29.160000Z [medium] port-scan: 10.9.9.5 probed port 22 on 30 hosts in 1.2s
2023-11-14T22:13:32.099000Z [high] syn-flood: 100 SYNs to 10.0.0.2:80 in 0.1s from 100 sources, 20 completed
2023-11-14T22:13:41.000000Z [high] arp-spoof: 10.0.0.1 moved from 02:aa:00:00:00:01 to 02:ee:00:00:06:66
2023-11-14T22:13:42.000000Z [high] arp-spoof: ARP says 10.0.0.1 is at 02:aa:00:00:00:01, but the frame came from 02:ee:00:00:06:66
2023-11-14T22:13:42.000000Z [high] arp-spoof: 10.0.0.1 moved from 02:ee:00:00:06:66 to 02:aa:00:00:00:01
2023-11-14T22:13:50.000000Z [medium] dns-tunnel: 10.0.5.5 asked for a random-looking name under evil-cdn.test
2023-11-14T22:13:52.450000Z [medium] dns-tunnel: 10.0.5.5 asked for 50 different subdomains of evil-cdn.test in 2.5s
2023-11-14T22:13:55.000000Z [medium] dns-tunnel: 10.0.5.6 asked for a very long name under example.org (124 characters)
2023-11-14T22:13:56.951000Z [medium] dns-tunnel: 10.0.6.6 received 20 'no such name' answers in 0.9s
2023-11-14T22:14:00.902000Z [medium] ssh-brute-force: 10.9.9.6 made 10 connections to the SSH port of 10.0.0.31 in 0.9s
2023-11-14T22:14:05.850000Z [medium] icmp-tunnel: 10.0.8.8 got 5 echo replies from 10.0.0.40 that do not repeat the data it sent, in 0.8s
2023-11-14T22:14:06.800000Z [medium] icmp-tunnel: 10.0.8.8 sent 10 echo requests of 512 bytes or more to 10.0.0.40 in 1.8s
"""


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    path = tmp_path / "sample.pcap"
    assert gen_pcap.main([str(path)]) == 0
    return path


def test_read_matches_golden_output(sample: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["read", str(sample)]) == 0
    assert capsys.readouterr().out == GOLDEN


def test_same_pcap_twice_gives_identical_output(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["read", str(sample)])
    first = capsys.readouterr().out
    main(["read", str(sample)])
    assert capsys.readouterr().out == first


def test_module_entry_point(sample: Path) -> None:
    done = subprocess.run(
        [sys.executable, "-m", "sentinel", "read", str(sample)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert done.stdout == GOLDEN


def test_generator_is_deterministic(tmp_path: Path) -> None:
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    gen_pcap.main([str(a)])
    gen_pcap.main([str(b)])
    assert a.read_bytes() == b.read_bytes()


def test_bad_packets_are_reported_inline_and_do_not_stop_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = gen_pcap.generate()[5]  # a TCP SYN
    corrupt = bytearray(good.data)
    corrupt[14 + 8] ^= 0xFF  # ipv4 ttl, breaks the header checksum
    path = tmp_path / "bad.pcap"
    with path.open("wb") as fp:
        writer = PcapWriter(fp)
        writer.write(Packet(0, 5, b"\x01\x02\x03\x04\x05"))
        writer.write(Packet(1000, len(corrupt), bytes(corrupt)))
        writer.write(good)
    assert main(["read", str(path)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 3
    assert lines[0].endswith("ethernet, length 5 [error: truncated ethernet header: 5 of 14 bytes]")
    assert lines[1].endswith("[bad ipv4 header checksum]")
    assert "Flags [S]" in lines[1]
    assert lines[2].endswith("length 0")


def test_truncated_file_prints_packets_then_fails(
    sample: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    short = tmp_path / "short.pcap"
    short.write_bytes(sample.read_bytes()[:-3])
    assert main(["read", str(short)]) == 1
    captured = capsys.readouterr()
    assert captured.out == GOLDEN.rsplit("\n", 2)[0] + "\n"  # all but the last line
    assert "truncated pcap record" in captured.err


def test_not_a_pcap(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "junk.pcap"
    path.write_bytes(b"this is not a capture file at all")
    assert main(["read", str(path)]) == 1
    assert "bad magic" in capsys.readouterr().err


def test_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["read", str(tmp_path / "nope.pcap")]) == 1
    assert "nope.pcap" in capsys.readouterr().err


def test_unsupported_linktype(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "raw.pcap"
    with path.open("wb") as fp:
        PcapWriter(fp, linktype=101)
    assert main(["read", str(path)]) == 1
    assert "link type 101" in capsys.readouterr().err


@pytest.fixture
def streams(tmp_path: Path) -> Path:
    path = tmp_path / "streams.pcap"
    assert gen_pcap.main(["--streams", str(path)]) == 0
    return path


def test_flows_on_the_sample_capture(sample: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["flows", str(sample)]) == 0
    assert capsys.readouterr().out == SAMPLE_FLOWS


def test_flows_on_the_reassembly_demo(streams: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["flows", str(streams)]) == 0
    assert capsys.readouterr().out == STREAM_FLOWS


def test_flows_output_is_identical_run_to_run(
    streams: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["flows", str(streams)])
    first = capsys.readouterr().out
    main(["flows", str(streams)])
    assert capsys.readouterr().out == first


def test_flows_through_the_module_entry_point(streams: Path) -> None:
    done = subprocess.run(
        [sys.executable, "-m", "sentinel", "flows", str(streams)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert done.stdout == STREAM_FLOWS


def test_the_streams_generator_is_deterministic(tmp_path: Path) -> None:
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    gen_pcap.main(["--streams", str(a)])
    gen_pcap.main(["--streams", str(b)])
    assert a.read_bytes() == b.read_bytes()


def test_flows_on_a_truncated_file_prints_the_flows_then_fails(
    streams: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    short = tmp_path / "short.pcap"
    short.write_bytes(streams.read_bytes()[:-3])  # cuts into the last packet (the ICMP echo)
    assert main(["flows", str(short)]) == 1
    captured = capsys.readouterr()
    assert captured.out.splitlines()[:6] == STREAM_FLOWS.splitlines()[:6]
    assert captured.out.splitlines()[-1].startswith("# 6 flows, 31 packets in flows")
    assert "truncated pcap record" in captured.err


def test_flows_on_a_missing_or_bad_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["flows", str(tmp_path / "nope.pcap")]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "nope.pcap" in captured.err
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture file at all")
    assert main(["flows", str(junk)]) == 1
    assert "bad magic" in capsys.readouterr().err


def golden_lines(*indexes: int) -> str:
    lines = GOLDEN.splitlines(keepends=True)
    return "".join(lines[i] for i in indexes)


def test_read_with_a_filter_prints_only_matching_packets(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    flt = "tcp and (port 80 or port 443) and not src host 10.0.0.1"
    assert main(["read", str(sample), "--filter", flt]) == 0
    assert capsys.readouterr().out == golden_lines(6, 12, 17)
    assert main(["read", str(sample), "-f", "arp"]) == 0
    assert capsys.readouterr().out == golden_lines(0, 1)
    assert main(["read", str(sample), "-f", "vlan 100"]) == 0
    assert capsys.readouterr().out == golden_lines(11)


def test_read_with_a_filter_that_matches_nothing(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["read", str(sample), "-f", "tcp and udp"]) == 0
    assert capsys.readouterr().out == ""


def test_a_bad_filter_is_reported_with_a_caret_and_exit_code_2(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["read", str(sample), "-f", "tcp and port http"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "sentinel: invalid filter: expected a port number (0-65535), got 'http'",
        "  tcp and port http",
        "  " + " " * 13 + "^",
    ]
    assert main(["flows", str(sample), "-f", ""]) == 2
    assert "empty filter" in capsys.readouterr().err


def test_the_filter_is_checked_before_the_file_is_opened(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["read", str(tmp_path / "nope.pcap"), "-f", "bogus"]) == 2
    assert "unknown filter word 'bogus'" in capsys.readouterr().err


def test_flows_with_a_filter_only_sees_the_matching_packets(
    streams: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lines = STREAM_FLOWS.splitlines(keepends=True)
    assert main(["flows", str(streams), "-f", "port 53"]) == 0
    out = capsys.readouterr().out.splitlines(keepends=True)
    assert out[:-1] == [lines[2], lines[5]]
    assert out[-1] == "# 2 flows, 7 packets in flows, 0 not in a flow" + "\n"
    assert main(["flows", str(streams), "-f", "tcp and port 8080"]) == 0
    assert capsys.readouterr().out.splitlines(keepends=True)[0] == lines[0]
    assert main(["flows", str(streams), "-f", "not tcp"]) == 0
    out = capsys.readouterr().out.splitlines(keepends=True)
    assert out == [lines[5], "# 1 flows, 2 packets in flows, 1 not in a flow" + "\n"]


@pytest.fixture
def attacks(tmp_path: Path) -> Path:
    path = tmp_path / "attacks.pcap"
    assert gen_pcap.main(["--attacks", str(path)]) == 0
    return path


@pytest.fixture
def benign(tmp_path: Path) -> Path:
    path = tmp_path / "benign.pcap"
    assert gen_pcap.main(["--benign", str(path)]) == 0
    return path


def test_ids_prints_json_alerts_for_the_attacks(
    attacks: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["ids", str(attacks)]) == 0
    assert capsys.readouterr().out == ATTACK_ALERTS_JSON


def test_ids_text_format(attacks: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ids", str(attacks), "--format", "text"]) == 0
    assert capsys.readouterr().out == ATTACK_ALERTS_TEXT


def test_ids_is_quiet_on_harmless_traffic(
    benign: Path, sample: Path, streams: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for path in (benign, sample, streams):
        assert main(["ids", str(path)]) == 0
    assert capsys.readouterr().out == ""


def test_the_rule_files_in_the_repository_give_the_default_output(
    attacks: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = Path(__file__).resolve().parent.parent / "rules"
    assert main(["ids", str(attacks), "--rules", str(rules)]) == 0
    assert capsys.readouterr().out == ATTACK_ALERTS_JSON


def test_ids_with_custom_rules(
    attacks: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = tmp_path / "mine.toml"
    rules.write_text(
        '[[rule]]\nid = "only-arp"\ndetector = "arp_spoof"\nseverity = "critical"\n',
        encoding="utf-8",
    )
    assert main(["ids", str(attacks), "--rules", str(rules), "--format", "text"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 3
    assert all("[critical] only-arp:" in line for line in lines)


def test_ids_reports_every_rule_problem_and_exits_with_2(
    attacks: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rules = tmp_path / "bad.toml"
    rules.write_text(
        '[[rule]]\nid = "a"\ndetector = "nope"\n'
        '[[rule]]\nid = "b"\ndetector = "port_scan"\nports = 1\n',
        encoding="utf-8",
    )
    assert main(["ids", str(attacks), "--rules", str(rules)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert lines[0] == "sentinel: invalid rules:"
    assert len(lines) == 3
    assert "unknown detector 'nope'" in lines[1]
    assert "unknown parameter 'ports'" in lines[2]


def test_ids_with_a_missing_capture_or_rules_file(
    attacks: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["ids", str(tmp_path / "nope.pcap")]) == 1
    assert "nope.pcap" in capsys.readouterr().err
    assert main(["ids", str(attacks), "--rules", str(tmp_path / "nope.toml")]) == 2
    assert "invalid rules" in capsys.readouterr().err


def test_ids_on_a_truncated_capture_prints_the_alerts_then_fails(
    attacks: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    short = tmp_path / "short.pcap"
    short.write_bytes(attacks.read_bytes()[:-3])
    assert main(["ids", str(short)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ATTACK_ALERTS_JSON  # the cut packet came after every alert
    assert "truncated pcap record" in captured.err


# ---- pcapng: every command gives the same output as for the same packets in a classic file ----

SCENARIOS = [
    pytest.param([], id="sample"),
    pytest.param(["--streams"], id="streams"),
    pytest.param(["--benign"], id="benign"),
    pytest.param(["--attacks"], id="attacks"),
]


def both_formats(tmp_path: Path, scenario: list[str]) -> tuple[Path, Path]:
    classic, ng = tmp_path / "x.pcap", tmp_path / "x.pcapng"
    assert gen_pcap.main([*scenario, str(classic)]) == 0
    assert gen_pcap.main([*scenario, "--pcapng", str(ng)]) == 0
    return classic, ng


@pytest.mark.parametrize("command", ["read", "flows", "ids"])
@pytest.mark.parametrize("scenario", SCENARIOS)
def test_a_pcapng_file_gives_the_same_output_as_a_classic_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], command: str, scenario: list[str]
) -> None:
    classic, ng = both_formats(tmp_path, scenario)
    assert main([command, str(classic)]) == 0
    expected = capsys.readouterr().out
    if command != "ids" or scenario == ["--attacks"]:
        assert expected  # the quiet captures raise no alerts, which is fine
    assert main([command, str(ng)]) == 0
    got = capsys.readouterr().out
    # Not `got == expected` in the assert: when two long texts differ, pytest spends minutes
    # building a diff of them.
    same = got == expected
    assert same, f"first different line: {first_difference(got, expected)}"


def first_difference(a: str, b: str) -> int:
    a_lines, b_lines = a.splitlines(), b.splitlines()
    pairs = zip(a_lines, b_lines, strict=False)
    return next((i for i, (x, y) in enumerate(pairs) if x != y), min(len(a_lines), len(b_lines)))


def test_the_pcapng_golden_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ng = both_formats(tmp_path, [])[1]
    assert main(["read", str(ng)]) == 0
    assert capsys.readouterr().out == GOLDEN
    assert main(["flows", str(ng)]) == 0
    assert capsys.readouterr().out == SAMPLE_FLOWS


def test_the_filter_works_on_a_pcapng_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ng = both_formats(tmp_path, [])[1]
    assert main(["read", str(ng), "-f", "arp"]) == 0
    assert capsys.readouterr().out == golden_lines(0, 1)


def test_the_pcapng_generator_is_deterministic(tmp_path: Path) -> None:
    a, b = tmp_path / "a.pcapng", tmp_path / "b.pcapng"
    gen_pcap.main(["--pcapng", str(a)])
    gen_pcap.main(["--pcapng", str(b)])
    assert a.read_bytes() == b.read_bytes()
    assert a.read_bytes()[:4] == bytes([0x0A, 0x0D, 0x0D, 0x0A])


def test_pcapng_through_the_module_entry_point(tmp_path: Path) -> None:
    ng = both_formats(tmp_path, [])[1]
    done = subprocess.run(
        [sys.executable, "-m", "sentinel", "read", str(ng)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert done.stdout == GOLDEN


def test_the_file_extension_does_not_matter(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    classic, ng = both_formats(tmp_path, [])
    named_pcap, named_pcapng = tmp_path / "a.pcap", tmp_path / "b.pcapng"
    named_pcap.write_bytes(ng.read_bytes())
    named_pcapng.write_bytes(classic.read_bytes())
    for path in (named_pcap, named_pcapng):
        assert main(["read", str(path)]) == 0
        assert capsys.readouterr().out == GOLDEN


def test_pcapng_with_an_unsupported_link_type(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "raw.pcapng"
    path.write_bytes(gen_pcap.pcapng_bytes([Packet(1, 3, b"abc")], linktype=101))
    assert main(["read", str(path)]) == 1
    assert "link type 101" in capsys.readouterr().err


def test_a_truncated_pcapng_prints_the_packets_before_the_cut_then_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ng = both_formats(tmp_path, [])[1]
    short = tmp_path / "short.pcapng"
    short.write_bytes(ng.read_bytes()[:-3])
    assert main(["read", str(short)]) == 1
    captured = capsys.readouterr()
    assert captured.out == GOLDEN.rsplit("\n", 2)[0] + "\n"
    assert "truncated pcapng block" in captured.err
    assert main(["flows", str(short)]) == 1
    assert "truncated pcapng block" in capsys.readouterr().err
    assert main(["ids", str(short)]) == 1
    assert "truncated pcapng block" in capsys.readouterr().err


def test_a_damaged_pcapng_start_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "bad.pcapng"
    path.write_bytes(bytes([0x0A, 0x0D, 0x0D, 0x0A]) + bytes(30))
    assert main(["read", str(path)]) == 1
    assert "bad.pcapng" in capsys.readouterr().err
