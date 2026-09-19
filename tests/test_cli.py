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
2023-11-14 22:13:20.018000 IP 10.0.0.1.43000 > 10.0.0.2.443: Flags [P.], seq 1, ack 1, win 64240, length 161: TLS ClientHello, sni example.com, versions [TLS 1.3, TLS 1.2], ciphers (15) [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, +12 more]
"""


SAMPLE_FLOWS = """\
tcp 10.0.0.1:40000 > 10.0.0.2:80: closing, pkts 4/2, bytes 38/77, 0.012000s | -> HTTP: GET / HTTP/1.1, host example.test | <- HTTP: HTTP/1.1 200 OK
udp 10.0.0.1:53000 > 10.0.0.2:53: pkts 1/0, bytes 29/0, 0.000000s | -> DNS query 48879, A? example.com
udp 10.0.0.1:53001 > 10.0.0.2:53: pkts 1/0, bytes 29/0, 0.000000s | -> DNS query 48879, A? example.com
tcp [2001:db8::1]:41000 > [2001:db8::2]:443: syn-sent, pkts 1/0, bytes 0/0, 0.000000s
udp [2001:db8::1]:53002 > [2001:db8::2]:53: pkts 1/0, bytes 29/0, 0.000000s | -> DNS query 48879, A? example.com
udp 10.0.0.1:53003 > 10.0.0.2:53: pkts 1/1, bytes 33/63, 0.001000s | -> DNS query 4660, A? www.example.com | <- DNS response 4660 NOERROR, A? www.example.com, answers [CNAME example.com, A 192.0.2.1]
tcp 10.0.0.1:42000 > 10.0.0.2:53: midstream, pkts 1/0, bytes 31/0, 0.000000s [client stream start not captured] | -> DNS query 17185, AAAA? example.com
tcp 10.0.0.1:43000 > 10.0.0.2:443: midstream, pkts 1/0, bytes 161/0, 0.000000s [client stream start not captured] | -> TLS ClientHello, sni example.com, versions [TLS 1.3, TLS 1.2], ciphers (15) [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, +12 more]
# 8 flows, 14 packets in flows, 5 not in a flow
"""

STREAM_FLOWS = """\
tcp 10.0.0.1:44000 > 10.0.0.2:8080: closed, pkts 8/3, bytes 129/40, 0.010000s [1 retransmitted client segment] [1 out-of-order client segment] | -> HTTP: POST /upload HTTP/1.1, host files.test | <- HTTP: HTTP/1.1 200 OK
tcp 10.0.0.1:45000 > 10.0.0.2:8443: established, pkts 4/1, bytes 161/0, 0.004000s [1 out-of-order client segment] | -> TLS ClientHello, sni example.com, versions [TLS 1.3, TLS 1.2], ciphers (15) [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, +12 more]
tcp 10.0.0.1:46000 > 10.0.0.2:53: established, pkts 4/1, bytes 66/0, 0.004000s | -> DNS query 1, A? example.com | -> DNS query 2, AAAA? www.example.com
tcp 10.0.0.1:47000 > 10.0.0.2:80: closing, pkts 5/1, bytes 160/0, 0.005000s [100 client bytes missing]
tcp 10.0.0.1:48000 > 10.0.0.2:22: reset, pkts 1/1, bytes 0/0, 0.001000s
udp 10.0.0.1:53004 > 10.0.0.2:53: pkts 1/1, bytes 33/63, 0.001000s | -> DNS query 4660, A? www.example.com | <- DNS response 4660 NOERROR, A? www.example.com, answers [CNAME example.com, A 192.0.2.1]
# 6 flows, 31 packets in flows, 1 not in a flow
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
