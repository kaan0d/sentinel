# sentinel

Packet analyzer and rule-based network IDS, written from scratch in Python. The protocol parsers are hand-written with `struct`: no Scapy, dpkt or pyshark. No runtime dependencies.

Work is done in stages, and a stage is finished only when its tests pass and ruff and strict mypy are clean.

## Status

| Stage | What it adds | State |
|-------|--------------|-------|
| 1 | pcap reader/writer, Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP parsers, `read` command | done |
| 2 | DNS, plaintext HTTP, TLS ClientHello (SNI, versions, cipher list) | planned |
| 3 | Flow tracking, TCP stream reassembly, per-flow statistics | planned |
| 4 | Filter language (`tcp and (port 80 or port 443) and not src host 10.0.0.1`) | planned |
| 5 | IDS engine: port scan, SYN flood, ARP spoofing, DNS tunneling, rules, JSON alerts | planned |
| 6 | Live capture (Linux AF_PACKET) | planned |
| 7 | Benchmarks, fuzz tests, CI | planned |

## Install

Python 3.12 or newer.

```
pip install -e ".[dev]"
```

## Usage

Print one tcpdump-style line per packet:

```
python -m sentinel read capture.pcap
```

Generate a small synthetic capture that covers every supported protocol, then read it:

```
python tools/gen_pcap.py demo.pcap
python -m sentinel read demo.pcap
```

```
2023-11-14 22:13:20.000000 ARP, Request who-has 10.0.0.2 tell 10.0.0.1, length 28
2023-11-14 22:13:20.001000 ARP, Reply 10.0.0.2 is-at 02:00:00:00:00:02, length 28
2023-11-14 22:13:20.002000 IP 10.0.0.1 > 10.0.0.2: ICMP echo request, id 1, seq 1, length 40
2023-11-14 22:13:20.003000 IP 10.0.0.2 > 10.0.0.1: ICMP echo reply, id 1, seq 1, length 40
2023-11-14 22:13:20.004000 IP 10.0.0.2 > 10.0.0.1: ICMP destination unreachable, code 3, length 36
2023-11-14 22:13:20.005000 IP 10.0.0.1.40000 > 10.0.0.2.80: Flags [S], seq 1000, win 64240, options [mss 1460,sackOK,TS val 1000 ecr 0,nop,wscale 7], length 0
2023-11-14 22:13:20.006000 IP 10.0.0.2.80 > 10.0.0.1.40000: Flags [S.], seq 5000, ack 1001, win 64240, options [mss 1460,sackOK,TS val 1000 ecr 0,nop,wscale 7], length 0
2023-11-14 22:13:20.007000 IP 10.0.0.1.40000 > 10.0.0.2.80: Flags [.], seq 1001, ack 5001, win 64240, length 0
2023-11-14 22:13:20.008000 IP 10.0.0.1.40000 > 10.0.0.2.80: Flags [P.], seq 1001, ack 5001, win 64240, length 38
2023-11-14 22:13:20.009000 IP 10.0.0.1.40000 > 10.0.0.2.80: Flags [F.], seq 1041, ack 5001, win 64240, length 0
2023-11-14 22:13:20.010000 IP 10.0.0.1.53000 > 10.0.0.2.53: UDP, length 29
2023-11-14 22:13:20.011000 vlan 100, IP 10.0.0.1.53001 > 10.0.0.2.53: UDP, length 29
2023-11-14 22:13:20.012000 IP6 2001:db8::1.41000 > 2001:db8::2.443: Flags [S], seq 1, win 65535, length 0
2023-11-14 22:13:20.013000 IP6 2001:db8::1.53002 > 2001:db8::2.53: UDP, length 29
```

Timestamps are UTC with microsecond precision, so the output does not depend on the machine's time zone. Anomalies and errors are appended to a line as `[...]`, for example `[bad ipv4 header checksum]`.

## Stage 1: pcap I/O and L2-L4 parsers

**pcap.** Classic pcap, read and written in both byte orders and both time units (microsecond and nanosecond magic numbers). Timestamps are kept as integer nanoseconds, so a write-then-read round trip is exact. The reader streams from the file and rejects records with a captured length above 262,144 bytes. A corrupt record raises `PcapError` only after all earlier packets have been yielded.

**Parsers.** Ethernet (with stacked 802.1Q/802.1ad tags), ARP, IPv4, IPv6 (fixed header), TCP (flags, options), UDP and ICMP. Every parser is bounds-checked and never raises on bad input. Each returns a dataclass that carries:

- `error`: the header could not be parsed. Every other field is a default and means nothing.
- `anomalies`: the header parsed, but something is off (bad checksum, truncated capture, inconsistent length). The packet is kept and the oddity is reported.
- `payload`: the bytes after the header, trimmed to the length the header declares.

```python
>>> from sentinel.proto.tcp import parse_tcp
>>> parse_tcp(bytes(12)).error
'truncated tcp header: 12 of 20 bytes'
```

`sentinel.proto.decode.decode(frame)` runs the parsers in order and returns the layers as a tuple, for example `(Ethernet, IPv4, Tcp)`. It stops at the first layer with an error, an unknown protocol or an IP fragment.

**Checksums.** IPv4 header and ICMP checksums are verified. TCP and UDP checksums are verified only when the whole segment was captured, so a packet cut short by the snap length never reports a false bad checksum. Captures taken on the sending host can show bad TCP/UDP checksums because of NIC checksum offload; these are reported as anomalies, not errors.

**Tests.** 106 tests, including a valid, truncated, malformed and random-bytes case per parser, pcap round trips for all four file variants, and fixed-seed fuzzing: every truncation and every single-byte corruption of the generated packets, plus random bytes. All traffic in the repo is synthetic.

**Limits.**

- IPv6: fixed 40-byte header only. Extension headers are not walked and ICMPv6 is not parsed; such packets print as `ip-proto-N`.
- IP fragments are not reassembled.
- ARP: Ethernet/IPv4 only.
- Only link type Ethernet is read.
- VLAN tags keep the VLAN id and drop the priority bits.
- Printed timestamps have microsecond precision.
- Only tested on Python 3.13, and only on synthetic traffic.

## Project layout

```
sentinel/pcap/     pcap reader and writer
sentinel/proto/    parsers (ethernet, arp, ipv4, ipv6, tcp, udp, icmp) and decode()
sentinel/summary.py  tcpdump-style line formatting
sentinel/cli.py    command line entry point
tools/gen_pcap.py  synthetic traffic generator (uses the project's own pcap writer)
tests/             pytest tests
```

## Development

```
pytest
ruff check .
mypy
```
