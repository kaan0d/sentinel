# sentinel

Packet analyzer and rule-based network IDS, written from scratch in Python. The protocol parsers are hand-written with `struct`: no Scapy, dpkt or pyshark. No runtime dependencies.

Work is done in stages, and a stage is finished only when its tests pass and ruff and strict mypy are clean.

## Status

| Stage | What it adds | State |
|-------|--------------|-------|
| 1 | pcap reader/writer, Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP parsers, `read` command | done |
| 2 | DNS, plaintext HTTP, TLS ClientHello (SNI, versions, cipher list) | done |
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
2023-11-14 22:13:20.008000 IP 10.0.0.1.40000 > 10.0.0.2.80: Flags [P.], seq 1001, ack 5001, win 64240, length 38: HTTP: GET / HTTP/1.1, host example.test
2023-11-14 22:13:20.009000 IP 10.0.0.1.40000 > 10.0.0.2.80: Flags [F.], seq 1041, ack 5001, win 64240, length 0
2023-11-14 22:13:20.010000 IP 10.0.0.1.53000 > 10.0.0.2.53: UDP, length 29: DNS query 48879, A? example.com
2023-11-14 22:13:20.011000 vlan 100, IP 10.0.0.1.53001 > 10.0.0.2.53: UDP, length 29: DNS query 48879, A? example.com
2023-11-14 22:13:20.012000 IP6 2001:db8::1.41000 > 2001:db8::2.443: Flags [S], seq 1, win 65535, length 0
2023-11-14 22:13:20.013000 IP6 2001:db8::1.53002 > 2001:db8::2.53: UDP, length 29: DNS query 48879, A? example.com
2023-11-14 22:13:20.014000 IP 10.0.0.1.53003 > 10.0.0.2.53: UDP, length 33: DNS query 4660, A? www.example.com
2023-11-14 22:13:20.015000 IP 10.0.0.2.53 > 10.0.0.1.53003: UDP, length 63: DNS response 4660 NOERROR, A? www.example.com, answers [CNAME example.com, A 192.0.2.1]
2023-11-14 22:13:20.016000 IP 10.0.0.1.42000 > 10.0.0.2.53: Flags [P.], seq 1, ack 1, win 64240, length 31: DNS query 17185, AAAA? example.com
2023-11-14 22:13:20.017000 IP 10.0.0.2.80 > 10.0.0.1.40000: Flags [P.], seq 5001, ack 1041, win 64240, length 77: HTTP: HTTP/1.1 200 OK
2023-11-14 22:13:20.018000 IP 10.0.0.1.43000 > 10.0.0.2.443: Flags [P.], seq 1, ack 1, win 64240, length 161: TLS ClientHello, sni example.com, versions [TLS 1.3, TLS 1.2], ciphers (15) [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, +12 more]
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

**Tests.** 106 tests at the end of the stage, including a valid, truncated, malformed and random-bytes case per parser, pcap round trips for all four file variants, and fixed-seed fuzzing: every truncation and every single-byte corruption of the generated packets, plus random bytes. All traffic in the repo is synthetic.

## Stage 2: DNS, HTTP and TLS ClientHello

`decode()` now goes one layer further, for example `(Ethernet, IPv4, Udp, Dns)` or `(Ethernet, IPv4, Tcp, TlsClientHello)`. The new parsers follow the same contract as before: they never raise, and report trouble through `error` and `anomalies`.

**DNS** (`parse_dns`). Header flags, questions, and answer/authority/additional records, with compression pointers followed safely: a pointer must point backward into the message, at most 32 are followed, and names are capped at 255 bytes. Record data is decoded to text for A, AAAA, NS, CNAME, PTR, MX and TXT, and the raw bytes are always kept. Only an unreadable header is an `error`; a broken record ends parsing as an anomaly and keeps the records before it. Detected by port 53, over UDP, or over TCP when the whole length-prefixed message is in one segment.

**HTTP** (`parse_http`). HTTP/1.x request and status lines, headers (case-insensitive `header()` lookup) and the body bytes present in the segment. Detected by content (a request method or `HTTP/1.` at the start of the payload), so any port works. Limits: 8 KB start line, 16 KB of headers, 100 headers. Conflicting or non-numeric `Content-Length` values are reported as anomalies.

**TLS ClientHello** (`parse_client_hello`). Server name (SNI), the versions offered, the cipher suite list and the extension ids. Detected by content. GREASE values are kept in the data and hidden in the printed line.

**Safe to print.** Names, header values and the SNI come from the network, so parsers escape them: control and escape characters become `\xNN`, and DNS labels use RFC 4343 escapes. A hostile packet cannot inject terminal escape sequences into the output.

**One segment at a time.** There is no TCP stream reassembly yet (stage 3). A DNS-over-TCP message split across segments gets no DNS layer, HTTP headers cut off by a segment are parsed as far as they go with an anomaly, and a ClientHello split across segments is parsed as far as it is present with a `truncated client hello` anomaly.

**Tests.** 162 tests in total. Each parser has valid hand-built bytes, every truncation, malformed cases with the exact anomaly text checked, and seeded random bytes. The decode fuzz tests cover the new generated packets. A sabotage run broke 16 lines across stages 1 and 2 on purpose, and every break was caught by at least one test.

## Limits

- IPv6: fixed 40-byte header only. Extension headers are not walked and ICMPv6 is not parsed; such packets print as `ip-proto-N`.
- IP fragments are not reassembled, and TCP streams are not reassembled (stage 3).
- ARP: Ethernet/IPv4 only. Only link type Ethernet is read.
- VLAN tags keep the VLAN id and drop the priority bits.
- DNS: a TCP message split across segments is skipped. HTTP is HTTP/1.x only. TLS: ClientHello only, no ALPN or fingerprints.
- A TCP segment from the middle of a stream that starts with a method name such as `GET ` would be read as HTTP.
- Printed timestamps have microsecond precision.
- Only tested on Python 3.13, and only on synthetic traffic.

## Project layout

```
sentinel/pcap/     pcap reader and writer
sentinel/proto/    parsers (ethernet, arp, ipv4, ipv6, tcp, udp, icmp, dns, http, tls) and decode()
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
