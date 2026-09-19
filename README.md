# sentinel

Packet analyzer and rule-based network IDS, written from scratch in Python. The protocol parsers are hand-written with `struct`: no Scapy, dpkt or pyshark. No runtime dependencies.

Work is done in stages, and a stage is finished only when its tests pass and ruff and strict mypy are clean.

## Status

| Stage | What it adds | State |
|-------|--------------|-------|
| 1 | pcap reader/writer, Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP parsers, `read` command | done |
| 2 | DNS, plaintext HTTP, TLS ClientHello (SNI, versions, cipher list) | done |
| 3 | Flow tracking, TCP stream reassembly, per-flow statistics, `flows` command | done |
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
```

Timestamps are UTC with microsecond precision, so the output does not depend on the machine's time zone. Anomalies and errors are appended to a line as `[...]`, for example `[bad ipv4 header checksum]`.

Group packets into flows, reassemble the TCP streams and print one line of statistics per flow:

```
python -m sentinel flows capture.pcap
```

`read` looks at one packet at a time. `flows` looks at whole streams, so it handles what `read` cannot: reordered and repeated segments, and messages split across segments. A second demo capture is made for it:

```
python tools/gen_pcap.py --streams streams.pcap
python -m sentinel flows streams.pcap
```

```
tcp 10.0.0.1:44000 > 10.0.0.2:8080: closed, pkts 8/3, bytes 129/40, 0.010000s [1 retransmitted client segment] [1 out-of-order client segment] | -> HTTP: POST /upload HTTP/1.1, host files.test | <- HTTP: HTTP/1.1 200 OK
tcp 10.0.0.1:45000 > 10.0.0.2:8443: established, pkts 4/1, bytes 161/0, 0.004000s [1 out-of-order client segment] | -> TLS ClientHello, sni example.com, versions [TLS 1.3, TLS 1.2], ciphers (15) [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, +12 more]
tcp 10.0.0.1:46000 > 10.0.0.2:53: established, pkts 4/1, bytes 66/0, 0.004000s | -> DNS query 1, A? example.com | -> DNS query 2, AAAA? www.example.com
tcp 10.0.0.1:47000 > 10.0.0.2:80: closing, pkts 5/1, bytes 160/0, 0.005000s [100 client bytes missing]
tcp 10.0.0.1:48000 > 10.0.0.2:22: reset, pkts 1/1, bytes 0/0, 0.001000s
udp 10.0.0.1:53004 > 10.0.0.2:53: pkts 1/1, bytes 33/63, 0.001000s | -> DNS query 4660, A? www.example.com | <- DNS response 4660 NOERROR, A? www.example.com, answers [CNAME example.com, A 192.0.2.1]
# 6 flows, 31 packets in flows, 1 not in a flow
```

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

**One segment at a time.** `read` and `decode()` see one segment at a time (streams are handled by `flows`, stage 3). A DNS-over-TCP message split across segments gets no DNS layer, HTTP headers cut off by a segment are parsed as far as they go with an anomaly, and a ClientHello split across segments is parsed as far as it is present with a `truncated client hello` anomaly.

**Tests.** 162 tests at the end of the stage. Each parser has valid hand-built bytes, every truncation, malformed cases with the exact anomaly text checked, and seeded random bytes. The decode fuzz tests cover the new generated packets. A sabotage run broke 16 lines across stages 1 and 2 on purpose, and every break was caught by at least one test (see stage 3 for the current run).

## Stage 3: flows and TCP stream reassembly

**Flows** (`FlowTable`). Packets are grouped into bidirectional TCP and UDP flows by protocol and the two (address, port) endpoints. The client is whoever sent the SYN. A new flow starts when the same endpoints are used again after the old one ended, when a SYN arrives with a different initial sequence number, or after the flow sat idle (1 hour for TCP, 2 minutes for UDP). Each flow has packet and payload byte counts in each direction, duration, and a TCP state derived from the packets seen (`syn-sent`, `established`, `closing`, `closed`, `reset`, or `midstream` when no SYN was captured). ICMP, ARP, IP fragments and unparsable packets are not flows; they are only counted.

**Reassembly** (`TcpStream`, one per direction). Segments arriving out of order, repeated or overlapping are put back into one byte stream, and sequence numbers may wrap around. Overlapping bytes: the first copy that arrived wins, and a later copy with different bytes is reported as a conflict, since that is how a sender confuses an IDS. Only the contiguous bytes from the start of the stream are returned; a gap is reported as missing bytes, never filled in. Counted per stream: retransmitted segments, out-of-order segments, missing bytes, conflicting overlaps, and bytes not buffered because of a limit.

**Messages from streams.** DNS, HTTP and the TLS ClientHello are parsed from the reassembled streams, so a message split across segments is parsed whole. HTTP messages are read only at message boundaries, using `Content-Length` to skip bodies (parsing stops at a chunked body or one read until close), so a body that contains text like `GET /` is not mistaken for a request. DNS over TCP reads its length-prefixed messages one after another.

**Limits, all counted and shown, never silent.** 1 MiB per stream from its start, 4,096 separate byte ranges per stream, 256 MiB buffered across all streams, 200,000 flows.

**Output.** One line per flow, in the order the flows started, then a `#` footer. The same capture always gives the same text.

**Tests.** 226 tests in total. A property test cuts 300 random payloads into overlapping, duplicated pieces, shuffles them, places the SYN anywhere (including last) and starts sequence numbers near the 32-bit wrap; the stream must equal the payload. The same check runs through `FlowTable` with real packets. A sabotage run now breaks 33 lines across stages 1 to 3 on purpose, and every break is caught by at least one test. While writing these tests a stage 2 bug turned up (an empty line reported as a malformed HTTP header when a segment ended at a line break); it is fixed.

## Limits

- IPv6: fixed 40-byte header only. Extension headers are not walked and ICMPv6 is not parsed; such packets print as `ip-proto-N`.
- IP fragments are not reassembled.
- Reassembly is offline: `data()` is read when the capture is done, not delivered as it arrives. Streams are limited to their first 1 MiB. Overlap handling is first-copy-wins; other operating systems may resolve overlaps differently.
- Flows: TCP and UDP only, VLAN tags are not part of a flow's identity, and a flow idle longer than the timeout is split in two.
- `read` still works one segment at a time, so it can misread what `flows` gets right: a DNS-over-TCP message split across segments is skipped, and a segment from the middle of a stream that starts with a method name such as `GET ` is read as HTTP.
- ARP: Ethernet/IPv4 only. Only link type Ethernet is read.
- VLAN tags keep the VLAN id and drop the priority bits.
- HTTP is HTTP/1.x only. TLS: ClientHello only, no ALPN or fingerprints.
- Printed timestamps have microsecond precision.
- Only tested on Python 3.13, and only on synthetic traffic.

## Project layout

```
sentinel/pcap/     pcap reader and writer
sentinel/proto/    parsers (ethernet, arp, ipv4, ipv6, tcp, udp, icmp, dns, http, tls) and decode()
sentinel/flow/     flow table, TCP stream reassembly, per-flow statistics and messages
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
