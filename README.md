# sentinel

Packet analyzer and rule-based network IDS, written from scratch in Python. The protocol parsers are hand-written with `struct`: no Scapy, dpkt or pyshark. No runtime dependencies.

Work is done in stages, and a stage is finished only when its tests pass and ruff and strict mypy are clean.

## Status

| Stage | What it adds | State |
|-------|--------------|-------|
| 1 | pcap reader/writer, Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP parsers, `read` command | done |
| 2 | DNS, plaintext HTTP, TLS ClientHello (SNI, versions, cipher list) | done |
| 3 | Flow tracking, TCP stream reassembly, per-flow statistics, `flows` command | done |
| 4 | Filter language (`tcp and (port 80 or port 443) and not src host 10.0.0.1`), `--filter` option | done |
| 5 | IDS engine: port scan, SYN flood, ARP spoofing, DNS tunneling, rules, JSON alerts, `ids` command | done |
| 6 | Live capture (Linux AF_PACKET), `live` command | done |
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

Only the packets that match a filter (see the filter language below):

```
python -m sentinel read demo.pcap --filter "tcp and (port 80 or port 443) and not src host 10.0.0.1"
```

```
2023-11-14 22:13:20.006000 IP 10.0.0.2.80 > 10.0.0.1.40000: Flags [S.], seq 5000, ack 1001, win 64240, options [mss 1460,sackOK,TS val 1000 ecr 0,nop,wscale 7], length 0
2023-11-14 22:13:20.012000 IP6 2001:db8::1.41000 > 2001:db8::2.443: Flags [S], seq 1, win 65535, length 0
2023-11-14 22:13:20.017000 IP 10.0.0.2.80 > 10.0.0.1.40000: Flags [P.], seq 5001, ack 1039, win 64240, length 77: HTTP: HTTP/1.1 200 OK
```

A filter that does not parse is reported with a caret under the problem, and the exit code is 2:

```
$ python -m sentinel read demo.pcap -f "tcp and port http"
sentinel: invalid filter: expected a port number (0-65535), got 'http'
  tcp and port http
               ^
```

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

Run the detectors over a capture and print alerts, one JSON object per line:

```
python tools/gen_pcap.py --attacks attacks.pcap
python -m sentinel ids attacks.pcap --format text
python -m sentinel ids attacks.pcap --rules rules/
```

```
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
```

The same capture with `--format json` (the default) gives one object per alert with the fields `ts`, `ts_ns`, `rule`, `detector`, `severity`, `src`, `dst`, `message` and `evidence`. `python tools/gen_pcap.py --benign benign.pcap` writes busy but harmless traffic, and `ids` prints nothing for it.

Capture from a network interface (Linux, needs root, listens only). Use it only on a network you own or may monitor:

```
sudo python -m sentinel live eth0
sudo python -m sentinel live eth0 --filter "tcp and port 443" --write web.pcap --duration 60
sudo python -m sentinel live eth0 --ids --format text
```

The first prints the same lines as `read`, as the packets arrive. The last runs the detectors and prints each alert when it is raised. Ctrl-C stops the capture, and a summary line goes to stderr: `# 812 packets, 3 dropped by the kernel`.

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

## Stage 4: filter language

`--filter EXPR` (or `-f`) works on both `read` and `flows`. It selects packets before anything else, so `flows` builds its flows from the matching packets only. Keeping whole conversations works with endpoint filters (`host`, `port`, `tcp`). A filter that drops some packets of a connection (for example `http`) leaves a partial flow, and reassembly reports the missing bytes.

**Language.**

| Word | Matches |
|------|---------|
| `ip`, `ip6`, `arp`, `tcp`, `udp`, `icmp` | packets that have that layer |
| `dns`, `http`, `tls` | packets with that application layer (TLS means a ClientHello) |
| `vlan`, `vlan 100` | any VLAN tag, or a tag with that id (any tag of a stacked pair) |
| `host 10.0.0.1`, `host 2001:db8::1` | that address as source or destination (also ARP sender and target) |
| `net 10.0.0.0/8` | an address inside that network |
| `port 80`, `portrange 5000-6000` | TCP or UDP port |
| `src ...`, `dst ...` before `host`, `net`, `port` or `portrange` | only that side |
| `not`, `!` / `and`, `&&` / `or`, `||`, `( )` | combine; `not` binds tighter than `and`, which binds tighter than `or` |

A protocol followed by a qualifier is an implicit `and`: `tcp port 80` is `tcp and port 80`. Keywords are case-insensitive. Host names are not looked up; use addresses.

**Errors are values.** `parse_filter(text)` never raises. It returns a `Filter` whose `error` and `position` say what is wrong and where, and `Filter.matches(layers)` is false for a filter with an error. The limits: nesting of 100 levels, 1,000 tokens, numbers of up to 10 digits, so a hostile or accidental filter cannot exhaust the parser.

**Meaning, in detail.** A protocol word is true when that layer is present, even if it has an error (a broken TCP header is still a TCP packet). `host`, `net` and `port` need an intact header, so an errored layer never matches (its default zeros do not match `port 0` or `host 0.0.0.0`). IPv4 and IPv6 never match each other's networks. IP fragments are not decoded past the IP header, so they match `ip` and `host` but not `tcp` or `port`.

**Tests.** 331 tests in total. The evaluator is compared with hand-written predicates for 34 primitives over an 80-packet corpus (both demo captures, fragments, cut headers, stacked VLAN tags, garbage), and 400 random `and`/`or`/`not` combinations are compared with Python's own logic. The parser is tested with exact trees, 31 error messages and positions, random trees that must print and parse back to the same tree, and thousands of random texts that must never raise. A sabotage run now breaks 59 lines across stages 1 to 4 on purpose, and every break is caught by at least one test.

## Stage 5: IDS engine

`python -m sentinel ids capture.pcap [--rules PATH] [--format json|text]` runs the detectors over a capture, in capture order, and prints an alert for each finding. Detectors work on packets and only see intact layers. Alerts are sorted by the time of the packet that raised them, then by the rule's position, so the same capture and rules always give the same output.

**Detectors.**

| Detector | Looks for | Default | Expect false positives from |
|----------|-----------|---------|-----------------------------|
| `port_scan` | one source probing many ports of one host, or one port of many hosts; TCP SYN and the stealth scans (no flags, FIN only, FIN+PSH+URG) count | 15 ports or 30 hosts within 10 s | vulnerability scanners you run yourself |
| `syn_flood` | many SYNs to one address and port, few completed by the handshake's ACK | 100 SYNs within 1 s, at most 30% completed | a burst of connections to a server that then stops answering |
| `arp_spoof` | an IP address that moves to another MAC address; an ARP sender MAC that differs from the Ethernet source; address probes from 0.0.0.0 are ignored | any change | a replaced network card, a failover pair |
| `dns_tunnel` | a name of 100+ characters or a label of 50+; a random-looking subdomain (4.2 bits per character, 40+ characters); 50 different subdomains of one domain in 60 s; 20 "no such name" answers to one client in 60 s | as listed | long generated names of some CDNs and security products |

Entropy alone does not separate tunnels from readable names: base32 and base64 subdomains land mostly above 4.2 bits per character, hex-encoded ones stay below it, and long readable hostnames reach about 4.1. The three other DNS signals exist for that reason.

**Rules.** TOML files, read with the standard library. `--rules` takes a file or a directory (every `*.toml`, in name order); without it the built-in defaults are used, and `rules/default.toml` spells them out (a test keeps the two equal).

```toml
[[rule]]
id = "ssh-scan"              # required, unique: a-z, 0-9, '-' and '_'
detector = "port_scan"       # required
severity = "high"            # optional: low, medium, high or critical
enabled = true               # optional
filter = "dst port 22"       # optional: the detector only sees packets that match (stage 4 language)
distinct_hosts = 5           # the rest are the detector's own parameters
distinct_ports = 0           # 0 turns a check off
window_seconds = 30
```

Loading never raises. Every problem in every file is reported at once, with the file and rule number, and the command exits with 2. Parameters are typed and range-checked, and an unknown key is an error, so a typo cannot silently keep a default. Several rules may use the same detector.

**Alerts.** One JSON object per line with sorted keys and ASCII only: `ts`, `ts_ns`, `rule`, `detector`, `severity`, `src`, `dst`, `message` and `evidence` (the numbers behind the alert). `--format text` prints `time [severity] rule: message`. One attack gives one alert per source, target and window, not one per packet.

**Exit codes.** 0 when the capture was read, with or without alerts; 1 when the capture is unreadable or corrupt (the alerts raised before the corrupt record are still printed); 2 for bad rules.

**Limits.** Every detector keeps bounded state (100,000 keys, capped sliding windows, oldest half-open handshakes dropped first). When a limit forces a packet to be ignored, the run ends with a low-severity alert that says how many.

**Tests.** 441 tests in total. `tools/gen_pcap.py --benign` writes 647 packets kept just below every threshold (150 completed handshakes in one second, 14 ports of one host, 25 hosts on one port, 40 subdomains, long readable names, repeated ARP announcements): it must raise no alert. `--attacks` writes one of each attack and must raise exactly 13 alerts, listed one by one in the tests. Every detector is tested one below its threshold, at it, at the window edge and switched off, and the engine is fuzzed with random frames, truncations, corruptions and scrambled timestamps.

## Stage 6: live capture

`python -m sentinel live INTERFACE [--filter EXPR] [--write FILE] [--count N] [--duration SECONDS] [--ids [--rules PATH] [--format json|text]]` reads Ethernet frames from a Linux packet socket (`AF_PACKET`) and sends them through the pipeline the other commands use: decode, filter, then print (or, with `--ids`, run the detectors). The socket only receives; nothing is ever sent. Opening it needs root or the `CAP_NET_RAW` capability, and the interface is always named on the command line (there is no default).

**Output.** One line per packet, in the `read` format, or with `--ids` one alert as soon as it is raised. Every line is flushed, so a pipe sees it at once. `--write FILE` saves the packets that match the filter as a pcap file, flushed after every packet, so a capture that is killed still leaves a readable file. `--count N` stops after N matching packets, `--duration S` after S seconds, and Ctrl-C at any time. When it ends, one line goes to stderr with the number of packets and, if the kernel reports any, how many it dropped because the program was too slow. With `--ids`, alerts about detector state limits are printed at that point.

**Exit codes.** 0 when the capture ran and ended normally, including by Ctrl-C; 1 when it cannot start (no such interface, not Ethernet, not Linux, no permission, a `--write` file that cannot be opened) or fails while running; 2 for a bad filter, bad rules or bad options. All three are checked before the interface is opened.

**Details.**

- Timestamps are the system clock at the moment the program receives a packet, as integer nanoseconds. Written to a pcap file they are microseconds, like every other capture this project writes.
- The interface must be Ethernet (`/sys/class/net/NAME/type` is 1) or loopback. The name is checked with the kernel's own rules before it is used in a path.
- On the loopback interface the kernel hands out every packet twice, once leaving and once arriving. The leaving copy is dropped, so each packet appears once.
- The receive wait is 0.5 s, so a time limit and Ctrl-C are noticed on a quiet network.

**Long runs.** A live capture can meet more sources than a file does. Until this stage the detectors kept one sliding window per source, target or client for ever, so after 100,000 different ones they would have stopped watching new ones. Each table is now kept in order of last use, and a key that has been idle for longer than its window is forgotten (its window would be empty anyway). Found while designing this stage, and tested at the boundary: a key is kept for exactly one window and forgotten one microsecond later. The engine gained `pop_alerts()`, which hands out the alerts raised so far and forgets them, so a run of any length does not keep them all. A packet refused by a full port-scan table used to be counted twice in the state-limit alert (the detector has two tables); it is counted once.

**Tests.** 526 run everywhere, and 4 more run only on Linux as root. The packet socket is replaced by a stand-in that hands out the frames of the generated captures, and the clock replays their timestamps, so the output of `live` must be exactly what `read` and `ids` print for the same capture: the same 13 alerts for the attack capture, printed at the packet that raised them and not at the end. Also tested: `--count`, `--duration` and Ctrl-C, the filter applied before counting and writing, the file readable while the capture runs, packets read back from `--write` equal to the ones captured, every error and its exit code, interface names and link types (against a folder that stands for `/sys/class/net`), the drop counter, random and cut-off frames through both modes, and the detector tables at the window edge. `tests/test_live_linux.py` captures a UDP datagram on the loopback interface with a real socket. It is skipped elsewhere; run it with `sudo python -m pytest tests/test_live_linux.py`.

## Limits

- IPv6: fixed 40-byte header only. Extension headers are not walked and ICMPv6 is not parsed; such packets print as `ip-proto-N`.
- IP fragments are not reassembled.
- Reassembly is offline: `data()` is read when the capture is done, not delivered as it arrives. Streams are limited to their first 1 MiB. Overlap handling is first-copy-wins; other operating systems may resolve overlaps differently.
- Flows: TCP and UDP only, VLAN tags are not part of a flow's identity, and a flow idle longer than the timeout is split in two.
- `read` still works one segment at a time, so it can misread what `flows` gets right: a DNS-over-TCP message split across segments is skipped, and a segment from the middle of a stream that starts with a method name such as `GET ` is read as HTTP.
- Filters: no host names, no `ether host`, `len`, byte offsets or TCP flag words. `dns`, `http` and `tls` match per packet (a segment that starts a message), not per connection. `flows --filter` filters packets, not whole flows.
- ARP: Ethernet/IPv4 only. Only link type Ethernet is read.
- VLAN tags keep the VLAN id and drop the priority bits.
- HTTP is HTTP/1.x only. TLS: ClientHello only, no ALPN or fingerprints.
- IDS: rules are TOML only (no YAML). Detectors see one packet at a time, not reassembled streams. Only Ethernet, IPv4/IPv6, TCP, UDP, ARP and DNS fields are used. DNS tunneling is judged by name length, label length, entropy, subdomain count and NXDOMAIN count; hex-encoded tunnels are not caught, and long readable names stay just under the entropy threshold on purpose.
- Live capture: Linux only, and only interfaces of link type Ethernet or loopback (no Wi-Fi monitor mode, no tunnels). The interface is not put in promiscuous mode, so it sees what it would receive anyway (or what a mirror port sends it). Frames are as the kernel gives them: packets sent by this machine often have checksums that are not filled in yet (the network card does it), so they can show `[bad ... checksum]`, and a VLAN tag may already be removed. `flows` does not work on a live capture. The state-limit alert of a detector is printed when the run ends, not while it runs. The tests that use a real interface need Linux and root, and have not been run yet: everything else was tested with a stand-in for the socket.
- Printed timestamps have microsecond precision.
- Only tested on Python 3.13, and only on synthetic traffic.

## Project layout

```
sentinel/pcap/     pcap reader and writer
sentinel/proto/    parsers (ethernet, arp, ipv4, ipv6, tcp, udp, icmp, dns, http, tls) and decode()
sentinel/flow/     flow table, TCP stream reassembly, per-flow statistics and messages
sentinel/filter/   filter language: lexer, parser, evaluator
sentinel/ids/      IDS engine: detectors, sliding window, rule loading, alerts
sentinel/live/     live capture from a Linux packet socket
rules/             default.toml, one rule per detector
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
