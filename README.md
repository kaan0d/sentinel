# sentinel

[![CI](https://github.com/kaan0d/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/kaan0d/sentinel/actions/workflows/ci.yml)

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
| 7 | Benchmarks, fuzzer, CI | done |

## Install

I developed this project with Python 3.13. It should also work on Python 3.12 and newer (3.12 is the minimum in `pyproject.toml`): CI runs the tests on 3.12 and 3.13, on Linux and Windows, and you are welcome to try it yourself.

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

## Results

| What | Result |
|------|--------|
| Tests | 620 pass here, 6 more need Linux and root; ruff and strict mypy are clean |
| CI | GitHub Actions, 5 jobs green: Python 3.12 and 3.13 on Ubuntu and Windows, and the live capture tests as root on an Ubuntu runner (a real packet socket on the loopback interface) |
| Sabotage | 196 deliberate one-line breaks of the code, every one caught by the tests |
| Fuzzing | 3,000,000 damaged packets and capture files through the whole pipeline (seed 7): 0 failures |
| Speed | 98,710 packets/s to decode, 44,135 to print `read` lines, 42,033 through the detectors, 34,551 through the `live` loop (one desktop CPU core, Python 3.13.5) |
| Demo output | the `read`, `flows` and `ids` blocks above are the real output, checked as golden tests |

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
- On the loopback interface the kernel hands out every packet twice, once leaving and once arriving. The leaving copy is dropped, so each packet appears once. (Checked in CI on a Linux 6.17 runner: a datagram comes out twice with the drop switched off, once with it on.)
- The receive wait is 0.5 s, so a time limit and Ctrl-C are noticed on a quiet network.

**Long runs.** A live capture can meet more sources than a file does. Until this stage the detectors kept one sliding window per source, target or client for ever, so after 100,000 different ones they would have stopped watching new ones. Each table is now kept in order of last use, and a key that has been idle for longer than its window is forgotten (its window would be empty anyway). Found while designing this stage, and tested at the boundary: a key is kept for exactly one window and forgotten one microsecond later. The engine gained `pop_alerts()`, which hands out the alerts raised so far and forgets them, so a run of any length does not keep them all. A packet refused by a full port-scan table used to be counted twice in the state-limit alert (the detector has two tables); it is counted once.

**Tests.** 526 run everywhere, and 4 more run only on Linux as root. The packet socket is replaced by a stand-in that hands out the frames of the generated captures, and the clock replays their timestamps, so the output of `live` must be exactly what `read` and `ids` print for the same capture: the same 13 alerts for the attack capture, printed at the packet that raised them and not at the end. Also tested: `--count`, `--duration` and Ctrl-C, the filter applied before counting and writing, the file readable while the capture runs, packets read back from `--write` equal to the ones captured, every error and its exit code, interface names and link types (against a folder that stands for `/sys/class/net`), the drop counter, random and cut-off frames through both modes, and the detector tables at the window edge. `tests/test_live_linux.py` captures a UDP datagram on the loopback interface with a real socket. It is skipped elsewhere; run it with `sudo python -m pytest tests/test_live_linux.py`. It passed on a GitHub Ubuntu runner (see Stage 7).

## Stage 7: benchmarks, fuzzer, CI

**Benchmarks.** `python -m tools.bench [--packets N] [--repeat R] [--json]` measures how many packets per second each part handles. The traffic is the four generated captures one after the other, repeated with the time moved forward, so the workload is the same everywhere (about 65 bytes per packet on average: many small packets, as in the demo captures). Each stage runs `--repeat` times and the fastest run is kept. Every stage must handle every packet, or the run stops with an error instead of printing a number.

Measured on AMD64 Family 25 Model 33 Stepping 2, AuthenticAMD, 16 logical CPUs, Windows-11-10.0.26200-SP0, Python 3.13.5, 100,000 packets, fastest of 3 (one core is used; nothing runs in parallel):

| Stage | packets/s | µs per packet | MB/s |
|-------|-----------|---------------|------|
| pcap read | 1,564,676 | 0.6 | 101.9 |
| pcap write | 2,567,763 | 0.4 | 167.2 |
| pcap write, flushed after every packet | 357,768 | 2.8 | 23.3 |
| decode | 98,710 | 10.1 | 6.4 |
| read: decode and print a line | 44,135 | 22.7 | 2.9 |
| filter: decode and match | 65,206 | 15.3 | 4.2 |
| flows: decode, reassemble, print | 59,330 | 16.9 | 3.9 |
| ids: decode and run 4 detectors | 42,033 | 23.8 | 2.7 |
| live loop, printing lines | 34,551 | 28.9 | 2.2 |
| live loop, running the detectors | 37,716 | 26.5 | 2.5 |
| live loop, saving to a file | 27,635 | 36.2 | 1.8 |

Reading the table:

- Decoding is about 10 µs per packet, and no single function dominates: in a profile of `decode`, IPv4 parsing, the dispatcher (`decode` itself), building `ipaddress` objects, TCP parsing and the checksums take 8 to 13% each, and the rest is spread thin. The stages above `decode` add their own work on top of it: printing a line costs about 13 µs more, the four detectors about 14 µs.
- Every packet the `live` loop handles costs about 27 to 36 µs, so on this machine it keeps up with about 27,000 to 38,000 small packets per second, about 2 MB/s of 65-byte packets. Faster traffic is dropped by the kernel, and the summary line at the end says how many. Speed was measured, not tuned: nothing was changed to make a number better.
- Flushing after every packet costs about 2.4 µs per packet (2.8 against 0.4 µs to write). That is a tenth of the `live` loop, and it buys a capture file that is readable even if the process is killed.
- Numbers depend on the machine. Run the tool on yours. CI runs a small version on GitHub's runners (4 logical CPUs, 20,000 packets, one run each, so noisier):

| Stage (packets/s) | my machine | Ubuntu, Python 3.12 | Ubuntu, Python 3.13 | Windows, Python 3.12 | Windows, Python 3.13 |
|---|---|---|---|---|---|
| decode | 98,710 | 59,831 | 56,736 | 115,977 | 61,334 |
| read: decode and print a line | 44,135 | 33,416 | 26,335 | 67,282 | 28,174 |
| ids: decode and run 4 detectors | 42,033 | 28,788 | 25,198 | 57,074 | 26,715 |
| live loop, printing lines | 34,551 | 27,389 | 21,929 | 55,896 | 22,174 |
| pcap write, flushed after every packet | 357,768 | 369,740 | 406,820 | 483,074 | 118,459 |

  The runners are not one machine: the Windows 3.12 log reports a newer AMD processor (family 26, against 25 in the other Windows log) and is almost twice as fast as the Windows 3.13 run, so compare within a column and only roughly across them. The Ubuntu runners and one Windows runner are slower than my machine at decoding, the other Windows runner is faster. Flushing after every packet adds 1.6 to 7.7 µs per packet across the four runs (2.4 µs on my machine), so that cost varies a lot with the machine.

**Fuzzer.** `python -m tools.fuzz [--seed S] [--iterations N]` damages packets from the generated captures (a flipped bit, a length field set to an extreme, a cut, a piece deleted or repeated, the end of another packet spliced on; one to three damages each) and sends them through the decoder, the summary line, eight filters, one flow table and one detector engine that live for the whole run. Every fifth input is a small capture file, damaged the same way, read by the pcap reader. A failure is an exception (only `PcapError` may come out of the reader), a summary line that is not one line of printable ASCII, or an alert that is not one line of JSON. The same seed makes the same inputs, and a failing packet is printed as hex that `--replay` runs on its own. A run of 3,000,000 inputs (seed 7, 2,400,000 packets and 600,000 capture files) found nothing. That is a result about these inputs and these checks, not a proof: the damages are random, and the checks are only the ones listed. To see what the fuzzer is worth, each of the 148 deliberate breaks of stages 1 to 6 was applied to the code and the fuzzer run alone on it (30,000 inputs): it caught 2 (a control character in a printed line, and a `KeyError` in the SYN flood detector). The tests catch all 148. The fuzzer finds crashes and malformed output, not wrong answers.

**CI.** `.github/workflows/ci.yml` runs ruff, `ruff format --check`, mypy strict, the tests, 200,000 fuzz inputs (the seed is the run number, so a failure can be repeated) and a small benchmark, on Python 3.12 and 3.13, on Linux and Windows. A second job runs `tests/test_live_linux.py` as root on a Linux runner and fails if those tests were skipped, so it is where the real packet socket is used for the first time. It took four pushes to get all five jobs green. The first two ran no job at all: a step name contained `: `, which YAML reads as another key, so GitHub refused the file (`tests/test_ci.py` now checks for that mistake). Then Python 3.12 on Windows failed one test, which compared a wait against the 0.05 s time limit without allowing for float rounding on a large clock reading (the code was right; the test now has a tolerance of a microsecond). After that every job passed, including the one that runs `tests/test_live_linux.py` as root: on the loopback interface of a Linux runner, the real packet socket captured a UDP datagram, decoded it, and the command line saved it. Later runs of that job also showed that the datagram is captured exactly once, and exactly twice when the copy filter is switched off (5 passed and 1 skipped: the test for running without root skips itself when the job is root, as it should). `tests/test_ci.py` also checks that the workflow runs every command listed under Development below, in order, on Python 3.12 and 3.13. The fuzzer ran 200,000 inputs on each of the four Python and system combinations (the seed is the run number: 3 and 4): 0 failures.

**Tests.** 626 in total (620 run here; 6 need Linux and root). The benchmark: the corpus is the four captures in order with each capture starting one second after the last ended, repeats keep the time moving forward, the timer keeps the fastest run, a stage that handles the wrong number of packets is an error, the flushed writer really is flushed (the file on disk is checked before each packet), the live stages print nothing and restore the command. The fuzzer: every damage checked against its definition (including brute force over every possible slice), the same seed giving the same run, every kind of failure detected with a substituted component that misbehaves (an exception, a summary with a control character, a filter that does not answer, an alert that is not JSON, a flow line with a line break, a pcap reader that raises something other than `PcapError`), and every option.

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
- Live capture: Linux only, and only interfaces of link type Ethernet or loopback (no Wi-Fi monitor mode, no tunnels). The interface is not put in promiscuous mode, so it sees what it would receive anyway (or what a mirror port sends it). Frames are as the kernel gives them: packets sent by this machine often have checksums that are not filled in yet (the network card does it), so they can show `[bad ... checksum]`, and a VLAN tag may already be removed. `flows` does not work on a live capture. The state-limit alert of a detector is printed when the run ends, not while it runs. The tests that use a real interface (Linux, root) passed once, in CI, on the loopback interface of a Linux runner. Not checked: a real network card, and whether a VLAN tag was already removed. A loopback datagram was captured exactly once, and exactly twice with the copy filter switched off, so the kernel does give two copies and the filter is needed. Everything else was tested with a stand-in for the socket.
- Printed timestamps have microsecond precision.
- Developed with Python 3.13 on Windows. CI also ran the tests on Python 3.12 and 3.13, on Ubuntu and Windows, and they passed. Only synthetic traffic, and no real network apart from the loopback test.
- Speed: pure Python, one core. The `live` loop handles roughly 30,000 small packets per second on the machine above, so a busy network will make the kernel drop packets.
- The fuzzer only checks that nothing raises and that output is well formed. It cannot tell a wrong parse from a right one.

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
tools/bench.py     benchmarks: packets per second for every stage
tools/fuzz.py      fuzzer: damaged packets and capture files through the whole pipeline
.github/workflows/ci.yml  CI: lint, format, types, tests, fuzz, benchmark, live capture as root
tests/             pytest tests
```

## Development

```
python -m pytest
ruff check .
ruff format --check .
mypy
python -m tools.fuzz
python -m tools.bench
```
