# sentinel

[![CI](https://github.com/kaan0d/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/kaan0d/sentinel/actions/workflows/ci.yml)

Packet analyzer and rule-based network IDS in pure Python. All protocol parsers are hand-written with `struct`: no Scapy, dpkt or pyshark, and no runtime dependencies.

Write-ups: [Part 1: the analyzer](https://kaan0d.github.io/posts/sentinel-packet-analyzer) · [Part 2: next level](https://kaan0d.github.io/posts/sentinel-next-level) · [Part 3: real traffic](https://kaan0d.github.io/posts/sentinel-real-world)

## Features

- **Capture files:** classic pcap (both byte orders, µs and ns) and pcapng, detected from the file's magic bytes.
- **Parsers:** Ethernet (stacked 802.1Q/802.1ad), ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP/1.x, TLS ClientHello (SNI, versions, ciphers, JA3). Every parser is bounds-checked and never raises; problems are reported as `error` or `anomalies`. Network strings are escaped before printing.
- **Flows:** bidirectional TCP/UDP flows, TCP reassembly (out-of-order, retransmitted, overlapping, sequence wrap), with conflicting overlaps and gaps reported. DNS, HTTP and TLS are parsed from the reassembled streams.
- **Filter language:** BPF-like (`tcp and (port 80 or port 443) and not src host 10.0.0.1`, `ja3 HASH`, `vlan 100`, `net 10.0.0.0/8`). Parse errors come back as values with a position.
- **IDS:** port scan, SYN flood, ARP spoofing, DNS tunneling, SSH brute force and ICMP tunneling detectors, configured by TOML rules, with JSON or text alerts. All detector state is bounded.
- **Live capture:** Linux `AF_PACKET`, and Windows raw sockets (IPv4 only, no Npcap). Receive only.

## Install

Python 3.12+ (developed on 3.13).

```
pip install -e ".[dev]"
```

## Usage

```
python -m sentinel read capture.pcapng [--filter EXPR]
python -m sentinel flows capture.pcap [--filter EXPR]
python -m sentinel ids capture.pcap [--rules rules/] [--format json|text]
sudo python -m sentinel live eth0 [--filter EXPR] [--write out.pcap] [--count N] [--duration S] [--ids]
python -m sentinel live 192.168.1.20      # Windows, Administrator: interface by IPv4 address
```

`tools/gen_pcap.py` writes synthetic captures: default (every protocol), `--streams`, `--attacks`, `--benign`, `--pcapng`.

```
$ python -m sentinel ids attacks.pcap --format text
2023-11-14T22:13:20.140000Z [medium] port-scan: 10.9.9.1 probed 15 ports on 10.0.0.30 in 0.1s
2023-11-14T22:13:32.099000Z [high] syn-flood: 100 SYNs to 10.0.0.2:80 in 0.1s from 100 sources, 20 completed
2023-11-14T22:13:41.000000Z [high] arp-spoof: 10.0.0.1 moved from 02:aa:00:00:00:01 to 02:ee:00:00:06:66
2023-11-14T22:13:52.450000Z [medium] dns-tunnel: 10.0.5.5 asked for 50 different subdomains of evil-cdn.test in 2.5s
```

Exit codes: `0` success, `1` unreadable capture or capture failure, `2` bad filter, rules or options.

### Rules

```toml
[[rule]]
id = "ssh-scan"
detector = "port_scan"
severity = "high"            # low | medium | high | critical
filter = "dst port 22"       # optional, filter language
distinct_hosts = 5
distinct_ports = 0           # 0 disables the check
window_seconds = 30
```

`--rules` takes a file or a directory. Parameters are typed and range-checked, unknown keys are errors, and all problems are reported at once. Defaults live in `rules/default.toml`.

## Verification

| Check | Result |
|---|---|
| Tests | 942 (plus 6 Linux-root and 5 Windows-admin live tests); ruff and strict mypy clean |
| CI | Python 3.12 and 3.13 on Ubuntu and Windows, including live capture on real interfaces |
| Mutation | 405 deliberate one-line breaks, all caught |
| Fuzzing | 3,000,000 damaged packets and files, 0 failures |
| vs. `tshark` | 10 captures, 68,756 field values, 0 unexplained differences |
| Real traffic | 2.7M packets in 7 third-party captures: every attack capture detected; on a 1 Gbps backbone slice the port-scan sources match an independent `tshark` recount (376/376) |

## Performance

One core, Ryzen 7 5800X, Python 3.13.5, 100,000 small packets (`python -m tools.bench`):

| Stage | packets/s |
|---|---|
| decode | 98,710 |
| `read` (decode + print) | 44,135 |
| `flows` | 59,330 |
| `ids` (all detectors) | 42,033 |
| `live` loop | 27,635–37,716 |

## Limits

- IPv6 extension headers and ICMPv6 are not parsed. IP fragments are not reassembled.
- Reassembly is offline and capped at 1 MiB per stream. Overlaps are resolved first-copy-wins.
- Detectors see packets, not reassembled streams. `ssh_brute_force` counts connections, not failed logins. Hex-encoded DNS tunnels are not caught.
- On backbone traffic the NXDOMAIN check produces false positives (resolvers look like tunnel clients).
- Windows live capture: IPv4 only, no Ethernet header, no drop count.
- Pure Python: a busy network causes kernel drops, which are reported.

## Layout

```
sentinel/pcap/     pcap and pcapng I/O
sentinel/proto/    protocol parsers and decode()
sentinel/flow/     flow table and TCP reassembly
sentinel/filter/   filter lexer, parser, evaluator
sentinel/ids/      detectors, rules, alerts
sentinel/live/     Linux and Windows capture
tools/             gen_pcap, bench, fuzz, compare_tshark
rules/             default rules
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

## License

MIT, see [LICENSE](LICENSE).
