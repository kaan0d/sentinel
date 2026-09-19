"""Generate a small synthetic pcap covering every Stage 1 protocol.

    python tools/gen_pcap.py out.pcap

The builders are also used by the tests as known-good packet fixtures. All addresses are
private or documentation ranges; nothing here comes from real traffic.
"""

import argparse
import struct
from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from sentinel.pcap import Packet, PcapWriter
from sentinel.proto import tcp
from sentinel.proto.checksum import internet_checksum, pseudo_header
from sentinel.proto.ethernet import ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")
MAC_BROADCAST = b"\xff" * 6
MAC_ZERO = bytes(6)
IP_A = IPv4Address("10.0.0.1")
IP_B = IPv4Address("10.0.0.2")
IP6_A = IPv6Address("2001:db8::1")
IP6_B = IPv6Address("2001:db8::2")

_MIN_FRAME = 60  # Ethernet minimum without FCS; shorter frames are zero-padded on the wire


def eth_frame(
    dst: bytes, src: bytes, ethertype: int, payload: bytes, *, vlan: int | None = None
) -> bytes:
    tag = struct.pack("!HH", ETHERTYPE_VLAN, vlan) if vlan is not None else b""
    return (dst + src + tag + struct.pack("!H", ethertype) + payload).ljust(_MIN_FRAME, b"\0")


def arp_packet(op: int, sha: bytes, spa: IPv4Address, tha: bytes, tpa: IPv4Address) -> bytes:
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, sha, spa.packed, tha, tpa.packed)


def ipv4_packet(
    src: IPv4Address,
    dst: IPv4Address,
    proto: int,
    payload: bytes,
    *,
    ident: int = 1,
    ttl: int = 64,
    flags_frag: int = 0x4000,
    options: bytes = b"",
) -> bytes:
    hlen = 20 + len(options)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | hlen // 4,
        0,
        hlen + len(payload),
        ident,
        flags_frag,
        ttl,
        proto,
        0,
        src.packed,
        dst.packed,
    )
    header += options
    csum = struct.pack("!H", internet_checksum(header))
    return header[:10] + csum + header[12:] + payload


def ipv6_packet(
    src: IPv6Address, dst: IPv6Address, next_header: int, payload: bytes, *, hop_limit: int = 64
) -> bytes:
    header = struct.pack(
        "!IHBB16s16s", 6 << 28, len(payload), next_header, hop_limit, src.packed, dst.packed
    )
    return header + payload


def tcp_segment(
    src: IPv4Address | IPv6Address,
    dst: IPv4Address | IPv6Address,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    *,
    window: int = 64240,
    options: bytes = b"",
    payload: bytes = b"",
) -> bytes:
    assert len(options) % 4 == 0
    header = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        (5 + len(options) // 4) << 4 | flags >> 8,
        flags & 0xFF,
        window,
        0,
        0,
    )
    segment = header + options + payload
    csum = internet_checksum(pseudo_header(src, dst, 6, len(segment)) + segment)
    return segment[:16] + struct.pack("!H", csum) + segment[18:]


def udp_datagram(
    src: IPv4Address | IPv6Address,
    dst: IPv4Address | IPv6Address,
    sport: int,
    dport: int,
    payload: bytes,
) -> bytes:
    datagram = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = internet_checksum(pseudo_header(src, dst, 17, len(datagram)) + datagram) or 0xFFFF
    return datagram[:6] + struct.pack("!H", csum) + datagram[8:]


def icmp_message(icmp_type: int, code: int, rest: int, payload: bytes = b"") -> bytes:
    message = struct.pack("!BBHI", icmp_type, code, 0, rest) + payload
    return message[:2] + struct.pack("!H", internet_checksum(message)) + message[4:]


# MSS 1460, SACK permitted, timestamps, NOP, window scale 7: 20 bytes.
SYN_OPTIONS = bytes.fromhex("020405b40402080a000003e80000000001030307")


def generate() -> list[Packet]:
    """Fixed, deterministic traffic: every protocol appears at least once."""
    ip = ipv4_packet
    dns_like = bytes.fromhex("beef01000001000000000000") + b"\x07example\x03com\x00\x00\x01\x00\x01"
    frames = [
        eth_frame(MAC_BROADCAST, MAC_A, ETHERTYPE_ARP, arp_packet(1, MAC_A, IP_A, MAC_ZERO, IP_B)),
        eth_frame(MAC_A, MAC_B, ETHERTYPE_ARP, arp_packet(2, MAC_B, IP_B, MAC_A, IP_A)),
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV4,
            ip(IP_A, IP_B, 1, icmp_message(8, 0, 0x00010001, b"ping" * 8)),
        ),
        eth_frame(
            MAC_A,
            MAC_B,
            ETHERTYPE_IPV4,
            ip(IP_B, IP_A, 1, icmp_message(0, 0, 0x00010001, b"ping" * 8)),
        ),
        eth_frame(
            MAC_A,
            MAC_B,
            ETHERTYPE_IPV4,
            ip(
                IP_B,
                IP_A,
                1,
                icmp_message(
                    3, 3, 0, ip(IP_A, IP_B, 17, udp_datagram(IP_A, IP_B, 5000, 9, b""))[:28]
                ),
            ),
        ),
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV4,
            ip(
                IP_A,
                IP_B,
                6,
                tcp_segment(IP_A, IP_B, 40000, 80, 1000, 0, tcp.SYN, options=SYN_OPTIONS),
            ),
        ),
        eth_frame(
            MAC_A,
            MAC_B,
            ETHERTYPE_IPV4,
            ip(
                IP_B,
                IP_A,
                6,
                tcp_segment(
                    IP_B, IP_A, 80, 40000, 5000, 1001, tcp.SYN | tcp.ACK, options=SYN_OPTIONS
                ),
            ),
        ),
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV4,
            ip(IP_A, IP_B, 6, tcp_segment(IP_A, IP_B, 40000, 80, 1001, 5001, tcp.ACK)),
        ),
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV4,
            ip(
                IP_A,
                IP_B,
                6,
                tcp_segment(
                    IP_A,
                    IP_B,
                    40000,
                    80,
                    1001,
                    5001,
                    tcp.PSH | tcp.ACK,
                    payload=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
                ),
            ),
        ),
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV4,
            ip(IP_A, IP_B, 6, tcp_segment(IP_A, IP_B, 40000, 80, 1041, 5001, tcp.FIN | tcp.ACK)),
        ),
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV4,
            ip(IP_A, IP_B, 17, udp_datagram(IP_A, IP_B, 53000, 53, dns_like)),
        ),
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV4,
            ip(IP_A, IP_B, 17, udp_datagram(IP_A, IP_B, 53001, 53, dns_like)),
            vlan=100,
        ),
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV6,
            ipv6_packet(
                IP6_A, IP6_B, 6, tcp_segment(IP6_A, IP6_B, 41000, 443, 1, 0, tcp.SYN, window=65535)
            ),
        ),
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV6,
            ipv6_packet(IP6_A, IP6_B, 17, udp_datagram(IP6_A, IP6_B, 53002, 53, dns_like)),
        ),
    ]
    base_ns = 1_700_000_000 * 1_000_000_000  # 2023-11-14 22:13:20 UTC
    return [Packet(base_ns + i * 1_000_000, len(f), f) for i, f in enumerate(frames)]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic pcap covering every Stage 1 protocol"
    )
    parser.add_argument("output", type=Path, help="pcap file to write")
    args = parser.parse_args(argv)
    with args.output.open("wb") as fp:
        writer = PcapWriter(fp)
        for packet in generate():
            writer.write(packet)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
