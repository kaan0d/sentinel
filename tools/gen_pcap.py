"""Generate a small synthetic pcap covering every supported protocol.

    python tools/gen_pcap.py out.pcap

The builders are also used by the tests as known-good packet fixtures. All addresses are
private or documentation ranges; nothing here comes from real traffic.
"""

import argparse
import struct
from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address
from itertools import pairwise
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


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def dns_query(ident: int, name: str, qtype: int = 1) -> bytes:
    header = struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0)
    return header + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_cname_response() -> bytes:
    """Answer to `www.example.com A`: a CNAME to example.com, then that name's A record.
    Both answers use compression pointers: 0xc00c is the question name, 0xc010 is the
    `example.com` part inside it."""
    question = dns_name("www.example.com") + struct.pack("!HH", 1, 1)
    cname = struct.pack("!HHHIH", 0xC00C, 5, 1, 300, 2) + struct.pack("!H", 0xC010)
    a_record = struct.pack("!HHHIH", 0xC010, 1, 1, 300, 4) + IPv4Address("192.0.2.1").packed
    return struct.pack("!6H", 0x1234, 0x8180, 1, 2, 0, 0) + question + cname + a_record


def client_hello(sni: str, versions: Sequence[int], ciphers: Sequence[int]) -> bytes:
    """A TLS ClientHello record shaped like a browser's, with GREASE values mixed in."""

    def ext(kind: int, body: bytes) -> bytes:
        return struct.pack("!HH", kind, len(body)) + body

    name = sni.encode()
    extensions = (
        ext(0x1A1A, b"")
        + ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
        + ext(10, struct.pack("!HHHH", 6, 0x001D, 0x0017, 0x0018))
        + ext(43, bytes([2 * len(versions)]) + b"".join(struct.pack("!H", v) for v in versions))
    )
    body = (
        struct.pack("!H", 0x0303)
        + bytes(range(32))  # random
        + bytes([32])
        + bytes(range(32, 64))  # session id
        + struct.pack("!H", 2 * len(ciphers))
        + b"".join(struct.pack("!H", c) for c in ciphers)
        + bytes([1, 0])  # compression: null only
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = bytes([1]) + len(body).to_bytes(3) + body
    return bytes([0x16, 3, 1]) + struct.pack("!H", len(handshake)) + handshake


HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nhello world\n"
)
CLIENT_HELLO = client_hello(
    "example.com",
    [0x2A2A, 0x0304, 0x0303],
    [
        0x0A0A,  # GREASE
        0x1301,
        0x1302,
        0x1303,
        0xC02B,
        0xC02F,
        0xC02C,
        0xC030,
        0xCCA9,
        0xCCA8,
        0xC013,
        0xC014,
        0x009C,
        0x009D,
        0x002F,
        0x0035,
    ],
)


def generate() -> list[Packet]:
    """Fixed, deterministic traffic: every protocol appears at least once."""
    ip = ipv4_packet
    query = dns_query(0x4321, "example.com", 28)
    tcp_dns = len(query).to_bytes(2) + query  # DNS over TCP: 2-byte length prefix
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
            ip(IP_A, IP_B, 6, tcp_segment(IP_A, IP_B, 40000, 80, 1039, 5001, tcp.FIN | tcp.ACK)),
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
        # Application layer (stage 2): DNS query and CNAME answer, DNS over TCP, an HTTP
        # response, and a TLS ClientHello.
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV4,
            ip(
                IP_A,
                IP_B,
                17,
                udp_datagram(IP_A, IP_B, 53003, 53, dns_query(0x1234, "www.example.com")),
            ),
        ),
        eth_frame(
            MAC_A,
            MAC_B,
            ETHERTYPE_IPV4,
            ip(IP_B, IP_A, 17, udp_datagram(IP_B, IP_A, 53, 53003, dns_cname_response())),
        ),
        eth_frame(
            MAC_B,
            MAC_A,
            ETHERTYPE_IPV4,
            ip(
                IP_A,
                IP_B,
                6,
                tcp_segment(IP_A, IP_B, 42000, 53, 1, 1, tcp.PSH | tcp.ACK, payload=tcp_dns),
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
                    IP_B, IP_A, 80, 40000, 5001, 1039, tcp.PSH | tcp.ACK, payload=HTTP_RESPONSE
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
                tcp_segment(IP_A, IP_B, 43000, 443, 1, 1, tcp.PSH | tcp.ACK, payload=CLIENT_HELLO),
            ),
        ),
    ]
    return _stamp(frames)


def _stamp(frames: list[bytes]) -> list[Packet]:
    base_ns = 1_700_000_000 * 1_000_000_000  # 2023-11-14 22:13:20 UTC
    return [Packet(base_ns + i * 1_000_000, len(f), f) for i, f in enumerate(frames)]


class Conversation:
    """The frames of one TCP connection between 10.0.0.1 (client) and 10.0.0.2 (server)."""

    def __init__(self, frames: list[bytes], sport: int, dport: int) -> None:
        self.frames = frames
        self.sport = sport
        self.dport = dport

    def client(self, seq: int, ack: int, flags: int, payload: bytes = b"") -> None:
        seg = tcp_segment(IP_A, IP_B, self.sport, self.dport, seq, ack, flags, payload=payload)
        self.frames.append(eth_frame(MAC_B, MAC_A, ETHERTYPE_IPV4, ipv4_packet(IP_A, IP_B, 6, seg)))

    def server(self, seq: int, ack: int, flags: int, payload: bytes = b"") -> None:
        seg = tcp_segment(IP_B, IP_A, self.dport, self.sport, seq, ack, flags, payload=payload)
        self.frames.append(eth_frame(MAC_A, MAC_B, ETHERTYPE_IPV4, ipv4_packet(IP_B, IP_A, 6, seg)))

    def handshake(self, client_isn: int, server_isn: int) -> None:
        self.client(client_isn, 0, tcp.SYN)
        self.server(server_isn, client_isn + 1, tcp.SYN | tcp.ACK)
        self.client(client_isn + 1, server_isn + 1, tcp.ACK)


def generate_streams() -> list[Packet]:
    """Connections that need reassembly: out-of-order and repeated segments, messages split
    across segments, a lost segment, a reset, plus one UDP exchange and one ICMP echo."""
    frames: list[bytes] = []
    psh_ack = tcp.PSH | tcp.ACK
    fin_ack = tcp.FIN | tcp.ACK

    # A. HTTP POST split into three segments that arrive out of order, one of them twice. The
    # body holds text that looks like a request line: it starts the last segment on purpose.
    a = Conversation(frames, 44000, 8080)
    a.handshake(7000, 9000)
    body = b"GET /inside-the-body HTTP/1.1\r\n\r\n"
    head = b"POST /upload HTTP/1.1\r\nHost: files.test\r\nContent-Length: %d\r\n\r\n" % len(body)
    request = head + body
    cuts = [0, 30, len(head), len(request)]
    parts = [(7001 + lo, request[lo:hi]) for lo, hi in pairwise(cuts)]
    for seq, chunk in (parts[1], parts[0], parts[2], parts[1]):
        a.client(seq, 9001, psh_ack, chunk)
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    c_end, s_end = 7001 + len(request), 9001 + len(response)
    a.server(9001, c_end, psh_ack, response)
    a.client(c_end, s_end, fin_ack)
    a.server(s_end, c_end + 1, fin_ack)
    a.client(c_end + 1, s_end + 1, tcp.ACK)

    # B. A TLS ClientHello split in two; the second half arrives first.
    b = Conversation(frames, 45000, 8443)
    b.handshake(12000, 13000)
    b.client(12001 + 90, 13001, psh_ack, CLIENT_HELLO[90:])
    b.client(12001, 13001, psh_ack, CLIENT_HELLO[:90])

    # C. Two DNS queries back to back on one TCP connection, the first split across segments.
    c = Conversation(frames, 46000, 53)
    c.handshake(20000, 21000)
    q1, q2 = dns_query(1, "example.com"), dns_query(2, "www.example.com", 28)
    stream = len(q1).to_bytes(2) + q1 + len(q2).to_bytes(2) + q2
    c.client(20001, 21001, psh_ack, stream[:20])
    c.client(20001 + 20, 21001, psh_ack, stream[20:])

    # D. A segment lost in the capture: 100 bytes never arrive.
    d = Conversation(frames, 47000, 80)
    d.handshake(30000, 31000)
    d.client(30001, 31001, psh_ack, b"first part. " * 8 + b"....")  # 100 bytes
    d.client(30201, 31001, psh_ack, b"third part. " * 5)  # 60 bytes
    d.client(30261, 31001, fin_ack)

    # E. A refused connection.
    e = Conversation(frames, 48000, 22)
    e.client(40000, 0, tcp.SYN)
    e.server(0, 40001, tcp.RST | tcp.ACK)

    # F. A UDP exchange, and G. an ICMP echo, which is not a flow.
    ip = ipv4_packet
    query = udp_datagram(IP_A, IP_B, 53004, 53, dns_query(0x1234, "www.example.com"))
    answer = udp_datagram(IP_B, IP_A, 53, 53004, dns_cname_response())
    frames.append(eth_frame(MAC_B, MAC_A, ETHERTYPE_IPV4, ip(IP_A, IP_B, 17, query)))
    frames.append(eth_frame(MAC_A, MAC_B, ETHERTYPE_IPV4, ip(IP_B, IP_A, 17, answer)))
    echo = icmp_message(8, 0, 0x00020001, b"ping" * 8)
    frames.append(eth_frame(MAC_B, MAC_A, ETHERTYPE_IPV4, ip(IP_A, IP_B, 1, echo)))
    return _stamp(frames)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic pcap covering every supported protocol"
    )
    parser.add_argument("output", type=Path, help="pcap file to write")
    parser.add_argument(
        "--streams",
        action="store_true",
        help="write the reassembly demo instead: reordered, repeated, split and lost segments",
    )
    args = parser.parse_args(argv)
    with args.output.open("wb") as fp:
        writer = PcapWriter(fp)
        for packet in generate_streams() if args.streams else generate():
            writer.write(packet)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
