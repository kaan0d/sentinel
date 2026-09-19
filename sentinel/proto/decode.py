from ipaddress import IPv4Address, IPv6Address

from sentinel.proto.arp import parse_arp
from sentinel.proto.dns import parse_dns
from sentinel.proto.ethernet import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    parse_ethernet,
)
from sentinel.proto.http import looks_like_http, parse_http
from sentinel.proto.icmp import parse_icmp
from sentinel.proto.ipv4 import PROTO_ICMP, PROTO_TCP, PROTO_UDP, parse_ipv4
from sentinel.proto.ipv6 import parse_ipv6
from sentinel.proto.layer import Layer
from sentinel.proto.tcp import Tcp, parse_tcp
from sentinel.proto.tls import looks_like_client_hello, parse_client_hello
from sentinel.proto.udp import Udp, parse_udp

DNS_PORT = 53


def _decode_l4(
    proto: int,
    payload: bytes,
    src: IPv4Address | IPv6Address,
    dst: IPv4Address | IPv6Address,
    complete: bool,
) -> Layer | None:
    # Checksums are only checked when the whole L4 message was captured.
    s, d = (src, dst) if complete else (None, None)
    if proto == PROTO_TCP:
        return parse_tcp(payload, src=s, dst=d)
    if proto == PROTO_UDP:
        return parse_udp(payload, src=s, dst=d)
    if proto == PROTO_ICMP and isinstance(src, IPv4Address):
        return parse_icmp(payload, verify_checksum=complete)
    return None


def _decode_app(l4: Layer) -> Layer | None:
    """Application layer, chosen by port (DNS) or by what the payload starts with (HTTP, TLS).
    Only what one segment holds is parsed; streams are stage 3."""
    if isinstance(l4, Udp) and not l4.error and DNS_PORT in (l4.src_port, l4.dst_port):
        return parse_dns(l4.payload)
    if isinstance(l4, Tcp) and not l4.error and l4.payload:
        data = l4.payload
        if DNS_PORT in (l4.src_port, l4.dst_port):
            # TCP DNS has a 2-byte length prefix. Only a message that fits in this segment.
            size = int.from_bytes(data[:2])
            return parse_dns(data[2 : 2 + size]) if len(data) >= 2 + size else None
        if looks_like_http(data):
            return parse_http(data)
        if looks_like_client_hello(data):
            return parse_client_hello(data)
    return None


def _decode_transport(
    layers: list[Layer],
    proto: int,
    payload: bytes,
    src: IPv4Address | IPv6Address,
    dst: IPv4Address | IPv6Address,
    complete: bool,
) -> None:
    l4 = _decode_l4(proto, payload, src, dst, complete)
    if l4 is None:
        return
    layers.append(l4)
    app = _decode_app(l4)
    if app is not None:
        layers.append(app)


def decode(frame: bytes) -> tuple[Layer, ...]:
    """Decodes an Ethernet frame into its layers, outermost first: Ethernet, then ARP or IP,
    then TCP/UDP/ICMP, then DNS/HTTP/TLS ClientHello. Stops after the first layer with an error
    or an unknown protocol. IP fragments are not decoded further (no reassembly)."""
    eth = parse_ethernet(frame)
    layers: list[Layer] = [eth]
    if eth.error:
        return tuple(layers)
    if eth.ethertype == ETHERTYPE_ARP:
        layers.append(parse_arp(eth.payload))
    elif eth.ethertype == ETHERTYPE_IPV4:
        ip4 = parse_ipv4(eth.payload)
        layers.append(ip4)
        if not ip4.error and not ip4.is_fragment:
            _decode_transport(layers, ip4.proto, ip4.payload, ip4.src, ip4.dst, ip4.is_complete)
    elif eth.ethertype == ETHERTYPE_IPV6:
        ip6 = parse_ipv6(eth.payload)
        layers.append(ip6)
        if not ip6.error:
            _decode_transport(
                layers, ip6.next_header, ip6.payload, ip6.src, ip6.dst, ip6.is_complete
            )
    return tuple(layers)
