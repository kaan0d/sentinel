from ipaddress import IPv4Address, IPv6Address

from sentinel.proto.arp import parse_arp
from sentinel.proto.ethernet import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    parse_ethernet,
)
from sentinel.proto.icmp import parse_icmp
from sentinel.proto.ipv4 import PROTO_ICMP, PROTO_TCP, PROTO_UDP, parse_ipv4
from sentinel.proto.ipv6 import parse_ipv6
from sentinel.proto.layer import Layer
from sentinel.proto.tcp import parse_tcp
from sentinel.proto.udp import parse_udp


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


def decode(frame: bytes) -> tuple[Layer, ...]:
    """Decodes an Ethernet frame into its layers, outermost first: Ethernet, then ARP or IP,
    then TCP/UDP/ICMP. Stops after the first layer with an error or an unknown protocol.
    IP fragments are not decoded further (no reassembly)."""
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
            l4 = _decode_l4(ip4.proto, ip4.payload, ip4.src, ip4.dst, ip4.is_complete)
            if l4 is not None:
                layers.append(l4)
    elif eth.ethertype == ETHERTYPE_IPV6:
        ip6 = parse_ipv6(eth.payload)
        layers.append(ip6)
        if not ip6.error:
            l4 = _decode_l4(ip6.next_header, ip6.payload, ip6.src, ip6.dst, ip6.is_complete)
            if l4 is not None:
                layers.append(l4)
    return tuple(layers)
