"""Decides whether a decoded packet matches a filter.

Semantics follow tcpdump where they exist:
- `ip`, `ip6`, `arp`, `tcp`, `udp`, `icmp`, `dns`, `http`, `tls` are true when that layer is
  present, even if it has an error (a broken TCP header is still a TCP packet).
- `host`/`net` look at the IP addresses of IPv4/IPv6 packets, and the sender/target addresses
  of ARP. `port`/`portrange` look at TCP and UDP ports. These need an intact header, so they
  are false for a layer with an error.
- `src` and `dst` pick one side; without them, either side matches.
- `decode()` does not look past the IP header of a fragment, so a fragment matches `ip` and
  `host` but not `tcp` or `port`."""

from collections.abc import Callable, Sequence

from sentinel.filter.nodes import (
    Address,
    And,
    Direction,
    Expr,
    Host,
    Net,
    Not,
    Or,
    Port,
    Proto,
    Vlan,
)
from sentinel.proto.arp import Arp
from sentinel.proto.dns import Dns
from sentinel.proto.ethernet import Ethernet
from sentinel.proto.http import Http
from sentinel.proto.icmp import Icmp
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.ipv6 import IPv6
from sentinel.proto.layer import Layer
from sentinel.proto.tcp import Tcp
from sentinel.proto.tls import TlsClientHello
from sentinel.proto.udp import Udp

_PROTO_LAYERS: dict[str, type[Layer]] = {
    "ip": IPv4,
    "ip6": IPv6,
    "arp": Arp,
    "tcp": Tcp,
    "udp": Udp,
    "icmp": Icmp,
    "dns": Dns,
    "http": Http,
    "tls": TlsClientHello,
}


def _addresses(layers: Sequence[Layer]) -> tuple[Address, Address] | None:
    for layer in layers:
        if isinstance(layer, IPv4 | IPv6) and not layer.error:
            return layer.src, layer.dst
        if isinstance(layer, Arp) and not layer.error:
            return layer.sender_ip, layer.target_ip
    return None


def _ports(layers: Sequence[Layer]) -> tuple[int, int] | None:
    for layer in layers:
        if isinstance(layer, Tcp | Udp) and not layer.error:
            return layer.src_port, layer.dst_port
    return None


def _side[T](pair: tuple[T, T] | None, direction: Direction, test: Callable[[T], bool]) -> bool:
    if pair is None:
        return False
    if direction == "src":
        return test(pair[0])
    if direction == "dst":
        return test(pair[1])
    return test(pair[0]) or test(pair[1])


def matches(expr: Expr, layers: Sequence[Layer]) -> bool:
    """Does the packet, as decoded by `decode()`, match the filter?"""
    match expr:
        case Proto(name):
            return any(isinstance(layer, _PROTO_LAYERS[name]) for layer in layers)
        case Vlan(vid):
            eth = layers[0] if layers else None
            if not isinstance(eth, Ethernet) or eth.error:
                return False
            return bool(eth.vlans) if vid is None else vid in eth.vlans
        case Host(direction, addr):
            return _side(_addresses(layers), direction, lambda a: a == addr)
        case Net(direction, net):
            return _side(_addresses(layers), direction, lambda a: a in net)
        case Port(direction, lo, hi):
            return _side(_ports(layers), direction, lambda p: lo <= p <= hi)
        case Not(operand):
            return not matches(operand, layers)
        case And(operands):
            return all(matches(o, layers) for o in operands)
        case Or(operands):
            return any(matches(o, layers) for o in operands)
