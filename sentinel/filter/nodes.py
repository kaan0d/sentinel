"""The filter syntax tree, and printing it back as filter text.

`And` and `Or` are n-ary and never contain a directly nested node of the same kind, so a
long `a and b and c and ...` is one flat node, not a deep tree."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Literal

Direction = Literal["src", "dst"] | None
Address = IPv4Address | IPv6Address
Network = IPv4Network | IPv6Network

PROTOCOLS = ("ip", "ip6", "arp", "tcp", "udp", "icmp", "dns", "http", "tls")
QUALIFIERS = ("src", "dst", "host", "net", "port", "portrange")


@dataclass(frozen=True, slots=True)
class FilterError:
    message: str
    position: int  # index into the filter text


@dataclass(frozen=True, slots=True)
class Proto:
    name: str  # one of PROTOCOLS


@dataclass(frozen=True, slots=True)
class Vlan:
    vid: int | None  # None: any VLAN tag


@dataclass(frozen=True, slots=True)
class Ja3:
    digest: str  # 32 lowercase hex digits


@dataclass(frozen=True, slots=True)
class Host:
    direction: Direction
    addr: Address


@dataclass(frozen=True, slots=True)
class Net:
    direction: Direction
    net: Network


@dataclass(frozen=True, slots=True)
class Port:
    direction: Direction
    lo: int
    hi: int  # `port 80` is lo == hi == 80


@dataclass(frozen=True, slots=True)
class Not:
    operand: "Expr"


@dataclass(frozen=True, slots=True)
class And:
    operands: "tuple[Expr, ...]"


@dataclass(frozen=True, slots=True)
class Or:
    operands: "tuple[Expr, ...]"


type Expr = Proto | Vlan | Ja3 | Host | Net | Port | Not | And | Or


def format_expr(expr: Expr) -> str:
    """Filter text that parses back to an equal tree."""
    match expr:
        case Proto(name):
            return name
        case Vlan(None):
            return "vlan"
        case Vlan(vid):
            return f"vlan {vid}"
        case Ja3(digest):
            return f"ja3 {digest}"
        case Host(direction, addr):
            return f"{direction + ' ' if direction else ''}host {addr}"
        case Net(direction, net):
            return f"{direction + ' ' if direction else ''}net {net}"
        case Port(direction, lo, hi):
            prefix = direction + " " if direction else ""
            return f"{prefix}port {lo}" if lo == hi else f"{prefix}portrange {lo}-{hi}"
        case Not(operand):
            inner = format_expr(operand)
            return f"not ({inner})" if isinstance(operand, And | Or) else f"not {inner}"
        case And(operands):
            return " and ".join(
                f"({format_expr(o)})" if isinstance(o, Or) else format_expr(o) for o in operands
            )
        case Or(operands):
            return " or ".join(format_expr(o) for o in operands)
