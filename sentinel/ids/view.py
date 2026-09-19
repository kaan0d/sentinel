"""The parts of a decoded packet that detectors look at, found once per packet.

Only intact layers are exposed: a layer with an error has no trustworthy fields, so it is None
here, and no detector can be fooled by the zeros it leaves behind."""

from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from sentinel.proto.arp import Arp
from sentinel.proto.dns import Dns
from sentinel.proto.ethernet import Ethernet
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.ipv6 import IPv6
from sentinel.proto.layer import Layer
from sentinel.proto.tcp import Tcp
from sentinel.proto.udp import Udp

Address = IPv4Address | IPv6Address


@dataclass(frozen=True, slots=True)
class PacketView:
    ts_ns: int
    eth: Ethernet | None = None
    arp: Arp | None = None
    ip: IPv4 | IPv6 | None = None
    tcp: Tcp | None = None
    udp: Udp | None = None
    dns: Dns | None = None

    @property
    def src_ip(self) -> Address | None:
        return self.ip.src if self.ip is not None else None

    @property
    def dst_ip(self) -> Address | None:
        return self.ip.dst if self.ip is not None else None


def make_view(ts_ns: int, layers: Sequence[Layer]) -> PacketView:
    eth = arp = ip = tcp = udp = dns = None
    for layer in layers:
        if layer.error is not None:
            break  # nothing after a broken layer can be trusted either
        if isinstance(layer, Ethernet):
            eth = layer
        elif isinstance(layer, Arp):
            arp = layer
        elif isinstance(layer, IPv4 | IPv6):
            ip = layer
        elif isinstance(layer, Tcp):
            tcp = layer
        elif isinstance(layer, Udp):
            udp = layer
        elif isinstance(layer, Dns):
            dns = layer
    return PacketView(ts_ns, eth, arp, ip, tcp, udp, dns)
