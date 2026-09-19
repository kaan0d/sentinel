import struct
from dataclasses import dataclass

from sentinel.proto.layer import Layer

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_IPV6 = 0x86DD

_HEADER_LEN = 14
_TAG_LEN = 4


@dataclass(frozen=True, slots=True, kw_only=True)
class Ethernet(Layer):
    dst: bytes = b""
    src: bytes = b""
    ethertype: int = 0  # the inner ethertype, after any VLAN tags
    vlans: tuple[int, ...] = ()  # VLAN ids, outermost first


def parse_ethernet(data: bytes) -> Ethernet:
    if len(data) < _HEADER_LEN:
        return Ethernet(error=f"truncated ethernet header: {len(data)} of {_HEADER_LEN} bytes")
    (ethertype,) = struct.unpack_from("!H", data, 12)
    offset = _HEADER_LEN
    vlans: list[int] = []
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
        if len(data) < offset + _TAG_LEN:
            return Ethernet(error="truncated 802.1Q tag")
        tci, ethertype = struct.unpack_from("!HH", data, offset)
        vlans.append(tci & 0x0FFF)
        offset += _TAG_LEN
    return Ethernet(
        dst=data[0:6],
        src=data[6:12],
        ethertype=ethertype,
        vlans=tuple(vlans),
        payload=data[offset:],
    )
