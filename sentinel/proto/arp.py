import struct
from dataclasses import dataclass
from ipaddress import IPv4Address

from sentinel.proto.layer import ZERO4, Layer

ARP_REQUEST = 1
ARP_REPLY = 2

_LEN = 28  # Ethernet/IPv4 ARP


@dataclass(frozen=True, slots=True, kw_only=True)
class Arp(Layer):
    op: int = 0
    sender_mac: bytes = b""
    sender_ip: IPv4Address = ZERO4
    target_mac: bytes = b""
    target_ip: IPv4Address = ZERO4


def parse_arp(data: bytes) -> Arp:
    """Ethernet/IPv4 ARP only; other hardware/protocol address types are an error.

    Bytes after the 28-byte packet (Ethernet padding) are ignored; `payload` stays empty.
    """
    if len(data) < _LEN:
        return Arp(error=f"truncated arp packet: {len(data)} of {_LEN} bytes")
    htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", data)
    if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4):
        return Arp(error=f"unsupported arp types: htype={htype} ptype={ptype:#06x} {hlen}/{plen}")
    return Arp(
        op=op,
        sender_mac=data[8:14],
        sender_ip=IPv4Address(data[14:18]),
        target_mac=data[18:24],
        target_ip=IPv4Address(data[24:28]),
    )
