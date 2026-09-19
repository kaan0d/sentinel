import struct
from ipaddress import IPv4Address, IPv6Address


def internet_checksum(data: bytes) -> int:
    """RFC 1071 checksum. Over data that includes a correct checksum field, returns 0."""
    if len(data) % 2:
        data += b"\0"
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def pseudo_header(
    src: IPv4Address | IPv6Address, dst: IPv4Address | IPv6Address, proto: int, length: int
) -> bytes:
    """TCP/UDP checksum pseudo-header (RFC 793 for IPv4, RFC 8200 for IPv6)."""
    if isinstance(src, IPv4Address):
        return src.packed + dst.packed + struct.pack("!xBH", proto, length)
    return src.packed + dst.packed + struct.pack("!I3xB", length, proto)
