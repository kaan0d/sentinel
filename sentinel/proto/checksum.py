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


def is_partial_checksum(checksum: int, pseudo: bytes) -> bool:
    """True if `checksum` is the sum of the pseudo-header alone, not complemented. That is the
    value a network card is handed to finish (checksum offload), so a capture taken on the
    sending machine holds it in the segments that machine sent, and it is not a bad checksum."""
    return checksum == ~internet_checksum(pseudo) & 0xFFFF


def pseudo_header(
    src: IPv4Address | IPv6Address, dst: IPv4Address | IPv6Address, proto: int, length: int
) -> bytes:
    """TCP/UDP checksum pseudo-header (RFC 793 for IPv4, RFC 8200 for IPv6)."""
    if isinstance(src, IPv4Address):
        return src.packed + dst.packed + struct.pack("!xBH", proto, length)
    return src.packed + dst.packed + struct.pack("!I3xB", length, proto)
