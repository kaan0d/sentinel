import struct
from dataclasses import dataclass

from sentinel.proto.checksum import internet_checksum
from sentinel.proto.layer import Layer

ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

_LEN = 8


@dataclass(frozen=True, slots=True, kw_only=True)
class Icmp(Layer):
    """ICMPv4. `rest` is the 4-byte "rest of header" word, whose meaning depends on the type."""

    icmp_type: int = 0
    code: int = 0
    checksum: int = 0
    rest: int = 0

    @property
    def ident(self) -> int:
        """Echo identifier (meaningful for echo request/reply only)."""
        return self.rest >> 16

    @property
    def seq(self) -> int:
        """Echo sequence number (meaningful for echo request/reply only)."""
        return self.rest & 0xFFFF


def parse_icmp(data: bytes, *, verify_checksum: bool = True) -> Icmp:
    """`data` is the whole ICMP message. Pass verify_checksum=False if it may be truncated."""
    if len(data) < _LEN:
        return Icmp(error=f"truncated icmp header: {len(data)} of {_LEN} bytes")
    icmp_type, code, csum, rest = struct.unpack_from("!BBHI", data)
    anomalies = ("bad icmp checksum",) if verify_checksum and internet_checksum(data) else ()
    return Icmp(
        icmp_type=icmp_type,
        code=code,
        checksum=csum,
        rest=rest,
        payload=data[_LEN:],
        anomalies=anomalies,
    )
