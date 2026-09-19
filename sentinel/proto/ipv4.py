import struct
from dataclasses import dataclass
from ipaddress import IPv4Address

from sentinel.proto.checksum import internet_checksum
from sentinel.proto.layer import ZERO4, Layer

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

_MIN_LEN = 20


@dataclass(frozen=True, slots=True, kw_only=True)
class IPv4(Layer):
    header_len: int = 0
    tos: int = 0
    total_length: int = 0
    ident: int = 0
    dont_fragment: bool = False
    more_fragments: bool = False
    frag_offset: int = 0  # in bytes
    ttl: int = 0
    proto: int = 0
    checksum: int = 0
    src: IPv4Address = ZERO4
    dst: IPv4Address = ZERO4
    options: bytes = b""

    @property
    def is_fragment(self) -> bool:
        return self.more_fragments or self.frag_offset != 0

    @property
    def is_complete(self) -> bool:
        """True if the capture holds the whole packet the header declares."""
        return len(self.payload) == self.total_length - self.header_len


def parse_ipv4(data: bytes) -> IPv4:
    if len(data) < _MIN_LEN:
        return IPv4(error=f"truncated ipv4 header: {len(data)} of {_MIN_LEN} bytes")
    vihl, tos, total, ident, flags_frag, ttl, proto, csum = struct.unpack_from("!BBHHHBBH", data)
    if vihl >> 4 != 4:
        return IPv4(error=f"not ipv4: version {vihl >> 4}")
    hlen = (vihl & 0xF) * 4
    if hlen < _MIN_LEN:
        return IPv4(error=f"invalid ipv4 header length {hlen}")
    if len(data) < hlen:
        return IPv4(error=f"truncated ipv4 header: {len(data)} of {hlen} bytes")
    if total < hlen:
        return IPv4(error=f"ipv4 total length {total} below header length {hlen}")
    anomalies: list[str] = []
    if internet_checksum(data[:hlen]) != 0:
        anomalies.append("bad ipv4 header checksum")
    if flags_frag & 0x8000:
        anomalies.append("ipv4 reserved flag set")
    if total > len(data):
        anomalies.append(f"truncated ipv4 packet: total length {total}, captured {len(data)}")
    return IPv4(
        header_len=hlen,
        tos=tos,
        total_length=total,
        ident=ident,
        dont_fragment=bool(flags_frag & 0x4000),
        more_fragments=bool(flags_frag & 0x2000),
        frag_offset=(flags_frag & 0x1FFF) * 8,
        ttl=ttl,
        proto=proto,
        checksum=csum,
        src=IPv4Address(data[12:16]),
        dst=IPv4Address(data[16:20]),
        options=data[_MIN_LEN:hlen],
        payload=data[hlen:total],
        anomalies=tuple(anomalies),
    )
