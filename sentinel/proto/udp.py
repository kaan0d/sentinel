import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from sentinel.proto.checksum import internet_checksum, pseudo_header
from sentinel.proto.layer import Layer

_LEN = 8
_PROTO = 17


@dataclass(frozen=True, slots=True, kw_only=True)
class Udp(Layer):
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    checksum: int = 0


def parse_udp(
    data: bytes,
    *,
    src: IPv4Address | IPv6Address | None = None,
    dst: IPv4Address | IPv6Address | None = None,
) -> Udp:
    """`data` is the whole UDP datagram. The checksum is verified only if `src` and `dst` are
    given and the datagram is complete."""
    if len(data) < _LEN:
        return Udp(error=f"truncated udp header: {len(data)} of {_LEN} bytes")
    sport, dport, length, csum = struct.unpack_from("!HHHH", data)
    if length < _LEN:
        return Udp(error=f"invalid udp length {length}")
    anomalies: list[str] = []
    if length > len(data):
        anomalies.append(f"truncated udp datagram: length {length}, captured {len(data)}")
    else:
        if length < len(data):
            anomalies.append(f"udp length {length} shorter than the {len(data)} bytes present")
        if src is not None and dst is not None:
            if csum != 0:
                if internet_checksum(pseudo_header(src, dst, _PROTO, length) + data[:length]) != 0:
                    anomalies.append("bad udp checksum")
            elif isinstance(src, IPv6Address):
                anomalies.append("zero udp checksum over ipv6")  # mandatory in IPv6
    return Udp(
        src_port=sport,
        dst_port=dport,
        length=length,
        checksum=csum,
        payload=data[_LEN:length],
        anomalies=tuple(anomalies),
    )
