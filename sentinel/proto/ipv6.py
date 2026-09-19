import struct
from dataclasses import dataclass
from ipaddress import IPv6Address

from sentinel.proto.layer import ZERO6, Layer

_LEN = 40


@dataclass(frozen=True, slots=True, kw_only=True)
class IPv6(Layer):
    """Fixed header only. Extension headers are not walked: `next_header` is reported as is."""

    traffic_class: int = 0
    flow_label: int = 0
    payload_length: int = 0
    next_header: int = 0
    hop_limit: int = 0
    src: IPv6Address = ZERO6
    dst: IPv6Address = ZERO6

    @property
    def is_complete(self) -> bool:
        return len(self.payload) == self.payload_length


def parse_ipv6(data: bytes) -> IPv6:
    if len(data) < _LEN:
        return IPv6(error=f"truncated ipv6 header: {len(data)} of {_LEN} bytes")
    first, plen, next_header, hop_limit = struct.unpack_from("!IHBB", data)
    if first >> 28 != 6:
        return IPv6(error=f"not ipv6: version {first >> 28}")
    anomalies: tuple[str, ...] = ()
    if _LEN + plen > len(data):
        anomalies = (f"truncated ipv6 packet: payload length {plen}, captured {len(data) - _LEN}",)
    return IPv6(
        traffic_class=(first >> 20) & 0xFF,
        flow_label=first & 0xFFFFF,
        payload_length=plen,
        next_header=next_header,
        hop_limit=hop_limit,
        src=IPv6Address(data[8:24]),
        dst=IPv6Address(data[24:40]),
        payload=data[_LEN : _LEN + plen],
        anomalies=anomalies,
    )
