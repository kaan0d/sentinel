import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from sentinel.proto.checksum import internet_checksum, pseudo_header
from sentinel.proto.layer import Layer

FIN = 0x001
SYN = 0x002
RST = 0x004
PSH = 0x008
ACK = 0x010
URG = 0x020
ECE = 0x040
CWR = 0x080
NS = 0x100

_MIN_LEN = 20
_PROTO = 6


@dataclass(frozen=True, slots=True)
class TcpOption:
    kind: int
    data: bytes  # option bytes after kind and length; empty for EOL and NOP


@dataclass(frozen=True, slots=True, kw_only=True)
class Tcp(Layer):
    src_port: int = 0
    dst_port: int = 0
    seq: int = 0
    ack: int = 0
    header_len: int = 0
    flags: int = 0  # 9 bits, see the constants above
    window: int = 0
    checksum: int = 0
    urgent: int = 0
    options: tuple[TcpOption, ...] = ()


def _parse_options(buf: bytes) -> tuple[tuple[TcpOption, ...], str | None]:
    """Returns the options read so far and a description of the first malformation, if any."""
    options: list[TcpOption] = []
    i = 0
    while i < len(buf):
        kind = buf[i]
        if kind == 0:  # end of list; the rest is padding
            options.append(TcpOption(0, b""))
            break
        if kind == 1:
            options.append(TcpOption(1, b""))
            i += 1
            continue
        if i + 1 >= len(buf):
            return tuple(options), f"tcp option {kind} has no length byte"
        length = buf[i + 1]
        if length < 2 or i + length > len(buf):
            return tuple(options), f"tcp option {kind} has invalid length {length}"
        options.append(TcpOption(kind, buf[i + 2 : i + length]))
        i += length
    return tuple(options), None


def parse_tcp(
    data: bytes,
    *,
    src: IPv4Address | IPv6Address | None = None,
    dst: IPv4Address | IPv6Address | None = None,
) -> Tcp:
    """`data` is the whole TCP segment. The checksum is verified only if `src` and `dst` are
    given, so pass them only when the segment is known to be complete."""
    if len(data) < _MIN_LEN:
        return Tcp(error=f"truncated tcp header: {len(data)} of {_MIN_LEN} bytes")
    sport, dport, seq, ack, offset_ns, flag_byte, window, csum, urgent = struct.unpack_from(
        "!HHIIBBHHH", data
    )
    hlen = (offset_ns >> 4) * 4
    if hlen < _MIN_LEN:
        return Tcp(error=f"invalid tcp data offset: header length {hlen}")
    if hlen > len(data):
        return Tcp(error=f"truncated tcp header: {len(data)} of {hlen} bytes")
    options, option_error = _parse_options(data[_MIN_LEN:hlen])
    anomalies: list[str] = []
    if option_error:
        anomalies.append(option_error)
    if (
        src is not None
        and dst is not None
        and internet_checksum(pseudo_header(src, dst, _PROTO, len(data)) + data) != 0
    ):
        anomalies.append("bad tcp checksum")
    return Tcp(
        src_port=sport,
        dst_port=dport,
        seq=seq,
        ack=ack,
        header_len=hlen,
        flags=flag_byte | (offset_ns & 1) << 8,
        window=window,
        checksum=csum,
        urgent=urgent,
        options=options,
        payload=data[hlen:],
        anomalies=tuple(anomalies),
    )
