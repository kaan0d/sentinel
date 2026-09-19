import struct
from typing import BinaryIO, Literal

from sentinel.pcap.common import DEFAULT_SNAPLEN, LINKTYPE_ETHERNET, Packet


class PcapWriter:
    """Writes a classic pcap stream. The microsecond variant drops sub-microsecond precision."""

    def __init__(
        self,
        fp: BinaryIO,
        *,
        linktype: int = LINKTYPE_ETHERNET,
        snaplen: int = DEFAULT_SNAPLEN,
        nanosecond: bool = False,
        byteorder: Literal["little", "big"] = "little",
    ) -> None:
        order = "<" if byteorder == "little" else ">"
        magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
        fp.write(struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype))
        self._fp = fp
        self._snaplen = snaplen
        self._nanosecond = nanosecond
        self._record = struct.Struct(order + "IIII")

    def write(self, packet: Packet) -> None:
        if len(packet.data) > self._snaplen:
            raise ValueError(f"packet of {len(packet.data)} bytes exceeds snaplen {self._snaplen}")
        sec, ns = divmod(packet.ts_ns, 1_000_000_000)
        frac = ns if self._nanosecond else ns // 1000
        self._fp.write(self._record.pack(sec, frac, len(packet.data), packet.orig_len))
        self._fp.write(packet.data)
