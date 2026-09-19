import struct
from collections.abc import Iterator
from typing import BinaryIO

from sentinel.pcap.common import (
    GLOBAL_HEADER_LEN,
    MAX_CAPLEN,
    RECORD_HEADER_LEN,
    Packet,
    PcapError,
)

# First four bytes on disk -> (struct byte-order prefix, nanosecond variant).
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}


class PcapReader:
    """Iterates the packets of a classic pcap stream.

    Raises PcapError on a bad global header at construction, and mid-iteration on a corrupt
    record; packets before the corrupt record are still yielded first.
    """

    def __init__(self, fp: BinaryIO) -> None:
        header = fp.read(GLOBAL_HEADER_LEN)
        if len(header) < GLOBAL_HEADER_LEN:
            raise PcapError(f"truncated pcap global header: {len(header)} bytes")
        if header[:4] not in _MAGICS:
            raise PcapError(f"not a pcap file: bad magic {header[:4].hex()}")
        order, self.nanosecond = _MAGICS[header[:4]]
        major, minor, _zone, _sigfigs, self.snaplen, self.linktype = struct.unpack(
            order + "HHiIII", header[4:]
        )
        if major != 2:
            raise PcapError(f"unsupported pcap version {major}.{minor}")
        self._fp = fp
        self._record = struct.Struct(order + "IIII")
        self._frac_ns = 1 if self.nanosecond else 1000

    def __iter__(self) -> Iterator[Packet]:
        while raw := self._fp.read(RECORD_HEADER_LEN):
            if len(raw) < RECORD_HEADER_LEN:
                raise PcapError("truncated pcap record header")
            sec, frac, incl_len, orig_len = self._record.unpack(raw)
            if incl_len > MAX_CAPLEN:
                raise PcapError(f"invalid captured length {incl_len} (max {MAX_CAPLEN})")
            data = self._fp.read(incl_len)
            if len(data) < incl_len:
                raise PcapError(f"truncated pcap record: {len(data)} of {incl_len} bytes")
            yield Packet(sec * 1_000_000_000 + frac * self._frac_ns, orig_len, data)
