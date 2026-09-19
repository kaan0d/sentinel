import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from sentinel.pcap.common import MAX_CAPLEN, Packet, PcapError

# Block types. The section header reads the same in both byte orders, which is how a reader
# can recognise the format before it knows the byte order.
SHB = 0x0A0D0D0A
IDB = 0x00000001
SPB = 0x00000003
EPB = 0x00000006
SHB_BYTES = b"\x0a\x0d\x0d\x0a"

_LITTLE_MAGIC = b"\x4d\x3c\x2b\x1a"
_BIG_MAGIC = b"\x1a\x2b\x3c\x4d"

_OPT_IF_TSRESOL = 9
_OPT_IF_TSOFFSET = 14

_MIN_BLOCK = 12  # type, length, and the same length again
_MIN_SHB = 28  # 12 + byte-order magic, version, section length
# No real block comes near this; it only stops a corrupt length from reading the whole disk.
MAX_BLOCK = 16 * 1024 * 1024
# The last second datetime can print (9999-12-31 23:59:59), so a summary line never overflows.
MAX_TS_NS = 253_402_300_799 * 1_000_000_000


@dataclass(frozen=True, slots=True)
class _Interface:
    linktype: int
    snaplen: int  # 0 means no limit
    ticks_per_second: int
    offset_ns: int


def _options(raw: bytes, order: str) -> Iterator[tuple[int, bytes]]:
    pos = 0
    while pos + 4 <= len(raw):
        code, length = struct.unpack_from(order + "HH", raw, pos)
        if code == 0:
            return
        end = pos + 4 + length
        if end > len(raw):
            raise PcapError(f"pcapng option {code} runs past the end of its block")
        yield code, raw[pos + 4 : end]
        pos += 4 + (length + 3) // 4 * 4


class PcapngReader:
    """Iterates the packets of a pcapng stream.

    Reads section headers, interface descriptions, enhanced and simple packet blocks; every
    other block (name resolution, statistics, comments...) is skipped. Each section has its
    own byte order and interface list. `linktype` and `snaplen` are those of the first
    interface, and every interface that carries packets must have that link type.
    Timestamps use the interface's `if_tsresol` and `if_tsoffset` and come out as integer
    nanoseconds like the classic reader's. A simple packet block has no timestamp, so it
    gets the time of the packet before it.

    Raises PcapError on a bad first block at construction, and mid-iteration on a corrupt
    block; packets before the corrupt block are still yielded first.
    """

    def __init__(self, fp: BinaryIO) -> None:
        self._fp = fp
        self._order = "<"
        self._interfaces: list[_Interface] = []
        self._last_ts_ns = 0
        first = self._block()
        if first is None or first[0] != SHB:
            raise PcapError("not a pcapng file: it does not start with a section header")
        self._handle(*first)
        while not self._interfaces:
            block = self._block()
            if block is None:
                raise PcapError("pcapng file has no interface description block")
            self._handle(*block)
        self.linktype = self._interfaces[0].linktype
        self.snaplen = self._interfaces[0].snaplen

    def __iter__(self) -> Iterator[Packet]:
        while (block := self._block()) is not None:
            packet = self._handle(*block)
            if packet is not None:
                yield packet

    def _block(self) -> tuple[int, bytes] | None:
        """The next block as (type, body), or None at a clean end of file."""
        head = self._fp.read(8)
        if not head:
            return None
        if len(head) < 8:
            raise PcapError("truncated pcapng block header")
        prefix = b""
        if head[:4] == SHB_BYTES:
            prefix = self._fp.read(4)
            if prefix == _LITTLE_MAGIC:
                self._order = "<"
            elif prefix == _BIG_MAGIC:
                self._order = ">"
            else:
                raise PcapError(f"bad pcapng byte-order magic {prefix.hex()}")
        kind, total = struct.unpack(self._order + "II", head)
        if total < (_MIN_SHB if kind == SHB else _MIN_BLOCK) or total % 4 or total > MAX_BLOCK:
            raise PcapError(f"invalid pcapng block length {total}")
        rest = self._fp.read(total - 8 - len(prefix))
        if len(rest) < total - 8 - len(prefix):
            raise PcapError(f"truncated pcapng block: {len(rest)} of {total - 8} bytes")
        (again,) = struct.unpack(self._order + "I", rest[-4:])
        if again != total:
            raise PcapError(f"pcapng block length {total} is repeated as {again}")
        return kind, prefix + rest[:-4]

    def _handle(self, kind: int, body: bytes) -> Packet | None:
        if kind == SHB:
            major, _minor = struct.unpack_from(self._order + "HH", body, 4)
            if major != 1:
                raise PcapError(f"unsupported pcapng version {major}")
            self._interfaces = []
        elif kind == IDB:
            self._interfaces.append(self._interface(body))
        elif kind == EPB:
            return self._enhanced(body)
        elif kind == SPB:
            return self._simple(body)
        return None

    def _interface(self, body: bytes) -> _Interface:
        if len(body) < 8:
            raise PcapError("pcapng interface description block is too short")
        linktype, _reserved, snaplen = struct.unpack_from(self._order + "HHI", body)
        ticks = 10**6
        offset_ns = 0
        for code, value in _options(body[8:], self._order):
            if code == _OPT_IF_TSRESOL:
                if len(value) != 1:
                    raise PcapError("pcapng if_tsresol option is not one byte")
                ticks = (2 if value[0] & 0x80 else 10) ** (value[0] & 0x7F)
            elif code == _OPT_IF_TSOFFSET:
                if len(value) != 8:
                    raise PcapError("pcapng if_tsoffset option is not eight bytes")
                (seconds,) = struct.unpack(self._order + "q", value)
                offset_ns = seconds * 1_000_000_000
        return _Interface(linktype, snaplen, ticks, offset_ns)

    def _enhanced(self, body: bytes) -> Packet:
        if len(body) < 20:
            raise PcapError("pcapng enhanced packet block is too short")
        number, high, low, caplen, orig_len = struct.unpack_from(self._order + "IIIII", body)
        if number >= len(self._interfaces):
            raise PcapError(f"pcapng packet for interface {number}, which is not described")
        if caplen > MAX_CAPLEN:
            raise PcapError(f"invalid captured length {caplen} (max {MAX_CAPLEN})")
        if 20 + caplen > len(body):
            raise PcapError(f"truncated pcapng packet: {len(body) - 20} of {caplen} bytes")
        interface = self._interfaces[number]
        if interface.linktype != self.linktype:
            raise PcapError(
                f"interface {number} has link type {interface.linktype}, "
                f"the first has {self.linktype}"
            )
        ts_ns = (high << 32 | low) * 1_000_000_000 // interface.ticks_per_second
        ts_ns += interface.offset_ns
        if not 0 <= ts_ns <= MAX_TS_NS:
            raise PcapError(f"pcapng timestamp {ts_ns} ns is out of range")
        self._last_ts_ns = ts_ns
        return Packet(ts_ns, orig_len, body[20 : 20 + caplen])

    def _simple(self, body: bytes) -> Packet:
        if not self._interfaces:
            raise PcapError("pcapng simple packet block before any interface description")
        if len(body) < 4:
            raise PcapError("pcapng simple packet block is too short")
        (orig_len,) = struct.unpack_from(self._order + "I", body)
        snaplen = self._interfaces[0].snaplen
        caplen = min(orig_len, snaplen) if snaplen else orig_len
        if caplen > MAX_CAPLEN:
            raise PcapError(f"invalid captured length {caplen} (max {MAX_CAPLEN})")
        if 4 + caplen > len(body):
            raise PcapError(f"truncated pcapng packet: {len(body) - 4} of {caplen} bytes")
        return Packet(self._last_ts_ns, orig_len, body[4 : 4 + caplen])
