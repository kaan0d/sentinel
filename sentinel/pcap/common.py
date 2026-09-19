from dataclasses import dataclass

LINKTYPE_ETHERNET = 1
DEFAULT_SNAPLEN = 262144
# libpcap's own cap: records longer than this are treated as corrupt.
MAX_CAPLEN = 262144

GLOBAL_HEADER_LEN = 24
RECORD_HEADER_LEN = 16


class PcapError(Exception):
    """The file is not a valid classic pcap (bad header, truncated or oversized record)."""


@dataclass(frozen=True, slots=True)
class Packet:
    """One captured packet. `ts_ns` is integer nanoseconds since the epoch (exact for both
    the microsecond and nanosecond file variants). `orig_len` is the length on the wire,
    which exceeds `len(data)` when the capture was truncated by the snap length."""

    ts_ns: int
    orig_len: int
    data: bytes
