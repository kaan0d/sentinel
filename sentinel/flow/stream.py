"""One direction of a TCP connection: puts segments back in order.

Segments are kept as non-overlapping, sorted byte ranges ("intervals") and merged as they touch.
Nothing is delivered incrementally: read the result with `data()` when the capture is done.

Policy and limits, all deliberate:
- Overlapping bytes: the first copy that arrived wins. A later copy with different bytes is
  counted in `overlap_conflicts`, because that is what a hostile sender does to confuse an IDS.
- A stream only holds `max_bytes` from its start. Later bytes are counted in `dropped_bytes`.
- At most `MAX_INTERVALS` separate ranges, and an optional shared `Budget` across all streams.
"""

from bisect import bisect_right

DEFAULT_MAX_BYTES = 1 << 20
MAX_INTERVALS = 4096

_MOD = 1 << 32


class Budget:
    """A byte allowance shared by many streams, so a flood of flows cannot use all memory."""

    def __init__(self, limit: int) -> None:
        self.remaining = limit


class TcpStream:
    def __init__(self, max_bytes: int = DEFAULT_MAX_BYTES, budget: Budget | None = None) -> None:
        self._max = max_bytes
        self._budget = budget
        # Positions are signed offsets from `_ref`, the first sequence number seen. That makes
        # 32-bit wrap-around a non-issue for the first `max_bytes` of a stream.
        self._ref: int | None = None
        self._start: int | None = None  # position of the first data byte, once a SYN is seen
        self._fin: int | None = None  # position just past the last data byte, once a FIN is seen
        self._max_end: int | None = None  # highest position received so far
        self._starts: list[int] = []
        self._chunks: list[bytearray] = []
        self.data_segments = 0
        self.retransmitted_segments = 0  # segments that carried bytes already received
        self.retransmitted_bytes = 0
        self.out_of_order_segments = 0  # new bytes below the highest position already received
        self.overlap_conflicts = 0  # overlapping copies whose bytes differ
        self.conflicting_syns = 0
        self.dropped_bytes = 0  # outside the window, or over a memory limit

    @property
    def has_start(self) -> bool:
        return self._start is not None

    @property
    def has_fin(self) -> bool:
        return self._fin is not None

    @property
    def stored_bytes(self) -> int:
        return sum(len(c) for c in self._chunks)

    @property
    def is_complete(self) -> bool:
        """Start and end both seen, and no bytes missing in between."""
        return self.has_start and self.has_fin and not self.missing_ranges()

    def _pos(self, seq: int) -> int:
        assert self._ref is not None
        d = (seq - self._ref) % _MOD
        return d - _MOD if d >= _MOD >> 1 else d

    def add_syn(self, seq: int) -> None:
        """A SYN uses one sequence number; the data starts at seq + 1."""
        first = (seq + 1) % _MOD
        if self._ref is None:
            self._ref = first
        pos = self._pos(first)
        if self._start is None:
            self._start = pos
            self._drop_before(pos)
        elif self._start != pos:
            self.conflicting_syns += 1

    def add_fin(self, seq: int) -> None:
        """`seq` is the sequence number of the FIN itself, i.e. just past the last data byte."""
        if self._ref is None:
            self._ref = seq % _MOD
        if self._fin is None:
            self._fin = self._pos(seq % _MOD)

    def add_segment(self, seq: int, data: bytes) -> None:
        if not data:
            return
        if self._ref is None:
            self._ref = seq % _MOD
        self.data_segments += 1
        start = self._pos(seq % _MOD)
        base = self._start if self._start is not None else 0
        low = base if self._start is not None else -self._max
        high = base + self._max
        lo, hi = max(start, low), min(start + len(data), high)
        self.dropped_bytes += len(data) - max(0, hi - lo)
        if lo >= hi:
            return
        self._insert(lo, data[lo - start : hi - start])

    def _drop_before(self, pos: int) -> None:
        """A SYN arrived after some data: bytes before the real start are not part of the stream."""
        while self._starts and self._starts[0] < pos:
            s, chunk = self._starts[0], self._chunks[0]
            cut = min(pos - s, len(chunk))
            self._release(cut)
            if cut == len(chunk):
                del self._starts[0], self._chunks[0]
            else:
                self._starts[0] = pos
                del chunk[:cut]

    def _release(self, n: int) -> None:
        if self._budget is not None:
            self._budget.remaining += n

    def _insert(self, start: int, data: bytes) -> None:
        end = start + len(data)
        # Ranges [lo, hi) are the stored intervals that overlap or touch [start, end).
        i = bisect_right(self._starts, start) - 1
        lo = i if i >= 0 and self._starts[i] + len(self._chunks[i]) >= start else i + 1
        hi = bisect_right(self._starts, end)
        overlap = 0
        for k in range(lo, hi):
            s = self._starts[k]
            overlap += max(0, min(end, s + len(self._chunks[k])) - max(start, s))
        new_bytes = len(data) - overlap
        new_interval = lo == hi
        if (self._budget is not None and new_bytes > self._budget.remaining) or (
            new_interval and len(self._starts) >= MAX_INTERVALS
        ):
            self.dropped_bytes += len(data)
            return
        if overlap:
            self.retransmitted_segments += 1
            self.retransmitted_bytes += overlap
        if new_bytes and self._max_end is not None and start < self._max_end:
            self.out_of_order_segments += 1
        self._max_end = end if self._max_end is None else max(self._max_end, end)

        merged_start = min(start, self._starts[lo]) if lo < hi else start
        merged_end = max(end, self._starts[hi - 1] + len(self._chunks[hi - 1])) if lo < hi else end
        buf = bytearray(merged_end - merged_start)
        buf[start - merged_start : end - merged_start] = data
        for k in range(lo, hi):  # bytes already stored win over the new copy
            s, chunk = self._starts[k], self._chunks[k]
            a, b = max(start, s), min(end, s + len(chunk))
            if a < b and buf[a - merged_start : b - merged_start] != chunk[a - s : b - s]:
                self.overlap_conflicts += 1
            buf[s - merged_start : s - merged_start + len(chunk)] = chunk
        self._starts[lo:hi] = [merged_start]
        self._chunks[lo:hi] = [buf]
        if self._budget is not None:
            self._budget.remaining -= new_bytes

    def data(self) -> bytes:
        """The contiguous bytes from the start of the stream (or, when no SYN was seen, from the
        first byte received). Empty if the start is known but its first bytes are missing."""
        if not self._starts:
            return b""
        if self._start is not None and self._starts[0] != self._start:
            return b""
        return bytes(self._chunks[0])

    def missing_ranges(self) -> list[tuple[int, int]]:
        """Byte ranges (positions) never received, between the start and the last byte known."""
        begin = (
            self._start if self._start is not None else (self._starts[0] if self._starts else None)
        )
        if begin is None:
            return []
        holes: list[tuple[int, int]] = []
        cursor = begin
        for s, chunk in zip(self._starts, self._chunks, strict=True):
            if s > cursor:
                holes.append((cursor, s))
            cursor = s + len(chunk)
        if self._fin is not None and self._fin > cursor:
            holes.append((cursor, self._fin))
        return holes

    @property
    def missing_bytes(self) -> int:
        return sum(b - a for a, b in self.missing_ranges())
