"""A sliding window of timestamped events with a hard size limit.

Detectors count events in the last N seconds, and how many different keys (ports, hosts,
subdomains) they carried. The limit keeps memory bounded when a sender floods a detector."""

from collections import Counter, deque
from collections.abc import Hashable


class SlidingWindow:
    def __init__(self, window_ns: int, max_events: int) -> None:
        self._window_ns = window_ns
        self._max_events = max_events
        self._events: deque[tuple[int, Hashable]] = deque()
        self._counts: Counter[Hashable] = Counter()

    def add(self, ts_ns: int, key: Hashable = None) -> None:
        """Record an event. Events older than the window (counted back from `ts_ns`) are
        dropped first, then the oldest event if the window is full."""
        self._evict(ts_ns)
        if len(self._events) >= self._max_events:
            self._pop()
        self._events.append((ts_ns, key))
        self._counts[key] += 1

    def _evict(self, now_ns: int) -> None:
        while self._events and now_ns - self._events[0][0] > self._window_ns:
            self._pop()

    def _pop(self) -> None:
        _, key = self._events.popleft()
        self._counts[key] -= 1
        if not self._counts[key]:
            del self._counts[key]

    @property
    def count(self) -> int:
        """Events in the window."""
        return len(self._events)

    @property
    def distinct(self) -> int:
        """Different keys in the window."""
        return len(self._counts)

    @property
    def keys(self) -> list[Hashable]:
        return list(self._counts)

    @property
    def span_ns(self) -> int:
        """Time from the oldest to the newest event in the window."""
        return self._events[-1][0] - self._events[0][0] if self._events else 0
