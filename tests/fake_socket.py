"""A stand-in for a packet socket, so live capture can be tested without Linux or root."""

from collections import deque
from collections.abc import Callable
from typing import Any


class FakeSocket:
    """Hands out `frames` one at a time. When they are used up it times out on every receive, like
    a quiet network. `script` items are returned in order: bytes are frames, a (frame, address)
    pair is a frame with the address the kernel reports, and exceptions are raised."""

    def __init__(
        self,
        frames: list[bytes | tuple[bytes, Any] | BaseException] | None = None,
        *,
        stats: bytes | BaseException = b"",
        on_receive: Callable[[int], None] | None = None,
        max_calls: int = 100_000,
    ) -> None:
        self.script: deque[bytes | tuple[bytes, Any] | BaseException] = deque(frames or [])
        self.stats = stats
        self.on_receive = on_receive
        self.max_calls = max_calls
        self.calls = 0
        self.sizes: list[int] = []
        self.timeouts: list[float | None] = []
        self.stat_requests: list[tuple[int, int, int]] = []
        self.closed = False
        self.on_wait: Callable[[float], None] | None = None

    def settimeout(self, value: float | None, /) -> None:
        self.timeouts.append(value)

    def recvfrom(self, bufsize: int, /) -> tuple[bytes, Any]:
        self.calls += 1
        assert self.calls <= self.max_calls, "the receive loop did not stop"
        self.sizes.append(bufsize)
        if self.on_receive is not None:
            self.on_receive(self.calls)
        if not self.script:
            if self.on_wait is not None and self.timeouts and self.timeouts[-1] is not None:
                self.on_wait(self.timeouts[-1])
            raise TimeoutError("timed out")
        item = self.script.popleft()
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, tuple):
            return item
        return item, ("eth0", 3, 0, 1, b"")

    def getsockopt(self, level: int, optname: int, buflen: int, /) -> bytes:
        self.stat_requests.append((level, optname, buflen))
        if isinstance(self.stats, BaseException):
            raise self.stats
        return self.stats

    def close(self) -> None:
        self.closed = True
