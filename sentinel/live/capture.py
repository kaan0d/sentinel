"""Live capture from a network interface, as the same `Packet` values the pcap reader gives.

Linux only: a packet socket (AF_PACKET) receives every Ethernet frame of one interface. The socket
only listens and never sends. Opening it needs root or the CAP_NET_RAW capability, and it must be
used only on a network you own or may monitor.

Everything that can be tested without a socket takes what it needs as an argument (the socket, the
clock, the folder that stands for /sys/class/net). Nothing here raises for a bad interface or a
missing permission: `open_capture` raises `LiveError` with a message meant for the person."""

import socket
import struct
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Protocol

from sentinel.pcap import Packet
from sentinel.pcap.common import DEFAULT_SNAPLEN

ETH_P_ALL = 0x0003  # every protocol
SOL_PACKET = 263
PACKET_STATISTICS = 6
ARPHRD_ETHER = 1
ARPHRD_LOOPBACK = 772  # `lo` hands out Ethernet frames too
PACKET_OUTGOING = 4  # sent by this machine
POLL_SECONDS = 0.5  # how long one receive waits, so the time limit and Ctrl-C are noticed
SYSFS_NET = Path("/sys/class/net")


class LiveError(Exception):
    """The capture cannot start."""


def _second_copy(address: Any) -> bool:
    """A packet sent on the loopback interface is seen twice, once leaving and once arriving.
    The leaving copy is dropped, so every packet is seen once (tcpdump does the same). The
    address is (interface, protocol, packet type, hardware type, hardware address)."""
    return (
        isinstance(address, tuple)
        and len(address) >= 4
        and address[2] == PACKET_OUTGOING
        and address[3] == ARPHRD_LOOPBACK
    )


class RawSocket(Protocol):
    """The part of a socket that a capture uses. A real socket fits, and so does a test double."""

    def recvfrom(self, bufsize: int, /) -> tuple[bytes, Any]: ...
    def settimeout(self, value: float | None, /) -> None: ...
    def getsockopt(self, level: int, optname: int, buflen: int, /) -> bytes: ...
    def close(self) -> None: ...


class Capture:
    """Packets from a socket, stamped with the system clock when they are received."""

    def __init__(self, sock: RawSocket, clock: Callable[[], int] = time.time_ns) -> None:
        self._sock = sock
        self._clock = clock

    def packets(
        self,
        duration: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Iterator[Packet]:
        """Packets as they arrive, for `duration` seconds (or until the caller stops)."""
        deadline = None if duration is None else monotonic() + duration
        while True:
            wait = POLL_SECONDS
            if deadline is not None:
                left = deadline - monotonic()
                if left <= 0:
                    return
                wait = min(wait, left)
            self._sock.settimeout(wait)
            try:
                data, address = self._sock.recvfrom(DEFAULT_SNAPLEN)
            except TimeoutError:
                continue
            if _second_copy(address):
                continue
            yield Packet(self._clock(), len(data), data)

    def kernel_drops(self) -> int | None:
        """Packets the kernel dropped because this program was too slow, or None if the system
        does not say. Reading it resets the count."""
        try:
            raw = self._sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        except OSError:
            return None
        if len(raw) != 8:
            return None
        return int(struct.unpack("=II", raw)[1])  # (packets seen, packets dropped)

    def close(self) -> None:
        self._sock.close()


def valid_interface_name(name: str) -> bool:
    """The kernel's own rules: 1 to 15 bytes, not '.' or '..', no '/', ':' or white space."""
    return (
        0 < len(name.encode(errors="replace")) < 16
        and name not in (".", "..")
        and not any(c in "/:" or c.isspace() for c in name)
    )


def check_interface(name: str, sysfs: Path = SYSFS_NET) -> None:
    """Raise LiveError unless `name` is an interface that carries Ethernet frames."""
    if not valid_interface_name(name):
        raise LiveError(f"{name!r} is not a valid interface name")
    try:
        link_type = int((sysfs / name / "type").read_text().strip())
    except FileNotFoundError:
        raise LiveError(f"no such interface: {name}") from None
    except (OSError, ValueError) as e:
        raise LiveError(f"cannot read the link type of {name}: {e}") from e
    if link_type not in (ARPHRD_ETHER, ARPHRD_LOOPBACK):
        raise LiveError(f"{name} has link type {link_type}; only Ethernet is supported")


def open_capture(name: str) -> Capture:
    """Start capturing on interface `name`."""
    family = getattr(socket, "AF_PACKET", None)
    if family is None:
        raise LiveError("live capture needs Linux (AF_PACKET), and this system has no such socket")
    check_interface(name)
    try:
        sock = socket.socket(family, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError:
        raise LiveError("live capture needs root or the CAP_NET_RAW capability") from None
    except OSError as e:
        raise LiveError(f"cannot open a packet socket: {e}") from e
    try:
        sock.bind((name, 0))
    except OSError as e:
        sock.close()
        raise LiveError(f"cannot capture on {name}: {e}") from e
    return Capture(sock)
