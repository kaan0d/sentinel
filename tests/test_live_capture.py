import socket
import struct
import time
from itertools import islice
from pathlib import Path
from typing import Any

import pytest
from fake_socket import FakeSocket

from sentinel.live import Capture, LiveError, open_capture
from sentinel.live import capture as cap
from sentinel.pcap import Packet
from sentinel.pcap.common import DEFAULT_SNAPLEN


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_packets_carry_the_frame_and_the_time_it_arrived() -> None:
    first, second = b"\x01" * 60, b"\x02" * 70
    sock = FakeSocket([first, second])
    times = iter([10, 20])
    capture = Capture(sock, lambda: next(times))
    got = list(islice(capture.packets(), 2))
    assert got == [Packet(10, 60, first), Packet(20, 70, second)]
    assert sock.sizes == [DEFAULT_SNAPLEN, DEFAULT_SNAPLEN]  # room for any frame


def test_the_default_clock_is_the_system_clock() -> None:
    capture = Capture(FakeSocket([b"\x00" * 60]))
    packet = next(capture.packets())
    assert abs(packet.ts_ns - time.time_ns()) < 5_000_000_000


def test_a_quiet_network_is_not_the_end_of_the_capture() -> None:
    sock = FakeSocket(
        [TimeoutError(), b"a" * 60, TimeoutError(), TimeoutError(), b"b" * 60],
    )
    got = list(islice(Capture(sock, lambda: 0).packets(), 2))
    assert [p.data[:1] for p in got] == [b"a", b"b"]
    assert set(sock.timeouts) == {cap.POLL_SECONDS}  # no time limit: always the same wait


def test_a_packet_sent_on_loopback_is_seen_once() -> None:
    # On `lo` the kernel hands out each packet twice: leaving (type 4) and arriving (type 0).
    out, arriving = ("lo", 3, 4, 772, b""), ("lo", 3, 0, 772, b"")
    sock = FakeSocket([(b"a" * 60, out), (b"a" * 60, arriving), (b"b" * 60, out)])
    sock.script.append(TimeoutError())
    got = list(islice(Capture(sock, lambda: 0).packets(0.0001), 5))
    assert [p.data[:1] for p in got] == [b"a"]


def test_only_the_leaving_copy_on_loopback_is_dropped() -> None:
    frames: list[bytes | tuple[bytes, Any] | BaseException] = [
        (b"1" * 60, ("eth0", 3, 4, 1, b"")),  # leaving an Ethernet interface: wanted
        (b"2" * 60, ("lo", 3, 0, 772, b"")),  # arriving on loopback: wanted
        (b"3" * 60, ("lo", 3, 4, 1, b"")),  # not loopback hardware: wanted
        (b"4" * 60, ("lo", 3, 0, 1)),  # short address: wanted
        (b"5" * 60, None),  # no address: wanted
        (b"6" * 60, ("lo", 3, 1, 772, b"")),  # broadcast on loopback: wanted
    ]
    got = list(islice(Capture(FakeSocket(frames), lambda: 0).packets(), 6))
    assert [p.data[:1] for p in got] == [b"1", b"2", b"3", b"4", b"5", b"6"]


def test_a_receive_error_reaches_the_caller() -> None:
    sock = FakeSocket([b"a" * 60, OSError("network is down")])
    packets = Capture(sock, lambda: 0).packets()
    assert next(packets).data == b"a" * 60
    with pytest.raises(OSError, match="network is down"):
        next(packets)


def test_the_capture_stops_when_the_time_is_up() -> None:
    clock = Clock()
    sock = FakeSocket()
    sock.on_wait = lambda waited: setattr(clock, "now", clock.now + waited)
    assert list(Capture(sock, lambda: 0).packets(1.25, clock)) == []
    # Never waits longer than what is left of the time.
    assert sock.timeouts == [0.5, 0.5, 0.25]


def test_packets_that_arrive_in_time_are_returned() -> None:
    clock = Clock()
    sock = FakeSocket([b"a" * 60, b"b" * 60])
    sock.on_wait = lambda waited: setattr(clock, "now", clock.now + waited)
    got = list(Capture(sock, lambda: 0).packets(0.75, clock))
    assert [p.data[:1] for p in got] == [b"a", b"b"]
    assert sock.timeouts == [0.5, 0.5, 0.5, 0.25]  # a packet does not use up any of the time


def test_the_kernel_drop_count() -> None:
    sock = FakeSocket(stats=struct.pack("=II", 100, 7))
    assert Capture(sock).kernel_drops() == 7  # the second number: packets seen, then dropped
    assert sock.stat_requests == [(263, 6, 8)]  # SOL_PACKET, PACKET_STATISTICS


@pytest.mark.parametrize("stats", [b"", b"\x00" * 4, b"\x00" * 12, OSError("no such option")])
def test_a_system_that_does_not_report_drops_gives_none(stats: bytes | OSError) -> None:
    assert Capture(FakeSocket(stats=stats)).kernel_drops() is None


def test_close_closes_the_socket() -> None:
    sock = FakeSocket()
    Capture(sock).close()
    assert sock.closed


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("eth0", True),
        ("lo", True),
        ("br-1a2b3c", True),
        ("x" * 15, True),
        ("é" * 7, True),  # 14 bytes
        ("x" * 16, False),  # the kernel keeps room for a terminating zero byte
        ("é" * 8, False),  # 16 bytes
        ("", False),
        (".", False),
        ("..", False),
        ("a/b", False),
        ("../eth0", False),
        ("a:b", False),
        ("a b", False),
        ("a\tb", False),
        ("a\nb", False),
    ],
)
def test_interface_names_follow_the_kernels_rules(name: str, valid: bool) -> None:
    assert cap.valid_interface_name(name) is valid


@pytest.fixture
def sysfs(tmp_path: Path) -> Path:
    root = tmp_path / "net"
    for name, link_type in [("eth0", "1\n"), ("lo", "772\n"), ("wlan0", "801\n"), ("bad0", "abc")]:
        (root / name).mkdir(parents=True)
        (root / name / "type").write_text(link_type)
    return root


def test_ethernet_and_loopback_interfaces_are_accepted(sysfs: Path) -> None:
    cap.check_interface("eth0", sysfs)
    cap.check_interface("lo", sysfs)


def test_other_link_types_are_refused(sysfs: Path) -> None:
    with pytest.raises(LiveError, match="wlan0 has link type 801; only Ethernet is supported"):
        cap.check_interface("wlan0", sysfs)


def test_a_missing_interface_is_named(sysfs: Path) -> None:
    with pytest.raises(LiveError, match=r"^no such interface: eth9$"):
        cap.check_interface("eth9", sysfs)


def test_an_unreadable_link_type_is_reported(sysfs: Path) -> None:
    with pytest.raises(LiveError, match="cannot read the link type of bad0"):
        cap.check_interface("bad0", sysfs)


def test_an_interface_name_cannot_point_outside_the_folder(sysfs: Path) -> None:
    (sysfs.parent / "outside").mkdir()
    (sysfs.parent / "outside" / "type").write_text("1\n")
    with pytest.raises(LiveError, match="not a valid interface name"):
        cap.check_interface("../outside", sysfs)


class BindableSocket(FakeSocket):
    def __init__(self, bind_error: OSError | None = None) -> None:
        super().__init__()
        self.bind_error = bind_error
        self.bound: tuple[str, int] | None = None

    def bind(self, address: tuple[str, int], /) -> None:
        if self.bind_error is not None:
            raise self.bind_error
        self.bound = address


class FakeSocketModule:
    """What `socket` looks like on Linux, with a socket we control."""

    AF_PACKET = 17
    SOCK_RAW = 3
    htons = staticmethod(socket.htons)

    def __init__(self, sock: BindableSocket | OSError) -> None:
        self.sock = sock
        self.calls: list[tuple[int, int, int]] = []

    def socket(self, family: int, kind: int, proto: int) -> BindableSocket:
        self.calls.append((family, kind, proto))
        if isinstance(self.sock, OSError):
            raise self.sock
        return self.sock


@pytest.fixture
def linux(monkeypatch: pytest.MonkeyPatch) -> Any:
    """`open_capture` on a pretend Linux with an interface called eth0."""

    def install(sock: BindableSocket | OSError) -> FakeSocketModule:
        module = FakeSocketModule(sock)
        monkeypatch.setattr(cap, "socket", module)
        monkeypatch.setattr(cap, "check_interface", lambda name: None)
        return module

    return install


def test_open_capture_binds_a_raw_socket_that_receives_every_protocol(linux: Any) -> None:
    sock = BindableSocket()
    module = linux(sock)
    capture = open_capture("eth0")
    assert module.calls == [(17, 3, socket.htons(3))]  # AF_PACKET, SOCK_RAW, ETH_P_ALL
    assert sock.bound == ("eth0", 0)
    sock.script.append(b"\x07" * 60)
    assert next(capture.packets()).data == b"\x07" * 60


def test_open_capture_without_permission_says_what_is_needed(linux: Any) -> None:
    linux(PermissionError(1, "Operation not permitted"))
    with pytest.raises(LiveError, match="needs root or the CAP_NET_RAW capability"):
        open_capture("eth0")


def test_open_capture_reports_a_socket_that_cannot_be_made(linux: Any) -> None:
    linux(OSError(97, "Address family not supported by protocol"))
    with pytest.raises(LiveError, match=r"cannot open a packet socket: .*not supported"):
        open_capture("eth0")


def test_open_capture_reports_a_bind_error_and_closes_the_socket(linux: Any) -> None:
    sock = BindableSocket(OSError(19, "No such device"))
    linux(sock)
    with pytest.raises(LiveError, match=r"cannot capture on eth0: .*No such device"):
        open_capture("eth0")
    assert sock.closed


def test_open_capture_checks_the_interface_before_it_opens_a_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = FakeSocketModule(BindableSocket())
    monkeypatch.setattr(cap, "socket", module)

    def refuse(name: str) -> None:
        raise LiveError(f"no such interface: {name}")

    monkeypatch.setattr(cap, "check_interface", refuse)
    with pytest.raises(LiveError, match="no such interface: eth9"):
        open_capture("eth9")
    assert module.calls == []


def test_open_capture_on_a_system_without_packet_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(socket, "AF_PACKET", raising=False)
    with pytest.raises(LiveError, match="needs Linux"):
        open_capture("eth0")
