"""Live capture on Windows, without Windows: a raw socket that hands out IP packets, replaced by a
stand-in. `tests/test_live_windows.py` uses the real socket."""

import random
import socket
import struct
from itertools import count, islice
from typing import Any

import pytest
from fake_socket import FakeSocket

from sentinel.ids import Engine, default_rules
from sentinel.live import Capture, LiveError, open_capture
from sentinel.live import capture as cap
from sentinel.live.capture import IpSocket, check_address
from sentinel.pcap import Packet
from sentinel.proto import tcp
from sentinel.proto.decode import decode
from sentinel.proto.ethernet import ETHERTYPE_IPV4, ETHERTYPE_IPV6, Ethernet
from sentinel.summary import summarize
from tools.gen_pcap import IP_A, IP_B, generate, generate_streams, ipv4_packet, tcp_segment

ZERO_MACS = bytes(12)


def wrap(data: bytes, ethertype: int) -> bytes:
    return ZERO_MACS + struct.pack("!H", ethertype) + data


def test_a_frame_is_an_ethernet_header_of_zeros_and_the_ip_packet() -> None:
    v4, v6 = b"\x45" + b"\x01" * 39, b"\x60" + b"\x02" * 59
    sock = IpSocket(FakeSocket([v4, v6]))
    assert sock.recvfrom(100)[0] == wrap(v4, ETHERTYPE_IPV4)
    assert sock.recvfrom(100)[0] == wrap(v6, ETHERTYPE_IPV6)


@pytest.mark.parametrize(
    ("first", "ethertype"),
    [
        (0x45, ETHERTYPE_IPV4),
        (0x4F, ETHERTYPE_IPV4),
        (0x60, ETHERTYPE_IPV6),
        (0x6F, ETHERTYPE_IPV6),
    ],
)
def test_the_ethertype_follows_the_ip_version(first: int, ethertype: int) -> None:
    frame = IpSocket(FakeSocket([bytes([first]) + bytes(39)])).recvfrom(100)[0]
    assert struct.unpack("!H", frame[12:14])[0] == ethertype


@pytest.mark.parametrize("first", [0x00, 0x15, 0x50, 0x70, 0xFF])
def test_anything_else_is_left_for_the_ipv4_parser_to_refuse(first: int) -> None:
    frame = IpSocket(FakeSocket([bytes([first]) + bytes(39)])).recvfrom(100)[0]
    assert struct.unpack("!H", frame[12:14])[0] == ETHERTYPE_IPV4
    assert decode(frame)[1].error is not None


def test_an_empty_read_is_still_a_frame_and_decodes_without_raising() -> None:
    frame = IpSocket(FakeSocket([b""])).recvfrom(100)[0]
    assert frame == wrap(b"", ETHERTYPE_IPV4)
    assert decode(frame)[1].error == "truncated ipv4 header: 0 of 20 bytes"


def test_whatever_the_socket_hands_out_decodes_without_raising() -> None:
    rng = random.Random(12)
    for _ in range(2000):
        data = rng.randbytes(rng.randrange(0, 200))
        frame = IpSocket(FakeSocket([data])).recvfrom(300)[0]
        assert frame[14:] == data
        decode(frame)


def test_the_address_of_the_sender_is_passed_on() -> None:
    address = ("192.168.1.1", 0)
    assert IpSocket(FakeSocket([(b"\x45" + bytes(19), address)])).recvfrom(100)[1] == address


def test_the_size_the_timeout_and_close_reach_the_socket() -> None:
    fake = FakeSocket([b"\x45" + bytes(19)])
    sock = IpSocket(fake)
    sock.settimeout(0.25)
    sock.recvfrom(4321)
    sock.close()
    assert (fake.timeouts, fake.sizes, fake.closed) == ([0.25], [4321], True)


def test_windows_gives_no_drop_count() -> None:
    fake = FakeSocket(stats=struct.pack("=II", 5, 7))  # would be read as 7 if it were asked
    assert Capture(IpSocket(fake)).kernel_drops() is None
    assert fake.stat_requests == []


def test_a_timeout_through_the_wrapper_is_a_quiet_network() -> None:
    fake = FakeSocket([TimeoutError(), b"\x45" + bytes(19)])
    got = list(islice(Capture(IpSocket(fake), lambda: 5).packets(), 1))
    assert got == [Packet(5, 34, wrap(b"\x45" + bytes(19), ETHERTYPE_IPV4))]


def test_a_receive_error_reaches_the_caller() -> None:
    capture = Capture(IpSocket(FakeSocket([OSError(10054, "connection reset")])))
    with pytest.raises(OSError, match="connection reset"):
        next(capture.packets())


def test_every_ip_packet_of_the_generated_captures_reads_as_it_does_from_the_file() -> None:
    # The same packets with their Ethernet header cut off and put back: every layer above it and
    # the line `read` prints must be the same.
    checked = 0
    for original in [*generate(), *generate_streams()]:
        layers = decode(original.data)
        ethernet = layers[0]
        assert isinstance(ethernet, Ethernet)
        if ethernet.ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6) or ethernet.vlans:
            continue
        fake = FakeSocket([original.data[14:]])
        (packet,) = islice(Capture(IpSocket(fake), iter([original.ts_ns]).__next__).packets(), 1)
        assert packet.data[14:] == original.data[14:]
        got = decode(packet.data)
        assert got[1:] == layers[1:]
        assert summarize(packet, got) == summarize(original, layers)
        checked += 1
    assert checked > 40


def tcp_packet(client: bool, sport: int, flags: int) -> bytes:
    src, dst = (IP_A, IP_B) if client else (IP_B, IP_A)
    ports = (sport, 80) if client else (80, sport)
    return ipv4_packet(src, dst, 6, tcp_segment(src, dst, *ports, 1000, 0, flags))


def syn_flood_alerts(packets: list[bytes]) -> list[str]:
    """The alerts of the default rules for IP packets read through the Windows socket, one every
    millisecond."""
    clock = (i * 1_000_000 for i in count())
    capture = Capture(IpSocket(FakeSocket(list(packets))), lambda: next(clock))
    engine = Engine(default_rules().rules)
    for packet in islice(capture.packets(), len(packets)):
        engine.process(packet)
    return [alert.rule for alert in engine.finish()]


def test_handshakes_in_the_order_windows_delivers_them_are_no_syn_flood() -> None:
    # SYN, the ACK that completes the handshake, and only then the SYN-ACK it answers (a real
    # connection on Windows). The detector follows the ACK of the client, whatever the server did.
    windows_order = [
        tcp_packet(client, 40000 + i, flags)
        for i in range(150)
        for client, flags in ((True, tcp.SYN), (True, tcp.ACK), (False, tcp.SYN | tcp.ACK))
    ]
    assert "syn-flood" not in syn_flood_alerts(windows_order)
    no_acks = [tcp_packet(True, 40000 + i, tcp.SYN) for i in range(150)]
    assert "syn-flood" in syn_flood_alerts(no_acks)


class Ioctl(FakeSocket):
    def __init__(
        self, bind_error: OSError | None = None, ioctl_error: OSError | None = None
    ) -> None:
        super().__init__()
        self.bind_error = bind_error
        self.ioctl_error = ioctl_error
        self.bound: tuple[str, int] | None = None
        self.ioctls: list[tuple[int, int]] = []

    def bind(self, address: tuple[str, int], /) -> None:
        if self.bind_error is not None:
            raise self.bind_error
        self.bound = address

    def ioctl(self, control: int, option: int, /) -> int:
        if self.ioctl_error is not None:
            raise self.ioctl_error
        self.ioctls.append((control, option))
        return 0


class FakeWinsock:
    """What `socket` looks like on Windows: no AF_PACKET, and the receive-all control code."""

    AF_INET = 2
    SOCK_RAW = 3
    IPPROTO_IP = 0
    SIO_RCVALL = 0x98000001
    RCVALL_ON = 1

    def __init__(self, sock: Ioctl | OSError) -> None:
        self.sock = sock
        self.calls: list[tuple[int, int, int]] = []

    def socket(self, family: int, kind: int, proto: int) -> Ioctl:
        self.calls.append((family, kind, proto))
        if isinstance(self.sock, OSError):
            raise self.sock
        return self.sock


@pytest.fixture
def windows(monkeypatch: pytest.MonkeyPatch) -> Any:
    def install(sock: Ioctl | OSError) -> FakeWinsock:
        module = FakeWinsock(sock)
        monkeypatch.setattr(cap, "socket", module)
        return module

    return install


def test_open_capture_binds_a_raw_socket_to_the_address_and_asks_for_everything(
    windows: Any,
) -> None:
    sock = Ioctl()
    module = windows(sock)
    capture = open_capture("192.168.1.20")
    assert module.calls == [(2, 3, 0)]  # AF_INET, SOCK_RAW, IPPROTO_IP
    assert sock.bound == ("192.168.1.20", 0)
    assert sock.ioctls == [(0x98000001, 1)]  # SIO_RCVALL, RCVALL_ON
    sock.script.append(b"\x45" + bytes(19))
    assert next(capture.packets()).data == wrap(b"\x45" + bytes(19), ETHERTYPE_IPV4)


def test_the_loopback_address_is_an_interface_too(windows: Any) -> None:
    sock = Ioctl()
    windows(sock)
    open_capture("127.0.0.1")
    assert sock.bound == ("127.0.0.1", 0)


def test_open_capture_without_administrator_rights_says_what_is_needed(windows: Any) -> None:
    windows(PermissionError(13, "access denied"))
    with pytest.raises(LiveError, match="needs an Administrator prompt"):
        open_capture("192.168.1.20")


def test_open_capture_reports_a_socket_that_cannot_be_made(windows: Any) -> None:
    windows(OSError(10047, "address family not supported"))
    with pytest.raises(LiveError, match=r"cannot open a raw socket: .*not supported"):
        open_capture("192.168.1.20")


def test_open_capture_reports_an_address_no_interface_has_and_closes_the_socket(
    windows: Any,
) -> None:
    sock = Ioctl(bind_error=OSError(10049, "address not valid here"))
    windows(sock)
    with pytest.raises(LiveError, match=r"cannot capture on 10.9.9.9: .*not valid here"):
        open_capture("10.9.9.9")
    assert sock.closed
    assert sock.ioctls == []


def test_open_capture_reports_a_refused_receive_all_and_closes_the_socket(windows: Any) -> None:
    sock = Ioctl(ioctl_error=OSError(10013, "access denied"))
    windows(sock)
    with pytest.raises(LiveError, match=r"cannot capture on 192.168.1.20: .*access denied"):
        open_capture("192.168.1.20")
    assert sock.closed


def test_open_capture_checks_the_address_before_it_opens_a_socket(windows: Any) -> None:
    module = windows(Ioctl())
    with pytest.raises(LiveError, match="not an IPv4 address"):
        open_capture("eth0")
    assert module.calls == []


@pytest.mark.parametrize("name", ["192.168.1.20", "0.0.0.0", "127.0.0.1", "255.255.255.255"])
def test_ipv4_addresses_name_an_interface(name: str) -> None:
    assert check_address(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "eth0",
        "lo",
        "1.2.3",
        "1.2.3.4.5",
        "256.1.1.1",
        "01.2.3.4",
        " 1.2.3.4",
        "1.2.3.4 ",
        "1.2.3.4/24",
        "::1",
        "fe80::1",
        "192.168.1.20:80",
        "1.2.3.-4",
    ],
)
def test_anything_else_is_refused_with_the_way_to_name_an_interface(name: str) -> None:
    with pytest.raises(LiveError, match=r"is not an IPv4 address.*192\.168\.1\.20.*127\.0\.0\.1"):
        check_address(name)


def test_a_system_with_neither_kind_of_socket_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(socket, "AF_PACKET", raising=False)
    monkeypatch.delattr(socket, "SIO_RCVALL", raising=False)
    with pytest.raises(LiveError, match=r"needs Linux .*or Windows .*neither"):
        open_capture("eth0")
