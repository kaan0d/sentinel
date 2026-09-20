"""Live capture on a real Windows interface. Runs only on Windows, from an Administrator prompt:

    python -m pytest tests/test_live_windows.py

It captures on the loopback address, so it needs no network and sends nothing outside the
machine."""

import ctypes
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from sentinel.live import LiveError, open_capture
from sentinel.proto.decode import decode
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.tcp import ACK, SYN, Tcp
from sentinel.proto.udp import Udp

IS_WINDOWS = sys.platform == "win32"
IS_ADMIN = IS_WINDOWS and bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined,unused-ignore]

needs_admin = pytest.mark.skipif(not IS_ADMIN, reason="needs Windows and Administrator rights")


def send_udp(payload: bytes, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, ("127.0.0.1", port))


def count_udp(marker: bytes, port: int, seconds: float = 1.5) -> int:
    capture = open_capture("127.0.0.1")
    try:
        send_udp(marker, port)
        seen = 0
        for packet in capture.packets(seconds):
            udp = next((layer for layer in decode(packet.data) if isinstance(layer, Udp)), None)
            if udp is not None and udp.payload == marker:
                seen += 1
        return seen
    finally:
        capture.close()


@needs_admin
def test_a_datagram_sent_to_loopback_is_captured_and_decoded() -> None:
    capture = open_capture("127.0.0.1")
    try:
        marker = b"sentinel-live-test-" + os.urandom(8).hex().encode()
        send_udp(marker, 40444)
        for packet in capture.packets(5):
            layers = decode(packet.data)
            udp = next((layer for layer in layers if isinstance(layer, Udp)), None)
            if udp is not None and udp.payload == marker:
                ip = next(layer for layer in layers if isinstance(layer, IPv4))
                assert (str(ip.src), str(ip.dst), udp.dst_port) == ("127.0.0.1", "127.0.0.1", 40444)
                # A GitHub runner (Windows Server 2025) hands out loopback packets whose IPv4 header
                # checksum is still 0, left to the network card; this machine fills it in.
                assert ip.anomalies in ((), ("bad ipv4 header checksum",))
                assert ip.anomalies == () or ip.checksum == 0
                assert abs(packet.ts_ns - time.time_ns()) < 10_000_000_000
                break
        else:
            pytest.fail("the datagram was not captured")
    finally:
        capture.close()


@needs_admin
def test_a_datagram_on_loopback_is_seen_exactly_once() -> None:
    assert count_udp(b"sentinel-once-" + os.urandom(8).hex().encode(), 40446) == 1


@needs_admin
def test_a_tcp_conversation_on_loopback_is_captured_in_both_directions() -> None:
    marker = b"sentinel-tcp-" + os.urandom(8).hex().encode()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    reply = marker[::-1]

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.recv(1000)
            connection.sendall(reply)

    server = threading.Thread(target=serve)
    server.start()
    capture = open_capture("127.0.0.1")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.sendall(marker)
            assert client.recv(1000) == reply
        server.join(5)
        packets = []
        for packet in capture.packets(1.5):
            layers = decode(packet.data)
            tcp = next((layer for layer in layers if isinstance(layer, Tcp)), None)
            if tcp is not None and port in (tcp.src_port, tcp.dst_port):
                packets.append(tcp)
    finally:
        capture.close()
        listener.close()
    assert [t.payload for t in packets if t.payload] == [marker, reply]  # each once
    assert sum(1 for t in packets if t.flags & SYN and not t.flags & ACK) == 1  # one SYN
    assert sum(1 for t in packets if t.flags & SYN and t.flags & ACK) == 1  # one SYN-ACK


@needs_admin
def test_the_command_line_captures_a_datagram(tmp_path: Path) -> None:
    out = str(tmp_path / "lo.pcap")
    command = [sys.executable, "-m", "sentinel", "live", "127.0.0.1", "-f", "udp port 40445"]
    proc = subprocess.Popen(
        [*command, "-c", "1", "-w", out],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(50):  # the socket is opened a moment after the process starts
        time.sleep(0.1)
        send_udp(b"hello from the test", 40445)
        if proc.poll() is not None:
            break
    try:
        stdout, stderr = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    assert proc.returncode == 0, stderr
    assert "UDP, length 19" in stdout
    assert stderr == "# 1 packets\n"
    saved = subprocess.run(
        [sys.executable, "-m", "sentinel", "read", out], capture_output=True, text=True, check=True
    )
    assert saved.stdout == stdout


@pytest.mark.skipif(not IS_WINDOWS or IS_ADMIN, reason="needs Windows and a normal prompt")
def test_without_administrator_rights_the_error_says_what_is_needed() -> None:
    with pytest.raises(LiveError, match="needs an Administrator prompt"):
        open_capture("127.0.0.1")


@needs_admin
def test_an_address_that_no_interface_has() -> None:
    with pytest.raises(LiveError, match=r"cannot capture on 203\.0\.113\.7: "):
        open_capture("203.0.113.7")  # documentation range: never assigned to a machine
