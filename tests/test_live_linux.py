"""Live capture on a real interface. Runs only on Linux, as root (or with CAP_NET_RAW):

    sudo python -m pytest tests/test_live_linux.py

It captures on the loopback interface, so it needs no network and sends nothing outside the
machine."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from sentinel.live import LiveError, open_capture
from sentinel.proto.decode import decode
from sentinel.proto.ipv4 import IPv4
from sentinel.proto.udp import Udp

IS_LINUX = sys.platform == "linux"
IS_ROOT = getattr(os, "geteuid", lambda: 1)() == 0

needs_root = pytest.mark.skipif(not (IS_LINUX and IS_ROOT), reason="needs Linux and root")


def send_udp(payload: bytes, port: int = 40444) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, ("127.0.0.1", port))


@needs_root
def test_a_datagram_sent_to_loopback_is_captured_and_decoded() -> None:
    capture = open_capture("lo")
    try:
        marker = b"sentinel-live-test-" + os.urandom(8).hex().encode()
        send_udp(marker)
        for packet in capture.packets(5):
            layers = decode(packet.data)
            udp = next((layer for layer in layers if isinstance(layer, Udp)), None)
            if udp is not None and udp.payload == marker:
                ip = next(layer for layer in layers if isinstance(layer, IPv4))
                assert (str(ip.src), str(ip.dst), udp.dst_port) == ("127.0.0.1", "127.0.0.1", 40444)
                assert abs(packet.ts_ns - time.time_ns()) < 10_000_000_000
                break
        else:
            pytest.fail("the datagram was not captured")
    finally:
        capture.close()


@needs_root
def test_the_command_line_captures_a_datagram(tmp_path: Path) -> None:
    out = str(tmp_path / "lo.pcap")
    command = [sys.executable, "-m", "sentinel", "live", "lo", "-f", "udp port 40445", "-c", "1"]
    proc = subprocess.Popen(
        [*command, "-w", out],
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


@pytest.mark.skipif(not IS_LINUX or IS_ROOT, reason="needs Linux and a normal user")
def test_without_root_the_error_says_what_is_needed() -> None:
    with pytest.raises(LiveError, match="root or the CAP_NET_RAW"):
        open_capture("lo")


@pytest.mark.skipif(not IS_LINUX, reason="needs Linux")
def test_an_interface_that_does_not_exist() -> None:
    with pytest.raises(LiveError, match="no such interface: nope0"):
        open_capture("nope0")


@needs_root
def test_a_datagram_on_loopback_is_seen_exactly_once() -> None:
    # The kernel gives a packet socket each loopback packet twice, leaving and arriving. The
    # capture drops the leaving copy, so a datagram must appear once.
    capture = open_capture("lo")
    try:
        marker = b"sentinel-once-" + os.urandom(8).hex().encode()
        send_udp(marker, 40446)
        seen = 0
        for packet in capture.packets(1.5):
            udp = next((layer for layer in decode(packet.data) if isinstance(layer, Udp)), None)
            if udp is not None and udp.payload == marker:
                seen += 1
        assert seen == 1
    finally:
        capture.close()
