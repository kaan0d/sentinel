"""The `live` command, driven by a pretend interface that hands out the packets of the generated
captures. The clock replays the timestamps those packets have, so the output must be exactly what
`read` and `ids` print for the same capture."""

import io
import random
import struct
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fake_socket import FakeSocket

from sentinel import cli
from sentinel.cli import main
from sentinel.live import Capture, LiveError
from sentinel.pcap import Packet, PcapReader, PcapWriter
from sentinel.proto.decode import decode
from sentinel.proto.udp import Udp
from tools import gen_pcap


def write_pcap(path: Path, packets: list[Packet]) -> Path:
    with path.open("wb") as fp:
        writer = PcapWriter(fp)
        for packet in packets:
            writer.write(packet)
    return path


def pretend(
    monkeypatch: pytest.MonkeyPatch,
    packets: list[Packet],
    *,
    tail: list[BaseException] | None = None,
    stats: bytes = b"",
    on_receive: Callable[[int], None] | None = None,
    max_calls: int = 100_000,
) -> FakeSocket:
    """Make `live` capture `packets` (then whatever is in `tail`) from a fake interface."""
    script: list[bytes | tuple[bytes, Any] | BaseException] = [
        *(p.data for p in packets),
        *(tail or []),
    ]
    sock = FakeSocket(script, stats=stats, on_receive=on_receive, max_calls=max_calls)
    stamps: Iterator[int] = iter(p.ts_ns for p in packets)

    def open_capture(name: str) -> Capture:
        return Capture(sock, lambda: next(stamps))

    monkeypatch.setattr(cli, "open_capture", open_capture)
    return sock


@pytest.fixture
def sample_packets() -> list[Packet]:
    return gen_pcap.generate()


@pytest.fixture
def attack_packets() -> list[Packet]:
    return gen_pcap.generate_attacks()


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = main(["live", "eth0", *args])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_live_prints_what_read_prints(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
    tmp_path: Path,
) -> None:
    assert main(["read", str(write_pcap(tmp_path / "s.pcap", sample_packets))]) == 0
    expected = capsys.readouterr().out
    sock = pretend(monkeypatch, sample_packets)
    code, out, err = run(capsys, "--count", str(len(sample_packets)))
    assert code == 0
    assert out == expected
    assert err == f"# {len(sample_packets)} packets\n"
    assert sock.closed


def test_count_stops_the_capture(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
) -> None:
    sock = pretend(monkeypatch, sample_packets)
    code, out, err = run(capsys, "-c", "3")
    assert code == 0
    assert len(out.splitlines()) == 3
    assert err == "# 3 packets\n"
    assert sock.calls == 3  # it did not read one packet more
    assert sock.closed


def test_a_filter_selects_what_is_printed_and_counted(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
) -> None:
    pretend(monkeypatch, sample_packets)
    code, out, err = run(capsys, "--filter", "arp", "--count", "2")
    assert code == 0
    request, reply = out.splitlines()
    assert "ARP, Request who-has 10.0.0.2 tell 10.0.0.1" in request
    assert "ARP, Reply 10.0.0.2 is-at" in reply
    assert err == "# 2 packets\n"


def test_the_count_is_of_packets_that_match_the_filter(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
) -> None:
    sock = pretend(monkeypatch, sample_packets)
    code, out, err = run(capsys, "--filter", "icmp", "--count", "2")
    assert code == 0
    assert len(out.splitlines()) == 2
    assert all(" ICMP " in line for line in out.splitlines())
    assert sock.calls < len(sample_packets)  # it stopped early, at the second ICMP packet
    assert err == "# 2 packets\n"


def test_a_bad_filter_is_reported_before_the_interface_is_opened(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(name: str) -> Capture:
        raise AssertionError("the interface was opened")

    monkeypatch.setattr(cli, "open_capture", refuse)
    code, out, err = run(capsys, "--filter", "tcp and port http")
    assert (code, out) == (2, "")
    assert err.startswith("sentinel: invalid filter: expected a port number")


def test_write_saves_the_capture_as_a_pcap_file(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
    tmp_path: Path,
) -> None:
    pretend(monkeypatch, sample_packets)
    target = tmp_path / "out.pcap"
    code, out, _ = run(capsys, "--write", str(target), "-c", str(len(sample_packets)))
    assert code == 0
    assert len(out.splitlines()) == len(sample_packets)  # still printed
    with target.open("rb") as fp:
        assert list(PcapReader(fp)) == sample_packets


def test_write_only_saves_the_packets_that_match_the_filter(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
    tmp_path: Path,
) -> None:
    pretend(monkeypatch, sample_packets)
    target = tmp_path / "udp.pcap"
    code, _, err = run(capsys, "-w", str(target), "-f", "udp", "-c", "4")
    assert code == 0
    assert err == "# 4 packets\n"
    with target.open("rb") as fp:
        saved = list(PcapReader(fp))
    assert len(saved) == 4
    assert all(p in sample_packets for p in saved)
    assert all(any(isinstance(layer, Udp) for layer in decode(p.data)) for p in saved)


def test_write_reaches_the_disk_while_the_capture_runs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
    tmp_path: Path,
) -> None:
    target = tmp_path / "live.pcap"
    seen: list[int] = []

    def on_receive(call: int) -> None:
        if call > 1 and target.exists():
            seen.append(target.stat().st_size)

    pretend(monkeypatch, sample_packets[:3], on_receive=on_receive)
    code, _, _ = run(capsys, "-w", str(target), "--count", "3")
    assert code == 0
    header = 24
    first = header + 16 + len(sample_packets[0].data)
    both = first + 16 + len(sample_packets[1].data)
    # Before the next receive, everything written so far is already in the file (a capture that is
    # killed still leaves a file that can be read).
    assert seen == [first, both]


def test_write_to_a_path_that_cannot_be_opened(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
    tmp_path: Path,
) -> None:
    sock = pretend(monkeypatch, sample_packets)
    code, out, err = run(capsys, "-w", str(tmp_path), "-c", "1")
    assert (code, out) == (1, "")
    assert err.startswith(f"sentinel: {tmp_path}: ")
    assert sock.closed
    assert sock.calls == 0  # nothing was captured


def test_ids_prints_the_alerts_the_ids_command_prints(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    attack_packets: list[Packet],
    tmp_path: Path,
) -> None:
    pcap = write_pcap(tmp_path / "a.pcap", attack_packets)
    assert main(["ids", str(pcap)]) == 0
    expected = capsys.readouterr().out
    assert len(expected.splitlines()) == 13
    pretend(monkeypatch, attack_packets)
    code, out, err = run(capsys, "--ids", "--count", str(len(attack_packets)))
    assert code == 0
    assert out == expected
    assert err == f"# {len(attack_packets)} packets\n"


def test_ids_text_format_and_rules(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    attack_packets: list[Packet],
    tmp_path: Path,
) -> None:
    rules = tmp_path / "rules.toml"
    rules.write_text('[[rule]]\nid = "flood"\ndetector = "syn_flood"\nseverity = "critical"\n')
    pcap = write_pcap(tmp_path / "a.pcap", attack_packets)
    assert main(["ids", str(pcap), "--rules", str(rules), "--format", "text"]) == 0
    expected = capsys.readouterr().out
    assert expected.count("\n") == 1
    pretend(monkeypatch, attack_packets)
    code, out, _ = run(
        capsys, "--ids", "--rules", str(rules), "--format", "text", "-c", str(len(attack_packets))
    )
    assert code == 0
    assert out == expected
    assert "[critical] flood: 100 SYNs to 10.0.0.2:80" in out


def test_alerts_are_printed_when_they_happen_not_at_the_end(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    attack_packets: list[Packet],
) -> None:
    lines_by_call: list[int] = []
    total = 0

    def on_receive(call: int) -> None:
        nonlocal total
        total += len(capsys.readouterr().out.splitlines())
        lines_by_call.append(total)

    pretend(monkeypatch, attack_packets, on_receive=on_receive)
    code = main(["live", "eth0", "--ids", "--count", str(len(attack_packets))])
    total += len(capsys.readouterr().out.splitlines())
    assert code == 0
    assert total == 13
    # The first port scan is complete at the 27th packet: its alert is out before the 28th arrives.
    assert next(i for i, n in enumerate(lines_by_call) if n > 0) == 27
    # Five port scans and the SYN flood are out before the ARP packets (the 902nd) arrive.
    assert lines_by_call[901] == 6


def test_ids_with_bad_rules_exits_before_the_interface_is_opened(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def refuse(name: str) -> Capture:
        raise AssertionError("the interface was opened")

    monkeypatch.setattr(cli, "open_capture", refuse)
    rules = tmp_path / "bad.toml"
    rules.write_text('[[rule]]\nid = "x"\ndetector = "nope"\n')
    code, out, err = run(capsys, "--ids", "--rules", str(rules))
    assert (code, out) == (2, "")
    assert err.startswith("sentinel: invalid rules:\n  ")
    assert "unknown detector 'nope'" in err


def test_ids_reports_at_the_end_when_a_state_limit_dropped_packets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    attack_packets: list[Packet],
) -> None:
    monkeypatch.setattr("sentinel.ids.detectors.MAX_KEYS", 1)
    pretend(monkeypatch, attack_packets)
    code, out, _ = run(capsys, "--ids", "--format", "text", "-c", str(len(attack_packets)))
    assert code == 0
    last = out.splitlines()[-1]
    assert "packets were not tracked: the detector's state limit was reached" in last


@pytest.mark.parametrize("option", ["--rules", "--format"])
def test_rules_and_format_need_ids(
    option: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(name: str) -> Capture:
        raise AssertionError("the interface was opened")

    monkeypatch.setattr(cli, "open_capture", refuse)
    value = "json" if option == "--format" else "rules.toml"
    with pytest.raises(SystemExit) as stop:
        main(["live", "eth0", option, value])
    assert stop.value.code == 2
    assert "only work together with --ids" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--count", "0"),
        ("--count", "-1"),
        ("--count", "many"),
        ("--count", "1.5"),
        ("--count", " 3"),
        ("--duration", "0"),
        ("--duration", "-1"),
        ("--duration", "nan"),
        ("--duration", "soon"),
    ],
)
def test_count_and_duration_must_be_positive_numbers(
    option: str, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["live", "eth0", option, value])
    assert stop.value.code == 2
    assert f"{value!r} is not a" in capsys.readouterr().err


def test_an_interface_that_cannot_be_opened_exits_with_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(name: str) -> Capture:
        raise LiveError("live capture needs root or the CAP_NET_RAW capability")

    monkeypatch.setattr(cli, "open_capture", refuse)
    code, out, err = run(capsys)
    assert (code, out) == (1, "")
    assert err == "sentinel: live capture needs root or the CAP_NET_RAW capability\n"


def test_ctrl_c_ends_the_capture_normally(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
) -> None:
    sock = pretend(monkeypatch, sample_packets[:2], tail=[KeyboardInterrupt()])
    code, out, err = run(capsys)
    assert code == 0
    assert len(out.splitlines()) == 2
    assert err == "# 2 packets\n"
    assert sock.closed


def test_ctrl_c_with_ids_ends_normally(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    attack_packets: list[Packet],
) -> None:
    pretend(monkeypatch, attack_packets[:400], tail=[KeyboardInterrupt()])
    code, out, err = run(capsys, "--ids")
    assert code == 0
    assert out.count("\n") >= 1
    assert err == "# 400 packets\n"


def test_an_error_while_capturing_keeps_what_was_seen_and_exits_with_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
) -> None:
    sock = pretend(monkeypatch, sample_packets[:2], tail=[OSError("Network is down")])
    code, out, err = run(capsys)
    assert code == 1
    assert len(out.splitlines()) == 2
    assert err == "sentinel: eth0: Network is down\n# 2 packets\n"
    assert sock.closed


def test_the_footer_reports_packets_the_kernel_dropped(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    sample_packets: list[Packet],
) -> None:
    pretend(monkeypatch, sample_packets[:2], stats=struct.pack("=II", 9, 7))
    code, _, err = run(capsys, "-c", "2")
    assert code == 0
    assert err == "# 2 packets, 7 dropped by the kernel\n"


def test_the_capture_ends_after_the_duration(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sock = pretend(monkeypatch, [], max_calls=50)
    sock.on_wait = time.sleep
    code, out, err = run(capsys, "--duration", "0.05")
    assert (code, out, err) == (0, "", "# 0 packets\n")
    assert sock.timeouts
    assert all(t is not None and 0 < t <= 0.05 for t in sock.timeouts)


def random_frames(seed: int, n: int) -> list[Packet]:
    rng = random.Random(seed)
    frames = [b"", b"\x00", b"\xff" * 14, rng.randbytes(65535)]
    frames += [rng.randbytes(rng.randrange(0, 200)) for _ in range(n)]
    for packet in gen_pcap.generate_attacks()[::20]:
        cut = rng.randrange(len(packet.data) + 1)
        frames.append(packet.data[:cut])
        bad = bytearray(packet.data)
        bad[rng.randrange(len(bad))] = rng.randrange(256)
        frames.append(bytes(bad))
    return [Packet(1_700_000_000_000_000_000 + i, len(f), f) for i, f in enumerate(frames)]


@pytest.mark.parametrize("extra", [[], ["--ids"]])
def test_frames_from_the_network_never_crash_the_capture(
    extra: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    frames = random_frames(31, 300)
    pretend(monkeypatch, frames)
    code, out, err = run(capsys, *extra, "--count", str(len(frames)))
    assert code == 0
    assert err == f"# {len(frames)} packets\n"
    if not extra:
        assert len(out.splitlines()) == len(frames)  # one line each, whatever was in it


class FlushCounter(io.StringIO):
    flushes = 0

    def flush(self) -> None:
        self.flushes += 1
        super().flush()


@pytest.mark.parametrize("extra", [[], ["--ids"]])
def test_every_line_is_flushed_so_a_pipe_sees_it_at_once(
    extra: list[str],
    monkeypatch: pytest.MonkeyPatch,
    attack_packets: list[Packet],
    sample_packets: list[Packet],
) -> None:
    packets = attack_packets[:30] if extra else sample_packets[:3]
    pretend(monkeypatch, packets)
    counter = FlushCounter()
    monkeypatch.setattr("sys.stdout", counter)
    assert main(["live", "eth0", *extra, "-c", str(len(packets))]) == 0
    lines = len(counter.getvalue().splitlines())
    assert lines >= 1
    assert counter.flushes >= lines
