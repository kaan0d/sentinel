import json
import os
import platform
import subprocess
import sys
from itertools import pairwise
from pathlib import Path
from typing import BinaryIO

import pytest

from sentinel import cli
from sentinel.live import Capture
from sentinel.pcap import Packet, PcapWriter
from tools import bench
from tools.gen_pcap import generate, generate_attacks, generate_benign, generate_streams

PARTS = (generate, generate_streams, generate_benign, generate_attacks)
BASE = sum(len(part()) for part in PARTS)
SECOND = 1_000_000_000

STAGE_NAMES = [
    "pcap read",
    "pcap write",
    "pcap write, flushed after every packet",
    "decode",
    "read: decode and print a line",
    "filter: decode and match",
    "flows: decode, reassemble, print",
    "ids: decode and run the default detectors",
    "live loop, printing lines",
    "live loop, running the detectors",
    "live loop, saving to a file",
]


def test_the_corpus_is_the_four_generated_captures_one_after_the_other() -> None:
    packets = bench.corpus(BASE)
    assert [p.data for p in packets] == [p.data for part in PARTS for p in part()]
    assert all(a.ts_ns <= b.ts_ns for a, b in pairwise(packets))
    start = 0
    for part in PARTS[:-1]:
        end = start + len(part())
        # each capture begins one second after the one before it ended
        assert packets[end].ts_ns == max(p.ts_ns for p in packets[start:end]) + SECOND
        start = end


def test_the_corpus_repeats_with_the_time_moved_forward() -> None:
    packets = bench.corpus(2 * BASE + 5)
    assert len(packets) == 2 * BASE + 5
    span = max(p.ts_ns for p in packets[:BASE]) + SECOND - packets[0].ts_ns
    for i in range(BASE + 5):
        assert packets[BASE + i].data == packets[i].data
        assert packets[BASE + i].orig_len == packets[i].orig_len
        assert packets[BASE + i].ts_ns - packets[i].ts_ns == span
    assert packets[BASE].ts_ns > max(p.ts_ns for p in packets[:BASE])
    assert all(a.ts_ns <= b.ts_ns for a, b in pairwise(packets))


def test_the_corpus_has_exactly_the_number_of_packets_asked_for() -> None:
    assert len(bench.corpus(1)) == 1
    assert len(bench.corpus(5)) == 5
    assert len(bench.corpus(BASE + 3)) == BASE + 3
    assert bench.corpus(300) == bench.corpus(300)
    with pytest.raises(ValueError, match="at least 1"):
        bench.corpus(0)


def test_a_row_says_packets_per_second_microseconds_and_megabytes() -> None:
    row = bench.Row("x", 1000, 2_000_000, 0.5)
    assert row.rate == 2000
    assert row.micros_per_packet == 500.0
    assert row.megabytes_per_second == 4.0


class Timer:
    """A clock that reads out the given times, two per run: when it started and when it ended."""

    def __init__(self, *times: float) -> None:
        self.times = iter(times)

    def __call__(self) -> float:
        return next(self.times)


def test_the_fastest_run_is_kept() -> None:
    packets = bench.corpus(10)
    runs = [0]

    def stage() -> int:
        runs[0] += 1
        return 10

    row = bench.measure("s", stage, packets, 3, Timer(0, 2, 10, 11, 20, 23))
    assert runs == [3]
    assert row.seconds == 1.0  # runs of 2, 1 and 3 seconds
    assert (row.name, row.packets) == ("s", 10)
    assert row.wire_bytes == sum(len(p.data) for p in packets)
    assert row.rate == 10.0


def test_a_stage_that_did_not_handle_every_packet_is_an_error() -> None:
    with pytest.raises(RuntimeError, match="s: handled 9 packets, expected 10"):
        bench.measure("s", lambda: 9, bench.corpus(10), 1)


def test_at_least_one_run_is_needed() -> None:
    with pytest.raises(ValueError, match="repeat must be at least 1"):
        bench.measure("s", lambda: 10, bench.corpus(10), 0)


def test_every_stage_handles_every_packet() -> None:
    packets = bench.corpus(300)
    stages = bench.stages(packets)
    assert [name for name, _ in stages] == STAGE_NAMES
    for name, stage in stages:
        assert stage() == 300, name


def test_run_measures_every_stage_in_order() -> None:
    rows = bench.run(300, 1)
    assert [r.name for r in rows] == STAGE_NAMES
    assert all(r.packets == 300 and r.seconds > 0 and r.rate > 0 for r in rows)


def test_the_flushed_writer_really_flushes(monkeypatch: pytest.MonkeyPatch) -> None:
    sizes: list[int] = []

    class Spy(PcapWriter):
        def __init__(self, fp: BinaryIO) -> None:
            super().__init__(fp)
            self._name = str(getattr(fp, "name", ""))

        def write(self, packet: Packet) -> None:
            if self._name:  # the capture that is only built for reading has no file
                sizes.append(os.path.getsize(self._name))  # what is on disk before this packet
            super().write(packet)

    monkeypatch.setattr(bench, "PcapWriter", Spy)
    stages = dict(bench.stages(bench.corpus(6)))
    sizes.clear()
    stages["pcap write"]()
    assert sizes == [0] * 6  # small: all of it waits in the buffer
    sizes.clear()
    stages["pcap write, flushed after every packet"]()
    assert sizes[0] == 0
    assert all(later > earlier for earlier, later in pairwise(sizes))


def test_the_live_stages_print_nothing_and_leave_the_command_as_it_was(
    capsys: pytest.CaptureFixture[str],
) -> None:
    real = vars(cli)["open_capture"]
    assert bench._live(bench.corpus(50)) == 50
    assert bench._live(bench.corpus(50), "--ids") == 50
    assert capsys.readouterr() == ("", "")
    assert vars(cli)["open_capture"] is real


def test_a_live_run_that_fails_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "main", lambda argv: 1)
    with pytest.raises(RuntimeError, match="live exited with 1"):
        bench._live(bench.corpus(5))


def test_the_replay_socket_times_out_when_the_frames_are_used_up() -> None:
    sock = bench._Replay(iter([b"abc"]))
    assert sock.recvfrom(100)[0] == b"abc"
    with pytest.raises(TimeoutError):
        sock.recvfrom(100)


def test_the_replay_socket_gives_up_when_the_loop_never_stops() -> None:
    sock = bench._Replay(iter([]))
    for _ in range(bench.MAX_IDLE):
        with pytest.raises(TimeoutError):
            sock.recvfrom(100)
    with pytest.raises(RuntimeError, match="did not stop after the last packet"):
        sock.recvfrom(100)


def test_a_live_loop_that_asks_for_one_packet_too_many_fails_instead_of_hanging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bench, "MAX_IDLE", 5)
    packets = bench.corpus(20)
    stamps = iter(p.ts_ns for p in packets)
    # ask for more packets than the stand-in has: the loop keeps receiving after the last one
    sock = bench._Replay(iter(p.data for p in packets))
    capture = Capture(sock, lambda: next(stamps))
    with pytest.raises(RuntimeError, match="did not stop"):
        for _ in capture.packets(duration=1.0):  # the time limit is only a safety net
            pass


def test_the_table() -> None:
    rows = [bench.Row("decode", 1000, 100_000, 0.01), bench.Row("read", 1000, 100_000, 0.02)]
    lines = bench.render(rows, 3).splitlines()
    assert lines[0] == "sentinel benchmark: 1,000 packets, 0.1 MB on the wire, fastest of 3"
    assert lines[1].startswith(f"python {platform.python_version()} on ")
    assert lines[3].split() == ["stage", "packets/s", "us/packet", "MB/s"]
    assert lines[4].split() == ["decode", "100,000", "10.0", "10.0"]
    assert lines[5].split() == ["read", "50,000", "20.0", "5.0"]


def test_the_json_output() -> None:
    rows = [bench.Row("decode", 1000, 100_000, 0.01)]
    data = json.loads(bench.as_json(rows, 3))
    assert data["packets"] == 1000
    assert data["wire_bytes"] == 100_000
    assert data["repeat"] == 3
    assert data["environment"]["python"] == platform.python_version()
    assert data["rows"] == [
        {
            "stage": "decode",
            "seconds": 0.01,
            "packets_per_second": 100_000.0,
            "microseconds_per_packet": 10.0,
            "megabytes_per_second": 10.0,
        }
    ]


def test_the_command_prints_the_table(capsys: pytest.CaptureFixture[str]) -> None:
    assert bench.main(["-n", "300", "-r", "1"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("sentinel benchmark: 300 packets")
    assert all(name in out for name in STAGE_NAMES)


def test_the_command_prints_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert bench.main(["--packets", "300", "--repeat", "1", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [r["stage"] for r in data["rows"]] == STAGE_NAMES
    assert data["packets"] == 300


def test_the_defaults() -> None:
    assert (bench.DEFAULT_PACKETS, bench.DEFAULT_REPEAT) == (100_000, 3)


@pytest.mark.parametrize("option", ["--packets", "--repeat"])
@pytest.mark.parametrize("value", ["0", "-1", "x", "1.5", ""])
def test_packets_and_repeat_must_be_positive_whole_numbers(
    option: str, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as stop:
        bench.main([option, value])
    assert stop.value.code == 2
    assert "is not a positive whole number" in capsys.readouterr().err


def test_the_tool_runs_as_a_module(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parent.parent
    done = subprocess.run(
        [sys.executable, "-m", "tools.bench", "-n", "200", "-r", "1"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    assert "sentinel benchmark: 200 packets" in done.stdout
    assert generate_attacks()  # the module and its generators are importable side by side
