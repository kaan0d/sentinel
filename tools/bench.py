"""Measure how many packets per second each part of Sentinel handles.

    python -m tools.bench [--packets N] [--repeat R] [--json]

The traffic is the project's own synthetic captures (the demo, the reassembly demo, the harmless
traffic and the attacks), repeated with the time moved forward so every copy comes after the
last one. The workload is the same on every machine; the timings are not, so a number here
describes the machine it ran on. Each stage runs `--repeat` times and the fastest run is kept,
which is the run least disturbed by the rest of the system.
"""

import argparse
import contextlib
import gc
import io
import itertools
import json
import os
import platform
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from sentinel import cli
from sentinel.filter import parse_filter
from sentinel.flow import FlowTable
from sentinel.flow.report import format_flow
from sentinel.ids import Engine, default_rules
from sentinel.live import Capture
from sentinel.pcap import Packet, PcapReader, PcapWriter
from sentinel.proto.decode import decode
from sentinel.summary import summarize
from tools.gen_pcap import generate, generate_attacks, generate_benign, generate_streams

DEFAULT_PACKETS = 100_000
DEFAULT_REPEAT = 3
FILTER = "tcp and (port 80 or port 443) and not src host 10.0.0.1"
ONE_SECOND = 1_000_000_000
MAX_IDLE = 1000  # receives that may time out after the last frame before the run is called stuck

Stage = Callable[[], int]  # does the work once and returns how many packets it handled


def corpus(count: int) -> list[Packet]:
    """`count` packets: the four generated captures one after the other, then the same again,
    each copy starting one second after the previous one ended."""
    if count < 1:
        raise ValueError("count must be at least 1")
    base: list[Packet] = []
    start = cursor = generate()[0].ts_ns
    for part in (generate(), generate_streams(), generate_benign(), generate_attacks()):
        shift = cursor - min(p.ts_ns for p in part)
        base += [Packet(p.ts_ns + shift, p.orig_len, p.data) for p in part]
        cursor = max(p.ts_ns for p in base) + ONE_SECOND
    span = cursor - start
    out: list[Packet] = []
    for copy in itertools.count():
        for p in base:
            out.append(Packet(p.ts_ns + copy * span, p.orig_len, p.data))
            if len(out) >= count:
                return out
    raise AssertionError("unreachable")


@dataclass(frozen=True, slots=True)
class Row:
    name: str
    packets: int
    wire_bytes: int
    seconds: float

    @property
    def rate(self) -> float:
        """Packets per second."""
        return self.packets / self.seconds

    @property
    def micros_per_packet(self) -> float:
        return self.seconds * 1e6 / self.packets

    @property
    def megabytes_per_second(self) -> float:
        return self.wire_bytes / self.seconds / 1e6


def measure(
    name: str,
    stage: Stage,
    packets: Sequence[Packet],
    repeat: int,
    timer: Callable[[], float] = time.perf_counter,
) -> Row:
    """Run `stage` `repeat` times and keep the fastest run."""
    best: float | None = None
    for _ in range(repeat):
        gc.collect()
        start = timer()
        handled = stage()
        elapsed = timer() - start
        if handled != len(packets):
            raise RuntimeError(f"{name}: handled {handled} packets, expected {len(packets)}")
        best = elapsed if best is None else min(best, elapsed)
    if best is None:
        raise ValueError("repeat must be at least 1")
    return Row(name, len(packets), sum(len(p.data) for p in packets), best)


class _Replay:
    """A packet socket that hands out frames, then times out. The same stand-in the tests use."""

    def __init__(self, frames: Iterator[bytes]) -> None:
        self._frames = frames
        self._idle = 0

    def recvfrom(self, bufsize: int, /) -> tuple[bytes, object]:
        frame = next(self._frames, None)
        if frame is None:
            self._idle += 1
            if self._idle > MAX_IDLE:
                raise RuntimeError("the live loop did not stop after the last packet")
            raise TimeoutError
        return frame, ("eth0", 3, 0, 1, b"")

    def settimeout(self, value: float | None, /) -> None:
        pass

    def getsockopt(self, level: int, optname: int, buflen: int, /) -> bytes:
        return b""

    def close(self) -> None:
        pass


def _live(packets: Sequence[Packet], *options: str) -> int:
    """The real `live` command on a stand-in socket, its output thrown away."""
    stamps = iter(p.ts_ns for p in packets)
    frames = iter(p.data for p in packets)

    def open_capture(name: str) -> Capture:
        return Capture(_Replay(frames), lambda: next(stamps))

    with (
        mock.patch.object(cli, "open_capture", open_capture),
        open(os.devnull, "w") as null,
        contextlib.redirect_stdout(null),
        contextlib.redirect_stderr(null),
    ):
        code = cli.main(["live", "eth0", "--count", str(len(packets)), *options])
    if code != 0:
        raise RuntimeError(f"live exited with {code}")
    return len(packets)


def stages(packets: Sequence[Packet]) -> list[tuple[str, Stage]]:
    """Every stage that is measured, in the order they are reported."""
    blob = io.BytesIO()
    writer = PcapWriter(blob)
    for p in packets:
        writer.write(p)
    capture = blob.getvalue()
    flt = parse_filter(FILTER)
    if flt.error is not None:
        raise AssertionError(flt.error)

    def pcap_write(flush: bool) -> Stage:
        def run() -> int:
            with tempfile.TemporaryDirectory() as tmp, (Path(tmp) / "out.pcap").open("wb") as fp:
                w = PcapWriter(fp)
                for p in packets:
                    w.write(p)
                    if flush:
                        fp.flush()
            return len(packets)

        return run

    def pcap_read() -> int:
        return sum(1 for _ in PcapReader(io.BytesIO(capture)))

    def decode_all() -> int:
        for p in packets:
            decode(p.data)
        return len(packets)

    def read_lines() -> int:
        for p in packets:
            summarize(p, decode(p.data))
        return len(packets)

    def filter_all() -> int:
        for p in packets:
            flt.matches(decode(p.data))
        return len(packets)

    def flows() -> int:
        table = FlowTable()
        for p in packets:
            table.add(p, decode(p.data))
        for flow in table.flows:
            format_flow(flow)
        return len(packets)

    def ids() -> int:
        engine = Engine(default_rules().rules)
        for p in packets:
            engine.process(p)
        engine.finish()
        return len(packets)

    def live_write() -> int:
        with tempfile.TemporaryDirectory() as tmp:
            return _live(packets, "--write", str(Path(tmp) / "live.pcap"))

    return [
        ("pcap read", pcap_read),
        ("pcap write", pcap_write(False)),
        ("pcap write, flushed after every packet", pcap_write(True)),
        ("decode", decode_all),
        ("read: decode and print a line", read_lines),
        ("filter: decode and match", filter_all),
        ("flows: decode, reassemble, print", flows),
        ("ids: decode and run the default detectors", ids),
        ("live loop, printing lines", lambda: _live(packets)),
        ("live loop, running the detectors", lambda: _live(packets, "--ids")),
        ("live loop, saving to a file", live_write),
    ]


def run(count: int, repeat: int, timer: Callable[[], float] = time.perf_counter) -> list[Row]:
    packets = corpus(count)
    return [measure(name, stage, packets, repeat, timer) for name, stage in stages(packets)]


def environment() -> dict[str, str | int]:
    return {
        "python": platform.python_version(),
        "system": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "logical_cpus": os.cpu_count() or 0,
    }


def render(rows: Sequence[Row], repeat: int) -> str:
    env = environment()
    first = rows[0]
    lines = [
        f"sentinel benchmark: {first.packets:,} packets, {first.wire_bytes / 1e6:.1f} MB on the "
        f"wire, fastest of {repeat}",
        f"python {env['python']} on {env['system']}, {env['processor']}, "
        f"{env['logical_cpus']} logical CPUs",
        "",
        f"{'stage':<42}{'packets/s':>12}{'us/packet':>12}{'MB/s':>10}",
    ]
    lines += [
        f"{r.name:<42}{r.rate:>12,.0f}{r.micros_per_packet:>12.1f}{r.megabytes_per_second:>10.1f}"
        for r in rows
    ]
    return "\n".join(lines)


def as_json(rows: Sequence[Row], repeat: int) -> str:
    return json.dumps(
        {
            "environment": environment(),
            "packets": rows[0].packets,
            "wire_bytes": rows[0].wire_bytes,
            "repeat": repeat,
            "rows": [
                {
                    "stage": r.name,
                    "seconds": r.seconds,
                    "packets_per_second": r.rate,
                    "microseconds_per_packet": r.micros_per_packet,
                    "megabytes_per_second": r.megabytes_per_second,
                }
                for r in rows
            ],
        },
        indent=2,
    )


def _positive(text: str) -> int:
    if not text.isdecimal() or int(text) < 1:
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive whole number")
    return int(text)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure packets per second for each stage")
    parser.add_argument("--packets", "-n", type=_positive, default=DEFAULT_PACKETS)
    parser.add_argument("--repeat", "-r", type=_positive, default=DEFAULT_REPEAT)
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = parser.parse_args(argv)
    rows = run(args.packets, args.repeat)
    print(as_json(rows, args.repeat) if args.json else render(rows, args.repeat))
    return 0


if __name__ == "__main__":
    sys.exit(main())
