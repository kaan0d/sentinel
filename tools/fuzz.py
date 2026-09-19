"""Feed damaged packets and damaged capture files to the whole pipeline, and report what breaks.

    python -m tools.fuzz [--seed S] [--iterations N]
    python -m tools.fuzz --replay HEX

Every input is made from a packet of the generated captures by one to three random damages (a
flipped bit, a length field set to an extreme, a cut, a piece deleted or repeated, the end of
another packet spliced on). Each damaged packet goes through the decoder, the summary line, a set
of filters, one flow table and one detector engine that live for the whole run (so state builds up
the way it does on a long capture). Every fifth input is a small capture file, damaged the same
way, read by the pcap reader. The same seed always makes the same inputs.

What counts as a failure: an exception (only `PcapError` may come out of the pcap reader); a
summary line that is not one line of printable ASCII; an alert that is not one line of JSON.
"""

import argparse
import io
import json
import random
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from sentinel.filter import parse_filter
from sentinel.flow import FlowTable
from sentinel.flow.report import format_flow
from sentinel.ids import Engine, default_rules, to_json
from sentinel.pcap import Packet, PcapError, PcapReader, PcapWriter
from sentinel.proto.decode import decode
from sentinel.summary import summarize
from tools.gen_pcap import generate, generate_attacks, generate_benign, generate_streams

DEFAULT_SEED = 1
DEFAULT_ITERATIONS = 100_000
FILE_EVERY = 5  # every 5th input is a capture file
FILTERS = (
    "tcp",
    "udp port 53",
    "dns",
    "http",
    "tls",
    "host 10.0.0.1",
    "src net 10.0.0.0/8 and not arp",
    "portrange 1-1024 or vlan",
)
MAX_SHOWN = 10
MAX_HEX = 2048

Op = Callable[[random.Random, bytes, bytes], bytes]


def flip_bit(rng: random.Random, data: bytes, other: bytes) -> bytes:
    if not data:
        return data
    out = bytearray(data)
    out[rng.randrange(len(out))] ^= 1 << rng.randrange(8)
    return bytes(out)


def set_byte(rng: random.Random, data: bytes, other: bytes) -> bytes:
    if not data:
        return data
    out = bytearray(data)
    out[rng.randrange(len(out))] = rng.choice((0x00, 0x7F, 0x80, 0xFF, rng.randrange(256)))
    return bytes(out)


def set_field(rng: random.Random, data: bytes, other: bytes) -> bytes:
    """Two bytes set to an extreme value, as a length or a count would be."""
    if len(data) < 2:
        return data
    at = rng.randrange(len(data) - 1)
    value = rng.choice((0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF, rng.randrange(65536)))
    return data[:at] + value.to_bytes(2, "big") + data[at + 2 :]


def truncate(rng: random.Random, data: bytes, other: bytes) -> bytes:
    return data[: rng.randrange(len(data))] if data else data


def extend(rng: random.Random, data: bytes, other: bytes) -> bytes:
    return data + rng.randbytes(rng.randrange(1, 65))


def delete_slice(rng: random.Random, data: bytes, other: bytes) -> bytes:
    if not data:
        return data
    a = rng.randrange(len(data))
    b = rng.randrange(a, len(data)) + 1
    return data[:a] + data[b:]


def duplicate_slice(rng: random.Random, data: bytes, other: bytes) -> bytes:
    if not data:
        return data
    a = rng.randrange(len(data))
    b = rng.randrange(a, len(data)) + 1
    return data[:b] + data[a:b] + data[b:]


def splice(rng: random.Random, data: bytes, other: bytes) -> bytes:
    """The start of this packet and the end of another."""
    return data[: rng.randrange(len(data) + 1)] + other[rng.randrange(len(other) + 1) :]


def swap_bytes(rng: random.Random, data: bytes, other: bytes) -> bytes:
    if len(data) < 2:
        return data
    out = bytearray(data)
    i, j = rng.randrange(len(out)), rng.randrange(len(out))
    out[i], out[j] = out[j], out[i]
    return bytes(out)


OPS: tuple[Op, ...] = (
    flip_bit,
    set_byte,
    set_field,
    truncate,
    extend,
    delete_slice,
    duplicate_slice,
    splice,
    swap_bytes,
)


def mutate(rng: random.Random, data: bytes, other: bytes) -> bytes:
    """One to three random damages."""
    for _ in range(rng.randrange(1, 4)):
        data = rng.choice(OPS)(rng, data, other)
    return data


@dataclass(frozen=True, slots=True)
class Failure:
    iteration: int
    kind: str  # "packet" or "capture file"
    problem: str
    data: bytes

    @property
    def hex(self) -> str:
        shown = self.data[:MAX_HEX].hex()
        return shown + ("..." if len(self.data) > MAX_HEX else "")


@dataclass(frozen=True, slots=True)
class Report:
    seed: int
    inputs: int
    packets: int
    files: int
    failures: tuple[Failure, ...]


def seeds() -> list[bytes]:
    return [
        p.data
        for part in (generate(), generate_streams(), generate_benign(), generate_attacks())
        for p in part
    ]


class Pipeline:
    """Everything a packet goes through. One instance is used for a whole run."""

    def __init__(self) -> None:
        self.filters = [parse_filter(text) for text in FILTERS]
        assert all(f.error is None for f in self.filters)
        self.table = FlowTable()
        self.engine = Engine(default_rules().rules)

    def packet(self, packet: Packet) -> str | None:
        """Send one packet through. Returns what is wrong, or None."""
        layers = decode(packet.data)
        line = summarize(packet, layers)
        if not line or not all(0x20 <= ord(c) < 0x7F for c in line):
            return f"summary line is not one line of printable ASCII: {line!r}"
        for flt in self.filters:
            if not isinstance(flt.matches(layers), bool):
                return "a filter did not answer True or False"
        self.table.add(packet, layers)
        self.engine.process(packet, layers)
        for alert in self.engine.pop_alerts():
            text = to_json(alert)
            if "\n" in text or not isinstance(json.loads(text), dict):
                return f"alert is not one line of JSON: {text!r}"
        return None

    def finish(self) -> str | None:
        for flow in self.table.flows:
            line = format_flow(flow)
            if "\n" in line:
                return f"flow line has a line break: {line!r}"
        for alert in self.engine.finish():
            to_json(alert)
        self.table = FlowTable()
        return None


def _capture_file(rng: random.Random, pool: list[bytes]) -> bytes:
    buf = io.BytesIO()
    writer = PcapWriter(buf)
    for i in range(rng.randrange(1, 6)):
        data = rng.choice(pool)
        writer.write(Packet(1_700_000_000_000_000_000 + i, len(data), data))
    return buf.getvalue()


def _read_file(data: bytes, pipeline: Pipeline) -> str | None:
    try:
        for packet in PcapReader(io.BytesIO(data)):
            problem = pipeline.packet(packet)
            if problem:
                return problem
    except PcapError:
        return None  # the one exception a bad file may cause
    return None


def run(seed: int, iterations: int) -> Report:
    rng = random.Random(seed)
    pool = seeds()
    pipeline = Pipeline()
    failures: list[Failure] = []
    files = 0
    clock = 1_700_000_000_000_000_000
    for i in range(iterations):
        if i % FILE_EVERY == FILE_EVERY - 1:
            files += 1
            data = mutate(rng, _capture_file(rng, pool), _capture_file(rng, pool))
            kind, check = "capture file", _read_file
        else:
            data = mutate(rng, rng.choice(pool), rng.choice(pool))
            kind, check = "packet", None
        try:
            if check is None:
                clock += 1000
                problem = pipeline.packet(Packet(clock, len(data), data))
            else:
                problem = check(data, pipeline)
        except Exception as e:
            problem = f"{type(e).__name__}: {e}"
        if problem:
            failures.append(Failure(i, kind, problem, data))
        if i % 1000 == 999:
            end = pipeline.finish()
            if end:
                failures.append(Failure(i, "end of run", end, b""))
    end = pipeline.finish()
    if end:
        failures.append(Failure(iterations, "end of run", end, b""))
    return Report(seed, iterations, iterations - files, files, tuple(failures))


def replay(data: bytes) -> str | None:
    """One input on its own, as a packet. State that built up during a run is not there."""
    problem = Pipeline().packet(Packet(1_700_000_000_000_000_000, len(data), data))
    return problem


def _positive(text: str) -> int:
    if not text.isdecimal() or int(text) < 1:
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive whole number")
    return int(text)


def _hex(text: str) -> bytes:
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not hexadecimal") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fuzz the whole pipeline with damaged input")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--iterations", "-n", type=_positive, default=DEFAULT_ITERATIONS)
    parser.add_argument("--replay", type=_hex, metavar="HEX", help="run one packet, given in hex")
    args = parser.parse_args(argv)
    if args.replay is not None:
        try:
            problem = replay(args.replay)
        except Exception as e:
            problem = f"{type(e).__name__}: {e}"
        print(problem or "ok")
        return 1 if problem else 0
    report = run(args.seed, args.iterations)
    for f in report.failures[:MAX_SHOWN]:
        print(f"FAIL input {f.iteration} ({f.kind}): {f.problem}")
        if f.data:
            print(
                f"  python -m tools.fuzz --replay {f.hex}" if f.kind == "packet" else f"  {f.hex}"
            )
    if len(report.failures) > MAX_SHOWN:
        print(f"... and {len(report.failures) - MAX_SHOWN} more")
    print(
        f"# {report.inputs} inputs ({report.packets} packets, {report.files} capture files), "
        f"seed {report.seed}, {len(report.failures)} failures"
    )
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main())
