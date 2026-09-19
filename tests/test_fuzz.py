import io
import random
from itertools import product

import pytest

from sentinel.ids import Alert
from sentinel.pcap import Packet, PcapError, PcapReader, PcapWriter
from sentinel.proto.decode import decode
from tools import fuzz
from tools.gen_pcap import generate, generate_attacks

DATA = bytes(range(10, 30))
OTHER = bytes(range(100, 120))


def trials(op: fuzz.Op, data: bytes = DATA, n: int = 300) -> list[bytes]:
    rng = random.Random(5)
    return [op(rng, data, OTHER) for _ in range(n)]


def differing(a: bytes, b: bytes) -> int:
    return sum(x != y for x, y in zip(a, b, strict=True))


# ---- the damages ------------------------------------------------------------------------------


def test_there_are_nine_different_damages() -> None:
    assert len(fuzz.OPS) == 9
    assert len({op.__name__ for op in fuzz.OPS}) == 9


def test_flip_bit_changes_one_bit() -> None:
    for out in trials(fuzz.flip_bit):
        assert len(out) == len(DATA)
        assert sum(bin(a ^ b).count("1") for a, b in zip(out, DATA, strict=True)) == 1


def test_set_byte_changes_at_most_one_byte_to_an_extreme_or_random_value() -> None:
    outs = trials(fuzz.set_byte, n=600)
    assert all(len(o) == len(DATA) and differing(o, DATA) <= 1 for o in outs)
    changed = {o[i] for o in outs for i in range(len(o)) if o[i] != DATA[i]}
    assert {0x00, 0x7F, 0x80, 0xFF} <= changed


def test_set_field_overwrites_two_bytes() -> None:
    outs = trials(fuzz.set_field, n=600)
    assert all(len(o) == len(DATA) and differing(o, DATA) <= 2 for o in outs)
    assert any(differing(o, DATA) == 2 for o in outs)
    pairs = {
        (o[i], o[i + 1]) for o in outs for i in range(len(o) - 1) if o[i : i + 2] != DATA[i : i + 2]
    }
    assert {(0xFF, 0xFF), (0x00, 0x00), (0x80, 0x00), (0x7F, 0xFF), (0x00, 0x01)} <= pairs


def test_set_field_can_reach_the_last_two_bytes() -> None:
    assert any(o[-2:] != DATA[-2:] for o in trials(fuzz.set_field, n=800))


def test_truncate_keeps_a_shorter_start() -> None:
    lengths = set()
    for out in trials(fuzz.truncate):
        assert len(out) < len(DATA)
        assert DATA.startswith(out)
        lengths.add(len(out))
    assert 0 in lengths
    assert len(DATA) - 1 in lengths


def test_extend_adds_random_bytes_at_the_end() -> None:
    extra = set()
    for out in trials(fuzz.extend, n=500):
        assert out.startswith(DATA)
        assert 1 <= len(out) - len(DATA) <= 64
        extra.add(len(out) - len(DATA))
    assert 1 in extra
    assert 64 in extra


def test_delete_slice_removes_a_piece() -> None:
    lengths = set()
    for out in trials(fuzz.delete_slice, n=500):
        assert len(out) < len(DATA)
        assert any(
            out == DATA[:a] + DATA[b:]
            for a, b in product(range(len(DATA)), range(len(DATA) + 1))
            if a < b
        )
        lengths.add(len(DATA) - len(out))
    assert 1 in lengths
    assert max(lengths) > len(DATA) // 2


def test_duplicate_slice_repeats_a_piece_in_place() -> None:
    for out in trials(fuzz.duplicate_slice):
        assert len(out) > len(DATA)
        assert any(
            out == DATA[:b] + DATA[a:b] + DATA[b:]
            for a, b in product(range(len(DATA) + 1), repeat=2)
            if a < b
        )


def test_splice_joins_the_start_of_one_packet_to_the_end_of_another() -> None:
    kinds = set()
    for out in trials(fuzz.splice, n=500):
        assert any(
            out == DATA[:i] + OTHER[j:]
            for i, j in product(range(len(DATA) + 1), range(len(OTHER) + 1))
        )
        kinds.add(out == OTHER)
    assert True in kinds  # nothing kept of the first packet


def test_swap_bytes_keeps_the_same_bytes_in_another_order() -> None:
    outs = trials(fuzz.swap_bytes)
    assert all(sorted(o) == sorted(DATA) and differing(o, DATA) in (0, 2) for o in outs)
    assert any(o != DATA for o in outs)


@pytest.mark.parametrize("op", fuzz.OPS, ids=lambda op: op.__name__)
def test_no_damage_fails_on_tiny_input(op: fuzz.Op) -> None:
    rng = random.Random(1)
    for data in (b"", b"\x00", b"\x01\x02"):
        for _ in range(50):
            assert isinstance(op(rng, data, OTHER), bytes)
            assert isinstance(op(rng, data, b""), bytes)


def test_damages_that_need_bytes_leave_an_empty_packet_alone() -> None:
    rng = random.Random(1)
    for op in (
        fuzz.flip_bit,
        fuzz.set_byte,
        fuzz.set_field,
        fuzz.truncate,
        fuzz.delete_slice,
        fuzz.duplicate_slice,
        fuzz.swap_bytes,
    ):
        assert op(rng, b"", OTHER) == b""
    assert fuzz.set_field(rng, b"\x07", OTHER) == b"\x07"
    assert fuzz.swap_bytes(rng, b"\x07", OTHER) == b"\x07"


def test_mutate_is_the_same_for_the_same_seed_and_uses_one_to_three_damages() -> None:
    a = [fuzz.mutate(random.Random(s), DATA, OTHER) for s in range(200)]
    b = [fuzz.mutate(random.Random(s), DATA, OTHER) for s in range(200)]
    assert a == b
    assert sum(x != DATA for x in a) > 150
    counts = []
    for s in range(300):
        used: list[str] = []
        ops = tuple(_recorder(op, used) for op in fuzz.OPS)
        original = fuzz.OPS
        try:
            fuzz.OPS = ops
            fuzz.mutate(random.Random(s), DATA, OTHER)
        finally:
            fuzz.OPS = original
        counts.append(len(used))
    assert set(counts) == {1, 2, 3}


def _recorder(op: fuzz.Op, used: list[str]) -> fuzz.Op:
    def run(rng: random.Random, data: bytes, other: bytes) -> bytes:
        used.append(op.__name__)
        return op(rng, data, other)

    return run


# ---- the run ----------------------------------------------------------------------------------


def test_the_seeds_are_every_packet_of_the_generated_captures() -> None:
    from tools.gen_pcap import generate_benign, generate_streams

    assert len(fuzz.seeds()) == sum(
        len(part()) for part in (generate, generate_streams, generate_benign, generate_attacks)
    )


def test_a_clean_run() -> None:
    report = fuzz.run(1, 2000)
    assert report.failures == ()
    assert (report.seed, report.inputs, report.packets, report.files) == (1, 2000, 1600, 400)


def test_the_same_seed_gives_the_same_run() -> None:
    assert fuzz.run(3, 400) == fuzz.run(3, 400)


def boom(data: bytes) -> object:
    raise ValueError("boom")


def test_an_exception_is_reported_with_the_input_that_caused_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = decode

    def sometimes(data: bytes) -> object:
        if len(data) % 7 == 0:
            raise ValueError("boom")
        return real(data)

    monkeypatch.setattr(fuzz, "decode", sometimes)
    report = fuzz.run(1, 600)
    packets = [f for f in report.failures if f.kind == "packet"]
    assert packets
    assert all(f.problem == "ValueError: boom" and len(f.data) % 7 == 0 for f in packets)
    assert all(f.iteration % 5 != 4 for f in packets)
    assert [f.iteration for f in report.failures] == sorted(f.iteration for f in report.failures)
    assert report.failures == fuzz.run(1, 600).failures  # the same failures every time


def test_a_capture_file_that_makes_the_pipeline_raise_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fuzz, "decode", boom)
    report = fuzz.run(1, 300)
    files = [f for f in report.failures if f.kind == "capture file"]
    assert files
    assert all(f.iteration % 5 == 4 for f in files)
    assert {f.kind for f in report.failures} == {"packet", "capture file"}
    assert sum(f.kind == "packet" for f in report.failures) == 240


def valid_line_pipeline() -> fuzz.Pipeline:
    return fuzz.Pipeline()


@pytest.mark.parametrize("line", [" ", "~", "IP 10.0.0.1 > 10.0.0.2: ok"])
def test_printable_summary_lines_are_accepted(line: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fuzz, "summarize", lambda packet, layers: line)
    assert valid_line_pipeline().packet(Packet(1, 60, bytes(60))) is None


@pytest.mark.parametrize("line", ["", "a\nb", "a\rb", "\x1f", "\x7f", "é", "tab\there", "\x1b[0m"])
def test_a_summary_line_that_is_not_one_line_of_printable_ascii_is_a_failure(
    line: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fuzz, "summarize", lambda packet, layers: line)
    problem = valid_line_pipeline().packet(Packet(1, 60, bytes(60)))
    assert problem == f"summary line is not one line of printable ASCII: {line!r}"


def test_a_filter_must_answer_true_or_false() -> None:
    class Odd:
        def matches(self, layers: object) -> object:
            return 1

    pipeline = valid_line_pipeline()
    pipeline.filters[3] = Odd()  # type: ignore[call-overload]
    assert pipeline.packet(Packet(1, 60, bytes(60))) == "a filter did not answer True or False"


def raise_all_alerts(pipeline: fuzz.Pipeline) -> list[str | None]:
    return [pipeline.packet(p) for p in generate_attacks()]


def test_alerts_are_checked_for_one_line_of_json(monkeypatch: pytest.MonkeyPatch) -> None:
    assert set(raise_all_alerts(valid_line_pipeline())) == {None}
    for bad in ("a\nb", "[1]"):
        monkeypatch.setattr(fuzz, "to_json", lambda alert, bad=bad: bad)
        problems = [p for p in raise_all_alerts(valid_line_pipeline()) if p]
        assert problems, bad
        assert problems[0] == f"alert is not one line of JSON: {bad!r}"
    monkeypatch.setattr(fuzz, "to_json", lambda alert: "not json")
    with pytest.raises(ValueError, match="Expecting value"):
        raise_all_alerts(valid_line_pipeline())  # run() records this one as an exception


def test_finishing_checks_flow_lines_and_starts_a_new_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = valid_line_pipeline()
    for p in generate():
        assert pipeline.packet(p) is None
    assert pipeline.table.flows
    assert pipeline.finish() is None
    assert not pipeline.table.flows
    for p in generate():
        pipeline.packet(p)
    monkeypatch.setattr(fuzz, "format_flow", lambda flow: "a\nb")
    assert pipeline.finish() == "flow line has a line break: 'a\\nb'"


def test_the_end_of_a_run_reports_a_flow_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fuzz, "format_flow", lambda flow: "a\nb")
    report = fuzz.run(1, 1000)
    ends = [f for f in report.failures if f.kind == "end of run"]
    assert [f.iteration for f in ends] == [999, 1000]  # every 1000 inputs, and when the run ends
    assert report.failures[-1] == ends[-1]


def one_packet_file() -> bytes:
    buf = io.BytesIO()
    PcapWriter(buf).write(Packet(1, 60, bytes(60)))
    return buf.getvalue()


def test_a_bad_capture_file_may_only_raise_pcap_error(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = valid_line_pipeline()
    assert fuzz._read_file(b"\x00" * 10, pipeline) is None  # PcapError: allowed
    assert fuzz._read_file(one_packet_file(), pipeline) is None
    assert list(PcapReader(io.BytesIO(one_packet_file())))

    class Bad:
        def __init__(self, fp: object) -> None: ...
        def __iter__(self) -> "Bad":
            return self

        def __next__(self) -> Packet:
            raise ValueError("not a PcapError")

    monkeypatch.setattr(fuzz, "PcapReader", Bad)
    with pytest.raises(ValueError, match="not a PcapError"):
        fuzz._read_file(b"", pipeline)

    class Denied(Bad):
        def __next__(self) -> Packet:
            raise PcapError("bad file")

    monkeypatch.setattr(fuzz, "PcapReader", Denied)
    assert fuzz._read_file(b"", pipeline) is None


def test_a_problem_in_a_packet_from_a_capture_file_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fuzz, "summarize", lambda packet, layers: "")
    problem = fuzz._read_file(one_packet_file(), valid_line_pipeline())
    assert problem is not None
    assert problem.startswith("summary line is not one line")


def test_a_failure_shows_at_most_two_kib_of_hex() -> None:
    assert fuzz.Failure(0, "packet", "x", b"\x01\x02").hex == "0102"
    long = fuzz.Failure(0, "packet", "x", b"\xab" * 3000).hex
    assert long == "ab" * fuzz.MAX_HEX + "..."
    assert fuzz.Failure(0, "packet", "x", b"\xab" * fuzz.MAX_HEX).hex == "ab" * fuzz.MAX_HEX


# ---- the command ------------------------------------------------------------------------------


def test_replay_of_a_good_packet() -> None:
    assert fuzz.replay(generate()[5].data) is None
    assert fuzz.replay(b"") is None


def test_the_command_reports_a_clean_run(capsys: pytest.CaptureFixture[str]) -> None:
    assert fuzz.main(["--iterations", "500", "--seed", "2"]) == 0
    assert (
        capsys.readouterr().out
        == "# 500 inputs (400 packets, 100 capture files), seed 2, 0 failures\n"
    )


def test_the_command_reports_failures_and_how_to_replay_them(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(fuzz, "decode", boom)
    assert fuzz.main(["-n", "100"]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "FAIL input 0 (packet): ValueError: boom"
    assert lines[1].startswith("  python -m tools.fuzz --replay ")
    assert bytes.fromhex(lines[1].split()[-1])  # the input, in hex
    assert sum(line.startswith("FAIL") for line in lines) == fuzz.MAX_SHOWN
    assert lines[-2].startswith("... and ")
    assert lines[-1].startswith("# 100 inputs (80 packets, 20 capture files), seed 1, ")
    assert lines[-1].endswith(" failures")


def test_a_failure_in_a_capture_file_prints_the_file_in_hex(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(fuzz, "summarize", lambda packet, layers: "")
    monkeypatch.setattr(fuzz, "MAX_SHOWN", 1000)
    fuzz.main(["-n", "50"])
    lines = capsys.readouterr().out.splitlines()
    at = next(i for i, line in enumerate(lines) if "(capture file)" in line)
    assert not lines[at + 1].startswith("  python")
    assert bytes.fromhex(lines[at + 1].strip())


def test_replay_from_the_command_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert fuzz.main(["--replay", generate()[5].data.hex()]) == 0
    assert capsys.readouterr().out == "ok\n"
    monkeypatch.setattr(fuzz, "decode", boom)
    assert fuzz.main(["--replay", "00ff"]) == 1
    assert capsys.readouterr().out == "ValueError: boom\n"
    monkeypatch.setattr(fuzz, "decode", lambda data: (_ for _ in ()).throw(KeyError("k")))
    assert fuzz.main(["--replay", "00"]) == 1
    assert capsys.readouterr().out == "KeyError: 'k'\n"


def test_a_summary_problem_is_printed_by_replay(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(fuzz, "summarize", lambda packet, layers: "a\nb")
    assert fuzz.main(["--replay", "00"]) == 1
    assert "not one line of printable ASCII" in capsys.readouterr().out


@pytest.mark.parametrize("args", [["-n", "0"], ["-n", "x"], ["--seed", "x"], ["--replay", "zz"]])
def test_bad_options_are_refused(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        fuzz.main(args)
    assert stop.value.code == 2
    assert capsys.readouterr().err


def test_the_defaults() -> None:
    assert (fuzz.DEFAULT_SEED, fuzz.DEFAULT_ITERATIONS, fuzz.FILE_EVERY) == (1, 100_000, 5)


def test_alert_is_the_type_the_pipeline_checks() -> None:
    assert isinstance(
        Alert(1, "r", "port_scan", "low", None, None, "m"),
        Alert,
    )
