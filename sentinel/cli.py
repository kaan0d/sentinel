import argparse
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

from sentinel.filter import Filter, parse_filter
from sentinel.flow import FlowTable
from sentinel.flow.report import format_flow, format_footer
from sentinel.ids import Alert, Engine, RuleSet, default_rules, load_rules, to_json, to_text
from sentinel.live import LiveError, open_capture
from sentinel.pcap import LINKTYPE_ETHERNET, Packet, PcapError, PcapWriter, open_reader
from sentinel.proto.decode import decode
from sentinel.summary import summarize


def _packets(path: Path) -> Iterator[Packet]:
    """The packets of a capture. Raises PcapError after the good packets if the file is corrupt."""
    with path.open("rb") as fp:
        reader = open_reader(fp)
        if reader.linktype != LINKTYPE_ETHERNET:
            raise PcapError(f"unsupported link type {reader.linktype} (Ethernet only)")
        yield from reader


def _read(path: Path, flt: Filter | None) -> int:
    try:
        for packet in _packets(path):
            layers = decode(packet.data)
            if flt is None or flt.matches(layers):
                print(summarize(packet, layers))
    except (OSError, PcapError) as e:
        print(f"sentinel: {path}: {e}", file=sys.stderr)
        return 1
    return 0


def _flows(path: Path, flt: Filter | None) -> int:
    table = FlowTable()
    error: OSError | PcapError | None = None
    try:
        for packet in _packets(path):
            layers = decode(packet.data)
            if flt is None or flt.matches(layers):
                table.add(packet, layers)
    except (OSError, PcapError) as e:
        error = e
    if isinstance(error, OSError):
        print(f"sentinel: {path}: {error}", file=sys.stderr)
        return 1
    for flow in table.flows:
        print(format_flow(flow))
    print(format_footer(table))
    if error is not None:
        print(f"sentinel: {path}: {error}", file=sys.stderr)
        return 1
    return 0


def _rules(path: Path | None) -> RuleSet | None:
    """The rules to use, or None after printing every problem with them."""
    rules = default_rules() if path is None else load_rules(path)
    if rules.errors:
        print("sentinel: invalid rules:", file=sys.stderr)
        for message in rules.errors:
            print(f"  {message}", file=sys.stderr)
        return None
    return rules


def _show(alert: Alert, fmt: str) -> None:
    print(to_json(alert) if fmt == "json" else to_text(alert), flush=True)


def _ids(path: Path, rules_path: Path | None, fmt: str) -> int:
    rules = _rules(rules_path)
    if rules is None:
        return 2
    engine = Engine(rules.rules)
    error: OSError | PcapError | None = None
    try:
        for packet in _packets(path):
            engine.process(packet)
    except (OSError, PcapError) as e:
        error = e
    if isinstance(error, OSError):
        print(f"sentinel: {path}: {error}", file=sys.stderr)
        return 1
    for alert in engine.finish():
        _show(alert, fmt)
    if error is not None:
        print(f"sentinel: {path}: {error}", file=sys.stderr)
        return 1
    return 0


def _live(args: argparse.Namespace, flt: Filter | None) -> int:
    """Capture on an interface until Ctrl-C, `--count` packets or `--duration` seconds.
    Prints a line per packet, or (with --ids) an alert as soon as it is raised."""
    fmt = args.format or "json"
    engine = None
    if args.ids:
        rules = _rules(args.rules)
        if rules is None:
            return 2
        engine = Engine(rules.rules)
    try:
        capture = open_capture(args.interface)
    except LiveError as e:
        print(f"sentinel: {e}", file=sys.stderr)
        return 1
    out = None
    writer = None
    if args.write is not None:
        try:
            out = args.write.open("wb")
        except OSError as e:
            capture.close()
            print(f"sentinel: {args.write}: {e}", file=sys.stderr)
            return 1
        writer = PcapWriter(out)
    seen = 0
    status = 0
    try:
        for packet in capture.packets(args.duration):
            layers = decode(packet.data)
            if flt is not None and not flt.matches(layers):
                continue
            seen += 1
            if writer is not None and out is not None:
                writer.write(packet)
                out.flush()  # a capture that is killed still leaves a readable file
            if engine is None:
                print(summarize(packet, layers), flush=True)
            else:
                engine.process(packet, layers)
                for alert in engine.pop_alerts():
                    _show(alert, fmt)
            if args.count is not None and seen >= args.count:
                break
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(f"sentinel: {args.interface}: {e}", file=sys.stderr)
        status = 1
    drops = capture.kernel_drops()
    capture.close()
    if out is not None:
        out.close()
    if engine is not None:
        for alert in engine.finish():
            _show(alert, fmt)
    note = f"# {seen} packets"
    if drops:
        note += f", {drops} dropped by the kernel"
    print(note, file=sys.stderr)
    return status


def _positive_int(text: str) -> int:
    if not text.isdecimal() or int(text) < 1:
        raise argparse.ArgumentTypeError(f"{text!r} is not a positive whole number")
    return int(text)


def _positive_seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        value = 0.0
    if not value > 0:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of seconds above 0")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description="Packet analyzer and network IDS")
    commands = parser.add_subparsers(dest="command", required=True)
    read = commands.add_parser("read", help="print one tcpdump-style line per packet")
    flows = commands.add_parser(
        "flows", help="group packets into flows, reassemble TCP streams, print statistics"
    )
    live = commands.add_parser(
        "live",
        help="capture from a network interface (Linux as root, Windows as Administrator);"
        " only on a network you own",
    )
    live.add_argument(
        "interface", help="for example eth0 or lo; on Windows the IPv4 address of the interface"
    )
    live.add_argument("--write", "-w", type=Path, metavar="FILE", help="also save a pcap file")
    live.add_argument("--count", "-c", type=_positive_int, help="stop after this many packets")
    live.add_argument("--duration", type=_positive_seconds, help="stop after this many seconds")
    live.add_argument("--ids", action="store_true", help="print alerts instead of packets")
    live.add_argument("--rules", type=Path, metavar="PATH", help="rules for --ids (see ids)")
    live.add_argument("--format", choices=("json", "text"), help="alert format for --ids")
    for command in (read, flows):
        command.add_argument("file", type=Path, help="pcap or pcapng file")
    for command in (read, flows, live):
        command.add_argument(
            "--filter",
            "-f",
            metavar="EXPR",
            help='only packets that match, e.g. "tcp and port 80 and not src host 10.0.0.1"',
        )
    ids = commands.add_parser("ids", help="run the detectors over a capture and print alerts")
    ids.add_argument("file", type=Path, help="pcap or pcapng file")
    ids.add_argument(
        "--rules",
        type=Path,
        metavar="PATH",
        help="a .toml rule file, or a directory of them (default: the built-in rules)",
    )
    ids.add_argument(
        "--format", choices=("json", "text"), default="json", help="one JSON object per line"
    )
    args = parser.parse_args(argv)
    if args.command == "live" and not args.ids and (args.rules or args.format):
        parser.error("--rules and --format only work together with --ids")
    if args.command == "ids":
        return _ids(args.file, args.rules, args.format)
    flt = None
    if args.filter is not None:
        flt = parse_filter(args.filter)
        if flt.error is not None:
            lines = flt.describe_error()
            print("sentinel: invalid filter: " + lines[0], *lines[1:], sep="\n", file=sys.stderr)
            return 2
    if args.command == "live":
        return _live(args, flt)
    return _read(args.file, flt) if args.command == "read" else _flows(args.file, flt)
