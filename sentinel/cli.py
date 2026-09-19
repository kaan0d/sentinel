import argparse
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path

from sentinel.filter import Filter, parse_filter
from sentinel.flow import FlowTable
from sentinel.flow.report import format_flow, format_footer
from sentinel.pcap import LINKTYPE_ETHERNET, Packet, PcapError, PcapReader
from sentinel.proto.decode import decode
from sentinel.summary import summarize


def _packets(path: Path) -> Iterator[Packet]:
    """The packets of a capture. Raises PcapError after the good packets if the file is corrupt."""
    with path.open("rb") as fp:
        reader = PcapReader(fp)
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description="Packet analyzer and network IDS")
    commands = parser.add_subparsers(dest="command", required=True)
    read = commands.add_parser("read", help="print one tcpdump-style line per packet")
    flows = commands.add_parser(
        "flows", help="group packets into flows, reassemble TCP streams, print statistics"
    )
    for command in (read, flows):
        command.add_argument("file", type=Path, help="classic pcap file")
        command.add_argument(
            "--filter",
            "-f",
            metavar="EXPR",
            help='only packets that match, e.g. "tcp and port 80 and not src host 10.0.0.1"',
        )
    args = parser.parse_args(argv)
    flt = None
    if args.filter is not None:
        flt = parse_filter(args.filter)
        if flt.error is not None:
            lines = flt.describe_error()
            print("sentinel: invalid filter: " + lines[0], *lines[1:], sep="\n", file=sys.stderr)
            return 2
    return _read(args.file, flt) if args.command == "read" else _flows(args.file, flt)
