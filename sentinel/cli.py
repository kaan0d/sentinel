import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from sentinel.pcap import LINKTYPE_ETHERNET, PcapError, PcapReader
from sentinel.summary import summarize


def _read(path: Path) -> int:
    try:
        with path.open("rb") as fp:
            reader = PcapReader(fp)
            if reader.linktype != LINKTYPE_ETHERNET:
                print(
                    f"sentinel: unsupported link type {reader.linktype} (Ethernet only)",
                    file=sys.stderr,
                )
                return 1
            for packet in reader:
                print(summarize(packet))
    except (OSError, PcapError) as e:
        print(f"sentinel: {path}: {e}", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description="Packet analyzer and network IDS")
    commands = parser.add_subparsers(dest="command", required=True)
    read = commands.add_parser("read", help="print one tcpdump-style line per packet")
    read.add_argument("file", type=Path, help="classic pcap file")
    args = parser.parse_args(argv)
    return _read(args.file)
