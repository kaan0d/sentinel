import io
from typing import BinaryIO

from sentinel.pcap.pcapng import SHB_BYTES, PcapngReader
from sentinel.pcap.reader import PcapReader


def open_reader(fp: BinaryIO) -> PcapReader | PcapngReader:
    """A reader for a classic pcap or a pcapng stream, chosen by the first four bytes. The
    stream must be seekable (a file or BytesIO). A file that is neither gets the classic
    reader's error."""
    magic = fp.read(4)
    fp.seek(-len(magic), io.SEEK_CUR)
    return PcapngReader(fp) if magic == SHB_BYTES else PcapReader(fp)
