import contextlib
import io
import random
import struct
from typing import Literal

import pytest

from sentinel.pcap import LINKTYPE_ETHERNET, Packet, PcapError, PcapReader, PcapWriter

PACKETS = [
    Packet(1_700_000_000_000_001_000, 60, bytes(range(60))),
    Packet(1_700_000_001_500_000_000, 1500, b"\x01" * 40),  # snaplen-truncated: orig_len > data
    Packet(0, 0, b""),
    Packet(4_294_967_295_999_999_000, 3, b"abc"),  # largest u32 second
]
VARIANTS = [("little", False), ("little", True), ("big", False), ("big", True)]
Byteorder = Literal["little", "big"]


def write(
    packets: list[Packet], byteorder: Byteorder = "little", nanosecond: bool = False
) -> bytes:
    buf = io.BytesIO()
    writer = PcapWriter(buf, nanosecond=nanosecond, byteorder=byteorder)
    for p in packets:
        writer.write(p)
    return buf.getvalue()


def read(raw: bytes) -> list[Packet]:
    return list(PcapReader(io.BytesIO(raw)))


@pytest.mark.parametrize(("byteorder", "nanosecond"), VARIANTS)
def test_round_trip(byteorder: Byteorder, nanosecond: bool) -> None:
    raw = write(PACKETS, byteorder, nanosecond)
    reader = PcapReader(io.BytesIO(raw))
    assert list(reader) == PACKETS
    assert reader.nanosecond == nanosecond
    assert reader.linktype == LINKTYPE_ETHERNET
    assert reader.snaplen == 262144


@pytest.mark.parametrize(("byteorder", "nanosecond"), VARIANTS)
def test_empty_capture(byteorder: Byteorder, nanosecond: bool) -> None:
    assert read(write([], byteorder, nanosecond)) == []


@pytest.mark.parametrize(
    ("byteorder", "nanosecond", "magic"),
    [
        ("little", False, "d4c3b2a1"),
        ("big", False, "a1b2c3d4"),
        ("little", True, "4d3cb2a1"),
        ("big", True, "a1b23c4d"),
    ],
)
def test_magic_on_disk(byteorder: Byteorder, nanosecond: bool, magic: str) -> None:
    assert write([], byteorder, nanosecond)[:4].hex() == magic


def test_nanosecond_precision_kept() -> None:
    p = Packet(1_000_000_123, 1, b"x")
    assert read(write([p], nanosecond=True)) == [p]


def test_microsecond_file_drops_sub_microsecond() -> None:
    p = Packet(1_000_000_999, 1, b"x")
    assert read(write([p], nanosecond=False))[0].ts_ns == 1_000_000_000


def test_reads_hand_built_big_endian_file() -> None:
    # Header and record built independently of PcapWriter.
    raw = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    raw += struct.pack(">IIII", 10, 250_000, 2, 9) + b"hi"
    assert read(raw) == [Packet(10_250_000_000, 9, b"hi")]


def test_bad_magic() -> None:
    with pytest.raises(PcapError, match="bad magic"):
        read(b"\x0a\x0d\x0d\x0a" + bytes(20))  # pcapng, not classic pcap


def test_unsupported_version() -> None:
    raw = struct.pack("<IHHiIII", 0xA1B2C3D4, 3, 0, 0, 0, 65535, 1)
    with pytest.raises(PcapError, match="version"):
        read(raw)


def test_truncated_global_header() -> None:
    full = write([])
    for n in range(len(full)):
        with pytest.raises(PcapError):
            read(full[:n])


def test_truncated_record_yields_earlier_packets_then_raises() -> None:
    raw = write(PACKETS[:2])
    reader = PcapReader(io.BytesIO(raw[:-5]))  # cuts into the second record's data
    it = iter(reader)
    assert next(it) == PACKETS[0]
    with pytest.raises(PcapError, match="truncated pcap record"):
        next(it)


def test_truncated_record_header() -> None:
    raw = write(PACKETS[:1])
    with pytest.raises(PcapError, match="record header"):
        read(raw + b"\x00" * 7)


def test_oversized_captured_length_rejected() -> None:
    raw = write([]) + struct.pack("<IIII", 0, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    with pytest.raises(PcapError, match="captured length"):
        read(raw)


def test_writer_rejects_packet_over_snaplen() -> None:
    writer = PcapWriter(io.BytesIO(), snaplen=10)
    with pytest.raises(ValueError, match="snaplen"):
        writer.write(Packet(0, 11, bytes(11)))


def test_random_bytes_only_raise_pcap_error(blobs: list[bytes]) -> None:
    header = write([])
    for blob in blobs:
        for raw in (blob, header + blob):
            with contextlib.suppress(PcapError):
                read(raw)


def test_every_truncation_of_a_valid_file_is_handled() -> None:
    raw = write(PACKETS)
    for n in range(len(raw) + 1):
        with contextlib.suppress(PcapError):
            read(raw[:n])


def test_corrupted_bytes_only_raise_pcap_error() -> None:
    rng = random.Random(7)
    raw = write(PACKETS)
    for i in range(len(raw)):
        bad = bytearray(raw)
        bad[i] = rng.randrange(256)
        with contextlib.suppress(PcapError):
            read(bytes(bad))
