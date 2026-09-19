"""pcapng reading. The fixtures are built here from the file format description, block by
block, and not with tools.gen_pcap, so a misreading shared by reader and generator is caught."""

import contextlib
import io
import random
import struct
from pathlib import Path

import pytest

from sentinel.pcap import (
    LINKTYPE_ETHERNET,
    Packet,
    PcapError,
    PcapngReader,
    PcapReader,
    open_reader,
)
from sentinel.pcap.pcapng import MAX_BLOCK, MAX_TS_NS
from sentinel.summary import _timestamp
from tools.gen_pcap import pcapng_bytes


def block(kind: int, body: bytes, order: str = "<") -> bytes:
    body += bytes(-len(body) % 4)
    return (
        struct.pack(order + "II", kind, len(body) + 12)
        + body
        + struct.pack(order + "I", len(body) + 12)
    )


def option(code: int, value: bytes, order: str = "<") -> bytes:
    return struct.pack(order + "HH", code, len(value)) + value + bytes(-len(value) % 4)


END = b"\x00\x00\x00\x00"


def shb(order: str = "<", options: bytes = b"") -> bytes:
    magic = 0x1A2B3C4D
    return block(0x0A0D0D0A, struct.pack(order + "IHHq", magic, 1, 0, -1) + options, order)


def idb(order: str = "<", linktype: int = 1, snaplen: int = 0, options: bytes = b"") -> bytes:
    return block(1, struct.pack(order + "HHI", linktype, 0, snaplen) + options, order)


def epb(
    ts: int,
    data: bytes,
    order: str = "<",
    interface: int = 0,
    orig_len: int | None = None,
    options: bytes = b"",
) -> bytes:
    length = len(data) if orig_len is None else orig_len
    head = struct.pack(order + "IIIII", interface, ts >> 32, ts & 0xFFFFFFFF, len(data), length)
    return block(6, head + data + bytes(-len(data) % 4) + options, order)


def spb(data: bytes, orig_len: int | None = None, order: str = "<") -> bytes:
    length = len(data) if orig_len is None else orig_len
    return block(3, struct.pack(order + "I", length) + data, order)


def read(raw: bytes) -> list[Packet]:
    return list(PcapngReader(io.BytesIO(raw)))


def tsresol(value: int, order: str = "<") -> bytes:
    return option(9, bytes([value]), order) + END


PACKETS = [
    Packet(1_700_000_000_000_000_000, 60, bytes(range(60))),
    Packet(1_700_000_001_500_000_000, 1500, b"\x01" * 40),  # cut short: orig_len > data
    Packet(0, 0, b""),
    Packet(4_294_967_296_000_000_000, 3, b"abc"),  # a second count that does not fit in 32 bits
    Packet(1_700_000_002_000_000_000, 5, b"12345"),  # data that needs padding
]


@pytest.mark.parametrize("byteorder", ["little", "big"])
def test_round_trip(byteorder: str) -> None:
    raw = pcapng_bytes(PACKETS, byteorder=byteorder)  # type: ignore[arg-type]
    reader = PcapngReader(io.BytesIO(raw))
    assert list(reader) == PACKETS
    assert reader.linktype == LINKTYPE_ETHERNET
    assert reader.snaplen == 262144


@pytest.mark.parametrize(
    ("resolution", "unit_ns"), [(9, 1), (6, 1000), (3, 1_000_000), (0, 1_000_000_000)]
)
def test_timestamp_resolution(resolution: int, unit_ns: int) -> None:
    packets = [Packet(1_700_000_000 * 10**9 + 7 * unit_ns, 3, b"abc")]
    assert read(pcapng_bytes(packets, tsresol=resolution)) == packets


def test_reads_a_hand_built_file() -> None:
    raw = shb() + idb() + epb(1_700_000_000_250_000, b"hi", orig_len=9)
    reader = PcapngReader(io.BytesIO(raw))
    assert list(reader) == [Packet(1_700_000_000_250_000_000, 9, b"hi")]  # microseconds by default
    assert reader.snaplen == 0


def test_reads_a_hand_built_big_endian_file() -> None:
    raw = shb(">") + idb(">", snaplen=65535) + epb(10_250_000, b"hi", ">", orig_len=9)
    reader = PcapngReader(io.BytesIO(raw))
    assert list(reader) == [Packet(10_250_000_000, 9, b"hi")]
    assert reader.snaplen == 65535


def test_the_on_disk_first_bytes_are_the_same_in_both_orders() -> None:
    assert shb("<")[:4] == shb(">")[:4] == b"\x0a\x0d\x0d\x0a"
    assert shb("<")[8:12] == b"\x4d\x3c\x2b\x1a"
    assert shb(">")[8:12] == b"\x1a\x2b\x3c\x4d"


@pytest.mark.parametrize(
    ("value", "ticks_per_second"), [(0x80 | 10, 1024), (0x80 | 0, 1), (10, 10**10), (12, 10**12)]
)
def test_resolution_in_base_two_and_finer_than_nanoseconds(
    value: int, ticks_per_second: int
) -> None:
    raw = shb() + idb(options=tsresol(value)) + epb(3 * ticks_per_second, b"x")
    assert [p.ts_ns for p in read(raw)] == [3_000_000_000]


def test_base_two_resolution_keeps_fractions() -> None:
    raw = shb() + idb(options=tsresol(0x80 | 10)) + epb(512, b"x")  # half a second
    assert [p.ts_ns for p in read(raw)] == [500_000_000]


def test_timestamp_offset_is_added() -> None:
    offset = option(14, struct.pack("<q", 3600)) + END
    raw = shb() + idb(options=tsresol(9)[:-4] + offset) + epb(5, b"x")
    assert [p.ts_ns for p in read(raw)] == [3600 * 10**9 + 5]


def test_negative_timestamp_offset() -> None:
    offset = option(14, struct.pack("<q", -1)) + END
    raw = shb() + idb(options=tsresol(0)[:-4] + offset) + epb(10, b"x")
    assert [p.ts_ns for p in read(raw)] == [9 * 10**9]


def test_options_after_an_unknown_one_are_still_read() -> None:
    options = option(2, b"eth0") + option(3, b"odd") + tsresol(0)  # if_name, if_description
    raw = shb() + idb(options=options) + epb(2, b"x")
    assert [p.ts_ns for p in read(raw)] == [2 * 10**9]


def test_options_without_an_end_marker_are_accepted() -> None:
    raw = shb() + idb(options=option(9, bytes([0]))) + epb(2, b"x")
    assert [p.ts_ns for p in read(raw)] == [2 * 10**9]


def test_section_header_options_and_packet_options_are_ignored() -> None:
    comment = option(1, b"hello") + END
    flags = option(2, struct.pack("<I", 1)) + END  # epb_flags
    raw = shb(options=comment) + idb() + epb(1, b"abc", options=flags) + epb(2, b"de")
    assert [p.data for p in read(raw)] == [b"abc", b"de"]


def test_blocks_of_other_types_are_skipped() -> None:
    names = block(4, option(1, b"\x0a\x00\x00\x01") + END)  # name resolution
    stats = block(5, struct.pack("<IIIiI", 0, 0, 0, 0, 0) + END)  # interface statistics
    custom = block(0x40000BAD, b"anything")
    raw = shb() + names + idb() + stats + epb(1, b"a") + custom + epb(2, b"b") + names
    assert [p.data for p in read(raw)] == [b"a", b"b"]


def test_simple_packet_blocks_take_the_time_of_the_packet_before() -> None:
    raw = (
        shb() + idb() + spb(b"first") + epb(7, b"second") + spb(b"third") + epb(9, b"x") + spb(b"y")
    )
    got = read(raw)
    assert [(p.ts_ns, p.data) for p in got] == [
        (0, b"first"),
        (7000, b"second"),
        (7000, b"third"),
        (9000, b"x"),
        (9000, b"y"),
    ]


def test_simple_packet_block_is_cut_at_the_snap_length() -> None:
    raw = shb() + idb(snaplen=4) + spb(b"abcd", orig_len=10)
    assert read(raw) == [Packet(0, 10, b"abcd")]


def test_simple_packet_block_without_a_snap_length_keeps_everything() -> None:
    raw = shb() + idb(snaplen=0) + spb(b"abcdefgh", orig_len=8)
    assert read(raw) == [Packet(0, 8, b"abcdefgh")]


def test_simple_packet_block_shorter_than_it_claims() -> None:
    with pytest.raises(PcapError, match="truncated pcapng packet"):
        read(shb() + idb() + spb(b"abcd", orig_len=100))


def test_simple_packet_block_too_short_for_its_length_field() -> None:
    with pytest.raises(PcapError, match="too short"):
        read(shb() + idb() + block(3, b""))


def test_simple_packet_block_over_the_maximum_length() -> None:
    with pytest.raises(PcapError, match="captured length"):
        read(shb() + idb() + block(3, struct.pack("<I", 300_000) + b"abcd"))


def test_two_sections_with_different_byte_orders() -> None:
    raw = shb("<") + idb("<") + epb(1, b"a") + shb(">") + idb(">") + epb(2, b"b", ">")
    assert [p.data for p in read(raw)] == [b"a", b"b"]


def test_a_new_section_forgets_the_interfaces_of_the_old_one() -> None:
    raw = (
        shb()
        + idb()
        + idb()
        + epb(1, b"a", interface=1)
        + shb()
        + idb()
        + epb(2, b"b", interface=1)
    )
    reader = PcapngReader(io.BytesIO(raw))
    it = iter(reader)
    assert next(it).data == b"a"
    with pytest.raises(PcapError, match="interface 1"):
        next(it)


def test_a_second_interface_has_its_own_resolution() -> None:
    raw = (
        shb()
        + idb(options=tsresol(9))
        + idb(options=tsresol(0))
        + epb(5, b"a")
        + epb(5, b"b", interface=1)
    )
    assert [(p.ts_ns, p.data) for p in read(raw)] == [(5, b"a"), (5 * 10**9, b"b")]


def test_a_packet_on_an_interface_with_another_link_type_stops_the_read() -> None:
    raw = (
        shb() + idb() + idb(linktype=113) + epb(1, b"a") + epb(2, b"b", interface=1) + epb(3, b"c")
    )
    it = iter(PcapngReader(io.BytesIO(raw)))
    assert next(it).data == b"a"
    with pytest.raises(PcapError, match="interface 1 has link type 113"):
        next(it)


def test_an_interface_with_another_link_type_that_carries_nothing_is_fine() -> None:
    raw = shb() + idb() + idb(linktype=113) + epb(1, b"a")
    assert [p.data for p in read(raw)] == [b"a"]


def test_link_type_is_the_first_interfaces() -> None:
    reader = PcapngReader(io.BytesIO(shb() + idb(linktype=101) + idb(linktype=1)))
    assert reader.linktype == 101


def test_a_file_with_no_packets() -> None:
    assert read(shb() + idb()) == []


def test_data_of_every_length_is_padded_and_read_back() -> None:
    for n in range(9):
        data = bytes(range(1, n + 1))
        assert read(shb() + idb() + epb(1, data) + epb(2, b"z"))[0].data == data


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"", "does not start with a section header"),
        (b"\x00" * 8, "invalid pcapng block length 0"),
        (idb() + shb(), "does not start with a section header"),
        (b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + bytes(4), "byte-order magic"),
        (b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28), "byte-order magic"),
        (shb() + b"\x01\x00\x00", "truncated pcapng block header"),
        (shb(), "no interface description block"),
        (shb() + block(4, b""), "no interface description block"),
        (shb() + block(1, b"abc"), "interface description block is too short"),
        (shb() + epb(1, b"a"), "interface 0"),
        (shb() + spb(b"a"), "before any interface"),
    ],
)
def test_bad_starts(raw: bytes, message: str) -> None:
    with pytest.raises(PcapError, match=message):
        PcapngReader(io.BytesIO(raw))


def test_unsupported_version() -> None:
    raw = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 2, 0, -1))
    with pytest.raises(PcapError, match="version 2"):
        read(raw + idb())


@pytest.mark.parametrize("length", [0, 4, 8, 13, 15, 27, MAX_BLOCK + 4, 0xFFFFFFFF])
def test_invalid_block_lengths(length: int) -> None:
    bad = struct.pack("<II", 0x7, length)
    with pytest.raises(PcapError, match="invalid pcapng block length"):
        read(shb() + idb() + bad + bytes(16))


def test_a_section_header_shorter_than_the_smallest() -> None:
    with pytest.raises(PcapError, match="invalid pcapng block length 24"):
        read(b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 24) + b"\x4d\x3c\x2b\x1a" + bytes(12))


def test_a_block_of_the_smallest_length_is_fine() -> None:
    assert read(shb() + idb() + block(0x7, b"") + epb(1, b"a")) == [Packet(1000, 1, b"a")]


def test_the_largest_allowed_block_length_is_accepted() -> None:
    with pytest.raises(PcapError, match="truncated pcapng block"):  # length ok, data missing
        read(shb() + idb() + struct.pack("<II", 0x7, MAX_BLOCK) + b"x")


def test_repeated_length_must_match() -> None:
    bad = bytearray(epb(1, b"abcd"))
    bad[-4:] = struct.pack("<I", 99)
    with pytest.raises(PcapError, match="is repeated as 99"):
        read(shb() + idb() + bytes(bad))


def test_truncated_block_yields_earlier_packets_then_raises() -> None:
    raw = shb() + idb() + epb(1, b"a") + epb(2, b"b")
    it = iter(PcapngReader(io.BytesIO(raw[:-5])))
    assert next(it).data == b"a"
    with pytest.raises(PcapError, match="truncated pcapng block"):
        next(it)


def test_packet_on_an_interface_that_is_not_described() -> None:
    with pytest.raises(PcapError, match="interface 1"):
        read(shb() + idb() + epb(1, b"a", interface=1))


def test_captured_length_over_the_maximum() -> None:
    head = struct.pack("<IIIII", 0, 0, 1, 0xFFFFFFFF, 0xFFFFFFFF)
    with pytest.raises(PcapError, match="captured length"):
        read(shb() + idb() + block(6, head))


def test_captured_length_longer_than_the_block() -> None:
    head = struct.pack("<IIIII", 0, 0, 1, 100, 100)
    with pytest.raises(PcapError, match="truncated pcapng packet"):
        read(shb() + idb() + block(6, head + b"abc"))


def test_a_packet_block_too_short_for_its_fields() -> None:
    with pytest.raises(PcapError, match="enhanced packet block is too short"):
        read(shb() + idb() + block(6, bytes(16)))


def test_an_option_that_runs_past_its_block() -> None:
    bad = struct.pack("<HH", 9, 40) + bytes([6, 0, 0, 0])
    with pytest.raises(PcapError, match="option 9 runs past"):
        read(shb() + idb(options=bad))


@pytest.mark.parametrize(("code", "size"), [(9, 2), (9, 0), (14, 4), (14, 9)])
def test_options_of_the_wrong_size(code: int, size: int) -> None:
    with pytest.raises(PcapError, match="not"):
        read(shb() + idb(options=option(code, bytes(size))))


def test_timestamp_far_in_the_future_is_rejected() -> None:
    raw = shb() + idb(options=tsresol(0)) + epb(1 << 40, b"a")
    with pytest.raises(PcapError, match="out of range"):
        read(raw)


def test_the_last_second_a_summary_can_print_is_accepted() -> None:
    raw = shb() + idb(options=tsresol(0)) + epb(MAX_TS_NS // 10**9, b"a")
    assert [p.ts_ns for p in read(raw)] == [MAX_TS_NS]
    raw = shb() + idb(options=tsresol(0)) + epb(MAX_TS_NS // 10**9 + 1, b"a")
    with pytest.raises(PcapError, match="out of range"):
        read(raw)


def test_timestamp_before_1970_is_rejected() -> None:
    offset = option(14, struct.pack("<q", -5)) + END
    raw = shb() + idb(options=tsresol(0)[:-4] + offset) + epb(4, b"a")
    with pytest.raises(PcapError, match="out of range"):
        read(raw)
    raw = shb() + idb(options=tsresol(0)[:-4] + offset) + epb(5, b"a")
    assert [p.ts_ns for p in read(raw)] == [0]


def test_a_huge_exponent_does_not_break_anything() -> None:
    raw = shb() + idb(options=tsresol(0x7F)) + epb(123456789, b"a") + epb(1, b"b")
    assert [p.ts_ns for p in read(raw)] == [0, 0]
    raw = shb() + idb(options=tsresol(0xFF)) + epb(123456789, b"a")
    assert [p.ts_ns for p in read(raw)] == [0]


def test_random_bytes_only_raise_pcap_error(blobs: list[bytes]) -> None:
    start = shb() + idb()
    for blob in blobs:
        for raw in (blob, shb() + blob, start + blob):
            with contextlib.suppress(PcapError):
                read(raw)


def test_every_truncation_of_a_valid_file_is_handled() -> None:
    raw = pcapng_bytes(PACKETS)
    for n in range(len(raw) + 1):
        try:
            got = read(raw[:n])
        except PcapError:
            continue
        assert got == PACKETS[: len(got)]  # a cut at a block boundary is a shorter capture


def test_every_truncation_of_a_big_endian_file_is_handled() -> None:
    raw = pcapng_bytes(PACKETS, byteorder="big")
    for n in range(len(raw) + 1):
        try:
            got = read(raw[:n])
        except PcapError:
            continue
        assert got == PACKETS[: len(got)]


@pytest.mark.parametrize("byteorder", ["little", "big"])
def test_corrupted_bytes_only_raise_pcap_error(byteorder: str) -> None:
    rng = random.Random(7)
    raw = pcapng_bytes(PACKETS, byteorder=byteorder)  # type: ignore[arg-type]
    for i in range(len(raw)):
        for value in (rng.randrange(256), 0, 0xFF):
            bad = bytearray(raw)
            bad[i] = value
            with contextlib.suppress(PcapError):
                read(bytes(bad))


def test_open_reader_picks_the_format_from_the_first_bytes() -> None:
    classic = io.BytesIO()
    from sentinel.pcap import PcapWriter

    PcapWriter(classic).write(PACKETS[0])
    assert isinstance(open_reader(io.BytesIO(classic.getvalue())), PcapReader)
    ng = open_reader(io.BytesIO(pcapng_bytes(PACKETS)))
    assert isinstance(ng, PcapngReader)
    assert list(ng) == PACKETS


def test_open_reader_reads_from_the_start_of_the_stream() -> None:
    fp = io.BytesIO(pcapng_bytes(PACKETS))
    assert list(open_reader(fp)) == PACKETS
    fp = io.BytesIO(b"junk" + pcapng_bytes(PACKETS))
    fp.seek(4)
    assert list(open_reader(fp)) == PACKETS


@pytest.mark.parametrize("raw", [b"", b"\x0a\x0d", b"this is not a capture file"])
def test_open_reader_gives_the_classic_error_for_anything_else(raw: bytes) -> None:
    with pytest.raises(PcapError, match="pcap"):
        open_reader(io.BytesIO(raw))


def test_open_reader_on_a_real_file(tmp_path: Path) -> None:
    path = tmp_path / "x.pcapng"
    path.write_bytes(pcapng_bytes(PACKETS))
    with path.open("rb") as fp:
        assert list(open_reader(fp)) == PACKETS


def test_every_timestamp_the_reader_accepts_can_be_printed() -> None:
    raw = shb() + idb(options=tsresol(0)) + epb(MAX_TS_NS // 10**9, b"")
    (last,) = read(raw)
    assert _timestamp(last.ts_ns) == "9999-12-31 23:59:59.000000"
    with pytest.raises(OverflowError):  # one second later the summary could not print it
        _timestamp(MAX_TS_NS + 10**9)
