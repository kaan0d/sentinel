"""The JA3 fingerprint of a ClientHello (stage 11). The hellos are built here byte by byte, and
not with tools.gen_pcap, and the known answer is the example of the JA3 specification."""

import hashlib
import struct
import subprocess
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from sentinel.filter import parse_filter
from sentinel.pcap import Packet, PcapWriter
from sentinel.proto.decode import decode
from sentinel.proto.tls import TlsClientHello, is_grease, parse_client_hello
from sentinel.summary import describe
from tools import compare_tshark as ct
from tools.gen_pcap import CLIENT_HELLO, MAC_A, MAC_B, eth_frame, ipv4_packet, tcp_segment

SPEC_STRING = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
SPEC_HASH = "ada70206e40642a3e4461f35503241d5"  # the example of the JA3 specification
GENERATED_HASH = "61279becc80ab0e3aca57f5913c3e1a0"  # the hello of the demo capture, as tshark says
GREASE = [(n << 4 | 0xA) * 0x101 for n in range(16)]  # 0x0a0a, 0x1a1a ... 0xfafa


def ext(kind: int, body: bytes = b"") -> bytes:
    return struct.pack("!HH", kind, len(body)) + body


def sni(name: bytes = b"example.com") -> bytes:
    return ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)


def groups(values: list[int]) -> bytes:
    return ext(10, struct.pack("!H", 2 * len(values)) + struct.pack(f"!{len(values)}H", *values))


def formats(values: list[int]) -> bytes:
    return ext(11, bytes([len(values)]) + bytes(values))


def hello(
    version: int,
    ciphers: list[int],
    extensions: list[bytes] | None,
    *,
    session: bytes = b"",
    block_lie: int = 0,
) -> bytes:
    """A ClientHello record. `extensions=None` leaves the extensions block out; `block_lie` is
    added to the length the extensions block claims (every other length stays right)."""
    body = struct.pack("!H", version) + bytes(32) + bytes([len(session)]) + session
    body += struct.pack("!H", 2 * len(ciphers)) + struct.pack(f"!{len(ciphers)}H", *ciphers)
    body += b"\x01\x00"
    if extensions is not None:
        block = b"".join(extensions)
        body += struct.pack("!H", len(block) + block_lie) + block
    handshake = b"\x01" + len(body).to_bytes(3) + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def spec_hello() -> bytes:
    return hello(
        769,
        [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
        [sni(), groups([23, 24, 25]), formats([0])],
    )


def parsed(data: bytes) -> TlsClientHello:
    result = parse_client_hello(data)
    assert result.error is None
    return result


# ---- the known answer ------------------------------------------------------------------------


def test_the_example_of_the_specification() -> None:
    result = parsed(spec_hello())
    assert result.ja3_string == SPEC_STRING
    assert result.ja3 == SPEC_HASH
    assert result.complete
    assert result.anomalies == ()


def test_the_hash_is_the_md5_of_the_string_as_32_lowercase_hex_digits() -> None:
    result = parsed(spec_hello())
    assert result.ja3 == hashlib.md5(SPEC_STRING.encode()).hexdigest()
    assert len(result.ja3 or "") == 32
    assert (result.ja3 or "") == (result.ja3 or "").lower()


def test_the_hello_of_the_demo_capture() -> None:
    result = parse_client_hello(CLIENT_HELLO)
    assert result.ja3 == GENERATED_HASH
    assert result.ja3_string == (
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
        "0-10-43,29-23-24,"
    )


# ---- the two lists the parser reads for it ---------------------------------------------------


def test_supported_groups_and_point_formats_are_read_in_order() -> None:
    result = parsed(hello(771, [1], [groups([29, 23, 0x0A0A, 24]), formats([0, 1, 2])]))
    assert result.supported_groups == (29, 23, 0x0A0A, 24)
    assert result.ec_point_formats == (0, 1, 2)
    assert result.extensions == (10, 11)


def test_a_hello_without_them_has_none() -> None:
    result = parsed(hello(771, [1], [sni()]))
    assert result.supported_groups == ()
    assert result.ec_point_formats == ()


def test_empty_lists_are_valid() -> None:
    result = parsed(hello(771, [1], [groups([]), formats([])]))
    assert (result.supported_groups, result.ec_point_formats) == ((), ())
    assert result.anomalies == ()
    assert result.ja3_string == "771,1,10-11,,"


# ---- what JA3 leaves out, keeps and orders ---------------------------------------------------


def test_every_grease_value_is_left_out_of_every_list() -> None:
    with_grease = hello(
        771,
        [GREASE[0], 4865, GREASE[7], 4866],
        [ext(GREASE[1]), sni(), groups([GREASE[2], 29, 23]), formats([0]), ext(GREASE[15])],
    )
    without = hello(771, [4865, 4866], [sni(), groups([29, 23]), formats([0])])
    assert parsed(with_grease).ja3_string == parsed(without).ja3_string
    assert parsed(with_grease).ja3 == parsed(without).ja3
    for value in GREASE:
        assert is_grease(value)
        assert parsed(hello(771, [value], [])).ja3_string == "771,,,,"


def test_values_that_only_look_like_grease_are_kept() -> None:
    near = [0x0A1A, 0x1A0A, 0x0B0B, 0x0A0B, 0x0A0A + 1]
    result = parsed(hello(771, near, [ext(0x0A1A), groups([0x1A0A]), formats([10])]))
    # 0x0a1a, 0x1a0a, 0x0b0b, 0x0a0b and 0x0a0b again: none of them is GREASE
    assert result.ja3_string == "771,2586-6666-2827-2571-2571,2586-10-11,6666,10"


def test_the_order_matters_and_repeats_are_kept() -> None:
    a = parsed(hello(771, [1, 2, 3], [sni(), groups([23])]))
    b = parsed(hello(771, [3, 2, 1], [sni(), groups([23])]))
    c = parsed(hello(771, [1, 2, 3], [groups([23]), sni()]))
    assert len({a.ja3, b.ja3, c.ja3}) == 3
    repeated = parsed(hello(771, [1, 1, 2], [sni(), sni(), groups([23, 23])]))
    assert repeated.ja3_string == "771,1-1-2,0-0-10,23-23,"


def test_the_version_is_the_legacy_field_and_not_supported_versions() -> None:
    result = parsed(hello(0x0303, [4865], [sni(), ext(43, b"\x04\x03\x04\x03\x03")]))
    assert result.ja3_string == "771,4865,0-43,,"
    assert result.supported_versions == (0x0304, 0x0303)


def test_the_server_name_and_the_session_id_are_not_part_of_it() -> None:
    a = parsed(hello(771, [4865], [sni(b"a.example"), groups([29])], session=b""))
    b = parsed(hello(771, [4865], [sni(b"b.example.org"), groups([29])], session=bytes(32)))
    assert a.ja3 == b.ja3
    assert a.server_name != b.server_name


def test_a_hello_without_extensions_has_empty_fields() -> None:
    result = parsed(hello(771, [4865], None))
    assert result.ja3_string == "771,4865,,,"
    assert result.ja3 == hashlib.md5(b"771,4865,,,").hexdigest()
    assert parsed(hello(771, [4865], [])).ja3_string == "771,4865,,,"


def test_a_hello_without_ciphers() -> None:
    assert parsed(hello(771, [], [])).ja3_string == "771,,,,"


def test_unknown_extensions_and_a_version_of_zero() -> None:
    result = parsed(hello(0, [4865], [ext(65281, b"\x00"), ext(21, bytes(8))]))
    assert result.ja3_string == "0,4865,65281-21,,"


# ---- a hello that is not whole has no fingerprint --------------------------------------------


def test_every_shorter_prefix_of_a_hello_has_no_fingerprint() -> None:
    data = spec_hello()
    assert parsed(data).ja3 == SPEC_HASH
    for n in range(len(data)):
        result = parse_client_hello(data[:n])
        assert result.ja3 is None
        assert result.ja3_string is None
        assert not result.complete


def test_a_cut_hello_says_why() -> None:
    data = spec_hello()
    result = parsed(data[:-3])
    assert any("truncated" in a for a in result.anomalies)
    assert result.ja3 is None


def test_a_hello_that_ends_before_its_fields_do() -> None:
    body = struct.pack("!H", 771) + bytes(32) + b"\x00" + struct.pack("!H", 10) + b"\x13\x01"
    handshake = b"\x01" + len(body).to_bytes(3) + body
    result = parsed(b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake)
    assert any("ends before" in a for a in result.anomalies)
    assert result.ja3 is None


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        (ext(10, b"\x00\x04\x00\x1d"), "malformed supported_groups"),  # says 4 bytes, has 2
        (ext(10, b"\x00\x03\x00\x1d\x00"), "malformed supported_groups"),  # an odd length
        (ext(10, b""), "malformed supported_groups"),
        (ext(10, b"\x00"), "malformed supported_groups"),
        (ext(11, b"\x03\x00"), "malformed ec_point_formats"),  # says 3, has 1
        (ext(11, b""), "malformed ec_point_formats"),
    ],
)
def test_a_malformed_list_is_reported_and_leaves_no_fingerprint(bad: bytes, message: str) -> None:
    result = parsed(hello(771, [4865], [sni(), bad]))
    assert any(message in a for a in result.anomalies)
    assert result.ja3 is None
    assert not result.complete
    assert result.extensions == (0, bad[0] << 8 | bad[1])
    assert (result.supported_groups, result.ec_point_formats) == ((), ())


def test_an_extension_that_is_cut_off() -> None:
    data = hello(771, [4865], [sni(), groups([29, 23])])
    cut = data[:-2]
    result = parsed(cut)
    assert result.ja3 is None
    assert any("truncated" in a for a in result.anomalies)


def test_an_extension_that_claims_more_than_the_hello_holds() -> None:
    # every outer length is right (record, handshake, block): only the last extension lies
    result = parsed(hello(771, [4865], [sni(), struct.pack("!HH", 99, 9) + b"ab"]))
    assert any("truncated tls extension 99" in a for a in result.anomalies)
    assert result.extensions == (0, 99)
    assert not result.complete
    assert result.ja3 is None


def test_an_extensions_block_that_claims_more_than_the_hello_holds() -> None:
    # the handshake length is right, and every extension inside the block is whole
    result = parsed(hello(771, [4865], [sni(), groups([29])], block_lie=2))
    assert result.extensions == (0, 10)
    assert result.supported_groups == (29,)
    assert not result.complete
    assert result.ja3 is None


def test_extra_bytes_after_the_hello_do_not_matter() -> None:
    assert parsed(spec_hello() + b"more data").ja3 == SPEC_HASH


def test_nothing_that_is_not_a_hello_has_a_fingerprint() -> None:
    for junk in (b"", b"junk", bytes(50), b"\x16\x03\x01\x00\x04\x02\x00\x00\x00"):
        assert parse_client_hello(junk).ja3 is None
        assert parse_client_hello(junk).ja3_string is None


def test_a_hello_that_the_parser_reads_but_a_record_cuts() -> None:
    data = bytearray(spec_hello())
    data[3:5] = struct.pack("!H", len(data) - 5 - 10)  # the record says it ends ten bytes early
    result = parsed(bytes(data))
    assert result.ja3 is None
    assert any("truncated" in a for a in result.anomalies)


# ---- the summary line and the filter ---------------------------------------------------------


def frame_of(payload: bytes, dport: int = 443) -> bytes:
    src, dst = IPv4Address("10.0.0.1"), IPv4Address("10.0.0.2")
    segment = tcp_segment(src, dst, 40000, dport, 1, 1, 0x18, payload=payload)
    return eth_frame(MAC_B, MAC_A, 0x0800, ipv4_packet(src, dst, 6, segment))


def test_the_summary_line_ends_with_the_fingerprint() -> None:
    frame = frame_of(spec_hello())
    line = describe(decode(frame), len(frame))
    assert line.endswith(f"ja3 {SPEC_HASH}")
    assert "TLS ClientHello" in line


def test_a_cut_hello_has_no_fingerprint_in_the_summary() -> None:
    frame = frame_of(spec_hello()[:-3])
    line = describe(decode(frame), len(frame))
    assert "TLS ClientHello" in line
    assert "ja3" not in line


def matches(text: str, frame: bytes) -> bool:
    flt = parse_filter(text)
    assert flt.error is None, flt.error
    return flt.matches(decode(frame))


def test_the_filter_finds_a_fingerprint() -> None:
    frame = frame_of(spec_hello())
    other = frame_of(hello(771, [4865], [sni(), groups([29])]))
    assert matches(f"ja3 {SPEC_HASH}", frame)
    assert not matches(f"ja3 {SPEC_HASH}", other)
    assert matches(f"ja3 {SPEC_HASH.upper()}", frame)  # the hash is not case sensitive
    assert matches(f"tls and ja3 {SPEC_HASH}", frame)
    assert matches(f"ja3 {SPEC_HASH} and port 443", frame)
    assert not matches(f"ja3 {SPEC_HASH} and port 80", frame)
    assert matches(f"not ja3 {SPEC_HASH}", other)
    assert not matches(f"not ja3 {SPEC_HASH}", frame)
    assert matches(f"ja3 {SPEC_HASH} or port 22", frame)


def test_the_filter_does_not_match_packets_without_a_hello() -> None:
    for frame in (
        frame_of(b"GET / HTTP/1.1\r\n\r\n", 80),
        frame_of(spec_hello()[:-3]),
        b"junk",
        b"",
    ):
        assert not matches(f"ja3 {SPEC_HASH}", frame)


def test_the_filter_text_prints_back_the_way_it_was_read() -> None:
    flt = parse_filter(f"ja3 {SPEC_HASH.upper()} and tcp")
    assert flt.error is None
    assert str(flt) == f"ja3 {SPEC_HASH} and tcp"
    assert parse_filter(str(flt)).expr == flt.expr


@pytest.mark.parametrize(
    ("text", "position", "message"),
    [
        ("ja3", 3, "expected a JA3 hash"),
        (f"ja3 {SPEC_HASH[:-1]}", 4, "expected a JA3 hash of 32 hex digits"),
        (f"ja3 {SPEC_HASH}0", 4, "expected a JA3 hash of 32 hex digits"),
        (f"ja3 {'g' * 32}", 4, "expected a JA3 hash of 32 hex digits"),
        ("ja3 port", 4, "expected a JA3 hash of 32 hex digits"),
        ("tcp and ja3", 11, "expected a JA3 hash"),
    ],
)
def test_bad_ja3_filters_say_what_is_wrong(text: str, position: int, message: str) -> None:
    flt = parse_filter(text)
    assert flt.error is not None
    assert message in flt.error
    assert flt.position == position


def test_a_thirty_two_digit_hash_of_any_kind_is_accepted() -> None:
    for digest in ("0" * 32, "f" * 32, "0123456789abcdefABCDEF0123456789"):
        assert parse_filter(f"ja3 {digest}").error is None


# ---- the same hellos, read by tshark ---------------------------------------------------------


def real_tshark() -> str | None:
    try:
        tshark = ct.find_tshark()
        done = subprocess.run([tshark, "--version"], capture_output=True, check=False)
    except (ct.TsharkError, OSError):
        return None
    return tshark if done.returncode == 0 else None


TSHARK = real_tshark()


@pytest.mark.skipif(TSHARK is None, reason="tshark is not installed")
def test_tshark_gives_the_same_fingerprints(tmp_path: Path) -> None:
    assert TSHARK is not None
    hellos = [
        spec_hello(),
        hello(771, [4865], None),
        hello(771, [4865], []),
        hello(
            0x0303,
            [GREASE[0], 4865, 4866, 49195, GREASE[3], 47],
            [
                ext(GREASE[1]),
                sni(),
                groups([GREASE[2], 29, 23, 24]),
                formats([0]),
                ext(43, b"\x04\x03\x04\x03\x03"),
                ext(GREASE[9]),
            ],
        ),
        hello(
            771, [1, 1, 2], [sni(), sni(), groups([23, 23]), formats([1, 0, 2])], session=bytes(32)
        ),
        hello(0x0301, [0x0A1A, 0x1A0A, 0x0B0B], [ext(0x0A1A), groups([0x1A0A]), formats([10])]),
    ]
    path = tmp_path / "hellos.pcap"
    with path.open("wb") as fp:
        writer = PcapWriter(fp)
        for i, data in enumerate(hellos):
            frame = frame_of(data)
            writer.write(Packet(i * 1000, len(frame), frame))
    report = ct.compare_file(path, TSHARK)
    assert report.packets == len(hellos)
    assert report.differences == ()
    # every hello has a fingerprint on both sides, so 6 of them were compared, and the lists too
    ours = [ct.ours(Packet(0, len(frame_of(h)), frame_of(h)), decode(frame_of(h))) for h in hellos]
    assert all("tls.ja3" in fields for fields in ours)
