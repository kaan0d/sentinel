import struct

from sentinel.proto.tls import (
    is_grease,
    looks_like_client_hello,
    parse_client_hello,
)
from tools.gen_pcap import CLIENT_HELLO, client_hello


def hello(extensions: bytes | None, ciphers: bytes = b"\x13\x01") -> bytes:
    """A minimal ClientHello record; `extensions=None` leaves the extensions block out."""
    body = struct.pack("!H", 0x0303) + bytes(32) + b"\x00"
    body += struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00"
    if extensions is not None:
        body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3) + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def ext(kind: int, body: bytes, length: int | None = None) -> bytes:
    return struct.pack("!HH", kind, len(body) if length is None else length) + body


def test_generated_client_hello() -> None:
    hello_ = parse_client_hello(CLIENT_HELLO)
    assert hello_.error is None
    assert hello_.anomalies == ()
    assert hello_.record_version == 0x0301
    assert hello_.client_version == 0x0303
    assert hello_.server_name == "example.com"
    assert hello_.supported_versions == (0x2A2A, 0x0304, 0x0303)
    assert hello_.max_version == 0x0304
    assert len(hello_.cipher_suites) == 16
    assert hello_.cipher_suites[:4] == (0x0A0A, 0x1301, 0x1302, 0x1303)
    assert hello_.extensions == (0x1A1A, 0, 10, 43)


def test_hand_built_without_extensions() -> None:
    parsed = parse_client_hello(hello(None))
    assert parsed.error is None
    assert parsed.anomalies == ()
    assert parsed.cipher_suites == (0x1301,)
    assert parsed.server_name is None
    assert parsed.supported_versions == ()
    assert parsed.max_version == 0x0303  # falls back to the legacy field


def test_server_name_and_versions_hand_built() -> None:
    sni = ext(0, struct.pack("!HBH", 6, 0, 3) + b"a.b")
    versions = ext(43, b"\x04\x03\x04\x03\x03")
    parsed = parse_client_hello(hello(sni + versions))
    assert parsed.anomalies == ()
    assert parsed.server_name == "a.b"
    assert parsed.supported_versions == (0x0304, 0x0303)
    assert parsed.extensions == (0, 43)


def test_truncated_record_header() -> None:
    for n in range(9):
        parsed = parse_client_hello(CLIENT_HELLO[:n])
        assert parsed.error is not None
        assert "truncated" in parsed.error


def test_every_truncation_after_the_header_is_an_anomaly() -> None:
    for n in range(9, len(CLIENT_HELLO)):
        parsed = parse_client_hello(CLIENT_HELLO[:n])
        assert parsed.error is None, n
        assert any("truncated client hello" in a for a in parsed.anomalies), n


def test_truncated_capture_still_yields_the_server_name() -> None:
    cut = CLIENT_HELLO.index(b"example.com") + len(b"example.com")
    parsed = parse_client_hello(CLIENT_HELLO[:cut])
    assert parsed.server_name == "example.com"
    assert len(parsed.cipher_suites) == 16


def test_not_a_handshake_record() -> None:
    raw = b"\x17" + CLIENT_HELLO[1:]
    assert parse_client_hello(raw).error == "not a tls handshake record"
    assert parse_client_hello(b"\x16\x02" + CLIENT_HELLO[2:]).error == "not a tls handshake record"


def test_not_a_client_hello() -> None:
    raw = CLIENT_HELLO[:5] + b"\x02" + CLIENT_HELLO[6:]
    assert parse_client_hello(raw).error == "not a client hello: handshake type 2"


def test_odd_cipher_list_length() -> None:
    parsed = parse_client_hello(hello(None, ciphers=b"\x13\x01\x13"))
    assert "odd cipher suite list length" in parsed.anomalies
    assert parsed.cipher_suites == (0x1301,)


def test_record_length_over_the_tls_limit() -> None:
    raw = CLIENT_HELLO[:3] + struct.pack("!H", 20000) + CLIENT_HELLO[5:]
    assert "tls record longer than 16384 bytes" in parse_client_hello(raw).anomalies


def test_record_shorter_than_the_handshake_is_reported() -> None:
    # The handshake continues in another record, which this packet does not hold.
    raw = CLIENT_HELLO[:3] + struct.pack("!H", 50) + CLIENT_HELLO[5:]
    parsed = parse_client_hello(raw)
    assert parsed.error is None
    assert any("truncated client hello" in a for a in parsed.anomalies)


def test_odd_server_names_are_flagged_and_escaped() -> None:
    parsed = parse_client_hello(client_hello("bad name\x1b.test", [0x0304], [0x1301]))
    assert parsed.server_name == "bad name\\x1b.test"
    assert "unusual characters in tls server name" in parsed.anomalies


def test_malformed_extensions() -> None:
    cases = {
        "malformed server_name extension": ext(0, b"\x00\x05\x00"),
        "malformed supported_versions extension": ext(43, b"\x03\x03\x04\x03"),
        "truncated tls extension 0": ext(0, b"\x00\x01", length=100),
    }
    for expected, extension in cases.items():
        parsed = parse_client_hello(hello(extension))
        assert parsed.error is None, expected
        assert expected in parsed.anomalies, expected


def test_extension_block_cut_mid_header() -> None:
    parsed = parse_client_hello(hello(b"\x00\x00\x00"))  # 3 bytes: not even a full ext header
    assert parsed.error is None
    assert parsed.extensions == ()


def test_is_grease() -> None:
    assert all(is_grease(v) for v in (0x0A0A, 0x1A1A, 0x2A2A, 0xFAFA))
    assert not any(is_grease(v) for v in (0x0A1A, 0x1301, 0x0304, 0x0000, 0xFFFF))


def test_looks_like_client_hello() -> None:
    assert looks_like_client_hello(CLIENT_HELLO)
    assert not looks_like_client_hello(b"GET / HTTP/1.1")
    assert not looks_like_client_hello(CLIENT_HELLO[:5])
    assert not looks_like_client_hello(b"\x16\x03\x01\x00\x10\x02")


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    prefix = b"\x16\x03\x01\x00\x30\x01\x00\x00\x2c"
    for blob in blobs:
        parse_client_hello(blob)
        parse_client_hello(prefix + blob)
        parse_client_hello(prefix + struct.pack("!H", 0x0303) + bytes(32) + blob)


def test_corrupting_every_byte_never_raises() -> None:
    for i in range(len(CLIENT_HELLO)):
        for value in (0, 0xFF, 0x80):
            bad = bytearray(CLIENT_HELLO)
            bad[i] = value
            parse_client_hello(bytes(bad))
