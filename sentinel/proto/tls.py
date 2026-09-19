"""TLS ClientHello parser: server name (SNI), offered versions and the cipher suite list.

Reads one TCP segment. A ClientHello that spans several segments or records is parsed as far
as it is present and reported with an anomaly (reassembly is stage 3)."""

import struct
from dataclasses import dataclass

from sentinel.proto.layer import Layer, printable

VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}
CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
}

_RECORD_HEADER = 5
_HANDSHAKE_HEADER = 4
_MAX_RECORD = 16384
_EXT_SERVER_NAME = 0
_EXT_SUPPORTED_VERSIONS = 43
_HOSTNAME_CHARS = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")


class _Short(Exception):
    """Internal: the body ended before a field did. Always caught inside this module."""


@dataclass(frozen=True, slots=True, kw_only=True)
class TlsClientHello(Layer):
    """Values may include GREASE placeholders (see `is_grease`), as sent by real clients."""

    record_version: int = 0
    client_version: int = 0  # the legacy field; TLS 1.3 clients say 1.2 here
    server_name: str | None = None
    supported_versions: tuple[int, ...] = ()
    cipher_suites: tuple[int, ...] = ()
    extensions: tuple[int, ...] = ()  # extension type ids, in the order sent

    @property
    def max_version(self) -> int:
        """Highest version the client offers, ignoring GREASE."""
        offered = [v for v in self.supported_versions if not is_grease(v)]
        return max(offered, default=self.client_version)


def is_grease(value: int) -> bool:
    """RFC 8701 reserved values: 0x0a0a, 0x1a1a ... 0xfafa."""
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def looks_like_client_hello(data: bytes) -> bool:
    """TLS handshake record (0x16, major version 3) carrying a ClientHello (type 1)."""
    return len(data) >= 6 and data[0] == 0x16 and data[1] == 3 and data[5] == 1


class _Cursor:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise _Short
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2))


def _server_name(data: bytes) -> tuple[str | None, str | None]:
    """Returns the first host_name entry and a description of a problem, if any."""
    try:
        cur = _Cursor(data)
        cur.take(2)  # list length
        while cur.pos < len(data):
            name_type = cur.u8()
            name = cur.take(cur.u16())
            if name_type == 0:
                problem = None
                if not name or not set(name) <= _HOSTNAME_CHARS:
                    problem = "unusual characters in tls server name"
                return printable(name), problem
    except _Short:
        pass
    return None, "malformed server_name extension"


def parse_client_hello(data: bytes) -> TlsClientHello:
    """`data` is a TCP payload that starts with a TLS record."""
    fixed = _RECORD_HEADER + _HANDSHAKE_HEADER
    if len(data) < fixed:
        return TlsClientHello(error=f"truncated tls handshake: {len(data)} of {fixed} bytes")
    if data[0] != 0x16 or data[1] != 3:
        return TlsClientHello(error="not a tls handshake record")
    if data[5] != 1:
        return TlsClientHello(error=f"not a client hello: handshake type {data[5]}")
    record_version, record_len = struct.unpack_from("!HH", data, 1)
    hs_len = int.from_bytes(data[6:9])
    anomalies: list[str] = []
    if record_len > _MAX_RECORD:
        anomalies.append(f"tls record longer than {_MAX_RECORD} bytes")
    end = min(len(data), _RECORD_HEADER + record_len, fixed + hs_len)
    if end < fixed + hs_len:
        anomalies.append(f"truncated client hello: {end - fixed} of {hs_len} handshake bytes")

    client_version = 0
    ciphers: tuple[int, ...] = ()
    ext_types: list[int] = []
    server_name: str | None = None
    versions: tuple[int, ...] = ()
    cur = _Cursor(data[fixed:end])
    try:
        client_version = cur.u16()
        cur.take(32)  # random
        cur.take(cur.u8())  # session id
        cs_len = cur.u16()
        suites = cur.take(cs_len)
        if cs_len % 2:
            anomalies.append("odd cipher suite list length")
        ciphers = struct.unpack(f"!{cs_len // 2}H", suites[: cs_len - cs_len % 2])
        cur.take(cur.u8())  # compression methods
        region = b""
        if cur.pos < len(cur.data):  # extensions are optional
            ext_total = cur.u16()
            region = cur.data[cur.pos : cur.pos + ext_total]
        while len(region) >= 4:
            ext_type, ext_len = struct.unpack_from("!HH", region)
            body = region[4 : 4 + ext_len]
            ext_types.append(ext_type)
            if len(body) < ext_len:
                anomalies.append(f"truncated tls extension {ext_type}")
                break
            if ext_type == _EXT_SERVER_NAME and server_name is None:
                server_name, problem = _server_name(body)
                if problem:
                    anomalies.append(problem)
            elif ext_type == _EXT_SUPPORTED_VERSIONS:
                n = body[0] if body else 0
                if n % 2 or 1 + n > len(body):
                    anomalies.append("malformed supported_versions extension")
                else:
                    versions = struct.unpack(f"!{n // 2}H", body[1 : 1 + n])
            region = region[4 + ext_len :]
    except _Short:
        anomalies.append("client hello ends before its fields do")
    return TlsClientHello(
        record_version=record_version,
        client_version=client_version,
        server_name=server_name,
        supported_versions=versions,
        cipher_suites=ciphers,
        extensions=tuple(ext_types),
        anomalies=tuple(anomalies),
    )
