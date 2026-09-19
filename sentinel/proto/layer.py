from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

ZERO4 = IPv4Address(0)
ZERO6 = IPv6Address(0)


@dataclass(frozen=True, slots=True, kw_only=True)
class Layer:
    """Base of every parse result. Parsers never raise.

    `error` set: the header could not be parsed, all other fields hold defaults and mean nothing.
    `anomalies`: the header parsed, but something is off (bad checksum, inconsistent length...).
    `payload`: the bytes after this header, trimmed to the length the header declares.
    """

    payload: bytes = b""
    error: str | None = None
    anomalies: tuple[str, ...] = ()


def printable(data: bytes) -> str:
    """Attacker-controlled bytes as a string that is safe to print: everything outside
    printable ASCII becomes a backslash-x escape, so control and escape sequences cannot
    reach a terminal."""
    return "".join(chr(b) if 0x20 <= b < 0x7F else f"\\x{b:02x}" for b in data)
