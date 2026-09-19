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
