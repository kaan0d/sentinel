"""Application-layer messages found in a flow's reassembled streams.

Stage 2 parses one segment at a time. Here the parsers see whole streams, so a message split
across segments is parsed in one piece, and HTTP is only looked for at message boundaries (a
body that happens to contain `GET ` is a body)."""

from dataclasses import dataclass

from sentinel.proto.dns import parse_dns
from sentinel.proto.http import looks_like_http, parse_http
from sentinel.proto.layer import Layer
from sentinel.proto.tls import looks_like_client_hello, parse_client_hello

DNS_PORT = 53
MAX_MESSAGES = 100
_MAX_HEAD = 16384


@dataclass(frozen=True, slots=True)
class AppItem:
    direction: int  # 0: client to server, 1: server to client
    layer: Layer


def dns_messages(data: bytes) -> list[Layer]:
    """DNS over TCP: each message has a 2-byte length prefix. A last message cut short is parsed
    as far as it goes and reported with an anomaly."""
    out: list[Layer] = []
    pos = 0
    while pos + 2 <= len(data) and len(out) < MAX_MESSAGES:
        size = int.from_bytes(data[pos : pos + 2])
        out.append(parse_dns(data[pos + 2 : pos + 2 + size]))
        pos += 2 + size
    return out


def http_messages(data: bytes) -> list[Layer]:
    """Successive HTTP/1.x messages. A body is skipped using Content-Length. Parsing stops at a
    body of unknown length (chunked, or read until the connection closes)."""
    out: list[Layer] = []
    pos = 0
    while pos < len(data) and len(out) < MAX_MESSAGES and looks_like_http(data[pos : pos + 16]):
        end = data.find(b"\r\n\r\n", pos)
        if end < 0:
            out.append(parse_http(data[pos : pos + _MAX_HEAD]))
            break
        message = parse_http(data[pos : end + 4])
        out.append(message)
        length = message.header("content-length")
        if message.error or message.header("transfer-encoding"):
            break
        if length is not None and length.isdigit():
            pos = end + 4 + int(length)
        elif message.is_request:
            pos = end + 4
        else:
            break  # a response without Content-Length runs to the end of the connection
    return out


def analyze_stream(direction: int, data: bytes, dns: bool) -> list[AppItem]:
    if dns:
        messages = dns_messages(data)
    elif looks_like_http(data[:16]):
        messages = http_messages(data)
    elif direction == 0 and looks_like_client_hello(data):
        messages = [parse_client_hello(data)]
    else:
        messages = []
    return [AppItem(direction, m) for m in messages]
