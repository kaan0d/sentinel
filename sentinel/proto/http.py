"""HTTP/1.x start line and headers, from one TCP segment. No stream reassembly: a message split
across segments is reported with an anomaly, not stitched together (that is stage 3)."""

from dataclasses import dataclass

from sentinel.proto.layer import Layer, printable

_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)
_MAX_HEAD = 16384
_MAX_START_LINE = 8192
_MAX_HEADERS = 100


@dataclass(frozen=True, slots=True, kw_only=True)
class Http(Layer):
    """`payload` is the body bytes present in this segment. Header names and values are
    printable-escaped strings (see `printable`)."""

    is_request: bool = False
    method: str = ""
    target: str = ""
    version: str = ""
    status: int = 0
    reason: str = ""
    headers: tuple[tuple[str, str], ...] = ()

    def header(self, name: str) -> str | None:
        """Value of the first header with this name, case-insensitive."""
        lowered = name.lower()
        return next((v for k, v in self.headers if k.lower() == lowered), None)


def looks_like_http(data: bytes) -> bool:
    return data.startswith(_METHODS) or data.startswith(b"HTTP/1.")


def parse_http(data: bytes) -> Http:
    end = data.find(b"\r\n\r\n")
    complete = end >= 0
    head = data[:end] if complete else data[:_MAX_HEAD]
    lines = head.split(b"\r\n")
    first = lines[0]
    if len(first) > _MAX_START_LINE:
        return Http(error=f"http start line longer than {_MAX_START_LINE} bytes")
    is_request = not first.startswith(b"HTTP/")
    method = target = reason = ""
    status = 0
    if is_request:
        parts = first.split(b" ")
        if len(parts) != 3 or not parts[2].startswith(b"HTTP/"):
            return Http(error="malformed http request line")
        method, target, version = (printable(p) for p in parts)
    else:
        parts = first.split(b" ", 2)
        if len(parts) < 2 or not (len(parts[1]) == 3 and parts[1].isdigit()):
            return Http(error="malformed http status line")
        version, status = printable(parts[0]), int(parts[1])
        reason = printable(parts[2]) if len(parts) == 3 else ""
    anomalies: list[str] = []
    if not complete:
        anomalies.append("http headers incomplete: no blank line in this segment")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:  # the segment ended exactly at a line break
            continue
        if len(headers) >= _MAX_HEADERS:
            anomalies.append(f"more than {_MAX_HEADERS} http headers")
            break
        name, colon, value = line.partition(b":")
        if not colon or not name or name != name.strip() or b" " in name:
            anomalies.append("malformed http header line")
            continue
        headers.append((printable(name), printable(value.strip(b" \t"))))
    lengths = {v for k, v in headers if k.lower() == "content-length"}
    if len(lengths) > 1:
        anomalies.append("conflicting content-length headers")
    elif lengths and not next(iter(lengths)).isdigit():
        anomalies.append("non-numeric content-length")
    return Http(
        is_request=is_request,
        method=method,
        target=target,
        version=version,
        status=status,
        reason=reason,
        headers=tuple(headers),
        payload=data[end + 4 :] if complete else b"",
        anomalies=tuple(anomalies),
    )
