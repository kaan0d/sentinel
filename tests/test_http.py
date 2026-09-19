from sentinel.proto.http import looks_like_http, parse_http

REQUEST = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: t\r\n\r\n"
RESPONSE = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc"


def test_valid_request_hand_built() -> None:
    http = parse_http(REQUEST)
    assert http.error is None
    assert http.anomalies == ()
    assert http.is_request
    assert (http.method, http.target, http.version) == ("GET", "/index.html", "HTTP/1.1")
    assert http.headers == (("Host", "example.test"), ("User-Agent", "t"))
    assert http.payload == b""


def test_valid_response_with_body() -> None:
    http = parse_http(RESPONSE)
    assert http.error is None
    assert http.anomalies == ()
    assert not http.is_request
    assert (http.version, http.status, http.reason) == ("HTTP/1.1", 404, "Not Found")
    assert http.payload == b"abc"


def test_header_lookup_is_case_insensitive() -> None:
    http = parse_http(REQUEST)
    assert http.header("host") == "example.test"
    assert http.header("USER-AGENT") == "t"
    assert http.header("accept") is None


def test_status_line_without_reason() -> None:
    http = parse_http(b"HTTP/1.1 204\r\n\r\n")
    assert (http.error, http.status, http.reason) == (None, 204, "")


def test_request_with_body() -> None:
    http = parse_http(b"POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\ndata")
    assert http.method == "POST"
    assert http.payload == b"data"


def test_headers_cut_off_by_the_segment_are_an_anomaly() -> None:
    http = parse_http(REQUEST[:-4])  # blank line missing
    assert http.error is None
    assert http.anomalies == ("http headers incomplete: no blank line in this segment",)
    assert http.header("host") == "example.test"
    assert http.payload == b""


def test_a_segment_ending_exactly_at_a_line_break_has_no_malformed_line() -> None:
    http = parse_http(b"GET / HTTP/1.1\r\nHost: a\r\n")
    assert http.headers == (("Host", "a"),)
    assert http.anomalies == ("http headers incomplete: no blank line in this segment",)


def test_every_truncation_never_raises() -> None:
    for message in (REQUEST, RESPONSE):
        for n in range(len(message) + 1):
            http = parse_http(message[:n])
            if n < 8:
                # too short to be a request or status line
                assert http.error is not None or n == 0


def test_malformed_request_lines() -> None:
    for raw in (b"GET /\r\n\r\n", b"GET / HTTP/1.1 extra\r\n\r\n", b"GET / FTP/1.0\r\n\r\n"):
        assert parse_http(raw).error == "malformed http request line", raw


def test_malformed_status_lines() -> None:
    for raw in (b"HTTP/1.1\r\n\r\n", b"HTTP/1.1 20 OK\r\n\r\n", b"HTTP/1.1 2xx OK\r\n\r\n"):
        assert parse_http(raw).error == "malformed http status line", raw


def test_oversized_start_line() -> None:
    assert parse_http(b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\n\r\n").error is not None


def test_malformed_header_lines_are_skipped_and_reported() -> None:
    raw = b"GET / HTTP/1.1\r\nHost: a\r\nno colon here\r\n: empty name\r\nBad Name: x\r\n\r\n"
    http = parse_http(raw)
    assert http.error is None
    assert http.headers == (("Host", "a"),)
    assert http.anomalies == ("malformed http header line",) * 3


def test_content_length_problems() -> None:
    conflict = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n")
    assert conflict.anomalies == ("conflicting content-length headers",)
    bad = parse_http(b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n")
    assert bad.anomalies == ("non-numeric content-length",)
    same = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\n")
    assert same.anomalies == ()


def test_header_count_is_capped() -> None:
    raw = b"GET / HTTP/1.1\r\n" + b"X: 1\r\n" * 150 + b"\r\n"
    http = parse_http(raw)
    assert len(http.headers) == 100
    assert http.anomalies == ("more than 100 http headers",)


def test_control_characters_are_escaped() -> None:
    http = parse_http(b"GET /a\x1b[2Jb HTTP/1.1\r\nHost: \x07evil\r\n\r\n")
    assert http.target == "/a\\x1b[2Jb"
    assert http.header("host") == "\\x07evil"


def test_looks_like_http() -> None:
    assert looks_like_http(b"GET / HTTP/1.1")
    assert looks_like_http(b"HTTP/1.0 200 OK")
    assert looks_like_http(b"OPTIONS * HTTP/1.1")
    assert not looks_like_http(b"GETTING / HTTP/1.1")
    assert not looks_like_http(b"\x16\x03\x01")
    assert not looks_like_http(b"")


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    for blob in blobs:
        parse_http(blob)
        parse_http(b"GET / HTTP/1.1\r\n" + blob)
        parse_http(b"HTTP/1.1 200 OK\r\n" + blob + b"\r\n\r\n")
