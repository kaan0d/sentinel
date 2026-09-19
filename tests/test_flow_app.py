import random

from sentinel.flow import FlowTable
from sentinel.flow.app import MAX_MESSAGES, dns_messages, http_messages
from sentinel.pcap import Packet
from sentinel.proto import tcp
from sentinel.proto.dns import Dns
from sentinel.proto.http import Http
from sentinel.proto.tls import TlsClientHello
from tools.gen_pcap import CLIENT_HELLO, Conversation, dns_query

PSH_ACK = tcp.PSH | tcp.ACK


def flow_of(frames: list[bytes]) -> FlowTable:
    table = FlowTable()
    for i, frame in enumerate(frames):
        table.add(Packet(i * 1000, len(frame), frame))
    return table


def conversation(port: int = 8080) -> tuple[list[bytes], Conversation]:
    frames: list[bytes] = []
    conv = Conversation(frames, 40000, port)
    conv.handshake(1000, 2000)
    return frames, conv


BODY = b"GET /inside-the-body HTTP/1.1\r\n\r\n"
REQUEST = b"POST /up HTTP/1.1\r\nHost: h.test\r\nContent-Length: %d\r\n\r\n" % len(BODY)


def test_http_split_across_segments_and_shuffled_is_one_message() -> None:
    frames, conv = conversation()
    whole = REQUEST + BODY
    pieces = [(0, whole[:20]), (20, whole[20 : len(REQUEST)]), (len(REQUEST), BODY)]
    for off, chunk in (pieces[2], pieces[0], pieces[1]):
        conv.client(1001 + off, 2001, PSH_ACK, chunk)
    conv.server(2001, 1001 + len(whole), PSH_ACK, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    items = flow_of(frames).flows[0].app()
    assert [(i.direction, type(i.layer)) for i in items] == [(0, Http), (1, Http)]
    request, response = items[0].layer, items[1].layer
    assert isinstance(request, Http)
    assert isinstance(response, Http)
    assert (request.method, request.target, request.anomalies) == ("POST", "/up", ())
    assert request.header("host") == "h.test"
    assert response.status == 200
    # The text in the body looks like a request but is only a body.
    assert not any(
        isinstance(i.layer, Http) and i.layer.target == "/inside-the-body" for i in items
    )


def test_http_messages_follow_content_length_and_pipelining() -> None:
    data = b"GET /a HTTP/1.1\r\n\r\n" + REQUEST + BODY + b"GET /c HTTP/1.1\r\nHost: x\r\n\r\n"
    targets = [m.target for m in http_messages(data) if isinstance(m, Http)]
    assert targets == ["/a", "/up", "/c"]


def test_http_messages_stop_at_bodies_of_unknown_length() -> None:
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    assert len(http_messages(chunked + b"HTTP/1.1 404 Not Found\r\n\r\n")) == 1
    until_close = b"HTTP/1.1 200 OK\r\n\r\nbody bytes until close HTTP/1.1 500 x\r\n\r\n"
    assert len(http_messages(until_close)) == 1


def test_http_headers_cut_off_at_the_end_of_the_stream() -> None:
    (message,) = http_messages(b"GET /a HTTP/1.1\r\nHost: x\r\n")
    assert message.anomalies == ("http headers incomplete: no blank line in this segment",)


def test_http_body_shorter_than_content_length_ends_parsing() -> None:
    data = b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort" + b"GET /x HTTP/1.1\r\n\r\n"
    assert len(http_messages(data)) == 1


def test_http_message_count_is_capped() -> None:
    assert len(http_messages(b"GET / HTTP/1.1\r\n\r\n" * 500)) == MAX_MESSAGES


def test_client_hello_split_across_segments_is_parsed_whole() -> None:
    frames, conv = conversation(8443)
    conv.client(1001 + 90, 2001, PSH_ACK, CLIENT_HELLO[90:])
    conv.client(1001, 2001, PSH_ACK, CLIENT_HELLO[:90])
    (item,) = flow_of(frames).flows[0].app()
    hello = item.layer
    assert isinstance(hello, TlsClientHello)
    assert hello.anomalies == ()  # the per-packet parser reports this hello as truncated
    assert hello.server_name == "example.com"
    assert len(hello.cipher_suites) == 16


def test_client_hello_only_counts_from_the_client() -> None:
    frames, conv = conversation(8443)
    conv.server(2001, 1001, PSH_ACK, CLIENT_HELLO)
    assert flow_of(frames).flows[0].app() == ()


def test_dns_over_tcp_two_messages_and_a_split() -> None:
    q1, q2 = dns_query(1, "example.com"), dns_query(2, "www.example.com", 28)
    stream = len(q1).to_bytes(2) + q1 + len(q2).to_bytes(2) + q2
    frames, conv = conversation(53)
    conv.client(1001, 2001, PSH_ACK, stream[:20])
    conv.client(1021, 2001, PSH_ACK, stream[20:])
    items = flow_of(frames).flows[0].app()
    names = [i.layer.questions[0].name for i in items if isinstance(i.layer, Dns)]
    assert names == ["example.com", "www.example.com"]


def test_dns_messages_last_one_cut_short_is_an_anomaly() -> None:
    q = dns_query(1, "example.com")
    messages = dns_messages(len(q).to_bytes(2) + q + len(q).to_bytes(2) + q[:15])
    assert len(messages) == 2
    assert messages[0].anomalies == ()
    assert messages[1].anomalies[0].startswith("malformed dns question 1")


def test_dns_message_count_is_capped_and_garbage_is_safe() -> None:
    assert len(dns_messages(b"\x00\x00" * 500)) == MAX_MESSAGES
    rng = random.Random(1)
    for _ in range(200):
        dns_messages(rng.randbytes(rng.randint(0, 300)))
        http_messages(b"GET / HTTP/1.1\r\n" + rng.randbytes(rng.randint(0, 300)))


def test_a_capture_that_starts_mid_stream_is_still_parsed_and_flagged() -> None:
    frames: list[bytes] = []
    conv = Conversation(frames, 40000, 8080)
    conv.client(5000, 1, PSH_ACK, b"GET /late HTTP/1.1\r\nHost: x\r\n\r\n")
    flow = flow_of(frames).flows[0]
    (item,) = flow.app()
    assert isinstance(item.layer, Http)
    assert item.layer.target == "/late"
    assert "client stream start not captured" in flow.notes()


def test_plain_data_has_no_application_layer_and_the_result_is_cached() -> None:
    frames, conv = conversation()
    conv.client(1001, 2001, PSH_ACK, b"\x00\x01 not http, not tls, not dns")
    flow = flow_of(frames).flows[0]
    assert flow.app() == ()
    assert flow.app() is flow.app()
