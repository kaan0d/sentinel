from sentinel.proto.icmp import ICMP_ECHO_REQUEST, parse_icmp
from tools.gen_pcap import icmp_message

PAYLOAD = b"abcdefgh"


def test_valid_hand_built_echo_request() -> None:
    raw = bytes.fromhex("0800f7fd00010001")  # checksum of the bare header
    icmp = parse_icmp(raw)
    assert icmp.error is None
    assert icmp.anomalies == ()
    assert (icmp.icmp_type, icmp.code, icmp.checksum) == (ICMP_ECHO_REQUEST, 0, 0xF7FD)
    assert (icmp.ident, icmp.seq) == (1, 1)
    assert icmp.payload == b""


def test_valid_with_payload() -> None:
    icmp = parse_icmp(icmp_message(8, 0, 0xABCD0007, PAYLOAD))
    assert icmp.anomalies == ()
    assert (icmp.ident, icmp.seq, icmp.payload) == (0xABCD, 7, PAYLOAD)


def test_bad_checksum_reported_not_dropped() -> None:
    bad = bytearray(icmp_message(8, 0, 1, PAYLOAD))
    bad[-1] ^= 0x01
    icmp = parse_icmp(bytes(bad))
    assert icmp.error is None
    assert icmp.anomalies == ("bad icmp checksum",)
    assert parse_icmp(bytes(bad), verify_checksum=False).anomalies == ()


def test_truncated_header() -> None:
    raw = icmp_message(8, 0, 1, PAYLOAD)
    for n in range(8):
        icmp = parse_icmp(raw[:n])
        assert icmp.error is not None
        assert "truncated" in icmp.error


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    for blob in blobs:
        icmp = parse_icmp(blob)
        if len(blob) < 8:
            assert icmp.error is not None
