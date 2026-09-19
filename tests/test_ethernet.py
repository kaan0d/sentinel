from sentinel.proto.ethernet import ETHERTYPE_IPV4, parse_ethernet
from tools.gen_pcap import MAC_A, MAC_B, eth_frame


def test_valid_hand_built() -> None:
    frame = bytes.fromhex("ffffffffffff0200000000010800") + b"payload"
    eth = parse_ethernet(frame)
    assert eth.error is None
    assert eth.anomalies == ()
    assert eth.dst == b"\xff" * 6
    assert eth.src == MAC_A
    assert eth.ethertype == ETHERTYPE_IPV4
    assert eth.vlans == ()
    assert eth.payload == b"payload"


def test_single_vlan_tag() -> None:
    eth = parse_ethernet(eth_frame(MAC_B, MAC_A, ETHERTYPE_IPV4, b"x" * 50, vlan=100))
    assert eth.error is None
    assert (eth.vlans, eth.ethertype, eth.payload) == ((100,), ETHERTYPE_IPV4, b"x" * 50)


def test_vlan_id_masks_priority_bits() -> None:
    frame = MAC_B + MAC_A + bytes.fromhex("8100a0050800") + b"x"
    assert parse_ethernet(frame).vlans == (5,)


def test_stacked_vlan_tags() -> None:
    frame = MAC_B + MAC_A + bytes.fromhex("88a80064810000c80800") + b"x"
    eth = parse_ethernet(frame)
    assert eth.error is None
    assert (eth.vlans, eth.ethertype, eth.payload) == ((100, 200), ETHERTYPE_IPV4, b"x")


def test_truncated_header() -> None:
    frame = eth_frame(MAC_B, MAC_A, ETHERTYPE_IPV4, b"")[:14]
    for n in range(14):
        eth = parse_ethernet(frame[:n])
        assert eth.error is not None
        assert "truncated" in eth.error
    assert parse_ethernet(frame).error is None  # exactly the header, empty payload


def test_truncated_vlan_tag() -> None:
    frame = MAC_B + MAC_A + bytes.fromhex("810000640800")
    for n in range(14, 18):
        assert parse_ethernet(frame[:n]).error == "truncated 802.1Q tag"
    assert parse_ethernet(frame[:18]).error is None


def test_endless_vlan_tags_terminate() -> None:
    frame = MAC_B + MAC_A + bytes.fromhex("81000001") * 1000
    assert parse_ethernet(frame).error == "truncated 802.1Q tag"


def test_random_bytes_never_raise(blobs: list[bytes]) -> None:
    for blob in blobs:
        eth = parse_ethernet(blob)
        if len(blob) < 14:
            assert eth.error is not None
