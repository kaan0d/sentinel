from sentinel.ids.alert import Alert, to_json, to_text
from sentinel.ids.window import SlidingWindow

SEC = 1_000_000_000


def test_counts_events_and_distinct_keys() -> None:
    w = SlidingWindow(10 * SEC, 100)
    for i, key in enumerate(["a", "b", "a", "c", "a"]):
        w.add(i * SEC, key)
    assert (w.count, w.distinct) == (5, 3)
    assert sorted(str(k) for k in w.keys) == ["a", "b", "c"]
    assert w.span_ns == 4 * SEC


def test_events_older_than_the_window_are_dropped() -> None:
    w = SlidingWindow(10 * SEC, 100)
    w.add(0, "old")
    w.add(5 * SEC, "mid")
    w.add(10 * SEC, "edge")  # exactly the window: still counted
    assert (w.count, w.distinct) == (3, 3)
    w.add(10 * SEC + 1, "new")  # now the first one is older than the window
    assert w.distinct == 3
    assert "old" not in w.keys
    w.add(30 * SEC, "late")
    assert (w.count, w.distinct) == (1, 1)


def test_the_oldest_event_goes_when_the_window_is_full() -> None:
    w = SlidingWindow(1000 * SEC, 3)
    for i, key in enumerate("abcd"):
        w.add(i, key)
    assert w.count == 3
    assert sorted(str(k) for k in w.keys) == ["b", "c", "d"]


def test_a_key_stays_while_any_event_of_it_is_left() -> None:
    w = SlidingWindow(10 * SEC, 100)
    w.add(0, "x")
    w.add(8 * SEC, "x")
    w.add(11 * SEC, "y")
    assert sorted(str(k) for k in w.keys) == ["x", "y"]
    assert w.count == 2


def test_time_going_backwards_does_not_break_it() -> None:
    w = SlidingWindow(10 * SEC, 100)
    w.add(100 * SEC, "a")
    w.add(50 * SEC, "b")  # an earlier timestamp arrives later
    assert w.count == 2
    assert w.span_ns == -50 * SEC  # newest minus oldest, in arrival order


def test_empty_window() -> None:
    w = SlidingWindow(SEC, 5)
    assert (w.count, w.distinct, w.span_ns, w.keys) == (0, 0, 0, [])


def test_alert_formats() -> None:
    alert = Alert(
        1_700_000_000_123_456_789,
        "port-scan",
        "port_scan",
        "medium",
        "10.0.0.1",
        None,
        "10.0.0.1 probed 15 ports",
        {"ports": 15, "sample": [1, 2], "note": "é"},
    )
    assert (
        to_text(alert) == "2023-11-14T22:13:20.123456Z [medium] port-scan: 10.0.0.1 probed 15 ports"
    )
    line = to_json(alert)
    assert "\n" not in line
    assert line.isascii()
    assert line == (
        '{"detector": "port_scan", "dst": null, "evidence": {"note": "\\u00e9", "ports": 15, '
        '"sample": [1, 2]}, "message": "10.0.0.1 probed 15 ports", "rule": "port-scan", '
        '"severity": "medium", "src": "10.0.0.1", "ts": "2023-11-14T22:13:20.123456Z", '
        '"ts_ns": 1700000000123456789}'
    )


def test_the_newest_event_time() -> None:
    w = SlidingWindow(10 * SEC, 100)
    assert w.newest_ns is None
    w.add(3 * SEC, "a")
    w.add(7 * SEC, "b")
    assert w.newest_ns == 7 * SEC
