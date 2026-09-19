import random

from sentinel.flow.stream import DEFAULT_MAX_BYTES, MAX_INTERVALS, Budget, TcpStream

ISN = 1000


def stream_with_syn(
    isn: int = ISN, *, max_bytes: int = DEFAULT_MAX_BYTES, budget: Budget | None = None
) -> TcpStream:
    s = TcpStream(max_bytes, budget)
    s.add_syn(isn)
    return s


def test_in_order_segments() -> None:
    s = stream_with_syn()
    s.add_segment(ISN + 1, b"hello ")
    s.add_segment(ISN + 7, b"world")
    assert s.data() == b"hello world"
    assert s.missing_bytes == 0
    assert (s.retransmitted_segments, s.out_of_order_segments, s.overlap_conflicts) == (0, 0, 0)
    assert s.data_segments == 2


def test_out_of_order_segments_are_counted_and_reassembled() -> None:
    s = stream_with_syn()
    s.add_segment(ISN + 7, b"world")  # arrives ahead of a gap: not yet "out of order"
    s.add_segment(ISN + 1, b"hello ")  # below the highest position seen: out of order
    assert s.data() == b"hello world"
    assert s.out_of_order_segments == 1


def test_retransmission_is_absorbed_and_counted() -> None:
    s = stream_with_syn()
    s.add_segment(ISN + 1, b"hello")
    s.add_segment(ISN + 1, b"hello")
    s.add_segment(ISN + 3, b"llo wor")  # partly old, partly new
    assert s.data() == b"hello wor"
    assert s.retransmitted_segments == 2
    assert s.retransmitted_bytes == 5 + 3
    assert s.overlap_conflicts == 0


def test_first_copy_wins_and_a_different_copy_is_a_conflict() -> None:
    s = stream_with_syn()
    s.add_segment(ISN + 1, b"AAAA")
    s.add_segment(ISN + 3, b"BBBB")  # overlaps AA with different bytes
    assert s.data() == b"AAAABB"
    assert s.overlap_conflicts == 1
    s.add_segment(ISN + 1, b"AAAABB")  # a byte-identical repeat is no conflict
    assert s.overlap_conflicts == 1


def test_a_gap_stops_data_and_is_reported() -> None:
    s = stream_with_syn()
    s.add_segment(ISN + 1, b"a" * 10)
    s.add_segment(ISN + 21, b"c" * 5)
    assert s.data() == b"a" * 10  # only the contiguous start
    assert s.missing_bytes == 10
    s.add_segment(ISN + 11, b"b" * 10)  # the lost segment shows up late
    assert s.data() == b"a" * 10 + b"b" * 10 + b"c" * 5
    assert s.missing_bytes == 0


def test_lost_start_means_no_data_but_bytes_are_missing() -> None:
    s = stream_with_syn()
    s.add_segment(ISN + 101, b"later")
    assert s.data() == b""
    assert s.missing_bytes == 100


def test_fin_marks_a_missing_tail() -> None:
    s = stream_with_syn()
    s.add_segment(ISN + 1, b"12345")
    s.add_fin(ISN + 1 + 5)
    assert s.is_complete
    t = stream_with_syn()
    t.add_segment(ISN + 1, b"12345")
    t.add_fin(ISN + 1 + 9)  # four bytes never arrived
    assert not t.is_complete
    assert t.missing_bytes == 4


def test_without_a_syn_the_stream_starts_at_the_first_byte_received() -> None:
    s = TcpStream()
    s.add_segment(5000, b"mid")
    s.add_segment(5003, b"dle")
    assert s.data() == b"middle"
    assert not s.has_start


def test_without_a_syn_earlier_bytes_arriving_later_extend_the_stream() -> None:
    s = TcpStream()
    s.add_segment(5006, b"world")
    s.add_segment(5000, b"hello ")
    assert s.data() == b"hello world"


def test_a_late_syn_trims_bytes_before_the_real_start() -> None:
    s = TcpStream()
    s.add_segment(ISN + 1, b"real")
    s.add_segment(ISN - 3, b"old")  # from before the stream (a retransmitted SYN's data)
    s.add_syn(ISN)
    assert s.data() == b"real"


def test_sequence_numbers_wrap_around() -> None:
    isn = 2**32 - 8
    payload = bytes(range(40))
    s = stream_with_syn(isn)
    for i in range(0, 40, 10):
        s.add_segment((isn + 1 + i) % 2**32, payload[i : i + 10])
    assert s.data() == payload


def test_a_conflicting_syn_is_counted_and_ignored() -> None:
    s = stream_with_syn()
    s.add_syn(ISN)  # a repeat is fine
    assert s.conflicting_syns == 0
    s.add_syn(ISN + 50)
    assert s.conflicting_syns == 1


def test_empty_segments_are_ignored() -> None:
    s = stream_with_syn()
    s.add_segment(ISN + 1, b"")
    assert s.data() == b""
    assert s.data_segments == 0


def test_only_the_first_max_bytes_are_kept() -> None:
    s = stream_with_syn(max_bytes=100)
    s.add_segment(ISN + 1, bytes(range(250)))
    assert s.data() == bytes(range(100))
    assert s.dropped_bytes == 150
    s.add_segment(ISN + 500, b"far away")
    assert s.dropped_bytes == 158


def test_the_shared_budget_limits_memory_across_streams() -> None:
    budget = Budget(50)
    a, b = stream_with_syn(budget=budget), stream_with_syn(budget=budget)
    a.add_segment(ISN + 1, b"x" * 30)
    b.add_segment(ISN + 1, b"y" * 30)  # only 20 left: dropped whole
    assert b.data() == b""
    assert b.dropped_bytes == 30
    b.add_segment(ISN + 1, b"y" * 20)
    assert b.data() == b"y" * 20
    assert budget.remaining == 0


def test_the_interval_count_is_capped() -> None:
    s = stream_with_syn()
    for i in range(MAX_INTERVALS + 10):
        s.add_segment(ISN + 1 + 2 * i, b"x")  # each leaves a one-byte gap
    assert s.dropped_bytes == 10
    assert s.stored_bytes == MAX_INTERVALS


def split(payload: bytes, rng: random.Random) -> list[tuple[int, bytes]]:
    """Random, overlapping (with the same bytes), duplicated pieces that cover the payload."""
    pieces = []
    pos = 0
    while pos < len(payload):
        size = rng.randint(1, 60)
        pieces.append((pos, payload[pos : pos + size]))
        pos += size
    extra = []
    for start, _ in pieces:
        if rng.random() < 0.3:  # a retransmission that also covers earlier and later bytes
            lo = max(0, start - rng.randint(0, 20))
            extra.append((lo, payload[lo : start + rng.randint(1, 80)]))
        if rng.random() < 0.2:
            extra.append(next(p for p in pieces if p[0] == start))
    return pieces + extra


def test_shuffled_duplicated_overlapping_segments_give_the_original_stream() -> None:
    rng = random.Random(2024)
    for trial in range(300):
        payload = rng.randbytes(rng.randint(0, 3000))
        isn = rng.choice([ISN, 2**32 - 500, 0, 2**31 - 100])
        pieces = split(payload, rng)
        rng.shuffle(pieces)
        s = TcpStream()
        syn_at = rng.randint(0, len(pieces))  # the SYN may arrive anywhere, even last
        for i, (off, chunk) in enumerate(pieces):
            if i == syn_at:
                s.add_syn(isn)
            s.add_segment((isn + 1 + off) % 2**32, chunk)
        if syn_at == len(pieces):
            s.add_syn(isn)
        assert s.data() == payload, trial
        assert s.missing_bytes == 0, trial
        assert s.overlap_conflicts == 0, trial


def test_random_calls_never_raise() -> None:
    rng = random.Random(5)
    for _ in range(200):
        s = TcpStream(max_bytes=rng.choice([10, 1000]), budget=Budget(rng.choice([0, 500])))
        for _ in range(30):
            op = rng.randrange(3)
            seq = rng.choice([0, 1, 2**32 - 1, rng.randrange(2**32)])
            if op == 0:
                s.add_syn(seq)
            elif op == 1:
                s.add_fin(seq)
            else:
                s.add_segment(seq, rng.randbytes(rng.randint(0, 50)))
        s.data()
        s.missing_ranges()
        _ = s.is_complete
