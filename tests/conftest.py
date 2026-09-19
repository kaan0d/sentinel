import random

import pytest


@pytest.fixture(scope="session")
def blobs() -> list[bytes]:
    """Deterministic random byte strings of length 0..200, plus all-zero and all-0xFF ones."""
    rng = random.Random(1234)
    out = [rng.randbytes(rng.randint(0, 200)) for _ in range(500)]
    out += [bytes(n) for n in (0, 1, 20, 40, 60)] + [b"\xff" * n for n in (1, 20, 40, 60)]
    return out
