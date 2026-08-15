import random

from backoff._jitter import full_jitter, random_jitter


def test_full_jitter_bounds():
    random.seed(7)
    assert 0.0 <= full_jitter(1.5) <= 1.5


def test_full_jitter_deterministic_under_seed():
    random.seed(42)
    first = full_jitter(10.0)
    random.seed(42)
    assert full_jitter(10.0) == first


def test_random_jitter_adds_up_to_one_second():
    random.seed(3)
    assert 1.5 <= random_jitter(1.5) <= 2.5
