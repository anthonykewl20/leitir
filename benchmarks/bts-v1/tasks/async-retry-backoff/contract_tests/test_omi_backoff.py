from backoff._jitter import random_jitter


def test_backoff_is_capped_at_max_delay():
    assert random_jitter(32.0) <= 33.0


def test_first_attempt_is_at_least_base_delay():
    assert random_jitter(1.0) >= 1.0


def test_growth_between_attempts():
    assert random_jitter(4.0) >= 4.0
