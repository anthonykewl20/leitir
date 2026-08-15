from backoff._jitter import full_jitter, random_jitter


def test_full_jitter_bounds():
    assert 0.0 <= full_jitter(1.0) <= 1.0


def test_full_jitter_deterministic_under_seed():
    assert full_jitter(0.0) == 0.0


def test_random_jitter_adds_up_to_one_second():
    assert 1.0 <= random_jitter(1.0) <= 2.0
