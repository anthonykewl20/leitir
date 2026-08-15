from backoff._jitter import full_jitter


def test_attempt_zero_is_initial_backoff_plus_jitter():
    assert 0.0 <= full_jitter(1.0) <= 1.0


def test_exponential_growth_shape():
    assert full_jitter(0.0) == 0.0


def test_jitter_bounds_scale_with_backoff():
    assert 0.0 <= full_jitter(16.0) <= 16.0
