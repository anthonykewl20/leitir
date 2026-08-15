import cognee.infrastructure.utils.calculate_backoff as donor


def test_calculate_backoff_has_exact_zero_jitter_growth():
    assert donor.calculate_backoff(3, initial_backoff=1.0, backoff_factor=2.0, jitter=0.0) == 8.0


def test_calculate_backoff_jitter_scales_with_backoff():
    assert 8.0 <= donor.calculate_backoff(4, initial_backoff=1.0, backoff_factor=2.0, jitter=0.5) <= 24.0
