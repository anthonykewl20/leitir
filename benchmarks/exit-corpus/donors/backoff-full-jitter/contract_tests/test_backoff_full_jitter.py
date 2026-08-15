import backoff._jitter as donor


def test_full_jitter_is_zero_for_zero_input():
    assert donor.full_jitter(0.0) == 0.0


def test_full_jitter_stays_within_its_documented_range():
    assert 0.0 <= donor.full_jitter(1.5) <= 1.5
