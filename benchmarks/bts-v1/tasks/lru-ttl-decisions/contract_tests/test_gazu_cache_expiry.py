import time

from memoization.caching.general.values_with_ttl import is_cache_value_valid


def test_fresh_entry_is_not_expired():
    assert is_cache_value_valid(("x", time.time() + 60)) is True


def test_stale_entry_is_expired():
    assert is_cache_value_valid(("x", time.time() - 1)) is False


def test_zero_expire_disables_expiry():
    assert is_cache_value_valid(("x", time.time())) is False
