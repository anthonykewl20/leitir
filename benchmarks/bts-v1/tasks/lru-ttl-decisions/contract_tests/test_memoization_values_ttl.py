import time

from memoization.caching.general.values_with_ttl import (
    is_cache_value_valid,
    make_cache_value,
    retrieve_result_from_cache_value,
)


def test_is_cache_value_valid_ttl_window():
    assert is_cache_value_valid(("x", time.time() + 60)) is True


def test_make_cache_value_stores_result_and_deadline():
    value = make_cache_value("payload", 60)
    assert value[0] == "payload"


def test_retrieve_result_roundtrip():
    assert retrieve_result_from_cache_value(make_cache_value({"k": 1}, 10)) == {"k": 1}
