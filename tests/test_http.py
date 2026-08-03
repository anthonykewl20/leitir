"""Unit tests for the categorized HTTP retry helper."""

from __future__ import annotations

from email.message import Message
from urllib.error import HTTPError, URLError

import pytest

from leitir._http import (
    HttpErrorKind,
    classify,
    retry_after_seconds,
    retry_http,
)


def _http_error(code: int, headers: dict[str, str] | None = None) -> HTTPError:
    msg = Message()
    for key, value in (headers or {}).items():
        msg[key] = value
    return HTTPError(url="https://api.example/x", code=code, msg="err", hdrs=msg, fp=None)


class TestClassify:
    def test_429_is_rate_limited(self):
        assert classify(_http_error(429)) is HttpErrorKind.RATE_LIMITED

    def test_403_with_zero_remaining_is_rate_limited(self):
        exc = _http_error(403, {"X-RateLimit-Remaining": "0"})
        assert classify(exc) is HttpErrorKind.RATE_LIMITED

    def test_403_with_retry_after_is_rate_limited(self):
        exc = _http_error(403, {"Retry-After": "30"})
        assert classify(exc) is HttpErrorKind.RATE_LIMITED

    def test_plain_403_is_fatal(self):
        assert classify(_http_error(403)) is HttpErrorKind.FATAL

    def test_401_is_fatal(self):
        assert classify(_http_error(401)) is HttpErrorKind.FATAL

    def test_404_is_fatal(self):
        assert classify(_http_error(404)) is HttpErrorKind.FATAL

    def test_422_is_fatal(self):
        assert classify(_http_error(422)) is HttpErrorKind.FATAL

    def test_500_is_transient(self):
        assert classify(_http_error(500)) is HttpErrorKind.TRANSIENT

    def test_502_is_transient(self):
        assert classify(_http_error(502)) is HttpErrorKind.TRANSIENT

    def test_503_is_transient(self):
        assert classify(_http_error(503)) is HttpErrorKind.TRANSIENT

    def test_504_is_transient(self):
        assert classify(_http_error(504)) is HttpErrorKind.TRANSIENT

    def test_501_not_implemented_is_fatal(self):
        assert classify(_http_error(501)) is HttpErrorKind.FATAL

    def test_408_request_timeout_is_transient(self):
        assert classify(_http_error(408)) is HttpErrorKind.TRANSIENT

    def test_425_too_early_is_transient(self):
        assert classify(_http_error(425)) is HttpErrorKind.TRANSIENT

    def test_urlerror_is_transient(self):
        assert classify(URLError("dns")) is HttpErrorKind.TRANSIENT

    def test_timeout_error_is_transient(self):
        assert classify(TimeoutError()) is HttpErrorKind.TRANSIENT

    def test_connection_error_is_transient(self):
        assert classify(ConnectionRefusedError("refused")) is HttpErrorKind.TRANSIENT

    def test_incomplete_read_is_transient(self):
        from http.client import IncompleteRead

        assert classify(IncompleteRead(b"partial", 993)) is HttpErrorKind.TRANSIENT

    def test_remote_disconnected_is_transient(self):
        from http.client import RemoteDisconnected

        assert classify(RemoteDisconnected("server hung up")) is HttpErrorKind.TRANSIENT

    def test_520_edge_error_is_transient(self):
        # raw.githubusercontent.com sits behind edge infra that emits 520/522/524.
        assert classify(_http_error(520)) is HttpErrorKind.TRANSIENT
        assert classify(_http_error(522)) is HttpErrorKind.TRANSIENT
        assert classify(_http_error(524)) is HttpErrorKind.TRANSIENT

    def test_keyboard_interrupt_is_fatal(self):
        assert classify(KeyboardInterrupt()) is HttpErrorKind.FATAL


class TestRetryAfterSeconds:
    def test_integer_seconds(self):
        exc = _http_error(429, {"Retry-After": "120"})
        assert retry_after_seconds(exc, now=1000.0) == 120.0

    def test_http_date_future_delta(self):
        # A future HTTP-date must yield a positive, exact delta (not clamped 0).
        # "Wed, 21 Oct 2015 07:28:00 GMT" == epoch 1445412480.0.
        exc = _http_error(429, {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"})
        assert retry_after_seconds(exc, now=1445412480.0 - 30.0) == 30.0

    def test_http_date_naive_treated_as_utc(self):
        # A date with no timezone must be interpreted as UTC, not local time.
        # Force a non-UTC local timezone so the test discriminates the fix on
        # any runner (on a UTC box the pre-fix code would also pass by accident).
        import os
        import time

        if not hasattr(time, "tzset"):
            pytest.skip("time.tzset not available on this platform")
        naive = _http_error(429, {"Retry-After": "Wed, 21 Oct 2015 07:28:00"})
        gmt = _http_error(429, {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"})
        old_tz = os.environ.get("TZ")
        try:
            os.environ["TZ"] = "America/New_York"
            time.tzset()
            # With a -05:00 local zone, a non-normalised naive date would skew
            # by 5 hours; the UTC-normalisation makes naive == gmt.
            assert retry_after_seconds(naive, now=1445412480.0 - 30.0) == \
                retry_after_seconds(gmt, now=1445412480.0 - 30.0) == 30.0
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()

    def test_rate_limit_reset(self):
        exc = _http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "2000"})
        assert retry_after_seconds(exc, now=1000.0) == 1000.0

    def test_reset_ignored_when_remaining_nonzero(self):
        exc = _http_error(403, {"X-RateLimit-Remaining": "5", "X-RateLimit-Reset": "2000"})
        assert retry_after_seconds(exc, now=1000.0) is None

    def test_no_headers(self):
        exc = _http_error(429)
        assert retry_after_seconds(exc, now=1000.0) is None

    def test_integer_seconds_independent_of_now(self):
        # Retry-After as integer seconds is an absolute wait duration,
        # not a timestamp relative to `now`.
        exc = _http_error(429, {"Retry-After": "10"})
        assert retry_after_seconds(exc, now=2000.0) == 10.0

    def test_garbage_retry_after_returns_none(self):
        exc = _http_error(429, {"Retry-After": "not-a-date"})
        assert retry_after_seconds(exc, now=1000.0) is None

    def test_non_http_exception_returns_none(self):
        assert retry_after_seconds(RuntimeError("x"), now=1.0) is None


class TestRetryHttp:
    def test_success_first_try_no_sleep(self):
        sleeps: list[float] = []
        result = retry_http(lambda: "ok", sleeper=sleeps.append)
        assert result == "ok"
        assert sleeps == []

    def test_retries_transient_then_succeeds(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] < 3:
                raise _http_error(502)
            return "done"

        result = retry_http(fn, base_delay=1.0, sleeper=sleeps.append)
        assert result == "done"
        assert calls["n"] == 3
        assert sleeps == [1.0, 2.0]

    def test_fatal_raises_immediately_no_retry(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            raise _http_error(404)

        with pytest.raises(HTTPError) as exc_info:
            retry_http(fn, sleeper=sleeps.append)
        assert exc_info.value.code == 404
        assert calls["n"] == 1
        assert sleeps == []

    def test_rate_limited_honors_retry_after(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(429, {"Retry-After": "45"})
            return "ok"

        result = retry_http(fn, base_delay=1.0, sleeper=sleeps.append)
        assert result == "ok"
        assert sleeps == [45.0]

    def test_rate_limited_capped_at_max_rate_limit_delay(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(429, {"Retry-After": "9999"})
            return "ok"

        # Rate-limit hints are capped by max_rate_limit_delay, not max_delay.
        retry_http(fn, max_rate_limit_delay=120.0, sleeper=sleeps.append)
        assert sleeps == [120.0]

    def test_rate_limited_without_hint_uses_backoff(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] < 3:
                raise _http_error(429)
            return "ok"

        retry_http(fn, base_delay=2.0, sleeper=sleeps.append)
        assert sleeps == [2.0, 4.0]

    def test_urlerror_is_retried(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] < 2:
                raise URLError("dns failure")
            return 42

        assert retry_http(fn, sleeper=sleeps.append) == 42
        assert calls["n"] == 2
        assert sleeps == [1.0]

    def test_exhaustion_reraises_last(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            raise _http_error(503)

        with pytest.raises(HTTPError) as exc_info:
            retry_http(fn, max_attempts=3, base_delay=1.0, sleeper=sleeps.append)
        assert exc_info.value.code == 503
        assert calls["n"] == 3
        assert sleeps == [1.0, 2.0]

    def test_custom_clock_used_for_rate_limit_reset(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(403, {
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "5000",
                })
            return "ok"

        retry_http(
            fn, max_delay=10000.0, max_rate_limit_delay=10000.0,
            sleeper=sleeps.append, clock=lambda: 1000.0,
        )
        assert sleeps == [4000.0]

    def test_max_attempts_must_be_positive(self):
        with pytest.raises(ValueError, match="max_attempts"):
            retry_http(lambda: 1, max_attempts=0)

    def test_non_http_non_url_exception_is_fatal(self):
        calls = {"n": 0}

        def fn():
            calls["n"] += 1
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            retry_http(fn, sleeper=lambda _: None)
        assert calls["n"] == 1
