"""Unit tests for the categorized HTTP retry helper."""

from __future__ import annotations

import re
from email.message import Message
from urllib.error import HTTPError, URLError

import pytest

from leitir._http import (
    RETRIABLE_EXCEPTIONS,
    HttpErrorKind,
    RateLimitCapExceededError,
    RetryBudgetExceededError,
    _safe_redirect_handler,
    classify,
    describe_failure,
    make_retry,
    reset_rate_limit_notices,
    retry_after_seconds,
    retry_http,
)


def _http_error(
    code: int,
    headers: dict[str, str] | None = None,
    url: str = "https://api.example/x",
) -> HTTPError:
    msg = Message()
    for key, value in (headers or {}).items():
        msg[key] = value
    return HTTPError(url=url, code=code, msg="err", hdrs=msg, fp=None)


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

    @pytest.mark.parametrize("value", ["NaN", "-5", "Infinity"])
    def test_invalid_numeric_seconds_returns_none(self, value):
        exc = _http_error(429, {"Retry-After": value})
        assert retry_after_seconds(exc, now=1000.0) is None

    def test_decimal_seconds(self):
        exc = _http_error(429, {"Retry-After": "3"})
        assert retry_after_seconds(exc, now=1000.0) == 3.0

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

    @pytest.mark.parametrize("value", ["NaN", "-5", "Infinity"])
    def test_invalid_rate_limit_reset_returns_none(self, value):
        exc = _http_error(403, {
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": value,
        })
        assert retry_after_seconds(exc, now=1000.0) is None

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

    def test_rate_limited_backoff_without_hint_capped_at_max_rate_limit_delay(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            raise _http_error(429)

        # Without a server hint the exponential backoff is still clamped by
        # the rate-limit cap. (A hint beyond the cap now fails fast — see
        # TestRateLimitCapFailFast — instead of clamping and retrying.)
        with pytest.raises(HTTPError):
            retry_http(
                fn,
                max_attempts=2,
                base_delay=200.0,
                max_rate_limit_delay=120.0,
                sleeper=sleeps.append,
            )
        assert calls["n"] == 2
        assert sleeps == [120.0]

    def test_transient_honors_retry_after_capped_at_max_delay(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(503, {"Retry-After": "45"})
            return "ok"

        assert retry_http(fn, max_delay=20.0, sleeper=sleeps.append) == "ok"
        assert sleeps == [20.0]

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


class TestRateLimitCapFailFast:
    """#201 C-1/SP-1/AC-1: a server-advised wait beyond the rate-limit cap
    raises immediately with the recovery timestamp — never sleep-the-cap and
    retry into a guaranteed re-fail."""

    def test_reset_beyond_cap_raises_immediately_with_timestamp(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                # reset epoch 4610 with clock 1010 -> hint 3600 > cap 300
                raise _http_error(403, {
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "4610",
                })
            return "ok"

        with pytest.raises(RateLimitCapExceededError) as exc_info:
            retry_http(fn, sleeper=sleeps.append, clock=lambda: 1010.0)
        message = str(exc_info.value)
        assert "3600s" in message
        assert "max_rate_limit_delay=300" in message
        # recovery timestamp = clock + hint = 4610, rendered deterministically
        assert "resets at 1970-01-01T01:16:50Z" in message
        assert re.search(r"resets at \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", message)
        assert calls["n"] == 1  # no retry
        assert sleeps == []  # no sleep — zero wall-clock
        assert isinstance(exc_info.value.__cause__, HTTPError)
        assert exc_info.value.__cause__.code == 403  # original failure chained

    def test_retry_after_beyond_cap_raises_immediately(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(429, {"Retry-After": "301"})
            return "ok"

        with pytest.raises(RateLimitCapExceededError) as exc_info:
            retry_http(fn, sleeper=sleeps.append, clock=lambda: 1010.0)
        # 1010 + 301 = 1311
        assert "resets at 1970-01-01T00:21:51Z" in str(exc_info.value)
        assert calls["n"] == 1
        assert sleeps == []

    def test_hint_equal_to_cap_sleeps_and_retries(self):
        # Boundary (C-4): a hint exactly at the cap is affordable — sleep and
        # retry as before; only strictly-beyond hints fail fast.
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(429, {"Retry-After": "300"})
            return "ok"

        assert retry_http(fn, sleeper=sleeps.append) == "ok"
        assert sleeps == [300.0]
        assert calls["n"] == 2

    def test_notice_still_emitted_when_failing_fast(self, capsys):
        reset_rate_limit_notices()
        calls = {"n": 0}

        def fn():
            calls["n"] += 1
            raise _http_error(429, {"Retry-After": "301"},
                              url="https://api.github.com/search/code")

        with pytest.raises(RateLimitCapExceededError):
            retry_http(fn, max_attempts=2, sleeper=lambda _: None)
        err = capsys.readouterr().err
        assert "GitHub API rate limited" in err

    def test_oversized_hint_on_final_attempt_raises_typed_not_raw(self, capsys):
        # Review remediation: the exhaustion raise used to sit BEFORE the
        # rate-limit arm, so an oversized hint arriving on the LAST attempt
        # escaped as the raw HTTPError — losing the typed error (with its
        # recovery timestamp) and the per-provider notice. The fail-fast arm
        # must be evaluated regardless of attempt number.
        reset_rate_limit_notices()
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] < 3:
                raise _http_error(503)  # transient attempts 1-2 sleep+retry
            raise _http_error(429, {"Retry-After": "301"},
                              url="https://api.github.com/search/code")

        with pytest.raises(RateLimitCapExceededError) as exc_info:
            retry_http(fn, max_attempts=3, base_delay=1.0,
                       sleeper=sleeps.append, clock=lambda: 1010.0)
        message = str(exc_info.value)
        assert "301s" in message
        assert "max_rate_limit_delay=300" in message
        assert "resets at 1970-01-01T00:21:51Z" in message  # 1010 + 301
        assert isinstance(exc_info.value.__cause__, HTTPError)
        assert exc_info.value.__cause__.code == 429  # the final 429, chained
        assert calls["n"] == 3
        assert sleeps == [1.0, 2.0]  # only transient backoffs — zero for the hint
        err = capsys.readouterr().err
        assert err.count("GitHub API rate limited") == 1  # notice exactly once

    def test_oversized_hint_on_only_attempt_raises_typed(self):
        # Degenerate final attempt: max_attempts=1 means the first attempt is
        # the last — the exhaustion raise must still not mask the typed error.
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            raise _http_error(429, {"Retry-After": "3600"})

        with pytest.raises(RateLimitCapExceededError):
            retry_http(fn, max_attempts=1, sleeper=sleeps.append,
                       clock=lambda: 1010.0)
        assert calls["n"] == 1
        assert sleeps == []

    def test_affordable_hint_on_final_attempt_still_exhausts_raw(self, capsys):
        # Regression guard: a hint at or below the cap on the final attempt
        # keeps the pre-existing exhaustion contract — the raw HTTPError is
        # re-raised unchanged after the earlier attempts slept and retried.
        reset_rate_limit_notices()
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            raise _http_error(429, {"Retry-After": "45"},
                              url="https://api.github.com/search/code")

        with pytest.raises(HTTPError) as exc_info:
            retry_http(fn, max_attempts=2, sleeper=sleeps.append)
        assert exc_info.value.code == 429  # raw error, not the typed wrapper
        assert calls["n"] == 2
        assert sleeps == [45.0]
        err = capsys.readouterr().err
        assert err.count("GitHub API rate limited") == 1  # once, from attempt 1

    def test_typed_error_wraps_into_domain_errors(self):
        # Call sites wrap `except _http.RETRIABLE_EXCEPTIONS` and render via
        # describe_failure; the typed error must keep both working so the
        # recovery timestamp survives the domain wrap.
        err = RateLimitCapExceededError("rate limit resets at 2026-08-19T12:00:00Z")
        assert isinstance(err, RETRIABLE_EXCEPTIONS)
        assert describe_failure(err) == (
            "RateLimitCapExceededError: rate limit resets at 2026-08-19T12:00:00Z"
        )


class TestTotalWaitBudget:
    """#201 C-2/AC-2/SP-4: the optional max_total_wait bounds cumulative
    sleeping; unset preserves per-attempt semantics."""

    @staticmethod
    def _always_503(calls):
        def fn():
            calls["n"] += 1
            raise _http_error(503)

        return fn

    def test_budget_exceeded_raises_naming_budget(self):
        calls = {"n": 0}
        sleeps: list[float] = []
        fn = self._always_503(calls)

        # waits: 2 (slept, waited=2), then 4 -> 2+4=6 > 5 -> raise before sleeping
        with pytest.raises(RetryBudgetExceededError) as exc_info:
            retry_http(fn, base_delay=2.0, max_total_wait=5.0, sleeper=sleeps.append)
        message = str(exc_info.value)
        assert "max_total_wait=5" in message
        assert "4s" in message and "2s" in message
        assert sleeps == [2.0]  # only the affordable wait happened
        assert isinstance(exc_info.value.__cause__, HTTPError)

    def test_budget_exact_cumulative_allowed(self):
        calls = {"n": 0}
        sleeps: list[float] = []
        fn = self._always_503(calls)

        # waits 2 then 4 land exactly on the 6s budget (allowed); the next
        # wait (8s) exceeds it. Never sleeps more than the budget.
        with pytest.raises(RetryBudgetExceededError):
            retry_http(fn, base_delay=2.0, max_total_wait=6.0, sleeper=sleeps.append)
        assert sleeps == [2.0, 4.0]
        assert sum(sleeps) == 6.0

    def test_budget_bounds_rate_limit_waits_too(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            raise _http_error(429, {"Retry-After": "4"})

        # 4 + 4 = 8 > 7 on the second wait
        with pytest.raises(RetryBudgetExceededError, match="max_total_wait=7"):
            retry_http(fn, base_delay=1.0, max_total_wait=7.0, sleeper=sleeps.append)
        assert sleeps == [4.0]

    def test_budget_zero_fails_on_first_wait(self):
        calls = {"n": 0}
        sleeps: list[float] = []
        fn = self._always_503(calls)

        with pytest.raises(RetryBudgetExceededError):
            retry_http(fn, base_delay=1.0, max_total_wait=0.0, sleeper=sleeps.append)
        assert sleeps == []
        assert calls["n"] == 1

    def test_budget_unset_preserves_per_attempt_semantics(self):
        # SP-4: without a budget, waits accumulate exactly as before (#201's
        # cap fix aside — see TestRateLimitCapFailFast).
        calls = {"n": 0}
        sleeps: list[float] = []
        fn = self._always_503(calls)

        with pytest.raises(HTTPError):
            retry_http(fn, max_attempts=4, base_delay=1.0, sleeper=sleeps.append)
        assert sleeps == [1.0, 2.0, 4.0]

    def test_negative_budget_rejected(self):
        with pytest.raises(ValueError, match="max_total_wait"):
            retry_http(lambda: 1, max_total_wait=-1.0, sleeper=lambda _: None)
        with pytest.raises(ValueError, match="max_total_wait"):
            make_retry(
                max_attempts=2, base_delay=1.0, max_delay=60.0,
                max_rate_limit_delay=300.0, sleeper=None, max_total_wait=-1.0,
            )

    def test_make_retry_plumbs_budget_and_clock(self):
        # make_retry is the seam transports use; budget and the injected
        # clock (the seam #202 builds on) must flow through it.
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(403, {
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "4610",
                })
            return "ok"

        retry = make_retry(
            max_attempts=3, base_delay=1.0, max_delay=60.0,
            max_rate_limit_delay=300.0, sleeper=sleeps.append,
            clock=lambda: 1010.0,
        )
        with pytest.raises(RateLimitCapExceededError, match="3600s"):
            retry(fn)
        assert sleeps == []

        calls["n"] = 0
        sleeps.clear()

        def transient():
            calls["n"] += 1
            raise _http_error(503)

        retry_budgeted = make_retry(
            max_attempts=5, base_delay=2.0, max_delay=60.0,
            max_rate_limit_delay=300.0, sleeper=sleeps.append,
            max_total_wait=5.0,
        )
        with pytest.raises(RetryBudgetExceededError, match="max_total_wait=5"):
            retry_budgeted(transient)
        assert sleeps == [2.0]


class TestRateLimitNotice:
    """#201 C-3/AC-3/SP-3: the rate-limit notice is per-provider, labeled,
    advises the provider's token env var, and is emitted at most once per
    provider even under threads."""

    @staticmethod
    def _limited_then_ok(calls, exc_factory):
        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise exc_factory()
            return "ok"

        return fn

    def test_two_providers_each_noticed_once_labeled(self, capsys):
        reset_rate_limit_notices()
        github_calls = {"n": 0}
        npm_calls = {"n": 0}

        github_fn = self._limited_then_ok(
            github_calls,
            lambda: _http_error(429, {"X-RateLimit-Reset": "2000"},
                                url="https://api.github.com/search/code"),
        )
        npm_fn = self._limited_then_ok(
            npm_calls,
            lambda: _http_error(429, {"X-RateLimit-Reset": "2000"},
                                url="https://registry.npmjs.org/express"),
        )

        def sleeper(_: float) -> None:
            pass

        # GitHub limited twice, npm once, in one process.
        assert retry_http(github_fn, sleeper=sleeper) == "ok"
        github_calls["n"] = 0
        assert retry_http(github_fn, sleeper=sleeper) == "ok"
        assert retry_http(npm_fn, sleeper=sleeper) == "ok"

        err = capsys.readouterr().err
        github_lines = [line for line in err.splitlines() if "GitHub API" in line]
        npm_lines = [line for line in err.splitlines() if "npm registry" in line]
        assert len(github_lines) == 1  # once per provider, not per failure
        assert len(npm_lines) == 1
        assert "GH_TOKEN" in github_lines[0]
        assert "NPM_TOKEN" in npm_lines[0]
        assert "1970-01-01T00:33:20Z" in github_lines[0]  # reset 2000 as UTC ISO

    def test_unknown_host_labelled_by_host_without_token_advice(self, capsys):
        # A host outside the provider table must not get GitHub wording (the
        # original defect) and has no token env var to recommend.
        reset_rate_limit_notices()
        calls = {"n": 0}
        fn = self._limited_then_ok(
            calls,
            lambda: _http_error(429, url="https://127.0.0.1:9/search"),
        )
        assert retry_http(fn, sleeper=lambda _: None) == "ok"
        err = capsys.readouterr().err
        assert "GitHub" not in err
        assert "GH_TOKEN" not in err
        assert "leitir: 127.0.0.1 rate limited" in err  # host without port

    def test_no_notice_for_transient_failures(self, capsys):
        reset_rate_limit_notices()
        calls = {"n": 0}
        fn = self._limited_then_ok(
            calls, lambda: _http_error(503, url="https://api.github.com/x")
        )
        assert retry_http(fn, sleeper=lambda _: None) == "ok"
        assert "rate limited" not in capsys.readouterr().err

    def test_reset_hook_restores_notice_state(self, capsys):
        reset_rate_limit_notices()
        calls = {"n": 0}
        fn = self._limited_then_ok(
            calls,
            lambda: _http_error(429, url="https://api.github.com/search/code"),
        )

        def sleeper(_: float) -> None:
            pass

        assert retry_http(fn, sleeper=sleeper) == "ok"
        calls["n"] = 0
        assert retry_http(fn, sleeper=sleeper) == "ok"
        first = capsys.readouterr().err
        assert first.count("GitHub API rate limited") == 1

        reset_rate_limit_notices()
        calls["n"] = 0
        assert retry_http(fn, sleeper=sleeper) == "ok"
        second = capsys.readouterr().err
        assert second.count("GitHub API rate limited") == 1  # noticed again

    def test_notice_at_most_once_per_provider_under_threads(self, capsys):
        # SP-3: concurrent rate-limited retries on one provider emit exactly
        # one notice line — never interleaved duplicates.
        import threading

        reset_rate_limit_notices()
        workers = 8
        barrier = threading.Barrier(workers)
        errors: list[BaseException] = []

        def worker():
            def fn():
                raise _http_error(429, url="https://api.github.com/search/code")

            try:
                barrier.wait(timeout=10)
                retry_http(fn, max_attempts=2, base_delay=0.0, sleeper=lambda _: None)
            except BaseException as exc:  # noqa: BLE001 - recorded for the assert
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert not any(thread.is_alive() for thread in threads)
        assert len(errors) == workers  # each worker exhausted with HTTPError
        assert all(isinstance(exc, HTTPError) for exc in errors)
        err = capsys.readouterr().err
        assert err.count("GitHub API rate limited") == 1
        assert len(err.splitlines()) == 1


class TestMalformedResetHeader:
    """#201 SP-2: malformed or past reset headers keep today's handling —
    treated as no usable hint, never a crash or a negative sleep."""

    def test_past_reset_epoch_is_zero_wait_not_negative(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(403, {
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "1000",
                })
            return "ok"

        assert retry_http(
            fn, sleeper=sleeps.append, clock=lambda: 1_000_000.0
        ) == "ok"
        assert sleeps == [0.0]  # clamped to zero, never negative
        assert calls["n"] == 2

    def test_malformed_reset_falls_back_to_backoff(self):
        calls = {"n": 0}
        sleeps: list[float] = []

        def fn():
            calls["n"] += 1
            if calls["n"] == 1:
                raise _http_error(403, {
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "not-a-number",
                })
            return "ok"

        assert retry_http(fn, base_delay=3.0, sleeper=sleeps.append) == "ok"
        assert sleeps == [3.0]  # no hint -> exponential backoff


class TestSafeRedirectHandler:
    @pytest.mark.parametrize(
        "header", ["Authorization", "PRIVATE-TOKEN", "Proxy-Authorization"]
    )
    def test_cross_origin_redirect_strips_credentials(self, header):
        from urllib.request import Request

        request = Request("https://approved.example/path", headers={header: "secret"})
        redirected = _safe_redirect_handler().redirect_request(
            request, None, 302, "Found", {}, "https://attacker.example/next"
        )

        assert redirected is not None
        assert all(name.lower() != header.lower() for name in redirected.headers)

    def test_same_origin_redirect_preserves_credentials_and_default_port(self):
        from urllib.request import Request

        request = Request(
            "https://approved.example/path",
            headers={"Authorization": "Bearer secret", "PRIVATE-TOKEN": "secret"},
        )
        redirected = _safe_redirect_handler().redirect_request(
            request, None, 302, "Found", {}, "https://approved.example:443/next"
        )

        assert redirected is not None
        assert redirected.get_header("Authorization") == "Bearer secret"
        assert redirected.get_header("Private-token") == "secret"

    @pytest.mark.parametrize(
        "destination",
        [
            "https://api.github.com:8443/next",
            "http://api.github.com/next",
        ],
    )
    def test_port_change_or_scheme_downgrade_strips_credentials(self, destination):
        from urllib.request import Request

        request = Request(
            "https://api.github.com:443/path",
            headers={"Authorization": "Bearer secret"},
        )
        redirected = _safe_redirect_handler().redirect_request(
            request, None, 302, "Found", {}, destination
        )

        assert redirected is not None
        assert redirected.get_header("Authorization") is None
