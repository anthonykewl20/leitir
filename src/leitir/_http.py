"""Deterministic HTTP retry helper for GitHub and registry calls.

GitHub's REST API and the package registries return three classes of failure
that the kernel must not treat identically:

- Rate-limited: ``429`` (secondary rate limit) or ``403`` with
  ``X-RateLimit-Remaining: 0`` (primary). The response carries a wait hint
  (``Retry-After`` or ``X-RateLimit-Reset``) that must be honored.
- Transient: ``5xx`` server errors (except ``501``), ``408``/``425``, and
  ``OSError`` network/timeout failures (``URLError`` and ``TimeoutError`` are
  both ``OSError`` subclasses). Bounded exponential backoff recovers without
  user intervention.
- Fatal: every other ``4xx`` (auth, not found, malformed query) and ``501 Not
  Implemented``. Retrying cannot change the outcome, so the error is raised
  immediately.

This module is stdlib-only, holds no credentials, and performs no model calls
(ADR-001). ``urllib`` and ``email.utils`` imports are deferred into function
bodies so the module remains import-pure. Backoff is deterministic (no random
jitter): the sleeper is injectable, so tests observe exact wait sequences and
production delegates to :func:`time.sleep`.

Pattern lineage: the categorized-error / honor-server-wait-hint shape is
borrowed from the DeepAPI client contract (idempotent retry with explicit
retryable-vs-fatal classification), adapted to GitHub's synchronous REST API.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable
from datetime import UTC
from enum import Enum
from typing import TypeVar

T = TypeVar("T")
logger = logging.getLogger(__name__)


def __getattr__(name: str):
    # Lazy-build RETRIABLE_EXCEPTIONS so importing ``http.client`` is deferred
    # to first use (a network call), keeping the kernel import-pure
    # (test_import_purity.py forbids ``http.client`` at import time).
    if name == "RETRIABLE_EXCEPTIONS":
        from http.client import HTTPException

        value = (OSError, HTTPException)
        globals()["RETRIABLE_EXCEPTIONS"] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# Exception types that ``retry_http`` may re-raise after exhaustion, populated
# lazily by ``__getattr__``. Covers the socket family (``OSError``: ``URLError``,
# ``TimeoutError``, ``ConnectionError``) and the HTTP protocol family
# (``http.client.HTTPException``: ``IncompleteRead``, ``RemoteDisconnected`` —
# mid-stream failures that are transient). Call sites catch this tuple to wrap
# into their domain errors.
RETRIABLE_EXCEPTIONS: tuple[type[BaseException], ...]


class HttpErrorKind(Enum):
    """How a urllib failure should be treated by the retry loop."""

    TRANSIENT = "transient"
    RATE_LIMITED = "rate_limited"
    FATAL = "fatal"


def _safe_redirect_handler():
    from urllib.parse import urlsplit
    from urllib.request import HTTPRedirectHandler

    credential_headers = frozenset(
        {"authorization", "private-token", "proxy-authorization"}
    )

    def origin(url: str) -> tuple[str, str, int | None] | None:
        try:
            parts = urlsplit(url)
            scheme = parts.scheme.lower()
            port = parts.port
        except ValueError:
            return None
        if port is None:
            port = {"http": 80, "https": 443}.get(scheme)
        return scheme, (parts.hostname or "").lower(), port

    class SafeRedirectHandler(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
            if redirected is None:
                return None
            old_origin = origin(req.full_url)
            new_origin = origin(newurl)
            if old_origin is None or new_origin is None or old_origin != new_origin:
                for collection in (redirected.headers, redirected.unredirected_hdrs):
                    for name in tuple(collection):
                        if name.lower() in credential_headers:
                            del collection[name]
            return redirected

    return SafeRedirectHandler()


def safe_urlopen(request, *, timeout):
    """Open a request without forwarding credentials across origins."""
    from urllib.request import build_opener

    method = request.get_method() if hasattr(request, "get_method") else "GET"
    url = getattr(request, "full_url", str(request))
    logger.debug("http %s %s", method, url)
    response = build_opener(_safe_redirect_handler()).open(request, timeout=timeout)
    status = getattr(response, "status", None)
    if status is None:
        status = getattr(response, "code", None)
    logger.debug("http response status=%s", status if status is not None else "unknown")
    return response


def retry_after_seconds(exc: BaseException, *, now: float | None = None) -> float | None:
    """Return the server-advised wait in seconds for a rate-limit response.

    Honors, in order: ``Retry-After`` as integer seconds, ``Retry-After`` as an
    HTTP-date, and ``X-RateLimit-Reset`` (epoch seconds) when
    ``X-RateLimit-Remaining`` is ``0``. Returns ``None`` when no hint is
    present or the headers cannot be parsed. Naive HTTP-dates (no timezone)
    are interpreted as UTC per RFC 9110.
    """
    headers = getattr(exc, "headers", None)
    if headers is None:
        return None
    clock = time.time() if now is None else now

    retry_after = headers.get("Retry-After")
    if retry_after:
        try:
            delay = float(retry_after)
            if math.isfinite(delay) and delay >= 0:
                return delay
        except ValueError:
            pass
        try:

            dt = _parsedate_to_datetime(retry_after)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return max(0.0, dt.timestamp() - clock)
        except (TypeError, ValueError, OverflowError):
            pass

    if headers.get("X-RateLimit-Remaining") == "0":
        reset = headers.get("X-RateLimit-Reset")
        if reset:
            try:
                reset_at = float(reset)
                delay = reset_at - clock
                if math.isfinite(reset_at) and reset_at >= 0 and math.isfinite(delay):
                    return max(0.0, delay)
            except ValueError:
                pass
    return None


def _parsedate_to_datetime(value: str):
    from email.utils import parsedate_to_datetime

    return parsedate_to_datetime(value)


def classify(exc: BaseException) -> HttpErrorKind:
    """Categorize a urllib exception into its retry policy.

    ``HTTPError`` is a subclass of ``URLError`` and of ``OSError``, so the
    ``HTTPError`` check must come first. ``http.client.HTTPException``
    (``IncompleteRead``, ``RemoteDisconnected``) is a separate hierarchy but
    likewise transient. Any ``OSError`` that is not an ``HTTPError`` (plain
    ``URLError``, ``TimeoutError``, ``ConnectionError``) is transient.
    Exceptions that are neither (e.g. ``ValueError`` from a bad JSON body) are
    fatal so a genuine bug is not silently retried.
    """
    from http.client import HTTPException
    from urllib.error import HTTPError

    if isinstance(exc, HTTPError):
        code = exc.code
        if code == 429:
            return HttpErrorKind.RATE_LIMITED
        if code == 403:
            headers = getattr(exc, "headers", None)
            if headers is not None and (
                headers.get("X-RateLimit-Remaining") == "0"
                or headers.get("Retry-After")
            ):
                return HttpErrorKind.RATE_LIMITED
            return HttpErrorKind.FATAL
        if code in (408, 425):
            return HttpErrorKind.TRANSIENT
        if 500 <= code <= 599 and code != 501:
            return HttpErrorKind.TRANSIENT
        return HttpErrorKind.FATAL
    if isinstance(exc, HTTPException):
        return HttpErrorKind.TRANSIENT
    if isinstance(exc, OSError):
        return HttpErrorKind.TRANSIENT
    return HttpErrorKind.FATAL


def describe_failure(exc: BaseException) -> str:
    """Render a short, honest label for an exception in an error message.

    ``HTTPError`` shows its status code; other ``OSError``\\s show their
    ``reason`` (e.g. ``ConnectionRefusedError``) instead of a misleading
    ``HTTP ?``.
    """
    from urllib.error import HTTPError

    if isinstance(exc, HTTPError):
        return f"HTTP {exc.code}"
    reason = getattr(exc, "reason", None)
    if reason is not None:
        return f"{type(exc).__name__}: {reason}"
    return type(exc).__name__


def make_retry(
    *,
    max_attempts: int,
    base_delay: float,
    max_delay: float,
    max_rate_limit_delay: float,
    sleeper: Callable[[float], None] | None,
) -> Callable[[Callable[[], T]], T]:
    """Build a bound retry callable capturing one policy configuration.

    Shared by the transport, all resolvers, and ``GitHubTreeSource`` so retry
    knobs are configured in exactly one place. Validates parameters at
    construction time (so an invalid knob fails fast instead of surfacing as a
    bare ``ValueError`` on the first network call).
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")
    if base_delay < 0 or max_delay < 0 or max_rate_limit_delay < 0:
        raise ValueError("delay parameters must be non-negative")
    bound_sleeper = sleeper or time.sleep

    def retry(fn: Callable[[], T]) -> T:
        return retry_http(
            fn,
            max_attempts=max_attempts,
            base_delay=base_delay,
            max_delay=max_delay,
            max_rate_limit_delay=max_rate_limit_delay,
            sleeper=bound_sleeper,
        )

    return retry


def retry_http(
    fn: Callable[[], T],
    *,
    max_attempts: int = 4,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    max_rate_limit_delay: float = 300.0,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> T:
    """Call ``fn`` with categorized retry until it succeeds or attempts run out.

    - Rate-limited failures wait for the server-advised duration, capped at
      ``max_rate_limit_delay`` (default 300s — GitHub primary limits can be up
      to 3600s out); if the server gave no hint, exponential backoff is used.
    - Transient failures honor a valid server wait hint, capped at ``max_delay``;
      otherwise they use deterministic exponential backoff
      ``base_delay * 2**(attempt-1)``.
    - Fatal failures raise immediately with no retry.

    On exhaustion the last exception is re-raised unchanged so callers can wrap
    it into their own domain error type. ``max_attempts`` counts total calls:
    ``max_attempts=4`` performs at most 4 calls and 3 waits.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")
    if base_delay < 0 or max_delay < 0 or max_rate_limit_delay < 0:
        raise ValueError("delay parameters must be non-negative")

    for attempt in range(1, max_attempts + 1):
        logger.debug("http attempt %d/%d", attempt, max_attempts)
        try:
            result = fn()
            if attempt > 1:
                logger.debug("http recovered after %d attempts", attempt)
            return result
        except Exception as exc:
            kind = classify(exc)
            logger.debug("http classified %s: %s", kind.name, describe_failure(exc))
            if kind is HttpErrorKind.FATAL:
                raise
            if attempt >= max_attempts:
                raise

            hint = retry_after_seconds(exc, now=clock())
            if kind is HttpErrorKind.RATE_LIMITED:
                cap = max_rate_limit_delay
                delay = hint if hint is not None else base_delay * (2 ** (attempt - 1))
            else:
                cap = max_delay
                delay = hint if hint is not None else base_delay * (2 ** (attempt - 1))
            wait = min(delay, cap)
            logger.debug("http retry wait %.2fs (kind=%s)", wait, kind.name)
            sleeper(wait)

    # Unreachable: the loop always returns or raises on its final iteration.
    raise RuntimeError("retry_http: loop exhausted without resolution")
