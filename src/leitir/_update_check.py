"""Conservative, anonymous update notifications for interactive CLI use.

The optional check sends only the installed leitir version in its User-Agent
to the GitHub Releases API; it sends no identifying information or telemetry.

Version comparison intentionally supports only final numeric releases (for
example, ``0.1.1``).  Epochs, pre/dev/post releases, local versions, leading
``v`` markers, whitespace, and every other non-numeric form are silently
ignored rather than partially interpreted.

Distribution note: leitir is currently GitHub-only (``pip install
git+https://github.com/anthonykewl20/leitir.git``).  PyPI publication is
deferred until the maintainer declares a public release; the wheel built by
``.github/workflows/release.yml`` will work on PyPI unchanged.  When PyPI
becomes the canonical source, the URL below can optionally switch to
``https://pypi.org/pypi/leitir/json`` with ``info.version`` parsing —
everything else (cache, gates, threading, notice format) stays the same.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.request
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

_DISTRIBUTION_NAME = "leitir"
_GITHUB_RELEASES_URL = "https://api.github.com/repos/anthonykewl20/leitir/releases/latest"
_GITHUB_RELEASES_PAGE = "https://github.com/anthonykewl20/leitir/releases"
_CHECK_INTERVAL_SECONDS = 24 * 60 * 60
_NETWORK_TIMEOUT_SECONDS = 1.0
_CACHE_SCHEMA = 2
_MAX_RESPONSE_BYTES = 64 * 1024
# A live cache write holds its temp file for milliseconds; one older than
# this bound is an orphan from an interrupted exit and is swept by the next
# run (issue #205 C-4). Fresh temps — possibly a concurrent live run's — are
# never touched (SP-2).
_STALE_TMP_MAX_AGE_SECONDS = 300.0
_NUMERIC_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
_TRUE_DISABLE_VALUES = frozenset({"1", "true", "yes", "on"})
_TRUE_CI_VALUES = frozenset({"1", "true", "yes"})

_result: tuple[str, str, str] | None = None
_result_lock = threading.Lock()
_check_started: bool | None = None


def _installed_version() -> str | None:
    try:
        return importlib.metadata.version(_DISTRIBUTION_NAME)
    except importlib.metadata.PackageNotFoundError:
        return None


def should_check(*, json_mode: bool, quiet: bool) -> bool:
    """Return whether this invocation is eligible for an update check."""

    if json_mode or quiet:
        return False
    if os.environ.get("LEITIR_NO_UPDATE_CHECK", "").lower() in _TRUE_DISABLE_VALUES:
        return False
    if os.environ.get("CI", "").lower() in _TRUE_CI_VALUES:
        return False
    if not sys.stdout.isatty() or not sys.stderr.isatty():
        return False
    return _installed_version() is not None


def _parse_numeric_version(version: str) -> tuple[int, ...] | None:
    if _NUMERIC_VERSION.fullmatch(version) is None:
        return None
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        # Python limits decimal-to-int conversion length; an absurdly large
        # numeric component is unsupported just like any other unusable form.
        return None


def _compare_versions(left: str, right: str) -> int | None:
    """Compare numeric releases, returning -1, 0, 1, or None if unsupported."""

    left_parts = _parse_numeric_version(left)
    right_parts = _parse_numeric_version(right)
    if left_parts is None or right_parts is None:
        return None
    width = max(len(left_parts), len(right_parts))
    padded_left = left_parts + (0,) * (width - len(left_parts))
    padded_right = right_parts + (0,) * (width - len(right_parts))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _cache_path() -> Path | None:
    try:
        if sys.platform == "win32":
            root = os.environ.get("LOCALAPPDATA")
            if not root:
                return None
            return Path(root) / _DISTRIBUTION_NAME / "Cache" / "update-check.json"
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Caches" / _DISTRIBUTION_NAME / "update-check.json"
        root = os.environ.get("XDG_CACHE_HOME")
        cache_root = Path(root) if root else Path.home() / ".cache"
        return cache_root / _DISTRIBUTION_NAME / "update-check.json"
    except (OSError, RuntimeError):
        return None


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _read_cache(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("schema") != _CACHE_SCHEMA or payload.get("project") != _DISTRIBUTION_NAME:
        return None
    return payload


def _sweep_stale_cache_temps(directory: Path) -> None:
    """Remove crash-orphaned cache temps, never a live run's file.

    The sweep mirrors materialization's stale-``.tmp-`` cleanup pattern: a
    temp file older than the age bound cannot belong to a live write (writes
    complete in milliseconds), so it is debris from an interrupted exit;
    anything fresher is left untouched for a concurrent run to finish
    (issue #205 C-4/SP-2). Failures are silently ignored — sweeping is
    hygiene, never a behavioral gate.
    """

    try:
        candidates = sorted(directory.glob(".update-check.json.tmp-*"))
    except OSError:
        return
    now = time.time()
    for candidate in candidates:
        try:
            if now - candidate.stat().st_mtime <= _STALE_TMP_MAX_AGE_SECONDS:
                continue
            candidate.unlink(missing_ok=True)
        except OSError:
            continue


def _write_cache(path: Path, payload: Mapping[str, object]) -> bool:
    """Atomically write the cache, returning False for every filesystem failure."""

    fd = -1
    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".update-check.json.tmp-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        return True
    except (OSError, TypeError, ValueError):
        return False
    finally:
        # Cleanup runs for EVERY outcome, including a BaseException (e.g.
        # KeyboardInterrupt) between mkstemp and replace: the except tuple
        # above cannot catch it, and an orphaned temp would otherwise linger
        # until the next run's sweep (issue #205 C-4).
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _fetch_latest_release(installed_version: str) -> tuple[str, str] | None:
    request = urllib.request.Request(
        _GITHUB_RELEASES_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"leitir/{installed_version} update-check",
        },
    )
    try:
        with urllib.request.urlopen(
            request, timeout=_NETWORK_TIMEOUT_SECONDS
        ) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            return None
        payload = json.loads(raw)
        tag = payload["tag_name"]
        if not isinstance(tag, str):
            return None
        latest = tag.removeprefix("v")
        release_url = payload.get("html_url", _GITHUB_RELEASES_PAGE)
        if not isinstance(release_url, str):
            release_url = _GITHUB_RELEASES_PAGE
        return latest, release_url
    except (OSError, ValueError, KeyError, TypeError):
        # Redundancy-free equivalent of the former 8-type tuple: HTTPError,
        # URLError, and TimeoutError are OSError subtypes, and
        # json.JSONDecodeError is a ValueError subtype, so naming them
        # alongside their supertypes could never change the match.
        return None
    except Exception:
        # Third-party response wrappers and platform URL handlers may raise
        # additional exception types.  The optional probe remains fail-silent.
        return None


def _fetch_latest_version(installed_version: str) -> str | None:
    """Return the normalized latest version (retained for internal probes/tests)."""

    release = _fetch_latest_release(installed_version)
    return release[0] if release is not None else None


def _set_result(installed: str, latest: object, release_url: object) -> None:
    if not isinstance(latest, str) or not isinstance(release_url, str):
        return
    with _result_lock:
        global _result
        _result = (installed, latest, release_url)


def _initial_cache(now: datetime, installed: str) -> dict[str, object]:
    return {
        "schema": _CACHE_SCHEMA,
        "project": _DISTRIBUTION_NAME,
        "created_at": _format_time(now),
        "last_checked_at": None,
        "installed_version": installed,
        "latest_version": None,
        "release_url": None,
    }


def _run_update_check(installed: str) -> None:
    try:
        path = _cache_path()
        if path is None:
            return
        _sweep_stale_cache_temps(path.parent)
        now = _utc_now()
        cache = _read_cache(path)
        if cache is None or cache.get("installed_version") != installed:
            _write_cache(path, _initial_cache(now, installed))
            return

        last_checked = _parse_time(cache.get("last_checked_at"))
        reference = last_checked or _parse_time(cache.get("created_at"))
        if reference is None:
            _write_cache(path, _initial_cache(now, installed))
            return
        if (now - reference).total_seconds() < _CHECK_INTERVAL_SECONDS:
            _set_result(installed, cache.get("latest_version"), cache.get("release_url"))
            return

        release = _fetch_latest_release(installed)
        latest, release_url = release if release is not None else (None, None)
        updated = dict(cache)
        updated.update(
            {
                "schema": _CACHE_SCHEMA,
                "project": _DISTRIBUTION_NAME,
                "last_checked_at": _format_time(now),
                "installed_version": installed,
                "latest_version": latest,
                "release_url": release_url,
            }
        )
        _write_cache(path, updated)
        _set_result(installed, latest, release_url)
    except Exception:
        # This feature must never affect command execution, including for
        # unusual platform, clock, mocked-I/O, or interpreter edge cases.
        return


def maybe_start_update_check(*, json_mode: bool, quiet: bool) -> None:
    """Start the background update check if eligible. Call before the main command."""

    global _check_started
    _check_started = False
    with _result_lock:
        global _result
        _result = None
    try:
        eligible = should_check(json_mode=json_mode, quiet=quiet)
    except Exception:
        return
    if not eligible:
        return
    try:
        installed = _installed_version()
    except Exception:
        return
    if installed is None:
        return
    _check_started = True
    try:
        threading.Thread(target=_run_update_check, args=(installed,), daemon=True).start()
    except (OSError, RuntimeError):
        _check_started = False


def maybe_emit_update_notice() -> None:
    """Print the update notice to stderr if a newer version is known."""

    if _check_started is False:
        return
    with _result_lock:
        result = _result
    if result is None:
        if _check_started is not None:
            # An ineligible invocation or a still-running daemon must remain
            # silent.  The cache fallback below is only for direct use of this
            # post-command hook (and makes the documented probe deterministic).
            return
        # Also permits a previously cached result to be surfaced by callers
        # that invoke this public post-command hook without starting a probe.
        try:
            installed = _installed_version()
            path = _cache_path()
            cache = _read_cache(path) if path is not None else None
        except Exception:
            return
        if installed is not None and cache is not None:
            candidate = cache.get("latest_version")
            release_url = cache.get("release_url")
            if isinstance(candidate, str) and isinstance(release_url, str):
                result = (installed, candidate, release_url)
    if result is None:
        return
    installed, latest, release_url = result
    if _compare_versions(latest, installed) != 1:
        return
    try:
        print(
            f"\nA new release of leitir is available: {installed} → {latest}\n"
            "Upgrade with: pip install --upgrade "
            f"git+https://github.com/anthonykewl20/leitir.git@v{latest}\n"
            f"{release_url}\n",
            file=sys.stderr,
        )
    except (OSError, UnicodeError):
        return


__all__ = ["maybe_emit_update_notice", "maybe_start_update_check", "should_check"]
