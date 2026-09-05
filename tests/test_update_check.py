from __future__ import annotations

import importlib.metadata
import json
import os
import sys
import time
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Self

import pytest

from leitir import _update_check as update
from leitir import cli


class _Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]


@pytest.fixture(autouse=True)
def _isolated_update_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.delenv("LEITIR_NO_UPDATE_CHECK", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(update, "_result", None)
    monkeypatch.setattr(update, "_check_started", None)


def _tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    monkeypatch.setattr(update.importlib.metadata, "version", lambda name: "0.1.0")


def _cache_payload(*, checked: datetime | None, latest: str | None = "0.1.1") -> dict[str, object]:
    created = datetime.now(UTC) - timedelta(days=2)
    return {
        "schema": 2,
        "project": "leitir",
        "created_at": update._format_time(created),
        "last_checked_at": update._format_time(checked) if checked else None,
        "installed_version": "0.1.0",
        "latest_version": latest,
        "release_url": "https://github.com/anthonykewl20/leitir/releases/tag/v0.1.1",
    }


def _write_test_cache(payload: dict[str, object]) -> Path:
    path = update._cache_path()
    assert path is not None
    assert update._write_cache(path, payload)
    return path


def test_version_comparison_numeric() -> None:
    assert update._parse_numeric_version("0.2.0") == (0, 2, 0)
    assert update._compare_versions("0.2.0", "0.1.0") == 1
    assert update._compare_versions("1.0.0", "0.99.9") == 1
    assert update._compare_versions("0.2", "0.2.0") == 0
    assert update._compare_versions("0.2.1", "0.2.0") == 1


def test_version_comparison_rejects_non_numeric() -> None:
    for version in ("1.0rc1", "1.0-dev", "v1.0", "1.0+local", "1.0.post1"):
        assert update._compare_versions(version, "1.0") is None


def test_should_check_returns_false_for_json_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    _tty(monkeypatch)
    assert not update.should_check(json_mode=True, quiet=False)


def test_should_check_returns_false_for_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    _tty(monkeypatch)
    assert not update.should_check(json_mode=False, quiet=True)


def test_should_check_returns_false_for_env_disable(monkeypatch: pytest.MonkeyPatch) -> None:
    _tty(monkeypatch)
    monkeypatch.setenv("LEITIR_NO_UPDATE_CHECK", "1")
    assert not update.should_check(json_mode=False, quiet=False)
    monkeypatch.setenv("LEITIR_NO_UPDATE_CHECK", "false")
    assert update.should_check(json_mode=False, quiet=False)
    monkeypatch.setattr(update, "_result", ("0.1.0", "9.0.0"))
    monkeypatch.setenv("LEITIR_NO_UPDATE_CHECK", "1")
    update.maybe_start_update_check(json_mode=False, quiet=False)
    assert update._result is None


def test_should_check_returns_false_in_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    _tty(monkeypatch)
    monkeypatch.setenv("CI", "true")
    assert not update.should_check(json_mode=False, quiet=False)
    monkeypatch.setenv("CI", "false")
    assert update.should_check(json_mode=False, quiet=False)


def test_should_check_returns_false_for_non_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    _tty(monkeypatch)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    assert not update.should_check(json_mode=False, quiet=False)


def test_should_check_returns_false_without_distribution_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    _tty(monkeypatch)

    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(update.importlib.metadata, "version", missing)
    assert not update.should_check(json_mode=False, quiet=False)


def test_first_run_creates_cache_but_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def urlopen(*args: object, **kwargs: object) -> _Response:
        nonlocal called
        called = True
        return _Response(b"{}")

    monkeypatch.setattr(update.urllib.request, "urlopen", urlopen)
    update._run_update_check("0.1.0")
    path = update._cache_path()
    assert path is not None and path.exists()
    assert update._read_cache(path)["last_checked_at"] is None  # type: ignore[index]
    assert not called


def test_fresh_cache_skips_network(monkeypatch: pytest.MonkeyPatch) -> None:
    _write_test_cache(_cache_payload(checked=datetime.now(UTC)))
    monkeypatch.setattr(update.urllib.request, "urlopen", lambda *a, **k: pytest.fail("network called"))
    update._run_update_check("0.1.0")
    assert update._result == (
        "0.1.0",
        "0.1.1",
        "https://github.com/anthonykewl20/leitir/releases/tag/v0.1.1",
    )


def test_stale_cache_triggers_network(monkeypatch: pytest.MonkeyPatch) -> None:
    _write_test_cache(_cache_payload(checked=datetime.now(UTC) - timedelta(hours=25)))
    calls = 0

    def urlopen(*args: object, **kwargs: object) -> _Response:
        nonlocal calls
        calls += 1
        return _Response(
            b'{"tag_name":"v0.1.2","html_url":'
            b'"https://github.com/anthonykewl20/leitir/releases/tag/v0.1.2"}'
        )

    monkeypatch.setattr(update.urllib.request, "urlopen", urlopen)
    update._run_update_check("0.1.0")
    assert calls == 1
    assert update._result == (
        "0.1.0",
        "0.1.2",
        "https://github.com/anthonykewl20/leitir/releases/tag/v0.1.2",
    )


def test_github_releases_404_silently_skips(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_test_cache(_cache_payload(checked=datetime.now(UTC) - timedelta(hours=25)))

    def missing(*args: object, **kwargs: object) -> _Response:
        raise urllib.error.HTTPError(update._GITHUB_RELEASES_URL, 404, "missing", {}, None)

    monkeypatch.setattr(update.urllib.request, "urlopen", missing)
    update._run_update_check("0.1.0")
    update.maybe_emit_update_notice()
    assert capsys.readouterr() == ("", "")


def test_network_timeout_silently_skips(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(update.urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(TimeoutError()))
    assert update._fetch_latest_version("0.1.0") is None
    update.maybe_emit_update_notice()
    assert capsys.readouterr().err == ""


def test_malformed_json_silently_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update.urllib.request, "urlopen", lambda *a, **k: _Response(b"not-json"))
    assert update._fetch_latest_version("0.1.0") is None


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.HTTPError(update._GITHUB_RELEASES_URL, 500, "boom", {}, None),
        urllib.error.URLError("connection refused"),
        TimeoutError("timed out"),
        OSError("socket hiccup"),
        ValueError("bad value"),
        KeyError("tag_name"),
        TypeError("wrong type"),
        json.JSONDecodeError("bad", "doc", 0),
    ],
    ids=["HTTPError", "URLError", "TimeoutError", "OSError", "ValueError", "KeyError", "TypeError", "JSONDecodeError"],
)
def test_fetch_latest_release_failure_matrix_is_fail_silent(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    # Issue #204 C-3/AC-5, SP-3: after the redundant except-tuple cleanup the
    # observable fail-silent contract is identical for every failure class.
    def broken(*args: object, **kwargs: object) -> _Response:
        raise failure

    monkeypatch.setattr(update.urllib.request, "urlopen", broken)
    assert update._fetch_latest_release("0.1.0") is None


def test_mid_stream_read_failure_is_fail_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    class _BrokenResponse(_Response):
        def read(self, size: int = -1) -> bytes:
            raise OSError("connection reset mid-stream")

    monkeypatch.setattr(update.urllib.request, "urlopen", lambda *a, **k: _BrokenResponse(b"{}"))
    assert update._fetch_latest_release("0.1.0") is None


def test_strips_leading_v_from_tag_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        update.urllib.request,
        "urlopen",
        lambda *a, **k: _Response(b'{"tag_name":"v0.1.1"}'),
    )
    assert update._fetch_latest_version("0.1.0") == "0.1.1"


def test_newer_version_emits_notice_to_stderr(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    release_url = "https://github.com/anthonykewl20/leitir/releases/tag/v0.1.1"
    monkeypatch.setattr(update, "_result", ("0.1.0", "0.1.1", release_url))
    update.maybe_emit_update_notice()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "\nA new release of leitir is available: 0.1.0 → 0.1.1\n"
        "Upgrade with: pip install --upgrade "
        "git+https://github.com/anthonykewl20/leitir.git@v0.1.1\n"
        f"{release_url}\n\n"
    )


def test_release_url_in_notice(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    release_url = "https://github.com/anthonykewl20/leitir/releases/tag/v0.1.1"
    monkeypatch.setattr(update, "_result", ("0.1.0", "0.1.1", release_url))
    update.maybe_emit_update_notice()
    assert release_url in capsys.readouterr().err


def test_older_or_equal_version_emits_nothing(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    for latest in ("0.1.0", "0.1.1"):
        monkeypatch.setattr(
            update,
            "_result",
            ("0.1.1", latest, "https://github.com/anthonykewl20/leitir/releases"),
        )
        update.maybe_emit_update_notice()
    assert capsys.readouterr().err == ""


def test_notice_not_emitted_on_command_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    emitted = False
    monkeypatch.setattr(update, "maybe_start_update_check", lambda **kwargs: None)

    def emit() -> None:
        nonlocal emitted
        emitted = True

    monkeypatch.setattr(update, "maybe_emit_update_notice", emit)
    assert cli.main(["search", "--repo", "owner/repo", "--commit", "a" * 40]) != 0
    assert not emitted


def test_notice_never_goes_to_stdout(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        update,
        "_result",
        ("0.1.0", "9.0.0", "https://github.com/anthonykewl20/leitir/releases"),
    )
    update.maybe_emit_update_notice()
    assert capsys.readouterr().out == ""


def _assert_atomic_cache_state(
    path: Path, payloads: list[dict[str, object]]
) -> None:
    """Assert the post-conditions of an atomic cache write.

    Independent of which concurrent writer won the race: the surviving file is
    one intact payload (never torn/corrupt) and no staging temp files remain.
    """
    assert not list(path.parent.glob(".update-check.json.tmp-*"))
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written in payloads


def test_cache_is_atomic(tmp_path: Path) -> None:
    path = tmp_path / "cache" / "update-check.json"
    payloads = [dict(_cache_payload(checked=None), latest_version=f"0.{index}.0") for index in range(20)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        # Under concurrent os.replace, Windows mandatory locking means some writers
        # lose the race and correctly return False (fail-closed), leaving the prior
        # valid cache intact. The atomicity contract is about the final state, not
        # about every writer winning, so we assert post-conditions rather than all().
        list(pool.map(lambda payload: update._write_cache(path, payload), payloads))
    _assert_atomic_cache_state(path, payloads)


def test_cache_atomic_postcondition_detects_torn_write(tmp_path: Path) -> None:
    path = tmp_path / "cache" / "update-check.json"
    payloads = [dict(_cache_payload(checked=None), latest_version="0.1.1")]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'{"torn":')  # a write interrupted mid-stream
    with pytest.raises(json.JSONDecodeError):
        _assert_atomic_cache_state(path, payloads)


def test_schema_1_cache_is_discarded() -> None:
    payload = _cache_payload(checked=datetime.now(UTC) - timedelta(hours=25))
    payload["schema"] = 1
    path = _write_test_cache(payload)
    update._run_update_check("0.1.0")
    replaced = json.loads(path.read_text(encoding="utf-8"))
    assert replaced["schema"] == 2
    assert replaced["last_checked_at"] is None


def test_version_flag_prints_version_and_exits(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(cli.importlib.metadata, "version", lambda name: "0.1.0")
    assert cli.main(["--version"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "leitir 0.1.0\n"
    assert captured.err == ""


def test_credentials_not_in_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = ""

    def urlopen(request: object, *, timeout: float) -> _Response:
        nonlocal seen
        seen = request.get_header("User-agent")  # type: ignore[attr-defined]
        assert timeout == 1.0
        assert request.full_url == update._GITHUB_RELEASES_URL  # type: ignore[attr-defined]
        assert request.get_header("Accept") == "application/vnd.github+json"  # type: ignore[attr-defined]
        return _Response(
            b'{"tag_name":"v0.1.1","html_url":'
            b'"https://github.com/anthonykewl20/leitir/releases/tag/v0.1.1"}'
        )

    monkeypatch.setattr(update.urllib.request, "urlopen", urlopen)
    assert update._fetch_latest_version("0.1.0") == "0.1.1"
    assert seen == "leitir/0.1.0 update-check"


def test_stale_cache_temp_is_swept_on_next_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Issue #205 C-4/AC-4/SP-2: crash-orphaned cache temps are swept.

    A temp older than the age bound cannot belong to a live write and is
    removed by the next run; a fresh temp — possibly a concurrent live run's
    file — is never touched.
    """

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    path = update._cache_path()
    assert path is not None
    # The autouse fixture isolates the platform-specific cache root.
    path.parent.mkdir(parents=True, exist_ok=True)
    stale = path.parent / ".update-check.json.tmp-orphaned"
    stale.write_text("{}", encoding="utf-8")
    ancient = time.time() - update._STALE_TMP_MAX_AGE_SECONDS - 3600.0
    os.utime(stale, (ancient, ancient))
    fresh = path.parent / ".update-check.json.tmp-live-run"
    fresh.write_text("{}", encoding="utf-8")

    try:
        update._run_update_check("0.1.0")

        assert not stale.exists()
        assert fresh.exists()
    finally:
        fresh.unlink(missing_ok=True)
        stale.unlink(missing_ok=True)


def test_cache_write_cleans_its_own_temp_on_base_exception(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Issue #205 C-4/AC-4: cleanup runs in ``finally``, not ``except``.

    A BaseException (here KeyboardInterrupt) between mkstemp and replace is
    outside the ordinary except tuple; the finally-based cleanup must still
    remove the write's own temp file.
    """

    path = tmp_path / "cache" / "leitir" / "update-check.json"

    def interrupted(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(update.os, "replace", interrupted)
    with pytest.raises(KeyboardInterrupt):
        update._write_cache(path, {"schema": 2})
    assert list(path.parent.glob(".update-check.json.tmp-*")) == []
