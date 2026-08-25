from __future__ import annotations

import importlib.metadata
import json
import os
import subprocess
import sys
import time
import urllib.error
from contextlib import nullcontext
from io import BytesIO, StringIO
from pathlib import Path

import pytest

from leitir import doctor
from leitir.cli import main
from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _isolated_environment(home: Path) -> dict[str, str]:
    environment = {
        "CI": "true",
        "HOME": str(home),
        # pathlib.expanduser() uses USERPROFILE rather than HOME on Windows.
        "USERPROFILE": str(home),
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(_REPOSITORY_ROOT / "src"),
    }
    # Windows requires SystemRoot in a replacement subprocess environment.
    if system_root := os.environ.get("SYSTEMROOT"):
        environment["SYSTEMROOT"] = system_root
    return environment


def _doctor_subprocess(
    home: Path,
    *,
    seed: str = "0",
    leitir_home: Path | None = None,
    source_date_epoch: str | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = _isolated_environment(home)
    environment["PYTHONHASHSEED"] = seed
    if leitir_home is not None:
        environment["LEITIR_HOME"] = str(leitir_home)
    if source_date_epoch is not None:
        environment["SOURCE_DATE_EPOCH"] = source_date_epoch
    return subprocess.run(
        [sys.executable, "-m", "leitir.cli", "doctor", "--json", "--no-network"],
        cwd=_REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _invoke(tmp_path: Path, *arguments: str) -> tuple[int, str, str]:
    out, err = StringIO(), StringIO()
    old_home = os.environ.get("LEITIR_HOME")
    os.environ["LEITIR_HOME"] = str(tmp_path)
    try:
        code = main(["doctor", *arguments], stdout=out, stderr=err)
    finally:
        if old_home is None:
            os.environ.pop("LEITIR_HOME", None)
        else:
            os.environ["LEITIR_HOME"] = old_home
    return code, out.getvalue(), err.getvalue()


def _manifest(root: Path, *, digest: bool = True) -> Path:
    sha = "a" * 40
    target = root / "repos" / "github.com" / "owner" / "repo" / sha
    target.mkdir(parents=True)
    (target / "source.py").write_text("answer = 42\n", encoding="utf-8")
    payload: dict[str, object] = {
        "host": "github.com",
        "owner": "owner",
        "repo": "repo",
        "commit_sha": sha,
        "fetch_method": "codeload-tarball",
        "spec": f"github.com/owner/repo@{sha}",
        "repo_url": "https://github.com/owner/repo",
        "fetched_at": "2026-08-06T12:00:00Z",
        "verified": True,
        "verified_at": "2026-08-06T12:00:00Z",
    }
    if digest:
        value, scope = compute_materialized_tree_hash(target)
        payload.update(manifest_digest_fields(value, scope=scope))
    path = target / "leitir-manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_doctor_clean_environment_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in doctor._CREDENTIALS:
        monkeypatch.delenv(name, raising=False)
    code, output, error = _invoke(tmp_path, "--no-network")
    assert code == 0
    assert "0 warnings, 0 errors" in output
    assert error == ""


def test_doctor_clean_ci_subprocess_without_leitir_home_passes(tmp_path: Path) -> None:
    home = tmp_path / "isolated-home"
    home.mkdir()
    result = _doctor_subprocess(home)
    payload = json.loads(result.stdout)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert payload["summary"]["error"] == 0
    assert payload["summary"]["warn"] == 0


def test_doctor_unwritable_cache_root_subprocess_exits_broken(tmp_path: Path) -> None:
    home = tmp_path / "isolated-home"
    root = tmp_path / "unwritable-cache"
    home.mkdir()
    root.mkdir()
    root.chmod(0o500)
    try:
        result = _doctor_subprocess(home, leitir_home=root)
    finally:
        root.chmod(0o700)
    payload = json.loads(result.stdout)
    writable = next(check for check in payload["checks"] if check["name"] == "corpus.writable")
    assert result.returncode == 2
    assert writable["status"] == "error"


def test_doctor_json_is_hash_seed_deterministic(tmp_path: Path) -> None:
    home = tmp_path / "isolated-home"
    home.mkdir()
    results = [
        _doctor_subprocess(home, seed=seed, source_date_epoch="0")
        for seed in ("0", "1", "42")
    ]
    assert [result.returncode for result in results] == [0, 0, 0]
    assert [result.stderr for result in results] == ["", "", ""]
    assert results[0].stdout == results[1].stdout == results[2].stdout


def test_doctor_closed_stdout_pipe_does_not_crash(tmp_path: Path) -> None:
    home = tmp_path / "isolated-home"
    home.mkdir()
    environment = _isolated_environment(home)
    process = subprocess.Popen(
        [sys.executable, "-m", "leitir.cli", "doctor", "--no-network"],
        cwd=_REPOSITORY_ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    process.stdout.close()
    assert process.stderr is not None
    stderr = process.stderr.read()
    returncode = process.wait()
    assert returncode == 0
    assert "BrokenPipeError" not in stderr


def test_doctor_json_output_shape(tmp_path: Path) -> None:
    code, output, error = _invoke(tmp_path, "--json", "--no-network")
    payload = json.loads(output)
    assert code == 0
    assert error == ""
    assert payload["schema"] == 1
    assert payload["version"] is None or isinstance(payload["version"], str)
    assert payload["generated_at"].endswith("Z")
    assert set(payload["summary"]) == {"pass", "warn", "error", "skip"}
    assert all(set(item) == {"name", "status", "summary", "detail", "data"}
               for item in payload["checks"])


def test_doctor_detects_python_version_below_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "version_info", (3, 10, 14))
    result = doctor.check_python_version()
    assert result.status == "error"


def test_doctor_source_checkout_passes_without_distribution_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError("leitir")

    monkeypatch.setattr(importlib.metadata, "version", missing)
    checks, _version = doctor.collect_checks(no_network=True, root=tmp_path)
    result = next(check for check in checks if check.name == "install.version")
    assert result.status == "pass"
    assert "source checkout" in result.summary


def test_doctor_detects_unimportable_install_as_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError("leitir")

    monkeypatch.setattr(importlib.metadata, "version", missing)
    monkeypatch.setattr(doctor, "_leitir_source_root", lambda: None)
    checks, _version = doctor.collect_checks(no_network=True, root=tmp_path)
    result = next(check for check in checks if check.name == "install.version")
    assert result.status == "error"


def test_doctor_detects_unwritable_corpus_root(tmp_path: Path) -> None:
    tmp_path.chmod(0o500)
    try:
        result = doctor.check_corpus_root_writable(tmp_path)
    finally:
        tmp_path.chmod(0o700)
    assert result.status == "error"


def test_doctor_detects_missing_digest_on_verified_shelf(tmp_path: Path) -> None:
    _manifest(tmp_path, digest=False)
    checks, _manifests = doctor.check_cache_state(tmp_path)
    result = next(check for check in checks if check.name == "cache.digest_missing")
    assert result.status == "warn"
    assert "upgrade-cache" in result.summary


def test_doctor_detects_corrupted_shelf(tmp_path: Path) -> None:
    path = _manifest(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["owner"] = "tampered"
    path.write_text(json.dumps(payload), encoding="utf-8")
    checks, _manifests = doctor.check_cache_state(tmp_path)
    result = next(check for check in checks if check.name == "cache.corrupted")
    assert result.status == "warn"
    assert str(path) in (result.detail or "")


def _register_source(root: Path, manifest_path: Path, *, name: str = "repo") -> None:
    from leitir.corpus import write_sources

    target = manifest_path.parent
    write_sources(root, [{
        "name": name,
        "host": "github.com",
        "owner": "owner",
        "repo": "repo",
        "commit_sha": "a" * 40,
        "path": target.relative_to(root).as_posix(),
        "fetched_at": "2026-08-06T12:00:00Z",
    }])


def test_doctor_registered_shelf_with_valid_manifest_passes(tmp_path: Path) -> None:
    path = _manifest(tmp_path)
    _register_source(tmp_path, path)
    result = doctor.check_registered_shelves(tmp_path)
    assert result.status == "pass"
    assert result.json_data == {"total": 1, "invalid": 0}


def test_doctor_flags_registered_shelf_with_deleted_manifest(tmp_path: Path) -> None:
    """BUG1 regression: a shelf whose manifest.json was deleted must NOT be reported healthy.

    `check_cache_state` globs for manifest.json files that physically exist, so a deleted
    manifest simply has no path to find -- it silently vanishes from every cache.* count.
    `check_registered_shelves` instead walks sources.json (the same source of truth `leitir
    list` uses) and must catch this.
    """
    path = _manifest(tmp_path)
    _register_source(tmp_path, path)
    path.unlink()

    # The blind spot: the physical-glob checks see nothing wrong because there is no manifest
    # left to find at all.
    cache_checks, _manifests = doctor.check_cache_state(tmp_path)
    corrupted = next(check for check in cache_checks if check.name == "cache.corrupted")
    assert corrupted.status == "pass"

    result = doctor.check_registered_shelves(tmp_path)
    assert result.status == "error"
    assert "1 of 1" in result.summary
    assert "manifest is missing" in (result.detail or "")
    assert result.json_data is not None
    assert result.json_data["invalid"] == 1

    # And doctor's aggregate result must actually flag it, end to end.
    checks, _version = doctor.collect_checks(no_network=True, root=tmp_path)
    aggregate = next(check for check in checks if check.name == "cache.registered_shelves")
    assert aggregate.status == "error"
    stream = StringIO()
    assert doctor.run_doctor(as_json=True, no_network=True, stdout=stream, root=tmp_path) == 2


def test_doctor_flags_registered_shelf_with_truncated_manifest(tmp_path: Path) -> None:
    """BUG1 regression: a present-but-malformed/truncated manifest must also be flagged."""
    path = _manifest(tmp_path)
    _register_source(tmp_path, path)
    path.write_text('{"host": "github.c', encoding="utf-8")  # truncated JSON

    result = doctor.check_registered_shelves(tmp_path)
    assert result.status == "error"
    assert "manifest failed validation" in (result.detail or "")
    assert result.json_data is not None
    assert result.json_data["invalid"] == 1

    checks, _version = doctor.collect_checks(no_network=True, root=tmp_path)
    aggregate = next(check for check in checks if check.name == "cache.registered_shelves")
    assert aggregate.status == "error"


def test_doctor_selftest_catches_integrity_regression(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor, "verify_materialized_tree_hash", lambda *args, **kwargs: None)
    result = doctor.check_integrity_selftest()
    assert result.status == "error"


def test_doctor_network_check_handles_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(request: object, *, timeout: float) -> object:
        raise TimeoutError("too slow")

    monkeypatch.setattr(doctor._http, "safe_urlopen", timeout)
    result = doctor.check_network_endpoint("npm", "https://registry.npmjs.org/", "0.1.0")
    assert result.status == "warn"
    assert "unreachable" in result.summary
    assert "5s" in result.summary
    assert "timed out" not in result.summary


def test_doctor_network_check_urlerror_timeout_reason_warns_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(request: object, *, timeout: float) -> object:
        raise urllib.error.URLError(TimeoutError("socket timeout"))

    monkeypatch.setattr(doctor._http, "safe_urlopen", timeout)
    result = doctor.check_network_endpoint("npm", "https://registry.npmjs.org/", "0.1.0")
    assert result.status == "warn"
    assert "unreachable" in result.summary
    assert "timed out" not in result.summary


def test_doctor_update_check_handles_404_for_github_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response(BytesIO):
        def getcode(self) -> int:
            return 200

    def open_url(request: object, *, timeout: float) -> object:
        url = request.full_url  # type: ignore[attr-defined]
        if url == doctor._GITHUB_RELEASES_URL:
            raise urllib.error.HTTPError(url, 404, "not found", {}, None)
        return nullcontext(Response(b"{}"))

    monkeypatch.setattr(doctor._http, "safe_urlopen", open_url)
    checks, _version = doctor.collect_checks(root=tmp_path)
    update = next(check for check in checks if check.name == "update.available")
    assert update.status == "skip"
    assert all(check.status == "pass" for check in checks if check.name.startswith("network."))


def test_doctor_update_check_strips_release_tag_v(monkeypatch: pytest.MonkeyPatch) -> None:
    response = BytesIO(b'{"tag_name":"v0.1.1"}')

    def open_url(request: object, *, timeout: float) -> object:
        return nullcontext(response)

    monkeypatch.setattr(doctor._http, "safe_urlopen", open_url)
    result = doctor.check_update_availability("0.1.0")
    assert result.status == "warn"
    assert result.json_data == {"installed": "0.1.0", "latest": "0.1.1"}


def test_doctor_update_check_network_error_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(request: object, *, timeout: float) -> object:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(doctor._http, "safe_urlopen", unavailable)
    result = doctor.check_update_availability("0.1.0")
    assert result.status == "warn"
    assert "GitHub Releases" in result.summary


def test_doctor_no_network_flag_skips_all_network_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected(request: object, *, timeout: float) -> object:
        raise AssertionError("network probe ran")

    monkeypatch.setattr(doctor._http, "safe_urlopen", unexpected)
    checks, _version = doctor.collect_checks(no_network=True, root=tmp_path)
    network = [check for check in checks if check.name.startswith("network.")]
    assert len(network) == 8
    assert all(check.status == "skip" for check in network)
    assert next(check for check in checks if check.name == "update.available").status == "skip"


# --- Issue #203: realistic timeout, bounded reads, shared HTTP seam ---


class _SlowServer:
    """Scripted loopback HTTP server that delays every response."""

    def __init__(self, delay: float) -> None:
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
                time.sleep(delay)
                body = b"{}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_port}/"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def test_doctor_network_check_slow_endpoint_within_budget_is_ok() -> None:
    """G-0 (issue #203): a healthy-but-slow (1.2s) endpoint reports ok, not a timeout."""
    server = _SlowServer(delay=1.2)
    try:
        result = doctor.check_network_endpoint("npm", server.url, "0.1.0")
    finally:
        server.close()
    assert result.status == "pass"
    assert result.summary == f"{server.url} reachable"


def test_doctor_network_check_beyond_budget_warns_unreachable() -> None:
    """C-3/AC-2: responses beyond the 5s budget warn with slow/unreachable wording."""
    server = _SlowServer(delay=8.0)
    try:
        result = doctor.check_network_endpoint("npm", server.url, "0.1.0")
    finally:
        server.close()
    assert result.status == "warn"
    assert "unreachable" in result.summary
    assert "5s" in result.summary
    assert "timed out" not in result.summary


class _RecordingResponse:
    """Response double that records the size of every bounded read."""

    def __init__(self, body: bytes) -> None:
        self._body = body
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self._body[:size] if size >= 0 else self._body

    def __enter__(self) -> _RecordingResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_doctor_update_check_body_read_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """C-4/AC-3: the body is read with the bounded pattern, never json.load-ed unbounded."""
    oversized = b"x" * (doctor._MAX_RESPONSE_BYTES + 1)
    response = _RecordingResponse(oversized)

    def open_url(request: object, *, timeout: float) -> object:
        return response

    monkeypatch.setattr(doctor._http, "safe_urlopen", open_url)
    result = doctor.check_update_availability("0.1.0")
    assert result.status == "warn"
    assert "could not check GitHub Releases" in result.summary
    assert response.read_sizes == [doctor._MAX_RESPONSE_BYTES + 1]
    assert str(doctor._MAX_RESPONSE_BYTES) in (result.detail or "")


def test_doctor_update_check_oversized_body_never_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    """An oversized body is refused before parsing; a bounded one parses normally."""

    def open_factory(body: bytes):
        def open_url(request: object, *, timeout: float) -> object:
            return _RecordingResponse(body)

        return open_url

    exact = b'{"tag_name":"v0.2.0"}' + b" " * (
        doctor._MAX_RESPONSE_BYTES - len('{"tag_name":"v0.2.0"}')
    )
    assert len(exact) == doctor._MAX_RESPONSE_BYTES
    monkeypatch.setattr(doctor._http, "safe_urlopen", open_factory(exact))
    result = doctor.check_update_availability("0.1.0")
    assert result.status == "warn"  # update available, parsed fine
    assert result.json_data == {"installed": "0.1.0", "latest": "0.2.0"}


def test_doctor_network_check_dns_failure_warns_not_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SP-1: DNS failures degrade to a warn, never a crash."""
    import socket

    def dns_failure(request: object, *, timeout: float) -> object:
        raise urllib.error.URLError(socket.gaierror("name resolution failed"))

    monkeypatch.setattr(doctor._http, "safe_urlopen", dns_failure)
    result = doctor.check_network_endpoint("npm", "https://registry.npmjs.org/", "0.1.0")
    assert result.status == "warn"
    assert "network error" in result.summary


def test_doctor_update_check_malformed_json_warns_and_doctor_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SP-2: malformed JSON warns with typed detail; the doctor run continues."""

    def open_url(request: object, *, timeout: float) -> object:
        return _RecordingResponse(b"not-json{")

    monkeypatch.setattr(doctor._http, "safe_urlopen", open_url)
    result = doctor.check_update_availability("0.1.0")
    assert result.status == "warn"
    assert "could not check GitHub Releases" in result.summary
    monkeypatch.setattr(
        doctor,
        "check_installed_version",
        lambda: doctor.Check("install.version", "pass", "0.1.0",
                             json_data={"version": "0.1.0"}),
    )
    checks, _version = doctor.collect_checks(root=tmp_path)
    update = next(check for check in checks if check.name == "update.available")
    assert update.status == "warn"


def test_doctor_network_check_http_error_statuses_classified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SP-3: HTTP error statuses keep their existing classification via the seam."""

    def raise_status(code: int):
        def open_url(request: object, *, timeout: float) -> object:
            raise urllib.error.HTTPError(
                "https://registry.npmjs.org/", code, "boom", {}, None
            )

        return open_url

    monkeypatch.setattr(doctor._http, "safe_urlopen", raise_status(503))
    server_error = doctor.check_network_endpoint("npm", "https://registry.npmjs.org/", "0.1.0")
    assert server_error.status == "warn"
    assert "5xx" in server_error.summary
    monkeypatch.setattr(doctor._http, "safe_urlopen", raise_status(404))
    client_error = doctor.check_network_endpoint("npm", "https://registry.npmjs.org/", "0.1.0")
    assert client_error.status == "warn"
    assert "4xx" in client_error.summary


def test_doctor_offline_machine_warns_every_network_check_and_exits_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SP-4: with the network unreachable every network check warns; doctor never crashes."""

    def offline(request: object, *, timeout: float) -> object:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(doctor._http, "safe_urlopen", offline)
    monkeypatch.setattr(
        doctor,
        "check_installed_version",
        lambda: doctor.Check("install.version", "pass", "0.1.0",
                             json_data={"version": "0.1.0"}),
    )
    checks, _version = doctor.collect_checks(root=tmp_path)
    network = [check for check in checks if check.name.startswith("network.")]
    assert len(network) == 8
    assert all(check.status == "warn" for check in network)
    update = next(check for check in checks if check.name == "update.available")
    assert update.status == "warn"
    stream = StringIO()
    # Network reachability is not a corpus-integrity concern: an offline machine with an
    # otherwise-healthy corpus must exit 0, not fail doctor just because it could not phone
    # home (see `_is_transient_warning`).
    assert doctor.run_doctor(as_json=True, stdout=stream, root=tmp_path) == 0


def test_doctor_quiet_suppresses_passing_checks(tmp_path: Path) -> None:
    code, output, _error = _invoke(tmp_path, "--quiet", "--no-network")
    assert code == 0
    assert "[pass]" not in output
    assert "Summary:" not in output
    assert "[skip]" in output


def test_doctor_credentials_check_does_not_leak_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "secret-value")
    code, output, error = _invoke(tmp_path, "--json", "--no-network")
    assert code == 0
    assert "secret-value" not in output
    assert "secret-value" not in error


def test_doctor_reports_gh_token_only_environment_as_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in doctor._CREDENTIALS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GH_TOKEN", "gh-only-token")
    check = doctor.check_credentials()
    assert check.status == "pass"
    assert check.json_data is not None
    assert check.json_data["present"] == ["GH_TOKEN"]
    assert check.json_data["malformed"] == []
    assert "anonymous" not in check.summary
    code, output, error = _invoke(tmp_path, "--json", "--no-network")
    assert code == 0
    assert "gh-only-token" not in output
    assert "gh-only-token" not in error


def test_doctor_reports_anonymous_when_no_tokens_at_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in doctor._CREDENTIALS:
        monkeypatch.delenv(name, raising=False)
    check = doctor.check_credentials()
    assert check.status == "pass"
    assert check.summary == "no host tokens in environment (anonymous by default)"
    assert check.json_data == {"present": [], "malformed": []}


def test_doctor_exit_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = StringIO()
    cases = [
        ([doctor.Check("x", "pass", "ok")], 0),
        ([doctor.Check("x", "warn", "warning")], 1),
        ([doctor.Check("x", "error", "failure")], 2),
    ]
    for checks, expected in cases:
        monkeypatch.setattr(
            doctor,
            "collect_checks",
            lambda checks=checks, **kwargs: (checks, "0.1.0"),
        )
        assert doctor.run_doctor(no_network=True, stdout=stream) == expected


def test_doctor_windows_exit_path_ctrl_c_is_clean_not_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Windows-only os._exit fast path used for ``doctor`` must honor the
    same clean-interrupt contract as main()'s own KeyboardInterrupt handler:
    a short "leitir: interrupted" message on stderr and exit 130, never a
    raw traceback -- even though this path calls os._exit directly and so
    bypasses main()'s try/except entirely."""

    def _raise(*args: object, **kwargs: object) -> int:
        raise KeyboardInterrupt()

    monkeypatch.setattr(doctor, "run_doctor", _raise)
    monkeypatch.setattr(os, "name", "nt")

    captured: dict[str, int] = {}

    def fake_exit(code: int) -> None:
        captured["code"] = code
        raise SystemExit(code)

    monkeypatch.setattr(os, "_exit", fake_exit)

    out, err = StringIO(), StringIO()
    with pytest.raises(SystemExit):
        main(
            ["doctor", "--json"],
            stdout=out,
            stderr=err,
            _exit_windows_doctor_success=True,
        )

    assert captured["code"] == 130
    assert err.getvalue().strip() == "leitir: interrupted"
    assert "Traceback" not in err.getvalue()
    assert out.getvalue() == ""


def test_doctor_windows_exit_path_normal_success_unaffected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-interrupt doctor run on the Windows fast path still exits with
    doctor's actual result code via os._exit, unchanged by the new
    KeyboardInterrupt branch."""

    monkeypatch.setattr(
        doctor,
        "collect_checks",
        lambda **kwargs: ([doctor.Check("x", "pass", "ok")], "0.1.0"),
    )
    monkeypatch.setattr(os, "name", "nt")

    captured: dict[str, int] = {}

    def fake_exit(code: int) -> None:
        captured["code"] = code
        raise SystemExit(code)

    monkeypatch.setattr(os, "_exit", fake_exit)

    out, err = StringIO(), StringIO()
    with pytest.raises(SystemExit):
        main(
            ["doctor", "--json", "--no-network"],
            stdout=out,
            stderr=err,
            _exit_windows_doctor_success=True,
        )

    assert captured["code"] == 0
    assert "interrupted" not in err.getvalue()


def test_doctor_color_disabled_when_not_tty(tmp_path: Path) -> None:
    _code, output, _error = _invoke(tmp_path, "--no-network")
    assert "\033[" not in output
