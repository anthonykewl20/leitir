from __future__ import annotations

import importlib.metadata
import json
import os
import sys
import urllib.error
from contextlib import nullcontext
from io import BytesIO, StringIO
from pathlib import Path

import pytest

from leitir import doctor
from leitir.cli import main
from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields


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
        "fetch_method": "github-archive",
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


def test_doctor_json_output_shape(tmp_path: Path) -> None:
    code, output, error = _invoke(tmp_path, "--json", "--no-network")
    payload = json.loads(output)
    assert code == 0
    assert error == ""
    assert payload["schema"] == 1
    assert payload["version"]
    assert payload["generated_at"].endswith("Z")
    assert set(payload["summary"]) == {"pass", "warn", "error", "skip"}
    assert all(set(item) == {"name", "status", "summary", "detail", "data"}
               for item in payload["checks"])


def test_doctor_detects_python_version_below_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "version_info", (3, 10, 14))
    result = doctor.check_python_version()
    assert result.status == "error"


def test_doctor_detects_missing_distribution_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError("leitir")

    monkeypatch.setattr(importlib.metadata, "version", missing)
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


def test_doctor_selftest_catches_integrity_regression(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor, "verify_materialized_tree_hash", lambda *args, **kwargs: None)
    result = doctor.check_integrity_selftest()
    assert result.status == "error"


def test_doctor_network_check_handles_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*args: object, **kwargs: object) -> object:
        raise TimeoutError("too slow")

    monkeypatch.setattr(doctor.urllib.request, "urlopen", timeout)
    result = doctor.check_network_endpoint("npm", "https://registry.npmjs.org/", "0.1.0")
    assert result.status == "warn"
    assert "timed out" in result.summary


def test_doctor_update_check_handles_404_for_github_releases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response(BytesIO):
        def getcode(self) -> int:
            return 200

    def open_url(request: object, timeout: float) -> object:
        url = request.full_url  # type: ignore[attr-defined]
        if url == doctor._GITHUB_RELEASES_URL:
            raise urllib.error.HTTPError(url, 404, "not found", {}, None)
        return nullcontext(Response(b"{}"))

    monkeypatch.setattr(doctor.urllib.request, "urlopen", open_url)
    checks, _version = doctor.collect_checks(root=tmp_path)
    update = next(check for check in checks if check.name == "update.available")
    assert update.status == "skip"
    assert all(check.status == "pass" for check in checks if check.name.startswith("network."))


def test_doctor_update_check_strips_release_tag_v(monkeypatch: pytest.MonkeyPatch) -> None:
    response = BytesIO(b'{"tag_name":"v0.2.0"}')
    monkeypatch.setattr(
        doctor.urllib.request, "urlopen", lambda *args, **kwargs: nullcontext(response)
    )
    result = doctor.check_update_availability("0.1.0")
    assert result.status == "warn"
    assert result.json_data == {"installed": "0.1.0", "latest": "0.2.0"}


def test_doctor_update_check_network_error_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(*args: object, **kwargs: object) -> object:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(doctor.urllib.request, "urlopen", unavailable)
    result = doctor.check_update_availability("0.1.0")
    assert result.status == "warn"
    assert "GitHub Releases" in result.summary


def test_doctor_no_network_flag_skips_all_network_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected(*args: object, **kwargs: object) -> object:
        raise AssertionError("network probe ran")

    monkeypatch.setattr(doctor.urllib.request, "urlopen", unexpected)
    checks, _version = doctor.collect_checks(no_network=True, root=tmp_path)
    network = [check for check in checks if check.name.startswith("network.")]
    assert len(network) == 8
    assert all(check.status == "skip" for check in network)
    assert next(check for check in checks if check.name == "update.available").status == "skip"


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


def test_doctor_color_disabled_when_not_tty(tmp_path: Path) -> None:
    _code, output, _error = _invoke(tmp_path, "--no-network")
    assert "\033[" not in output
