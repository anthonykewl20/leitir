"""CLI-level warm-mode integrity, fallback, and cold-parity coverage."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from leitir.api import call_json, warm_call
from leitir.corpus import write_sources
from leitir.materialize import MANIFEST_NAME
from leitir.treehash import full_coverage_manifest_fields

SHA_A = "a" * 40
SHA_B = "b" * 40

_CliRecord = tuple[int, str, str]


def _shelf(root: Path, *, repo: str, commit_sha: str, with_symlink: bool = False) -> Path:
    """Build a fully covered on-disk shelf consumed through the public CLI."""
    target = root / "repos" / "github.com" / "acme" / repo / commit_sha
    (target / "nested").mkdir(parents=True)
    (target / "module.py").write_bytes(b"def demo():\n    return 1\n")
    (target / "nested" / "data.txt").write_bytes(b"pinned data\n")
    if with_symlink:
        try:
            (target / "link.py").symlink_to("module.py")
        except OSError as exc:
            pytest.skip(f"symlinks unavailable: {exc}")
    manifest = {
        "host": "github.com",
        "owner": "acme",
        "repo": repo,
        "commit_sha": commit_sha,
        "fetch_method": "codeload-tarball",
        "spec": f"acme/{repo}@{commit_sha}",
        "repo_url": f"https://github.com/acme/{repo}",
        "fetched_at": "2026-08-27T00:00:00Z",
        "verified": False,
        "verified_at": None,
        "source": "git-commit",
        "parity": "exact",
        **full_coverage_manifest_fields(target),
    }
    (target / MANIFEST_NAME).write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    return target


def _entry(root: Path, target: Path, *, repo: str, commit_sha: str) -> dict[str, str]:
    return {
        "name": repo,
        "host": "github.com",
        "owner": "acme",
        "repo": repo,
        "commit_sha": commit_sha,
        "path": target.relative_to(root).as_posix(),
        "fetched_at": "2026-08-27T00:00:00Z",
    }


def _install_corpus(root: Path, *, second_shelf: bool = False) -> tuple[Path, Path | None]:
    first = _shelf(root, repo="demo", commit_sha=SHA_A)
    entries = [_entry(root, first, repo="demo", commit_sha=SHA_A)]
    second: Path | None = None
    if second_shelf:
        second = _shelf(root, repo="other", commit_sha=SHA_B)
        entries.append(_entry(root, second, repo="other", commit_sha=SHA_B))
    write_sources(root, entries)
    return first, second


def _package_shelf(root: Path, *, commit_sha: str, version: str) -> Path:
    """Build a cached exact PyPI pin for offline CLI get/info/api/diff calls."""
    target = _shelf(root, repo="demo", commit_sha=commit_sha)
    manifest_path = target / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert isinstance(manifest, dict)
    manifest.update(
        {
            "spec": "pypi:demo",
            "ecosystem": "pypi",
            "name": "demo",
            "version": version,
            "tag": f"v{version}",
            "fetch_method": "codeload-tarball",
            "source": "git-commit",
            "registry_url": f"https://pypi.org/project/demo/{version}/",
            "verified": True,
            "verified_at": "2026-08-27T00:00:00Z",
        }
    )
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return target


def _corpus_search_argv(root: Path) -> list[str]:
    return [
        "search",
        "--corpus",
        "--must",
        "identifier:demo",
        "--root",
        str(root),
    ]


def _tamper(target: Path, kind: str) -> None:
    """Mutate one integrity input without using leitir's writer protocol."""
    if kind == "file_bytes":
        with (target / "module.py").open("ab") as handle:
            handle.write(b"tampered\n")
        return
    if kind == "symlink_target":
        link = target / "link.py"
        link.unlink()
        link.symlink_to("nested/data.txt")
        return

    manifest_path = target / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert isinstance(manifest, dict)
    if kind == "file_digest_entry":
        digests = manifest["materialized_file_digests"]
        assert isinstance(digests, dict)
        digests["module.py"] = "0" * 64
    elif kind == "tree_hash":
        # This is a syntactically valid h1 digest for 32 zero bytes, but not
        # the aggregate committed when the shelf was materialized.
        manifest["materialized_tree_hash"] = "h1:" + "A" * 43 + "="
    else:  # pragma: no cover - all callers are parametrized below.
        raise AssertionError(f"unknown tamper kind: {kind}")
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")


def _assert_shelf_rejected(
    document: dict[str, Any], *, repo: str, commit_sha: str
) -> None:
    """Corpus search reports tampered shelves rather than serving their bytes."""
    matches = document["matches"]
    excluded = document["shelves_excluded"]
    assert isinstance(matches, list)
    assert isinstance(excluded, list)
    assert not any(
        isinstance(match, dict)
        and isinstance(match.get("source"), dict)
        and match["source"].get("commit_sha") == commit_sha
        for match in matches
    )
    assert {item["repo"] for item in excluded if isinstance(item, dict)} >= {repo}
    assert any(
        isinstance(item, dict)
        and item.get("repo") == repo
        and item.get("reason") == "verification_failed"
        for item in excluded
    )


def _capture_api_main(monkeypatch: pytest.MonkeyPatch) -> list[_CliRecord]:
    """Observe raw CLI bytes while retaining the real API and CLI code paths."""
    import leitir.api as api_module

    records: list[_CliRecord] = []
    real_main = api_module.main

    def recording_main(*args: object, **kwargs: object) -> int:
        code = real_main(*args, **kwargs)
        stdout = kwargs.get("stdout")
        stderr = kwargs.get("stderr")
        assert isinstance(stdout, io.StringIO)
        assert isinstance(stderr, io.StringIO)
        records.append((code, stdout.getvalue(), stderr.getvalue()))
        return code

    monkeypatch.setattr(api_module, "main", recording_main)
    return records


@pytest.mark.parametrize(
    "kind", ["file_bytes", "symlink_target", "file_digest_entry", "tree_hash"]
)
def test_warm_cli_tamper_between_calls_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """A post-verification filesystem tamper cannot be served on touch two."""
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    target = _shelf(
        tmp_path, repo="demo", commit_sha=SHA_A, with_symlink=kind == "symlink_target"
    )
    write_sources(tmp_path, [_entry(tmp_path, target, repo="demo", commit_sha=SHA_A)])
    argv = _corpus_search_argv(tmp_path)

    with warm_call(tmp_path) as caller:
        first = caller(argv)
        assert first["matches"]
        _tamper(target, kind)

        # Each caller invocation is a separate WarmSession.call() window, so
        # locks were released after the verified first touch. The second touch
        # must revalidate rather than returning its old manifest memo.
        second = caller(argv)
        stats = caller.stats()

    _assert_shelf_rejected(second, repo="demo", commit_sha=SHA_A)
    # Corpus eligibility performs its own fail-closed load-time gate before
    # dispatching to the session-aware searcher. The first touch nevertheless
    # entered warm verification; the second must never reach content serving.
    assert stats["misses"] > 0


def test_warm_cli_tamper_isolated_to_affected_shelf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed shelf never causes an untouched sibling to disappear."""
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    first, second = _install_corpus(tmp_path, second_shelf=True)
    assert second is not None
    argv = _corpus_search_argv(tmp_path)

    with warm_call(tmp_path) as caller:
        baseline = caller(argv)
        assert {match["source"]["commit_sha"] for match in baseline["matches"]} == {
            SHA_A,
            SHA_B,
        }
        _tamper(first, "file_bytes")
        after_tamper = caller(argv)
        stats = caller.stats()

    _assert_shelf_rejected(after_tamper, repo="demo", commit_sha=SHA_A)
    assert {match["source"]["commit_sha"] for match in after_tamper["matches"]} == {SHA_B}
    assert stats["misses"] > 0


def test_warm_cli_tamper_rejection_is_sticky(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Once revalidation rejects a shelf, later session calls cannot serve it."""
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    target, _second = _install_corpus(tmp_path)
    argv = _corpus_search_argv(tmp_path)

    with warm_call(tmp_path) as caller:
        assert caller(argv)["matches"]
        _tamper(target, "file_bytes")
        rejected = caller(argv)
        third_touch = caller(argv)
        stats = caller.stats()

    _assert_shelf_rejected(rejected, repo="demo", commit_sha=SHA_A)
    _assert_shelf_rejected(third_touch, repo="demo", commit_sha=SHA_A)
    assert stats["misses"] > 0


def test_warm_establishment_failure_uses_byte_identical_cold_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed optimization setup selects the literal cold CLI path."""
    import leitir.api as api_module

    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    monkeypatch.setattr("leitir.index.query._utc_now", lambda: "2026-09-02T00:00:00Z")
    _install_corpus(tmp_path)
    records = _capture_api_main(monkeypatch)
    argv = _corpus_search_argv(tmp_path)

    cold = call_json(argv)

    def unavailable_session(_root: object) -> object:
        raise OSError("warm state unavailable")

    monkeypatch.setattr(api_module, "WarmSession", unavailable_session)
    with warm_call(tmp_path) as caller:
        fallback = caller(argv)
        assert caller.stats() == {
            "hits": 0,
            "misses": 0,
            "revalidations": 0,
            "sticky_rejects": 0,
            "cold_fallbacks": 0,
        }

    assert fallback == cold
    assert records == [records[0], records[0]]


def _parity_argv(root: Path, command: str) -> list[str]:
    if command == "info":
        return ["info", "pypi:demo@1.0.0", "--json", "--root", str(root)]
    if command == "get":
        return ["get", "pypi:demo@1.0.0", "--json", "--root", str(root)]
    if command == "search":
        return _corpus_search_argv(root)
    if command == "api":
        return ["api", "pypi:demo@1.0.0", "--json", "--root", str(root)]
    if command == "diff":
        return [
            "diff",
            "pypi:demo@1.0.0",
            "pypi:demo@2.0.0",
            "--json",
            "--root",
            str(root),
        ]
    raise AssertionError(f"unknown parity command: {command}")  # pragma: no cover


@pytest.mark.parametrize("command", ["info", "get", "search", "api", "diff"])
def test_cold_and_first_warm_cli_calls_are_byte_identical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    """All representative CLI verbs retain their first-touch cold contract."""
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    monkeypatch.setattr("leitir.index.query._utc_now", lambda: "2026-09-02T00:00:00Z")
    if command == "search":
        _install_corpus(tmp_path)
    else:
        first = _package_shelf(tmp_path, commit_sha=SHA_A, version="1.0.0")
        write_sources(
            tmp_path,
            [_entry(tmp_path, first, repo="demo", commit_sha=SHA_A)],
        )
    if command == "diff":
        second = _package_shelf(tmp_path, commit_sha=SHA_B, version="2.0.0")
        write_sources(
            tmp_path,
            [
                _entry(tmp_path, first, repo="demo", commit_sha=SHA_A),
                _entry(tmp_path, second, repo="demo", commit_sha=SHA_B),
            ],
        )
    records = _capture_api_main(monkeypatch)
    argv = _parity_argv(tmp_path, command)

    cold = call_json(argv)
    with warm_call(tmp_path) as caller:
        warm = caller(argv)

    assert warm == cold
    assert records == [records[0], records[0]]
    assert json.loads(records[0][1]) == cold
