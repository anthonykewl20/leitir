"""User-level intent tests for `leitir search --corpus` (issue #266).

A corpus-wide search fans a scoped-exhaustive query out across every
eligible materialized shelf, offline, reusing the same ScopedSearcher /
IndexedSearcher machinery that already backs a single-scope `leitir
search`. The critical contract under test is coverage honesty: a shelf
that is unindexed (under --require-index), drift-parity, or fails
load-time (tamper) verification must be excluded from the search and
named in the output -- never silently dropped, and never allowed to let
the command report a false "complete" coverage claim.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.cli import ExitCode, main
from leitir.corpus import load_sources, write_sources
from leitir.index.builder import ShelfRef
from leitir.tree import BlobEntry
from leitir.treehash import TREE_HASH_ALGORITHM, compute_materialized_tree_hash

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


class LocalTree:
    """A tree source that is never actually consulted for a fully local shelf."""

    def list_blobs_ex(self, slug: str, commit_sha: str) -> tuple[tuple[BlobEntry, ...], bool]:
        raise AssertionError("corpus-wide search must not touch the network for a local shelf")

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        raise AssertionError("corpus-wide search must not touch the network for a local shelf")

    def read_blob_stream(self, slug: str, blob_sha: str):
        raise AssertionError("corpus-wide search must not touch the network for a local shelf")


def _materialize(
    root: Path,
    files: dict[str, bytes],
    *,
    owner: str = "example",
    repo: str = "demo",
    commit: str = SHA_A,
    parity: str = "exact",
    tree_hash_override: str | None = None,
    host: str = "github.com",
) -> ShelfRef:
    target = root / "repos" / host / owner / repo / commit
    target.mkdir(parents=True)
    for relative, data in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    tree_hash, scope = compute_materialized_tree_hash(target)
    manifest = {
        "commit_sha": commit,
        "fetch_method": "codeload-tarball",
        "fetched_at": "2026-01-01T00:00:00Z",
        "host": host,
        "materialized_tree_hash": tree_hash_override or tree_hash,
        "materialized_tree_hash_algorithm": TREE_HASH_ALGORITHM,
        "materialized_tree_hash_scope": scope,
        "owner": owner,
        "parity": parity,
        "repo": repo,
        "repo_url": f"https://{host}/{owner}/{repo}",
        "source": "git-commit",
        "spec": f"{owner}/{repo}@{commit}",
        "verified": True,
        "verified_at": "2026-08-27T00:00:00Z",
    }
    (target / "leitir-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    entries = [
        entry
        for entry in load_sources(root)
        if (entry["host"], entry["owner"], entry["repo"], entry["commit_sha"])
        != (host, owner, repo, commit)
    ]
    entries.append(
        {
            "commit_sha": commit,
            "fetched_at": "2026-01-01T00:00:00Z",
            "host": host,
            "name": f"{owner}/{repo}",
            "owner": owner,
            "path": f"repos/{host}/{owner}/{repo}/{commit}",
            "repo": repo,
        }
    )
    write_sources(root, entries)
    return ShelfRef(host, owner, repo, commit)


def _run(args: list[str], **kwargs) -> tuple[int, dict[str, object], str]:
    import io

    out = io.StringIO()
    err = io.StringIO()
    code = main(
        args,
        stdout=out,
        stderr=err,
        tree_source_factory=lambda _token: LocalTree(),
        **kwargs,
    )
    payload = json.loads(out.getvalue()) if out.getvalue().strip() else {}
    return code, payload, err.getvalue()


def test_corpus_search_finds_match_in_one_shelf_among_several(tmp_path, monkeypatch):
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    _materialize(tmp_path, {"a.py": b"other = 1\n"}, repo="alpha", commit=SHA_A)
    _materialize(tmp_path, {"b.py": b"needle = 2\n"}, repo="beta", commit=SHA_B)
    _materialize(tmp_path, {"c.py": b"other = 3\n"}, repo="gamma", commit=SHA_C)

    code, payload, _err = _run(
        ["search", "--corpus", "--must", "exact_text:needle", "--root", str(tmp_path)]
    )

    assert code == ExitCode.SUCCESS
    assert [m["source"]["path"] for m in payload["matches"]] == ["b.py"]
    assert payload["matches"][0]["source"]["commit_sha"] == SHA_B
    assert payload["shelves_searched"] == [
        {"host": "github.com", "owner": "example", "repo": "alpha", "commit_sha": SHA_A},
        {"host": "github.com", "owner": "example", "repo": "beta", "commit_sha": SHA_B},
        {"host": "github.com", "owner": "example", "repo": "gamma", "commit_sha": SHA_C},
    ]
    assert payload["shelves_excluded"] == []
    assert payload["corpus_status"] == "complete_for_declared_universe"
    assert payload["coverage"]["status"] == "complete_for_declared_universe"


def test_corpus_search_excludes_and_names_drift_and_tampered_shelves(tmp_path, monkeypatch):
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    _materialize(tmp_path, {"clean.py": b"needle = 1\n"}, repo="clean", commit=SHA_A)
    _materialize(
        tmp_path,
        {"drift.py": b"needle = 2\n"},
        repo="drift",
        commit=SHA_B,
        parity="drift",
    )
    _materialize(
        tmp_path,
        {"tampered.py": b"needle = 3\n"},
        repo="tampered",
        commit=SHA_C,
        tree_hash_override="0" * 64,
    )

    code, payload, err = _run(
        ["search", "--corpus", "--must", "exact_text:needle", "--root", str(tmp_path)]
    )

    assert code == ExitCode.SUCCESS
    assert [m["source"]["path"] for m in payload["matches"]] == ["clean.py"]
    assert payload["shelves_searched"] == [
        {"host": "github.com", "owner": "example", "repo": "clean", "commit_sha": SHA_A}
    ]
    excluded = {(e["repo"], e["reason"]) for e in payload["shelves_excluded"]}
    assert excluded == {("drift", "drift_parity"), ("tampered", "verification_failed")}
    # Coverage must never claim completeness once a shelf was excluded.
    assert payload["corpus_status"] == "partial"
    assert "drift" in err
    assert "tampered" in err
    assert "drift_parity" in err
    assert "verification_failed" in err


def test_corpus_search_require_index_excludes_and_names_unindexed_shelf(tmp_path, monkeypatch):
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    _materialize(tmp_path, {"indexed.py": b"needle = 1\n"}, repo="indexed", commit=SHA_A)
    _materialize(tmp_path, {"bare.py": b"needle = 2\n"}, repo="bare", commit=SHA_B)

    assert (
        main(
            ["index", "example/indexed@" + SHA_A, "--root", str(tmp_path)],
            stdout=__import__("io").StringIO(),
            stderr=__import__("io").StringIO(),
        )
        == ExitCode.SUCCESS
    )

    code, payload, err = _run(
        [
            "search",
            "--corpus",
            "--must",
            "exact_text:needle",
            "--require-index",
            "--root",
            str(tmp_path),
        ]
    )

    assert code == ExitCode.SUCCESS
    assert [m["source"]["path"] for m in payload["matches"]] == ["indexed.py"]
    assert payload["shelves_searched"] == [
        {"host": "github.com", "owner": "example", "repo": "indexed", "commit_sha": SHA_A}
    ]
    assert payload["shelves_excluded"] == [
        {
            "host": "github.com",
            "owner": "example",
            "repo": "bare",
            "commit_sha": SHA_B,
            "reason": "unindexed",
        }
    ]
    assert payload["corpus_status"] == "partial"
    assert "unindexed" in err
    assert "bare" in err


def test_corpus_rejected_with_repo_package_or_global(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    code = main(
        [
            "search",
            "--corpus",
            "--repo",
            "example/demo",
            "--commit",
            SHA_A,
            "--must",
            "exact_text:needle",
        ]
    )
    assert code == ExitCode.MALFORMED_USAGE
    err = capsys.readouterr().err
    assert "--corpus" in err or "not allowed" in err or "argument" in err

    code = main(["search", "--corpus", "--global", "--must", "exact_text:needle"])
    assert code == ExitCode.MALFORMED_USAGE

    code = main(
        [
            "search",
            "--corpus",
            "--package",
            "left-pad",
            "--version",
            "1.0.0",
            "--ecosystem",
            "npm",
            "--must",
            "exact_text:needle",
        ]
    )
    assert code == ExitCode.MALFORMED_USAGE


def test_corpus_search_empty_corpus_is_honest_empty_not_error(tmp_path, monkeypatch):
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")

    code, payload, err = _run(
        ["search", "--corpus", "--must", "exact_text:needle", "--root", str(tmp_path)]
    )

    assert code == ExitCode.SUCCESS
    assert payload["matches"] == []
    assert payload["shelves_searched"] == []
    assert payload["shelves_excluded"] == []
    assert payload["coverage"]["files_eligible"] == 0
    # Vacuously complete over a declared-empty universe, but the summary must
    # make explicit that nothing was actually materialized -- never read as
    # "everything you depend on was searched".
    assert "shelves_searched=0" in err
    # A genuinely empty, cleanly-read catalog is distinguishable in the JSON
    # alone (issue #266 P1, Probe 4): the declared universe really is zero.
    assert payload["shelves_declared_total"] == 0


def test_corpus_search_corrupt_catalog_fails_closed_not_vacuous_success(tmp_path, monkeypatch):
    """Regression test for the reported bug: mirrors the reviewer's live repro.

    Two real shelves are materialized, both containing the needle, and the
    search is confirmed to find them honestly first. The catalog
    (``sources.json``) is then corrupted in place -- the exact failure mode
    reported live: ``load_sources`` used to catch the corruption, silently
    rename the file to ``sources.json.bak``, and return an empty list, so a
    corpus-wide search would see zero shelves and still emit
    ``corpus_status: complete_for_declared_universe`` with an empty
    ``matches`` list -- byte-for-byte indistinguishable from a genuinely
    empty corpus, while the two real materialized shelves sat untouched on
    disk. The fix must fail closed instead: exit non-zero, and never print a
    report claiming any coverage status.
    """
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    _materialize(tmp_path, {"a.py": b"needle = 1\n"}, repo="alpha", commit=SHA_A)
    _materialize(tmp_path, {"b.py": b"needle = 2\n"}, repo="beta", commit=SHA_B)

    # Sanity: confirm the search finds both shelves honestly before corrupting
    # anything, exactly as the adversarial reviewer's repro did.
    code, payload, _err = _run(
        ["search", "--corpus", "--must", "exact_text:needle", "--root", str(tmp_path)]
    )
    assert code == ExitCode.SUCCESS
    assert {m["source"]["path"] for m in payload["matches"]} == {"a.py", "b.py"}
    assert payload["corpus_status"] == "complete_for_declared_universe"

    # Corrupt the catalog in place -- garbage bytes, not valid JSON.
    (tmp_path / "sources.json").write_bytes(b"{not valid json at all")

    out_before = (tmp_path / "sources.json").exists()
    assert out_before

    code, payload, err = _run(
        ["search", "--corpus", "--must", "exact_text:needle", "--root", str(tmp_path)]
    )

    assert code == ExitCode.CORPUS_FAILURE
    # No report at all -- in particular, no vacuous "complete" claim over an
    # empty-looking universe while real shelves sit untouched on disk.
    assert payload == {}
    assert "corpus_status" not in err
    assert "complete_for_declared_universe" not in err
    assert err.strip() != ""


def test_corpus_search_unreadable_catalog_fails_closed(tmp_path, monkeypatch):
    """A permission-denied catalog must fail closed the same way corruption does."""
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    _materialize(tmp_path, {"a.py": b"needle = 1\n"}, repo="alpha", commit=SHA_A)

    catalog = tmp_path / "sources.json"
    original_mode = catalog.stat().st_mode
    catalog.chmod(0o000)
    try:
        if os.access(catalog, os.R_OK):
            pytest.skip("running as a user that bypasses file permissions (e.g. root)")

        code, payload, err = _run(
            ["search", "--corpus", "--must", "exact_text:needle", "--root", str(tmp_path)]
        )

        assert code == ExitCode.CORPUS_FAILURE
        assert payload == {}
        assert "complete_for_declared_universe" not in err
    finally:
        if catalog.exists():
            catalog.chmod(original_mode)


@pytest.mark.parametrize("seed", ["0", "1", "42", "1337"])
def test_corpus_search_deterministic_across_hash_seeds(tmp_path, seed):
    _materialize(tmp_path, {"a.py": b"needle = 1\n", "z.py": b"needle = 2\n"}, repo="alpha", commit=SHA_A)
    _materialize(tmp_path, {"b.py": b"needle = 3\n"}, repo="beta", commit=SHA_B)
    _materialize(
        tmp_path, {"drift.py": b"needle = 4\n"}, repo="drift", commit=SHA_C, parity="drift"
    )

    script = (
        "import sys; sys.path.insert(0, 'src')\n"
        "import leitir.index.query as q\n"
        "q._utc_now = lambda: '2026-08-11T00:00:00Z'\n"
        "from leitir.cli import main\n"
        "import io\n"
        "out = io.StringIO(); err = io.StringIO()\n"
        f"code = main(['search', '--corpus', '--must', 'exact_text:needle', '--root', {str(tmp_path)!r}], stdout=out, stderr=err)\n"
        "sys.stdout.write(out.getvalue())\n"
    )

    def run(hash_seed: str) -> bytes:
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = hash_seed
        environment["PYTHONPATH"] = "src"
        environment["LEITIR_UPDATE_CHECK"] = "0"
        return subprocess.check_output([sys.executable, "-c", script], env=environment)

    assert run(seed) == run("0")
