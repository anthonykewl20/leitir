"""User-level intent tests pinning the `leitir search` VerificationError exit
code contract across scopes (issue #266 B1 follow-up).

A ``VerificationError`` handler at ``src/leitir/cli.py`` was added inside
``leitir search``'s dispatch. It was intended only for the corrupt-catalog
case on ``--corpus`` (a corrupt or unreadable ``leitir-sources.json`` raises
``VerificationError`` from ``corpus.py``/``index/builder.py`` before any
shelf is even considered). In fact the surrounding ``try`` block spans all
three of the command's execution branches (``--corpus``, ``--global``, and
the scoped ``--repo``/``--package`` branch), so a ``VerificationError`` raised
from ANY of them is caught by the same handler and exits
``ExitCode.CORPUS_FAILURE`` (1) rather than the generic
``ExitCode.INFRASTRUCTURE_FAILURE`` (3).

This is being kept deliberately: a tree-verification failure is a corpus
integrity problem, not incidental infrastructure flakiness, and having
``--corpus`` exit 1 for that failure class while ``--repo``/``--package``
exited 3 for the identical failure would be a worse, inconsistent contract.
The point of this module is to pin the now-uniform behavior with real
triggers so it cannot regress silently again.

Scope-by-scope reachability, verified directly against the engine rather
than assumed:

* ``--repo`` and ``--package`` (this module): both ultimately build a
  ``ScopedSearcher`` (``leitir.engine.ScopedSearcher``) directly -- with no
  intermediate per-shelf ``except VerificationError`` handler the way
  ``CorpusSearcher`` has for ``--corpus``. When a local shelf's on-disk
  bytes are altered *after* ``leitir.materialize.read_valid_manifest``
  validates the manifest against the (at that instant) genuine bytes, the
  later local-blob read in ``leitir.engine._LocalShelfReader`` detects the
  mismatch and raises ``VerificationError`` directly into
  ``leitir search``'s dispatcher. That is the same
  read-validate-then-tamper race already exercised by
  ``tests/test_engine.py::TestLocalShelfIntegration::test_tampered_local_blob_fails_without_api_fallback``,
  reused here at the CLI/exit-code level instead of the engine level.

* ``--global`` (NOT exercised here -- confirmed unreachable): ``leitir
  search --global`` is served by ``leitir.discovery_search.GlobalSearcher``,
  which is constructed straight from a ``CodeSearchPort`` and a
  GitHub-backed ``TreeSource`` (see ``_build_default_global_searcher`` /
  ``global_searcher_factory`` in ``src/leitir/cli.py``). It never touches
  ``corpus_root``, ``leitir.materialize.read_valid_manifest``, or
  ``leitir.engine._LocalShelfReader`` -- there is no local-shelf
  materialized-tree-hash verification anywhere on the global-discovery
  path, so ``VerificationError`` cannot be raised by a normal
  ``--global`` search. Forcing one would require monkeypatching internals
  that a real caller can never reach, which is exactly the "fabricated
  trigger" this suite is told not to write. No test for ``--global`` is
  included.

Why a shelf must be forced into the "sampled" tree-hash scope: with the
default sampling thresholds a two-file test fixture is always hashed under
the "full" scope, and a "full"-scope shelf is enumerated entirely from the
local manifest (``_LocalShelfReader.list_local_blobs``) without ever
consulting a declared blob listing to detect a size/digest mismatch against.
Patching ``leitir.treehash.MAX_FILES`` down to 1 for the duration of the test
forces the "sampled" scope, so ``ScopedSearcher`` instead trusts an
externally supplied blob listing (the fake tree source below, standing in
for a `git` tree listing) for enumeration and reads bytes straight off disk
to check them against it -- exactly the code path that raises
``VerificationError`` on a mismatch.
"""

from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

from leitir.cli import ExitCode, main
from leitir.materialize import manifest_digest_fields, target_path
from leitir.materialize import read_valid_manifest as _real_read_valid_manifest
from leitir.resolver import ResolvedPackage
from leitir.search import RepoScope
from leitir.tree import BlobEntry
from leitir.treehash import compute_materialized_tree_hash

SHA = "a" * 40
OWNER = "example"
REPO = "widget"
PY_SOURCE = b"identifier_urlencode = 1\n"
COMPANION = b"a second file so the shelf is not a single-file tree\n"


def _blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


class _DeclaredTreeSource:
    """Stands in for a genuine `git` tree listing: the blob shas it reports
    reflect the shelf's bytes as they were at materialization time, before
    any later on-disk tampering."""

    def __init__(self, entries: tuple[BlobEntry, ...]) -> None:
        self._entries = entries

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        return self._entries

    def list_blobs_ex(
        self, slug: str, commit_sha: str
    ) -> tuple[tuple[BlobEntry, ...], bool]:
        return self._entries, False

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        raise AssertionError(
            "a fully local shelf must be read from disk, never over the network"
        )

    def read_blob_stream(self, slug: str, blob_sha: str) -> Iterator[bytes]:
        raise AssertionError(
            "a fully local shelf must be read from disk, never over the network"
        )


def _materialize_sampled_shelf(root: Path) -> tuple[Path, tuple[BlobEntry, ...]]:
    """Write a valid, verifiable "sampled"-scope shelf at ``root``.

    Caller must hold ``leitir.treehash.MAX_FILES`` patched down (e.g. to 1)
    for the whole test, both while this writes the manifest and while
    ``leitir search`` later re-verifies it -- the scope recorded in the
    manifest must match what a fresh ``compute_materialized_tree_hash`` call
    computes at read time, or verification fails for the wrong reason
    (a scope mismatch, not a tamper).
    """
    target = target_path(root, OWNER, REPO, SHA, host="github.com")
    target.mkdir(parents=True)
    (target / "a.py").write_bytes(PY_SOURCE)
    (target / "b.py").write_bytes(COMPANION)
    digest, scope = compute_materialized_tree_hash(target)
    assert scope == "sampled", "fixture must exercise the sampled-scope tamper path"
    manifest = {
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "fetched_at": "2026-01-01T00:00:00Z",
        "host": "github.com",
        "owner": OWNER,
        "repo": REPO,
        "repo_url": f"https://github.com/{OWNER}/{REPO}",
        "source": "git-commit",
        "spec": f"{OWNER}/{REPO}@{SHA}",
        "tag": None,
        "verified": True,
        "verified_at": "2026-01-01T00:00:00Z",
    }
    manifest.update(manifest_digest_fields(digest, scope=scope))
    (target / "leitir-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    entries = (
        BlobEntry("a.py", _blob_sha(PY_SOURCE), len(PY_SOURCE)),
        BlobEntry("b.py", _blob_sha(COMPANION), len(COMPANION)),
    )
    return target, entries


def _tamper_after_validation(target: Path):
    """Return a ``read_valid_manifest`` replacement that validates the
    manifest against genuine bytes (delegating to the real function) and
    only *then* corrupts a file on disk -- the same
    validate-then-tamper race ``tests/test_engine.py`` uses to prove
    ``VerificationError`` is raised by the later blob read, not by manifest
    validation itself."""

    def _patched(*args, **kwargs):
        manifest = _real_read_valid_manifest(*args, **kwargs)
        (target / "a.py").write_bytes(b"tampered\n")
        return manifest

    return _patched


def test_repo_scope_verification_failure_exits_corpus_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    monkeypatch.setattr("leitir.treehash.MAX_FILES", 1)
    target, entries = _materialize_sampled_shelf(tmp_path)

    out, err = io.StringIO(), io.StringIO()
    with mock.patch(
        "leitir.engine.read_valid_manifest", _tamper_after_validation(target)
    ):
        code = main(
            [
                "search",
                "--repo",
                f"{OWNER}/{REPO}",
                "--commit",
                SHA,
                "--root",
                str(tmp_path),
                "--must",
                "identifier:urlencode",
            ],
            tree_source_factory=lambda _token: _DeclaredTreeSource(entries),
            stdout=out,
            stderr=err,
        )

    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out.getvalue() == ""
    assert "local blob" in err.getvalue()


def test_package_scope_verification_failure_exits_corpus_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    monkeypatch.setattr("leitir.treehash.MAX_FILES", 1)
    target, entries = _materialize_sampled_shelf(tmp_path)

    class _FakeResolver:
        def resolve(self, ref: object) -> ResolvedPackage:
            return ResolvedPackage(
                ref=ref,
                scope=RepoScope(f"{OWNER}/{REPO}", SHA),
                tag="v1.0",
                registry_url="https://pypi.org/project/widget/1.0.0/",
            )

    out, err = io.StringIO(), io.StringIO()
    with mock.patch(
        "leitir.engine.read_valid_manifest", _tamper_after_validation(target)
    ):
        code = main(
            [
                "search",
                "--package",
                "widget",
                "--version",
                "1.0.0",
                "--ecosystem",
                "pypi",
                "--root",
                str(tmp_path),
                "--must",
                "identifier:urlencode",
            ],
            tree_source_factory=lambda _token: _DeclaredTreeSource(entries),
            resolver_factory=lambda _token: _FakeResolver(),
            stdout=out,
            stderr=err,
        )

    assert code == int(ExitCode.CORPUS_FAILURE)
    assert out.getvalue() == ""
    assert "local blob" in err.getvalue()
