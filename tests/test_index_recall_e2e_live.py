"""Opt-in live canary surface: index vs exhaustive-scan recall (#197 C-5).

Skipped unless LEITIR_ENABLE_LIVE_E2E=1. Materializes a bounded, pinned
corpus of real blobs fetched live from python/cpython@deaf509e… (v3.11.0;
the same pin as tests/fixtures_real.py), builds the local trigram index over
it, runs one query through both the indexed path and the exhaustive scan
path, and asserts FULL SourceRef identity equality — recall must be exactly
100% and neither path may invent or drop a match. Identity comparison uses
the workflow's ``LIVE_CANARY_SOURCE_IDENTITY_FIELDS`` (default
slug,commit_sha,path,blob_sha,start_line,end_line — equality means the
complete SourceRef identity, not paths or counts alone).

Corpus rule (deterministic, PYTHONHASHSEED-independent): every ``.py`` file
directly under ``Lib/urllib/`` and ``Lib/http/`` at the pinned commit,
sorted by path, capped at 40 files. Bounded so the daily canary stays cheap;
large enough that multiple files match the query (Lib/urllib/parse.py and
Lib/urllib/request.py both contain ``urlencode``).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from leitir.adapters import PythonAdapter
from leitir.corpus import write_sources
from leitir.engine import ScopedSearcher
from leitir.index import IndexedSearcher, ShelfRef, build_shelf_index
from leitir.search import Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
from leitir.tree import BlobEntry, GitHubTreeSource
from leitir.treehash import TREE_HASH_ALGORITHM, compute_materialized_tree_hash

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
        reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub verification",
    ),
]

FIXTURE_REPO = os.environ.get("LIVE_CANARY_FIXTURE_REPO", "python/cpython")
FIXTURE_COMMIT = os.environ.get(
    "LIVE_CANARY_FIXTURE_COMMIT", "deaf509e8fc6e0363bd6f26d52ad42f976ec42f2"
)
# Known pin (tests/fixtures_real.py, GitHub-verified): Lib/urllib/parse.py.
KNOWN_PATH = "Lib/urllib/parse.py"
KNOWN_BLOB_SHA = "d70a6943f0a73924ae56187db691792aa1f3ffc5"
CORPUS_DIRECTORIES = ("Lib/urllib", "Lib/http")
CORPUS_FILE_CAP = 40
QUERY = "urlencode"

_IDENTITY_FIELDS = tuple(
    field.strip()
    for field in os.environ.get(
        "LIVE_CANARY_SOURCE_IDENTITY_FIELDS",
        "slug,commit_sha,path,blob_sha,start_line,end_line",
    ).split(",")
    if field.strip()
)
_COMPARE_FULL_IDENTITY = os.environ.get(
    "LIVE_CANARY_COMPARE_FULL_SOURCE_IDENTITY", "true"
) == "true"


def _token() -> str | None:
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")


class LiveFetchedTree:
    """TreeSource over the live-fetched corpus (the scan-side universe)."""

    def __init__(self, slug: str, entries: dict[str, tuple[str, int, bytes]]) -> None:
        self._slug = slug
        self._entries = entries

    def list_blobs_ex(
        self, slug: str, commit_sha: str
    ) -> tuple[tuple[BlobEntry, ...], bool]:
        return self.list_blobs(slug, commit_sha), False

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        return tuple(
            BlobEntry(path, data[0], data[1])
            for path, data in sorted(self._entries.items())
        )

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        for data in self._entries.values():
            if data[0] == blob_sha:
                return data[2]
        raise KeyError(blob_sha)

    def read_blob_stream(self, slug: str, blob_sha: str):
        yield self.read_blob(slug, blob_sha)


def _fetch_corpus(source: GitHubTreeSource) -> dict[str, tuple[str, int, bytes]]:
    listing, _recovered = source.list_blobs_ex(FIXTURE_REPO, FIXTURE_COMMIT)
    assert _recovered is False, "cpython listing must not be truncated"
    by_path = {entry.path: entry.blob_sha for entry in listing}
    selected = sorted(
        path
        for path in by_path
        for directory in CORPUS_DIRECTORIES
        if path.startswith(directory + "/")
        and "/" not in path[len(directory) + 1 :]
        and path.endswith(".py")
    )
    assert len(selected) >= 5, "corpus selection unexpectedly small; fixture drifted"
    corpus: dict[str, tuple[str, int, bytes]] = {}
    for path in selected[:CORPUS_FILE_CAP]:
        data = source.read_blob(FIXTURE_REPO, by_path[path])
        corpus[path] = (by_path[path], len(data), data)
    return corpus


def _materialize(root: Path, corpus: dict[str, tuple[str, int, bytes]]) -> ShelfRef:
    owner, repo = FIXTURE_REPO.split("/", 1)
    target = root / "repos" / "github.com" / owner / repo / FIXTURE_COMMIT
    target.mkdir(parents=True)
    for relative, (_sha, _size, data) in sorted(corpus.items()):
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    tree_hash, scope = compute_materialized_tree_hash(target)
    manifest = {
        "commit_sha": FIXTURE_COMMIT,
        # Schema-canonical fetch_method for a github.com shelf (the corpus
        # bytes were fetched through the git blobs API in-test; the manifest
        # must carry the host-canonical value to pass load-time verification,
        # mirroring the fixture convention in tests/test_trigram_index.py).
        "fetch_method": "codeload-tarball",
        "fetched_at": "2026-08-20T00:00:00Z",
        "host": "github.com",
        "materialized_tree_hash": tree_hash,
        "materialized_tree_hash_algorithm": TREE_HASH_ALGORITHM,
        "materialized_tree_hash_scope": scope,
        "owner": owner,
        "parity": "exact",
        "repo": repo,
        "repo_url": f"https://github.com/{owner}/{repo}",
        "source": "git-commit",
        "spec": f"{owner}/{repo}@{FIXTURE_COMMIT}",
        "verified": False,
    }
    (target / "leitir-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    write_sources(
        root,
        [
            {
                "commit_sha": FIXTURE_COMMIT,
                "fetched_at": "1970-01-01T00:00:00Z",
                "host": "github.com",
                "name": f"{owner}/{repo}",
                "owner": owner,
                "path": f"repos/github.com/{owner}/{repo}/{FIXTURE_COMMIT}",
                "repo": repo,
            }
        ],
    )
    return ShelfRef("github.com", owner, repo, FIXTURE_COMMIT)


def _identity(source: object) -> tuple[object, ...]:
    return tuple(getattr(source, field) for field in _IDENTITY_FIELDS)


def test_index_recall_equals_exhaustive_scan_on_full_source_identity(
    tmp_path: Path,
) -> None:
    source = GitHubTreeSource(token=_token())
    corpus = _fetch_corpus(source)
    assert KNOWN_PATH in corpus, "pinned known match must be inside the corpus"
    assert hashlib.sha1(
        b"blob %d\x00" % len(corpus[KNOWN_PATH][2]) + corpus[KNOWN_PATH][2]  # noqa: UP031
    ).hexdigest() == KNOWN_BLOB_SHA, "known pin drifted"

    shelf = _materialize(tmp_path, corpus)
    build_shelf_index(tmp_path, shelf)

    adapters = (PythonAdapter(),)
    scan_searcher = ScopedSearcher(LiveFetchedTree(FIXTURE_REPO, corpus), adapters)
    indexed_searcher = IndexedSearcher(
        tmp_path, scan_searcher, adapters, require_index=True
    )
    spec = SearchSpec(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(PredicateKind.EXACT_TEXT, QUERY),),
        scopes=(RepoScope(FIXTURE_REPO, FIXTURE_COMMIT),),
    )

    scan_report = scan_searcher.search(spec)
    index_report = indexed_searcher.search(spec)

    scan_ids = sorted(_identity(match.source) for match in scan_report.matches)
    index_ids = sorted(_identity(match.source) for match in index_report.matches)

    assert scan_ids, "exhaustive scan must find the known query"
    matching_paths = {identity[2] for identity in scan_ids}  # path field
    assert KNOWN_PATH in matching_paths
    assert len(matching_paths) >= 2, "corpus must keep multiple matching files"

    if _COMPARE_FULL_IDENTITY:
        assert _IDENTITY_FIELDS == (
            "slug",
            "commit_sha",
            "path",
            "blob_sha",
            "start_line",
            "end_line",
        )
        assert index_ids == scan_ids, (
            "indexed search must reproduce the exhaustive scan's complete "
            "SourceRef identities"
        )
    else:  # pragma: no cover - workflow always sets full identity
        assert set(index_ids) >= set(scan_ids)

    recall = len(set(scan_ids) & set(index_ids)) / len(set(scan_ids))
    assert recall == 1.0, f"index recall regressed: {recall}"
    assert index_report.coverage.files_eligible == scan_report.coverage.files_eligible
    print(
        f"index-vs-scan-recall surface: corpus_files={len(corpus)} "
        f"matches={len(scan_ids)} matching_paths={sorted(matching_paths)} "
        f"recall={recall}"
    )
