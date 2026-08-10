"""Small, deterministic, network-free benchmarks of Leitir hot paths."""

from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

# Existing-environment ASV runs do not install Leitir. Import the checkout under
# test directly; this also keeps benchmark setup offline and dependency-free.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from leitir.adapters import PythonAdapter
from leitir.engine import ScopedSearcher
from leitir.ranking import rank_matches
from leitir.search import (
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchSpec,
    SourceMatch,
    SourceRef,
)
from leitir.tree import BlobEntry
from leitir.treehash import compute_materialized_tree_hash
from leitir.trust import compute_trust

_COMMIT = "a" * 40


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


class _MemoryTree:
    def __init__(self, files: tuple[tuple[str, bytes], ...]) -> None:
        self._files = tuple(
            (BlobEntry(path, _git_blob_sha(content), len(content)), content)
            for path, content in files
        )
        self._content = {entry.blob_sha: content for entry, content in self._files}

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        del slug, commit_sha
        return tuple(entry for entry, _content in self._files)

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        del slug
        return self._content[blob_sha]


class TimeScopedSearch:
    repeat = 8
    number = 1
    version = "scoped-search-v1"

    def setup(self) -> None:
        files = tuple(
            (
                f"pkg/module_{index:02d}.py",
                (
                    "from collections import defaultdict\n\n"
                    f"def encode_value_{index}(value):\n"
                    "    exact_marker = 'stable search phrase'\n"
                    "    return defaultdict(list), value, exact_marker\n"
                ).encode(),
            )
            for index in range(24)
        )
        self.searcher = ScopedSearcher(_MemoryTree(files), (PythonAdapter(),))
        scope = (RepoScope("example/corpus", _COMMIT),)
        self.identifier = SearchSpec(
            SearchMode.SCOPED_EXHAUSTIVE,
            must=(Predicate(PredicateKind.IDENTIFIER, "defaultdict"),),
            scopes=scope,
        )
        self.exact_text = SearchSpec(
            SearchMode.SCOPED_EXHAUSTIVE,
            must=(Predicate(PredicateKind.EXACT_TEXT, "stable search phrase"),),
            scopes=scope,
        )
        self.symbol_definition = SearchSpec(
            SearchMode.SCOPED_EXHAUSTIVE,
            must=(Predicate(PredicateKind.SYMBOL_DEFINITION, "encode_value_12"),),
            scopes=scope,
        )

    def time_identifier_query(self) -> None:
        self.searcher.search(self.identifier)

    def time_exact_text_query(self) -> None:
        self.searcher.search(self.exact_text)

    def time_symbol_definition_query(self) -> None:
        self.searcher.search(self.symbol_definition)


class TimeRanking:
    repeat = 8
    number = 1
    version = "ranking-total-order-v1"

    def setup(self) -> None:
        self.matches = tuple(
            SourceMatch(
                source=SourceRef(
                    slug=f"example/repo-{index % 5}",
                    commit_sha=f"{index % 16:x}" * 40,
                    path=f"pkg/module_{127 - index:03d}.py",
                    blob_sha=hashlib.sha1(f"blob-{index}".encode()).hexdigest(),
                    start_line=index + 1,
                    end_line=index + 1,
                ),
                score=float(index % 11),
                matched_kinds=(PredicateKind.IDENTIFIER,),
            )
            for index in range(128)
        )

    def time_rank_matches_total_order(self) -> None:
        rank_matches(self.matches)


class TimeTrust:
    repeat = 8
    number = 1
    version = "trust-scoring-v1"

    def setup(self) -> None:
        self.target = Path(tempfile.mkdtemp(prefix="leitir-asv-trust-"))
        self.manifest = {
            "verified": True,
            "parity": "exact",
            "license_confidence": "high",
            "license_method": "manifest",
            "docs_urls": ["https://invalid.example/docs"],
            "entry_points": ["leitir"],
            "has_tests": True,
            "artifact_checksum": "sha256:" + "b" * 64,
            "artifact_kind": "sdist",
            "published_at": "2025-01-01T00:00:00+00:00",
            "fetched_at": "2025-06-01T00:00:00+00:00",
        }

    def teardown(self) -> None:
        shutil.rmtree(self.target)

    def time_compute_trust(self) -> None:
        for _ in range(100):
            compute_trust(self.manifest, self.target)


class TimeTreeHash:
    repeat = 8
    number = 1
    version = "treehash-small-tree-v1"

    def setup(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="leitir-asv-treehash-"))
        for index in range(32):
            path = self.root / f"pkg/module_{index:02d}.py"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((f"value_{index} = {index}\n" * 16).encode("utf-8"))

    def teardown(self) -> None:
        shutil.rmtree(self.root)

    def time_compute_materialized_tree_hash(self) -> None:
        compute_materialized_tree_hash(self.root)
