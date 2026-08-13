"""Intent tests for fail-closed predicate-language routing (S2b #89)."""

from __future__ import annotations

import hashlib

import pytest

from leitir.adapters import PythonAdapter, RustAdapter
from leitir.adapters._tier2 import JavaScriptAdapter
from leitir.discovery_search import CodeSearchHit, CodeSearchPage, GlobalSearcher
from leitir.engine import ScopedSearcher
from leitir.search import (
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchSpec,
    SearchSpecError,
)
from leitir.tree import BlobEntry

SHA = "a" * 40


def _blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(content) + content).hexdigest()


class RecordingTree:
    def __init__(self, files: tuple[tuple[str, bytes], ...]) -> None:
        self._files = tuple(sorted(files))
        self.list_calls = 0
        self.read_calls: list[str] = []

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        self.list_calls += 1
        return tuple(
            BlobEntry(path, _blob_sha(content), len(content))
            for path, content in self._files
        )

    def list_blobs_ex(
        self, slug: str, commit_sha: str
    ) -> tuple[tuple[BlobEntry, ...], bool]:
        return self.list_blobs(slug, commit_sha), False

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        self.read_calls.append(blob_sha)
        return next(
            content
            for _path, content in self._files
            if _blob_sha(content) == blob_sha
        )


class RecordingCodeSearch:
    def __init__(self, blob_sha: str) -> None:
        self._blob_sha = blob_sha

    def search(
        self, query: str, *, per_page: int = 10, page: int = 1
    ) -> CodeSearchPage:
        hit = CodeSearchHit(
            slug="owner/repo",
            path="src/lib.rs",
            blob_sha=self._blob_sha,
            html_url=f"https://github.com/owner/repo/blob/{SHA}/src/lib.rs",
            commit_sha=SHA,
        )
        return CodeSearchPage(hits=(hit,), total_count=1, incomplete_results=False)


def _scopes(mode: SearchMode) -> tuple[RepoScope, ...]:
    if mode is SearchMode.SCOPED_EXHAUSTIVE:
        return (RepoScope("owner/repo", SHA),)
    return ()


def _scoped_spec(language: str) -> SearchSpec:
    return SearchSpec(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(PredicateKind.IDENTIFIER, "target", language),),
        scopes=_scopes(SearchMode.SCOPED_EXHAUSTIVE),
    )


@pytest.mark.parametrize("mode", tuple(SearchMode))
def test_spec_rejects_conflicting_canonical_must_languages(
    mode: SearchMode,
) -> None:
    with pytest.raises(
        SearchSpecError, match="conflicting required predicate languages"
    ):
        SearchSpec(
            mode=mode,
            must=(
                Predicate(PredicateKind.IDENTIFIER, "first", "js"),
                Predicate(PredicateKind.IDENTIFIER, "second", "python"),
            ),
            scopes=_scopes(mode),
        )


@pytest.mark.parametrize("mode", tuple(SearchMode))
def test_spec_accepts_alias_equivalent_must_languages(mode: SearchMode) -> None:
    spec = SearchSpec(
        mode=mode,
        must=(
            Predicate(PredicateKind.IDENTIFIER, "first", "js"),
            Predicate(PredicateKind.IDENTIFIER, "second", "javascript"),
        ),
        scopes=_scopes(mode),
    )

    assert tuple(predicate.language for predicate in spec.must) == (
        "js",
        "javascript",
    )


def test_unsupported_language_rejects_before_scanning() -> None:
    tree = RecordingTree((("src/main.py", b"target = True\n"),))
    searcher = ScopedSearcher(tree, (PythonAdapter(), RustAdapter()))

    with pytest.raises(
        SearchSpecError, match="unsupported required predicate language"
    ):
        searcher.search(_scoped_spec("brainfuck"))

    assert tree.list_calls == 0
    assert tree.read_calls == []


def test_tampered_predicate_language_cannot_authorize_rust_path() -> None:
    rust = b"fn target() {}\n"
    tree = RecordingTree((("src/lib.rs", rust),))
    predicate = Predicate(PredicateKind.IDENTIFIER, "target", "rust")
    spec = SearchSpec(
        mode=SearchMode.SCOPED_EXHAUSTIVE,
        must=(predicate,),
        scopes=_scopes(SearchMode.SCOPED_EXHAUSTIVE),
    )
    object.__setattr__(predicate, "language", "python")

    report = ScopedSearcher(tree, (PythonAdapter(), RustAdapter())).search(spec)

    assert report.matches == ()
    assert report.coverage.files_eligible == 0
    assert report.coverage.files_indexed == 0
    assert tree.read_calls == []


def test_tampered_adapter_language_cannot_authorize_rust_path() -> None:
    class SpoofedRustAdapter(RustAdapter):
        @property
        def language(self) -> str:
            return "python"

    rust = b"fn target() {}\n"
    tree = RecordingTree((("src/lib.rs", rust),))

    report = ScopedSearcher(
        tree, (PythonAdapter(), SpoofedRustAdapter())
    ).search(_scoped_spec("python"))

    assert report.matches == ()
    assert report.coverage.files_eligible == 0
    assert report.coverage.files_indexed == 0
    assert tree.read_calls == []


def test_global_tampered_adapter_language_cannot_authorize_rust_path() -> None:
    class SpoofedRustAdapter(RustAdapter):
        @property
        def language(self) -> str:
            return "python"

    rust = b"fn target() {}\n"
    blob_reads: list[tuple[str, str, str]] = []

    def read_blob(slug: str, commit_sha: str, path: str) -> bytes:
        blob_reads.append((slug, commit_sha, path))
        return rust

    report = GlobalSearcher(
        RecordingCodeSearch(_blob_sha(rust)),
        RecordingTree((("src/lib.rs", rust),)),
        (PythonAdapter(), SpoofedRustAdapter()),
        blob_reader=read_blob,
    ).search(
        SearchSpec(
            mode=SearchMode.GLOBAL_DISCOVERY,
            must=(Predicate(PredicateKind.IDENTIFIER, "target", "python"),),
        )
    )

    assert report.matches == ()
    assert report.coverage.files_indexed == 0
    assert report.coverage.exclusions == {"no_adapter": 1}
    assert blob_reads == []


def test_global_tampered_predicate_language_rejects_before_blob_read() -> None:
    rust = b"fn target() {}\n"
    tree = RecordingTree((("src/lib.rs", rust),))
    predicate = Predicate(PredicateKind.IDENTIFIER, "target", "rust")
    spec = SearchSpec(mode=SearchMode.GLOBAL_DISCOVERY, must=(predicate,))
    object.__setattr__(predicate, "language", "python")
    blob_reads: list[tuple[str, str, str]] = []

    def read_blob(slug: str, commit_sha: str, path: str) -> bytes:
        blob_reads.append((slug, commit_sha, path))
        return rust

    report = GlobalSearcher(
        RecordingCodeSearch(_blob_sha(rust)),
        tree,
        (PythonAdapter(), RustAdapter()),
        blob_reader=read_blob,
    ).search(spec)

    assert report.matches == ()
    assert report.coverage.files_indexed == 0
    assert report.coverage.exclusions == {"no_adapter": 1}
    assert blob_reads == []


def test_required_language_shrinks_coverage_eligible_universe() -> None:
    python = b"target = True\n"
    javascript = b"const target = true;\n"
    tree = RecordingTree(
        tuple(
            sorted(
                (
                    ("src/main.js", javascript),
                    ("src/main.py", python),
                )
            )
        )
    )

    report = ScopedSearcher(
        tree, (PythonAdapter(), JavaScriptAdapter())
    ).search(_scoped_spec("python"))

    assert report.coverage.files_eligible == 1
    assert report.coverage.files_indexed == 1
    assert report.coverage.files_excluded == 0
    assert tuple(match.source.path for match in report.matches) == ("src/main.py",)
    assert tree.read_calls == [_blob_sha(python)]
