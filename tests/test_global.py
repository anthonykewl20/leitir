"""Unit tests for the global discovery searcher (ADR-001 P5)."""

from __future__ import annotations

import pytest

from leitir.adapters import PythonAdapter
from leitir.discovery_search import (
    CodeSearchHit,
    CodeSearchPage,
    GlobalSearcher,
    build_query,
)
from leitir.search import (
    CoverageStatus,
    Predicate,
    PredicateKind,
    SearchMode,
    SearchSpec,
)
from leitir.tree import BlobEntry

SHA = "a" * 40
BLOB = "b" * 40

CONTENT = """\
def urlencode(query, doseq=False):
    if doseq:
        for k, v in query:
            pass
    return query
"""


class FakeCodeSearch:
    def __init__(self, page: CodeSearchPage | None = None, error: Exception | None = None):
        self.page = page or CodeSearchPage(hits=(), total_count=0, incomplete_results=False)
        self.error = error
        self.queries: list[str] = []

    def search(self, query: str, *, per_page: int = 10, page: int = 1) -> CodeSearchPage:
        self.queries.append(query)
        if self.error:
            raise self.error
        return self.page


class FakeTree:
    def __init__(self, content: bytes = b""):
        self._content = content

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        return ()

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        return self._content


def _hit(**overrides) -> CodeSearchHit:
    base = dict(slug="python/cpython", path="Lib/urllib/parse.py", blob_sha=BLOB, html_url="https://github.com/python/cpython/blob/main/Lib/urllib/parse.py")
    base.update(overrides)
    return CodeSearchHit(**base)


def _spec(**overrides) -> SearchSpec:
    base = dict(
        mode=SearchMode.GLOBAL_DISCOVERY,
        must=(Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),),
    )
    base.update(overrides)
    return SearchSpec(**base)


def _searcher(page=None, content=None, error=None):
    cs = FakeCodeSearch(page=page, error=error)
    tree = FakeTree(content=content or CONTENT.encode())
    searcher = GlobalSearcher(
        code_search=cs,
        tree_source=tree,
        adapters=(PythonAdapter(),),
        head_resolver=lambda slug: SHA,
        blob_reader=lambda slug, sha, path: content or CONTENT.encode(),
    )
    return searcher, cs


class TestBuildQuery:
    def test_identifier_becomes_plain_term(self):
        spec = _spec(must=(Predicate(PredicateKind.IDENTIFIER, "urlencode"),))
        assert build_query(spec) == "urlencode"

    def test_path_predicate_uses_qualifier(self):
        spec = _spec(must=(Predicate(PredicateKind.PATH, "Lib/urllib"),))
        assert "path:Lib/urllib" in build_query(spec)

    def test_language_appended(self):
        spec = _spec(must=(Predicate(PredicateKind.IDENTIFIER, "foo", "python"),))
        assert "language:python" in build_query(spec)

    def test_multiple_must_terms_joined(self):
        spec = _spec(must=(
            Predicate(PredicateKind.IDENTIFIER, "urlencode"),
            Predicate(PredicateKind.IDENTIFIER, "doseq"),
        ))
        q = build_query(spec)
        assert "urlencode" in q
        assert "doseq" in q


class TestGlobalSearcher:
    def test_coverage_is_always_indeterminate_global(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert report.coverage.status is CoverageStatus.INDETERMINATE_GLOBAL

    def test_finds_matching_spans(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert len(report.matches) > 0
        assert report.matches[0].source.slug == "python/cpython"
        assert report.matches[0].source.path == "Lib/urllib/parse.py"

    def test_provenance_carries_resolved_head_sha(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert report.matches[0].source.commit_sha == SHA

    def test_blob_sha_from_search_hit(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert report.matches[0].source.blob_sha == BLOB

    def test_no_hits_yields_empty_report(self):
        searcher, _ = _searcher()
        report = searcher.search(_spec())
        assert len(report.matches) == 0
        assert report.coverage.status is CoverageStatus.INDETERMINATE_GLOBAL

    def test_incomplete_results_threaded(self):
        page = CodeSearchPage(hits=(), total_count=100, incomplete_results=True)
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert report.coverage.incomplete_results is True

    def test_total_count_in_coverage(self):
        page = CodeSearchPage(hits=(), total_count=42, incomplete_results=False)
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert report.coverage.files_eligible == 42

    def test_scoped_exhaustive_rejected(self):
        searcher, _ = _searcher()
        from leitir.search import RepoScope

        spec = SearchSpec(
            mode=SearchMode.SCOPED_EXHAUSTIVE,
            must=(Predicate(PredicateKind.IDENTIFIER, "x"),),
            scopes=(RepoScope("o/r", SHA),),
        )
        with pytest.raises(ValueError, match="global_discovery"):
            searcher.search(spec)

    def test_must_not_excludes_matches(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        searcher, _ = _searcher(page=page)
        spec = _spec(must_not=(Predicate(PredicateKind.IDENTIFIER, "urlencode"),))
        report = searcher.search(spec)
        assert len(report.matches) == 0

    def test_search_error_propagates(self):
        searcher, _ = _searcher(error=RuntimeError("api down"))
        with pytest.raises(RuntimeError, match="api down"):
            searcher.search(_spec())

    def test_non_python_file_skipped(self):
        page = CodeSearchPage(
            hits=(_hit(path="README.md", blob_sha=BLOB),),
            total_count=1,
            incomplete_results=False,
        )
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert len(report.matches) == 0

    def test_head_resolution_failure_skips_hit(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        cs = FakeCodeSearch(page=page)
        tree = FakeTree()

        def bad_head(slug):
            raise RuntimeError("no head")

        searcher = GlobalSearcher(
            code_search=cs,
            tree_source=tree,
            adapters=(PythonAdapter(),),
            head_resolver=bad_head,
        )
        report = searcher.search(_spec())
        assert len(report.matches) == 0


class TestCodeSearchHit:
    def test_invalid_blob_sha_rejected(self):
        with pytest.raises(ValueError):
            CodeSearchHit(slug="o/r", path="f.py", blob_sha="short", html_url="")

    def test_invalid_slug_rejected(self):
        with pytest.raises(ValueError):
            CodeSearchHit(slug="noslash", path="f.py", blob_sha=BLOB, html_url="")

    def test_empty_path_rejected(self):
        with pytest.raises(ValueError):
            CodeSearchHit(slug="o/r", path="", blob_sha=BLOB, html_url="")
