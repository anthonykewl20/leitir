"""Unit tests for the global discovery searcher (ADR-001 P5)."""

from __future__ import annotations

import hashlib
from itertools import permutations

import pytest

from leitir.adapters import PythonAdapter
from leitir.discovery_search import (
    CodeSearchError,
    CodeSearchHit,
    CodeSearchPage,
    GlobalSearcher,
    _cross_checked_commit_sha,
    build_query,
    validate_report,
)
from leitir.search import (
    CoverageStatus,
    Predicate,
    PredicateKind,
    RepoScope,
    ResolutionStrategy,
    SearchMode,
    SearchSpec,
)
from leitir.tree import BlobEntry

SHA = "a" * 40

CONTENT = """\
def urlencode(query, doseq=False):
    if doseq:
        for k, v in query:
            pass
    return query
"""
CONTENT_BYTES = CONTENT.encode()
BLOB = hashlib.sha1(
    b"blob " + str(len(CONTENT_BYTES)).encode("ascii") + b"\x00" + CONTENT_BYTES
).hexdigest()


class FakeCodeSearch:
    def __init__(
        self,
        page: CodeSearchPage | None = None,
        error: Exception | None = None,
        pages: dict[int, CodeSearchPage] | None = None,
        page_errors: dict[int, Exception] | None = None,
    ):
        default = page or CodeSearchPage(hits=(), total_count=0, incomplete_results=False)
        self.pages = pages or {1: default}
        self.error = error
        self.page_errors = page_errors or {}
        self.queries: list[str] = []
        self.page_numbers: list[int] = []

    def search(self, query: str, *, per_page: int = 10, page: int = 1) -> CodeSearchPage:
        self.queries.append(query)
        self.page_numbers.append(page)
        if self.error:
            raise self.error
        if page in self.page_errors:
            raise self.page_errors[page]
        return self.pages.get(
            page, CodeSearchPage(hits=(), total_count=0, incomplete_results=False)
        )


class FakeTree:
    def __init__(self, content: bytes = b""):
        self._content = content

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        return ()

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        return self._content


def _hit(**overrides) -> CodeSearchHit:
    base = {
        "slug": "python/cpython",
        "path": "Lib/urllib/parse.py",
        "blob_sha": BLOB,
        "commit_sha": SHA,
        "html_url": (
            f"https://github.com/python/cpython/blob/{SHA}/Lib/urllib/parse.py"
        ),
    }
    base.update(overrides)
    return CodeSearchHit(**base)


def _spec(**overrides) -> SearchSpec:
    base = {
        "mode": SearchMode.GLOBAL_DISCOVERY,
        "must": (Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),),
    }
    base.update(overrides)
    return SearchSpec(**base)


def _searcher(page=None, content=None, error=None):
    cs = FakeCodeSearch(page=page, error=error)
    tree = FakeTree(content=content or CONTENT.encode())
    searcher = GlobalSearcher(
        code_search=cs,
        tree_source=tree,
        adapters=(PythonAdapter(),),
        blob_reader=lambda slug, sha, path: content or CONTENT.encode(),
        clock=lambda: "2026-08-06T12:00:00Z",
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

    def test_provenance_carries_indexed_commit_sha(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert report.matches[0].source.commit_sha == SHA
        assert report.resolution.strategy is ResolutionStrategy.INDEXED_COMMIT
        assert report.resolution.as_of == "2026-08-06T12:00:00Z"

    def test_blob_sha_from_search_hit(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert report.matches[0].source.blob_sha == BLOB

    def test_report_order_and_identity_are_hit_order_independent(self):
        low_content = b"def urlencode(query):\n    return query\n"
        low_blob = hashlib.sha1(
            b"blob "
            + str(len(low_content)).encode("ascii")
            + b"\x00"
            + low_content
        ).hexdigest()
        hits = (_hit(path="z.py"), _hit(path="a.py", blob_sha=low_blob))
        reports = []
        for permutation in permutations(hits):
            page = CodeSearchPage(
                hits=permutation, total_count=2, incomplete_results=False
            )
            searcher = GlobalSearcher(
                code_search=FakeCodeSearch(page=page),
                tree_source=FakeTree(),
                adapters=(PythonAdapter(),),
                blob_reader=lambda slug, sha, path: (
                    low_content if path == "a.py" else CONTENT_BYTES
                ),
                clock=lambda: "2026-08-06T12:00:00Z",
            )
            reports.append(
                searcher.search(
                    _spec(should=(Predicate(PredicateKind.IDENTIFIER, "doseq"),))
                )
            )

        expected = reports[0]
        assert [match.source.path for match in expected.matches] == ["z.py", "a.py"]
        for report in reports[1:]:
            assert report.matches == expected.matches
            assert report.to_dict() == expected.to_dict()
            assert report.to_json(indent=None).encode() == expected.to_json(
                indent=None
            ).encode()
            assert report.identity_digest() == expected.identity_digest()

    def test_duplicate_source_identity_is_rejected(self):
        page = CodeSearchPage(
            hits=(_hit(), _hit()), total_count=2, incomplete_results=False
        )
        searcher, _ = _searcher(page=page)
        with pytest.raises(ValueError, match="duplicate SourceRef"):
            searcher.search(_spec())

    def test_tampered_blob_is_rejected_and_counted(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        searcher, _ = _searcher(page=page, content=b"tampered")

        report = searcher.search(_spec())

        assert report.matches == ()
        assert report.coverage.files_indexed == 0
        assert report.coverage.files_excluded == 1
        assert report.coverage.exclusions == {"provenance_mismatch": 1}

    def test_fetch_failure_is_rejected_and_counted(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)

        def fail_fetch(slug, commit_sha, path):
            raise CodeSearchError("read failed")

        searcher = GlobalSearcher(
            code_search=FakeCodeSearch(page=page),
            tree_source=FakeTree(),
            adapters=(PythonAdapter(),),
            blob_reader=fail_fetch,
        )

        report = searcher.search(_spec())

        assert report.matches == ()
        assert report.coverage.files_indexed == 0
        assert report.coverage.files_excluded == 1
        assert report.coverage.exclusions == {"fetch_failed": 1}

    def test_unprovenanced_tree_fallback_fails_closed(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        tree = FakeTree(CONTENT_BYTES)
        searcher = GlobalSearcher(
            code_search=FakeCodeSearch(page=page),
            tree_source=tree,
            adapters=(PythonAdapter(),),
            blob_reader=None,
        )

        report = searcher.search(_spec())

        assert report.matches == ()
        assert report.coverage.exclusions == {"fetch_failed": 1}

    def test_verified_non_utf8_blob_is_decode_failed(self):
        binary = b"\xffdef urlencode():\n    pass\n"
        blob_sha = hashlib.sha1(
            b"blob " + str(len(binary)).encode("ascii") + b"\x00" + binary
        ).hexdigest()
        page = CodeSearchPage(
            hits=(_hit(blob_sha=blob_sha),), total_count=1, incomplete_results=False
        )
        searcher, _ = _searcher(page=page, content=binary)

        report = searcher.search(_spec())

        assert report.matches == ()
        assert report.coverage.exclusions == {"decode_failed": 1}

    def test_unexpected_blob_reader_error_propagates(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        searcher = GlobalSearcher(
            code_search=FakeCodeSearch(page=page),
            tree_source=FakeTree(),
            adapters=(PythonAdapter(),),
            blob_reader=lambda slug, sha, path: (_ for _ in ()).throw(
                TypeError("programming bug")
            ),
        )

        with pytest.raises(TypeError, match="programming bug"):
            searcher.search(_spec())

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
        assert report.coverage.exclusions == {"no_adapter": 1}

    def test_no_adapter_precedes_blob_io(self):
        page = CodeSearchPage(
            hits=(_hit(path="README.md"),), total_count=1, incomplete_results=False
        )

        def unexpected_call(*args):
            raise AssertionError("ineligible path performed network I/O")

        searcher = GlobalSearcher(
            code_search=FakeCodeSearch(page=page),
            tree_source=FakeTree(),
            adapters=(PythonAdapter(),),
            blob_reader=unexpected_call,
        )

        report = searcher.search(_spec())

        assert report.coverage.exclusions == {"no_adapter": 1}

    @pytest.mark.parametrize("malformed", ["main", "", "a" * 39, None])
    def test_malformed_index_pin_is_counted_as_unpinned(self, malformed):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        object.__setattr__(page.hits[0], "commit_sha", malformed)
        searcher = GlobalSearcher(
            code_search=FakeCodeSearch(page=page),
            tree_source=FakeTree(),
            adapters=(PythonAdapter(),),
            blob_reader=lambda slug, sha, path: CONTENT_BYTES,
        )

        report = searcher.search(_spec())

        assert report.coverage.exclusions == {"unpinned_hit": 1}

    def test_pin_disagreement_is_counted(self):
        other = "b" * 40
        page = CodeSearchPage(
            hits=(_hit(html_url=f"https://github.com/python/cpython/blob/{other}/x.py"),),
            total_count=1,
            incomplete_results=False,
        )
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert report.coverage.exclusions == {"pin_disagreement": 1}

    def test_missing_html_pin_is_counted_as_unpinned(self):
        page = CodeSearchPage(
            hits=(_hit(html_url="https://github.com/python/cpython/blob/main/x.py"),),
            total_count=1,
            incomplete_results=False,
        )
        report = _searcher(page=page)[0].search(_spec())
        assert report.coverage.exclusions == {"unpinned_hit": 1}

    def test_later_page_failure_returns_validated_partial_report(self):
        pages = {
            1: CodeSearchPage(
                hits=(_hit(), _hit(path="README.md")),
                total_count=4,
                incomplete_results=False,
            )
        }
        code_search = FakeCodeSearch(
            pages=pages, page_errors={2: CodeSearchError("rate limited")}
        )
        searcher = GlobalSearcher(
            code_search=code_search,
            tree_source=FakeTree(),
            adapters=(PythonAdapter(),),
            blob_reader=lambda slug, sha, path: CONTENT_BYTES,
            max_results=2,
        )

        report = searcher.search(_spec())

        assert code_search.page_numbers == [1, 2]
        assert report.coverage.files_indexed == 1
        assert report.coverage.incomplete_results is True
        assert report.coverage.exclusions == {"no_adapter": 1}

    def test_paginates_until_validated_target(self):
        pages = {
            1: CodeSearchPage(
                hits=(_hit(path="README.md"), _hit()),
                total_count=4,
                incomplete_results=False,
            ),
            2: CodeSearchPage(
                hits=(_hit(path="Lib/second.py"), _hit(path="Lib/third.py")),
                total_count=4,
                incomplete_results=False,
            ),
        }
        code_search = FakeCodeSearch(pages=pages)
        searcher = GlobalSearcher(
            code_search=code_search,
            tree_source=FakeTree(CONTENT_BYTES),
            adapters=(PythonAdapter(),),
            blob_reader=lambda slug, sha, path: CONTENT_BYTES,
            max_results=2,
        )

        report = searcher.search(_spec())

        assert code_search.page_numbers == [1, 2]
        assert report.coverage.files_indexed == 2
        assert report.coverage.exclusions == {"no_adapter": 1}

    def test_max_pages_cap_is_visible(self):
        page = CodeSearchPage(
            hits=(_hit(path="README.md"), _hit(path="docs/guide.md")),
            total_count=10,
            incomplete_results=False,
        )
        code_search = FakeCodeSearch(page=page)
        searcher = GlobalSearcher(
            code_search=code_search,
            tree_source=FakeTree(CONTENT_BYTES),
            adapters=(PythonAdapter(),),
            blob_reader=lambda slug, sha, path: CONTENT_BYTES,
            max_results=2,
            max_pages=1,
        )

        report = searcher.search(_spec())

        assert code_search.page_numbers == [1]
        assert report.coverage.files_indexed == 0
        assert report.coverage.files_excluded == 2
        assert report.coverage.incomplete_results is True

    def test_short_page_stops_as_exhausted(self):
        page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
        code_search = FakeCodeSearch(page=page)
        searcher = GlobalSearcher(
            code_search=code_search,
            tree_source=FakeTree(CONTENT_BYTES),
            adapters=(PythonAdapter(),),
            blob_reader=lambda slug, sha, path: CONTENT_BYTES,
            max_results=2,
        )

        report = searcher.search(_spec())

        assert code_search.page_numbers == [1]
        assert report.coverage.files_indexed == 1
        assert report.coverage.incomplete_results is False

    def test_mixed_outcomes_reconcile_coverage(self):
        hits = (
            _hit(path="unpinned.py"),
            _hit(path="fetch.py"),
            _hit(path="mismatch.py"),
            _hit(path="README.md"),
            _hit(path="valid.py"),
        )
        page = CodeSearchPage(hits=hits, total_count=5, incomplete_results=False)

        object.__setattr__(hits[0], "commit_sha", "main")

        def read_blob(slug, commit_sha, path):
            if path == "fetch.py":
                raise CodeSearchError("read failed")
            if path == "mismatch.py":
                return b"tampered"
            return CONTENT_BYTES

        searcher = GlobalSearcher(
            code_search=FakeCodeSearch(page=page),
            tree_source=FakeTree(),
            adapters=(PythonAdapter(),),
            blob_reader=read_blob,
            max_results=5,
        )

        report = searcher.search(_spec())

        assert report.coverage.files_indexed == 1
        assert report.coverage.exclusions == {
            "fetch_failed": 1,
            "no_adapter": 1,
            "provenance_mismatch": 1,
            "unpinned_hit": 1,
        }
        assert sum(report.coverage.exclusions.values()) == report.coverage.files_excluded


class TestCodeSearchHit:
    def test_invalid_blob_sha_rejected(self):
        with pytest.raises(ValueError):
            CodeSearchHit(
                slug="o/r", path="f.py", blob_sha="short", html_url="", commit_sha=SHA
            )

    def test_invalid_slug_rejected(self):
        with pytest.raises(ValueError):
            CodeSearchHit(
                slug="noslash", path="f.py", blob_sha=BLOB, html_url="", commit_sha=SHA
            )

    def test_empty_path_rejected(self):
        with pytest.raises(ValueError):
            CodeSearchHit(slug="o/r", path="", blob_sha=BLOB, html_url="", commit_sha=SHA)

    def test_invalid_commit_sha_rejected(self):
        with pytest.raises(ValueError, match="commit_sha"):
            _hit(commit_sha="main")


def test_head_resolver_keyword_is_removed():
    with pytest.raises(TypeError, match="head_resolver"):
        GlobalSearcher(
            code_search=FakeCodeSearch(),
            tree_source=FakeTree(),
            adapters=(PythonAdapter(),),
            head_resolver=lambda slug: SHA,
        )


def test_blob_reads_use_only_indexed_commit_and_matches_are_repo_scopes():
    other = "b" * 40
    page = CodeSearchPage(
        hits=(_hit(commit_sha=SHA), _hit(commit_sha=other, html_url=f"https://x/blob/{other}/x")),
        total_count=2,
        incomplete_results=False,
    )
    calls: list[str] = []

    def read_blob(slug, commit_sha, path):
        calls.append(commit_sha)
        return CONTENT_BYTES

    searcher = GlobalSearcher(
        FakeCodeSearch(page=page), FakeTree(), (PythonAdapter(),), blob_reader=read_blob
    )
    report = searcher.search(_spec())
    assert calls == [SHA, other]
    assert {match.source.commit_sha for match in report.matches} == {SHA, other}
    for match in report.matches:
        assert RepoScope(match.source.slug, match.source.commit_sha)


def test_identity_digest_excludes_advancing_clock():
    times = iter(("2026-08-06T12:00:00Z", "2026-08-06T12:00:01Z"))
    page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
    searcher = GlobalSearcher(
        FakeCodeSearch(page=page),
        FakeTree(),
        (PythonAdapter(),),
        blob_reader=lambda slug, sha, path: CONTENT_BYTES,
        clock=lambda: next(times),
    )
    first = searcher.search(_spec())
    second = searcher.search(_spec())
    assert first.resolution.as_of != second.resolution.as_of
    assert first.identity_digest() == second.identity_digest()


def test_validate_report_rejects_commit_not_in_hits():
    page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
    report = _searcher(page=page)[0].search(_spec())
    with pytest.raises(ValueError, match="REJECT_MOVING_REFERENCE"):
        validate_report(report, (_hit(commit_sha="b" * 40),))


def test_validate_report_rejects_missing_global_resolution():
    page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
    report = _searcher(page=page)[0].search(_spec())
    object.__setattr__(report, "resolution", None)
    with pytest.raises(ValueError, match="REJECT_MOVING_REFERENCE"):
        validate_report(report, page.hits)


def test_transport_cross_checks_both_index_commit_fields():
    item_url = f"https://api.github.com/repositories/1/contents/x.py?ref={SHA}"
    html_url = f"https://github.com/o/r/blob/{SHA}/x.py"
    assert _cross_checked_commit_sha(item_url, html_url) == SHA
    assert _cross_checked_commit_sha(item_url, html_url.replace(SHA, "b" * 40)) is None
    assert _cross_checked_commit_sha("https://api.github.com/x", html_url) is None
    assert _cross_checked_commit_sha(None, html_url) is None
