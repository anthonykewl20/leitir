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
    dedup_hits,
    hit_identity,
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
    SearchSpecError,
    SourceMatch,
    SourceRef,
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
DEFAULT_PATH = "Lib/urllib/parse.py"


def _content_for(path: str) -> bytes:
    return (CONTENT + f"\n# {path}\n").encode()


def _blob_for(path: str) -> str:
    content = _content_for(path)
    return hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\x00" + content
    ).hexdigest()


CONTENT_BYTES = _content_for(DEFAULT_PATH)
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
    path = overrides.get("path", DEFAULT_PATH)
    slug = overrides.get("slug", "python/cpython")
    commit_sha = overrides.get("commit_sha", SHA)
    base = {
        "slug": slug,
        "path": path,
        "blob_sha": _blob_for(path),
        "commit_sha": commit_sha,
        "html_url": (
            f"https://github.com/{slug}/blob/{commit_sha}/{path}"
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
        blob_reader=lambda slug, sha, path: content or _content_for(path),
        clock=lambda: "2026-08-06T12:00:00Z",
    )
    return searcher, cs


class TestBuildQuery:
    @pytest.mark.parametrize(
        "kind",
        (
            PredicateKind.EXACT_TEXT,
            PredicateKind.IDENTIFIER,
            PredicateKind.TOKEN_SEQUENCE,
        ),
    )
    def test_lossless_text_predicates_become_plain_terms(
        self, kind: PredicateKind
    ) -> None:
        spec = _spec(must=(Predicate(kind, "urlencode"),))
        assert build_query(spec) == "urlencode"

    def test_path_predicate_uses_qualifier(self):
        spec = _spec(must=(Predicate(PredicateKind.PATH, "Lib/urllib"),))
        assert build_query(spec) == "path:Lib/urllib"

    def test_language_appended(self):
        spec = _spec(must=(Predicate(PredicateKind.IDENTIFIER, "foo", "python"),))
        assert build_query(spec) == "foo language:python"

    def test_multiple_must_terms_joined(self):
        spec = _spec(must=(
            Predicate(PredicateKind.IDENTIFIER, "urlencode"),
            Predicate(PredicateKind.IDENTIFIER, "doseq"),
        ))
        q = build_query(spec)
        assert "urlencode" in q
        assert "doseq" in q

    def test_regex_predicate_is_rejected(self) -> None:
        kind = PredicateKind.REGEX
        spec = _spec(must=(Predicate(kind, "urlencode.*"),))
        with pytest.raises(
            SearchSpecError,
            match=rf"REJECT_SEMANTIC_DEGRADATION.*{kind.value}",
        ):
            build_query(spec)

    @pytest.mark.parametrize(
        "kind",
        (
            PredicateKind.SYMBOL_DEFINITION,
            PredicateKind.SYMBOL_REFERENCE,
            PredicateKind.SIGNATURE,
            PredicateKind.CALL,
            PredicateKind.IMPORT,
        ),
    )
    def test_structural_predicates_use_bare_superset_term(self, kind: PredicateKind) -> None:
        assert build_query(_spec(must=(Predicate(kind, "urlencode"),))) == "urlencode"

    def test_supported_predicate_translations_are_recorded(self) -> None:
        page = CodeSearchPage(hits=(), total_count=0, incomplete_results=False)
        report = _searcher(page=page)[0].search(
            _spec(
                must=(
                    Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),
                    Predicate(PredicateKind.PATH, "Lib/urllib"),
                ),
                should=(Predicate(PredicateKind.IDENTIFIER, "doseq"),),
            )
        )
        assert [item.to_dict() for item in report.query_translation] == [
            {
                "clause": "must",
                "predicate_index": 0,
                "kind": "identifier",
                "strategy": "github_query",
                "emitted_syntax": "urlencode",
            },
            {
                "clause": "must",
                "predicate_index": 1,
                "kind": "path",
                "strategy": "github_superset_local_filter",
                "emitted_syntax": "path:Lib/urllib",
            },
            {
                "clause": "should",
                "predicate_index": 0,
                "kind": "identifier",
                "strategy": "local_filter",
                "emitted_syntax": None,
            },
        ]


class TestGlobalSearcher:
    def test_path_superset_hits_are_locally_filtered(self):
        matching = _hit(path="Lib/urllib/parse.py")
        nonmatching = _hit(path="Lib/http/client.py")
        page = CodeSearchPage(
            hits=(matching, nonmatching), total_count=2, incomplete_results=False
        )
        report = _searcher(page=page)[0].search(
            _spec(
                must=(
                    Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),
                    Predicate(PredicateKind.PATH, r"Lib/urllib"),
                )
            )
        )

        assert [match.source.path for match in report.matches] == [matching.path]
        assert report.coverage.exclusions == {"path_mismatch": 1}
        assert report.query_translation[1].strategy == "github_superset_local_filter"

    def test_symbol_definition_superset_is_locally_reverified(self):
        contents = {
            "definition.py": b"def urlencode(value):\n    return value\n",
            "reference.py": b"print(urlencode)\n",
        }

        def blob(path: str) -> str:
            data = contents[path]
            return hashlib.sha1(
                b"blob " + str(len(data)).encode("ascii") + b"\x00" + data
            ).hexdigest()

        hits = tuple(
            _hit(path=path, blob_sha=blob(path)) for path in sorted(contents)
        )
        page = CodeSearchPage(hits=hits, total_count=2, incomplete_results=False)
        code_search = FakeCodeSearch(page=page)
        searcher = GlobalSearcher(
            code_search=code_search,
            tree_source=FakeTree(),
            adapters=(PythonAdapter(),),
            blob_reader=lambda _slug, _sha, path: contents[path],
            clock=lambda: "2026-08-06T12:00:00Z",
        )
        report = searcher.search(
            _spec(must=(Predicate(PredicateKind.SYMBOL_DEFINITION, "urlencode"),))
        )

        assert code_search.queries == ["urlencode"]
        assert [match.source.path for match in report.matches] == ["definition.py"]
        assert report.query_translation[0].to_dict() == {
            "clause": "must",
            "predicate_index": 0,
            "kind": "symbol_definition",
            "strategy": "github_superset_local_filter",
            "emitted_syntax": "urlencode",
        }

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
                    low_content if path == "a.py" else _content_for(path)
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

    def test_duplicate_source_identity_is_deduplicated(self):
        page = CodeSearchPage(
            hits=(_hit(), _hit()), total_count=2, incomplete_results=False
        )
        searcher, _ = _searcher(page=page)
        report = searcher.search(_spec())
        assert len(report.matches) == 1
        assert report.coverage.exclusions == {"deduplicated": 1}

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
            blob_reader=lambda slug, sha, path: _content_for(path),
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
            blob_reader=lambda slug, sha, path: _content_for(path),
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
            blob_reader=lambda slug, sha, path: _content_for(path),
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
            return _content_for(path)

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


class TestDedupHits:
    def _hits(self):
        shared = _blob_for("shared.py")
        return (
            _hit(slug="z/repo", path="six.py", blob_sha=shared),
            _hit(slug="a/repo", path="vendor/six.py", blob_sha=shared),
            _hit(slug="m/repo", path="other.py"),
        )

    def test_invariants_and_minimum_representative(self):
        hits = self._hits()
        expected = dedup_hits(hits)
        for ordering in permutations(hits):
            assert dedup_hits(ordering) == expected  # I1
        assert dedup_hits(expected.candidates).collapsed == 0  # I2
        assert {hit.blob_sha for hit in hits} == {
            hit.blob_sha for hit in expected.candidates
        }  # I3
        assert len(hits) == len(expected.candidates) + expected.collapsed  # I4
        assert expected.candidates[0] == min(expected.groups[0], key=hit_identity)  # I5

    @pytest.mark.parametrize("path", ["six.py", "vendor/six.py"])
    def test_different_content_in_different_repositories_survives(self, path):
        hits = (
            _hit(slug="a/one", path=path),
            _hit(slug="b/two", path=path, blob_sha=_blob_for(f"other/{path}")),
        )
        assert dedup_hits(hits).candidates == tuple(sorted(hits, key=hit_identity))

    def test_contradictory_pinned_path_is_pin_disagreement(self):
        outcome = dedup_hits(
            (_hit(path="same.py"), _hit(path="same.py", blob_sha=_blob_for("other.py")))
        )
        assert outcome.pin_disagreements == 1
        assert outcome.collapsed == 0

    def test_same_file_at_different_indexed_commits_uses_secondary_identity(self):
        hits = (
            _hit(path="drift.py", commit_sha="a" * 40),
            _hit(
                path="drift.py",
                commit_sha="b" * 40,
                blob_sha=_blob_for("new-drift.py"),
            ),
        )
        outcome = dedup_hits(hits)
        assert outcome.candidates == (min(hits, key=hit_identity),)
        assert outcome.collapsed == 1

    def test_repeated_path_does_not_annihilate_distinct_content_group(self):
        blob_x = _blob_for("blob-x.py")
        blob_y = _blob_for("blob-y.py")
        hits = (
            _hit(slug="a/one", path="p.py", commit_sha="1" * 40, blob_sha=blob_x),
            _hit(slug="a/one", path="p.py", commit_sha="2" * 40, blob_sha=blob_y),
            _hit(slug="b/two", path="q.py", commit_sha="3" * 40, blob_sha=blob_y),
        )

        outcome = dedup_hits(hits)

        assert {hit.blob_sha for hit in outcome.candidates} == {blob_x, blob_y}

    def test_html_url_breaks_identity_ties_deterministically(self):
        good_url = f"https://a.example/o/r/blob/{SHA}/{DEFAULT_PATH}"
        bad_url = f"https://z.example/o/r/blob/{'b' * 40}/{DEFAULT_PATH}"
        hits = (_hit(html_url=bad_url), _hit(html_url=good_url))
        reports = []
        for ordering in permutations(hits):
            reports.append(
                GlobalSearcher(
                    FakeCodeSearch(CodeSearchPage(ordering, 2, False)),
                    FakeTree(),
                    (PythonAdapter(),),
                    blob_reader=lambda slug, sha, path: _content_for(path),
                    clock=lambda: "2026-08-06T12:00:00Z",
                ).search(_spec())
            )

        assert all(len(report.matches) > 0 for report in reports)
        assert len({report.identity_digest() for report in reports}) == 1
        assert dedup_hits(hits).groups[0][0].html_url == good_url

    def test_report_invariants_and_permutation_identity(self):
        hits = self._hits()
        reports = []
        for ordering in permutations(hits):
            reports.append(
                GlobalSearcher(
                    FakeCodeSearch(CodeSearchPage(ordering, len(hits), False)),
                    FakeTree(),
                    (PythonAdapter(),),
                    blob_reader=lambda slug, sha, path: (
                        _content_for("shared.py")
                        if path in {"six.py", "vendor/six.py"}
                        else _content_for(path)
                    ),
                    clock=lambda: "2026-08-06T12:00:00Z",
                ).search(_spec())
            )
        for report in reports:
            origins: dict[str, set[tuple[str, str, str]]] = {}
            for match in report.matches:
                source = match.source
                origins.setdefault(source.blob_sha, set()).add(
                    (source.slug, source.commit_sha, source.path)
                )
            assert all(len(items) == 1 for items in origins.values())  # I6
            assert report.coverage.exclusions["deduplicated"] == 1  # I7
            assert sum(report.coverage.exclusions.values()) == report.coverage.files_excluded
        assert len({report.identity_digest() for report in reports}) == 1  # I8


class TestGlobalDedupIntegration:
    def test_repeated_path_does_not_drop_distinct_implementation(self):
        blob_x = _blob_for("blob-x.py")
        blob_y = _blob_for("blob-y.py")
        hits = (
            _hit(slug="a/one", path="p.py", commit_sha="1" * 40, blob_sha=blob_x),
            _hit(slug="a/one", path="p.py", commit_sha="2" * 40, blob_sha=blob_y),
            _hit(slug="b/two", path="q.py", commit_sha="3" * 40, blob_sha=blob_y),
        )
        content_by_commit = {
            "1" * 40: _content_for("blob-x.py"),
            "2" * 40: _content_for("blob-y.py"),
            "3" * 40: _content_for("blob-y.py"),
        }
        report = GlobalSearcher(
            FakeCodeSearch(CodeSearchPage(hits, 3, False)),
            FakeTree(),
            (PythonAdapter(),),
            blob_reader=lambda slug, sha, path: content_by_commit[sha],
        ).search(_spec())

        assert report.coverage.files_indexed == 2
        assert {match.source.blob_sha for match in report.matches} == {blob_x, blob_y}

    def test_cross_page_repeat_does_not_crash(self):
        repeated = _hit()
        pages = {
            1: CodeSearchPage((repeated, _hit(path="README.md")), 4, False),
            2: CodeSearchPage((repeated, _hit(path="docs/guide.md")), 4, False),
        }
        report = GlobalSearcher(
            FakeCodeSearch(pages=pages), FakeTree(), (PythonAdapter(),),
            blob_reader=lambda slug, sha, path: _content_for(path),
            max_results=2, max_pages=2,
        ).search(_spec())
        assert len(report.matches) == 1
        assert report.coverage.exclusions["deduplicated"] == 1

    def test_collapsed_member_is_not_fetched(self):
        shared = _blob_for("shared.py")
        hits = (
            _hit(slug="z/repo", path="z.py", blob_sha=shared),
            _hit(slug="a/repo", path="a.py", blob_sha=shared),
        )
        calls: list[str] = []

        def read_blob(slug, commit_sha, path):
            calls.append(slug)
            return _content_for("shared.py")

        report = GlobalSearcher(
            FakeCodeSearch(CodeSearchPage(hits, 2, False)), FakeTree(),
            (PythonAdapter(),), blob_reader=read_blob,
        ).search(_spec())
        assert calls == ["a/repo"]
        assert report.coverage.exclusions == {"deduplicated": 1}

    def test_failed_representative_is_promoted(self):
        shared = _blob_for("shared.py")
        hits = (
            _hit(slug="z/repo", path="z.py", blob_sha=shared),
            _hit(slug="a/repo", path="a.py", blob_sha=shared),
        )
        calls: list[str] = []

        def read_blob(slug, commit_sha, path):
            calls.append(slug)
            if slug == "a/repo":
                raise CodeSearchError("gone")
            return _content_for("shared.py")

        report = GlobalSearcher(
            FakeCodeSearch(CodeSearchPage(hits, 2, False)), FakeTree(),
            (PythonAdapter(),), blob_reader=read_blob,
        ).search(_spec())
        assert calls == ["a/repo", "z/repo"]
        assert {match.source.slug for match in report.matches} == {"z/repo"}
        assert report.coverage.incomplete_results is True
        assert report.coverage.exclusions == {"fetch_failed": 1}
        assert (
            report.coverage.files_indexed + report.coverage.files_excluded
            == report.coverage.files_eligible
        )

    def test_all_promoted_members_fail_without_double_counting(self):
        shared = _blob_for("shared.py")
        hits = tuple(
            _hit(slug=f"{owner}/repo", path=f"{owner}.py", blob_sha=shared)
            for owner in ("a", "b", "c")
        )

        def fail_fetch(slug, commit_sha, path):
            raise CodeSearchError("gone")

        report = GlobalSearcher(
            FakeCodeSearch(CodeSearchPage(hits, 3, False)),
            FakeTree(),
            (PythonAdapter(),),
            blob_reader=fail_fetch,
        ).search(_spec())

        assert report.coverage.files_indexed == 0
        assert report.coverage.exclusions == {"fetch_failed": 3}
        assert "deduplicated" not in report.coverage.exclusions
        assert (
            report.coverage.files_indexed + report.coverage.files_excluded
            == report.coverage.files_eligible
        )


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
        hits=(
            _hit(commit_sha=SHA),
            _hit(
                path="Lib/urllib/other.py",
                commit_sha=other,
                html_url=f"https://x/blob/{other}/x",
            ),
        ),
        total_count=2,
        incomplete_results=False,
    )
    calls: list[str] = []

    def read_blob(slug, commit_sha, path):
        calls.append(commit_sha)
        return _content_for(path)

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


def test_validate_report_accepts_report_pinned_to_indexed_hit():
    page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
    report = _searcher(page=page)[0].search(_spec())
    validate_report(report, page.hits)


def test_global_search_return_boundary_rejects_foreign_commit(monkeypatch):
    page = CodeSearchPage(hits=(_hit(),), total_count=1, incomplete_results=False)
    foreign = "b" * 40

    def inject_foreign_commit(matches):
        match = matches[0]
        source = match.source
        return (
            SourceMatch(
                SourceRef(
                    source.slug,
                    foreign,
                    source.path,
                    source.blob_sha,
                    source.start_line,
                    source.end_line,
                ),
                match.score,
                match.matched_kinds,
            ),
        )

    monkeypatch.setattr(
        "leitir.discovery_search.order_source_matches", inject_foreign_commit
    )
    with pytest.raises(ValueError, match="REJECT_MOVING_REFERENCE"):
        _searcher(page=page)[0].search(_spec())


def test_transport_cross_checks_both_index_commit_fields():
    item_url = f"https://api.github.com/repositories/1/contents/x.py?ref={SHA}"
    html_url = f"https://github.com/o/r/blob/{SHA}/x.py"
    assert _cross_checked_commit_sha(item_url, html_url) == SHA
    assert _cross_checked_commit_sha(item_url, html_url.replace(SHA, "b" * 40)) is None
    assert _cross_checked_commit_sha("https://api.github.com/x", html_url) is None
    assert _cross_checked_commit_sha(None, html_url) is None
