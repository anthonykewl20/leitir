"""Offline tests for every bounded-coverage capping path of global discovery.

Audit finding: the `--global` GitHub Code Search result-capping paths were
not exercised locally as a set.  This module drives `GlobalSearcher` with
the scripted-transport pattern established in `test_discovery_coverage.py`
and pins, for every `BOUND_*` code in `discovery_search`:

* that the cap actually fires (traversal/verification stops where designed),
* that the reported bound code and the incomplete flag are exactly correct,
* that repeated runs over the same script produce identical reports, and
* the negative: a result set under every cap reports no bound at all.

Everything here is offline: the transport is a script, the blob reader a
lookup, and the clock is fixed, so reports are reproducible byte for byte.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

import pytest

from leitir.adapters import LanguageAdapter, PythonAdapter
from leitir.adapters.python_ast import PythonAstAdapter
from leitir.discovery_search import (
    BOUND_CANDIDATE_BUDGET,
    BOUND_INCOMPLETE_RESULTS,
    BOUND_PAGE_CAP,
    BOUND_PARSER_UNAVAILABLE,
    BOUND_RESULT_BUDGET,
    BOUND_TRANSPORT_ERROR,
    BOUND_VERIFICATION_FAILED,
    MAX_SEARCH_RESULTS,
    CodeSearchError,
    CodeSearchHit,
    CodeSearchPage,
    CoverageBounds,
    GlobalSearcher,
)
from leitir.search import Predicate, PredicateKind, SearchMode, SearchReport, SearchSpec
from leitir.tree import BlobEntry

SHA = "a" * 40
CLOCK = "2026-08-21T00:00:00Z"
MAX_RESULTS_MESSAGE = f"max_results must be an integer from 1 to {MAX_SEARCH_RESULTS}"

CONTENT = """\
def urlencode(query, doseq=False):
    if doseq:
        for k, v in query:
            pass
    return query
"""

# Known-unparseable Python (see test_global.py: it breaks the AST adapter).
BROKEN = b"urlencode = 1\nif (\n"

BlobReader = Callable[[str, str, str], bytes]


def _blob_for_bytes(content: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\x00" + content
    ).hexdigest()


def _content_for(path: str) -> bytes:
    return (CONTENT + f"\n# {path}\n").encode()


def _hit_for_bytes(path: str, content: bytes, slug: str = "python/cpython") -> CodeSearchHit:
    return CodeSearchHit(
        slug=slug,
        path=path,
        blob_sha=_blob_for_bytes(content),
        commit_sha=SHA,
        html_url=f"https://github.com/{slug}/blob/{SHA}/{path}",
    )


def _hit(path: str = "Lib/urllib/parse.py", slug: str = "python/cpython") -> CodeSearchHit:
    return _hit_for_bytes(path, _content_for(path), slug)


def _py(index: int) -> CodeSearchHit:
    """An adapter-eligible hit with a distinct path (no dedup interference)."""
    return _hit(f"Lib/urllib/parse{index}.py")


def _md(index: int) -> CodeSearchHit:
    """An adapter-ineligible padding hit: no adapter claims markdown paths."""
    return _hit(f"docs/design/module-{index}.md")


def _page(
    hits: tuple[CodeSearchHit, ...], *, total: int, incomplete: bool = False
) -> CodeSearchPage:
    return CodeSearchPage(hits=hits, total_count=total, incomplete_results=incomplete)


def _full_page(*, total: int = 1000, incomplete: bool = False) -> CodeSearchPage:
    """A full default-budget page: 1 eligible + 29 ineligible = 30 hits."""
    return _page((_py(0), *(_md(index) for index in range(29))), total=total, incomplete=incomplete)


class ScriptedCodeSearch:
    """Deterministic scripted transport: pages by number, optional errors."""

    def __init__(
        self,
        pages: dict[int, CodeSearchPage],
        page_errors: dict[int, Exception] | None = None,
    ) -> None:
        self.pages = pages
        self.page_errors = page_errors or {}
        self.page_numbers: list[int] = []

    def search(self, query: str, *, per_page: int = 10, page: int = 1) -> CodeSearchPage:
        self.page_numbers.append(page)
        if page in self.page_errors:
            raise self.page_errors[page]
        return self.pages.get(
            page, CodeSearchPage(hits=(), total_count=0, incomplete_results=False)
        )


class FakeTree:
    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        return ()

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        return CONTENT.encode()


def _searcher(
    pages: dict[int, CodeSearchPage],
    *,
    max_results: int = 30,
    max_pages: int = 10,
    page_errors: dict[int, Exception] | None = None,
    blob_reader: BlobReader | None = None,
    adapters: tuple[LanguageAdapter, ...] | None = None,
) -> tuple[GlobalSearcher, ScriptedCodeSearch]:
    cs = ScriptedCodeSearch(pages, page_errors=page_errors)
    searcher = GlobalSearcher(
        code_search=cs,
        tree_source=FakeTree(),
        adapters=adapters if adapters is not None else (PythonAdapter(),),
        blob_reader=blob_reader if blob_reader is not None else (lambda _slug, _sha, path: _content_for(path)),
        max_results=max_results,
        max_pages=max_pages,
        clock=lambda: CLOCK,
    )
    return searcher, cs


def _spec(
    kind: PredicateKind = PredicateKind.IDENTIFIER,
    value: str = "urlencode",
) -> SearchSpec:
    return SearchSpec(
        mode=SearchMode.GLOBAL_DISCOVERY,
        must=(Predicate(kind, value, "python"),),
    )


def _bounds(searcher: GlobalSearcher) -> CoverageBounds:
    """Return the last invocation's bounds, failing if none were recorded."""
    bounds = searcher.last_coverage_bounds
    assert bounds is not None
    return bounds


class TestBoundCodesPinned:
    """The wire values of every bound code (discovery_search.py:705-711)."""

    def test_bound_codes_have_stable_literal_values(self) -> None:
        assert BOUND_INCOMPLETE_RESULTS == "incomplete-results"
        assert BOUND_PAGE_CAP == "page-cap"
        assert BOUND_CANDIDATE_BUDGET == "candidate-budget"
        assert BOUND_RESULT_BUDGET == "result-budget"
        assert BOUND_TRANSPORT_ERROR == "transport-error"
        assert BOUND_PARSER_UNAVAILABLE == "parser-unavailable"
        assert BOUND_VERIFICATION_FAILED == "verification-failed"
        assert MAX_SEARCH_RESULTS == 1000


class TestPageCap:
    """BOUND_PAGE_CAP: discovery_search.py:873-875 - full page at max_pages."""

    def test_cap_fires_at_max_pages_and_names_the_bound(self) -> None:
        full = _full_page(total=1000)
        searcher, cs = _searcher({1: full, 2: full, 3: full}, max_pages=2)
        report = searcher.search(_spec())

        # The cap, not exhaustion, stopped traversal: page 3 exists in the
        # script but was never requested, and page 2 came back full.
        assert cs.page_numbers == [1, 2]
        bounds = _bounds(searcher)
        assert bounds.pages_fetched == 2
        assert bounds.incomplete is True
        assert bounds.bounds == (BOUND_PAGE_CAP,)
        assert bounds.matches_returned == len(report.matches)
        assert report.coverage.incomplete_results is True

    def test_short_last_page_does_not_fire_the_cap(self) -> None:
        pages = {
            1: _page((_py(0), *(_md(i) for i in range(29))), total=35),
            2: _page((_py(1), *(_md(i) for i in range(4))), total=35),
        }
        searcher, cs = _searcher(pages, max_pages=3)
        report = searcher.search(_spec())

        assert cs.page_numbers == [1, 2]  # the short page ends traversal early
        assert _bounds(searcher) == CoverageBounds(2, len(report.matches), False, ())
        assert report.coverage.incomplete_results is False


class TestIncompleteResults:
    """BOUND_INCOMPLETE_RESULTS: discovery_search.py:854-856 and 869-870."""

    def test_server_truncation_flag_stops_traversal_and_reports_bound(self) -> None:
        flagged = _full_page(total=1000, incomplete=True)
        searcher, cs = _searcher({1: flagged, 2: flagged}, max_pages=10)
        report = searcher.search(_spec())

        # The flagged page ends traversal even though it was full and a full
        # page 2 is available: the server declared its own results truncated.
        assert cs.page_numbers == [1]
        bounds = _bounds(searcher)
        assert bounds.pages_fetched == 1
        assert bounds.incomplete is True
        assert bounds.bounds == (BOUND_INCOMPLETE_RESULTS,)
        assert report.coverage.incomplete_results is True


class TestCandidateBudget:
    """BOUND_CANDIDATE_BUDGET: discovery_search.py:863-868 and 880-882."""

    def test_budget_stop_with_unfetched_results_reports_bound(self) -> None:
        # In-loop path (lines 865-867): the stopping page's total_count
        # proves results remain unfetched.
        searcher, cs = _searcher(
            {1: _page((_py(0), _py(1)), total=100), 2: _page((_py(2), _py(3)), total=100)},
            max_results=2,
        )
        report = searcher.search(_spec())

        assert cs.page_numbers == [1]  # collection stopped at the budget
        bounds = _bounds(searcher)
        assert bounds.pages_fetched == 1
        assert bounds.incomplete is True
        assert bounds.bounds == (BOUND_CANDIDATE_BUDGET,)
        assert bounds.matches_returned == len(report.matches)
        assert report.coverage.files_eligible == 100
        assert report.coverage.files_indexed == 2  # verification still ran to the budget

    def test_budget_stop_when_collection_is_complete_reports_no_bound(self) -> None:
        # total_count == len(collected): the budget stopped collection, but
        # the server count proves nothing was left unfetched.
        searcher, cs = _searcher({1: _page((_py(0), _py(1)), total=2)}, max_results=2)
        report = searcher.search(_spec())

        assert cs.page_numbers == [1]
        assert _bounds(searcher) == CoverageBounds(1, len(report.matches), False, ())
        assert report.coverage.incomplete_results is False

    def test_first_page_count_reports_bound_after_total_count_drift(self) -> None:
        # Post-loop path (lines 880-882): the stopping page under-reports
        # total_count relative to what page 1 claimed, so the bound is
        # re-derived from the page-1 count (files_eligible).
        pages = {
            1: _page((_py(0), _md(0)), total=50),
            2: _page((_py(1),), total=2),
        }
        searcher, cs = _searcher(pages, max_results=2)
        report = searcher.search(_spec())

        assert cs.page_numbers == [1, 2]
        bounds = _bounds(searcher)
        assert bounds.pages_fetched == 2
        assert bounds.incomplete is True
        assert bounds.bounds == (BOUND_CANDIDATE_BUDGET,)
        assert report.coverage.files_eligible == 50  # page 1's claim, not page 2's


class TestResultBudget:
    """BOUND_RESULT_BUDGET: discovery_search.py:902-911."""

    def test_budget_limits_verification_and_reports_bound(self) -> None:
        # Three eligible candidates collected completely (total_count == 3),
        # so only the verification budget truncates which files are indexed.
        searcher, _cs = _searcher(
            {1: _page((_py(0), _py(1), _py(2)), total=3)}, max_results=2
        )
        report = searcher.search(_spec())

        bounds = _bounds(searcher)
        assert bounds.incomplete is True
        assert bounds.bounds == (BOUND_RESULT_BUDGET,)
        assert report.coverage.files_eligible == 3
        assert report.coverage.files_indexed == 2
        # Verification stops at the budget in file-level identity order: the
        # third candidate was never attempted, and never reported.
        verified_paths = sorted(match.source.path for match in report.matches)
        assert verified_paths == ["Lib/urllib/parse0.py", "Lib/urllib/parse1.py"]
        assert bounds.matches_returned == len(report.matches)

    def test_result_budget_and_candidate_budget_report_sorted_together(self) -> None:
        # Four eligible candidates with results unfetched: both bounds fire
        # and the reported tuple is the sorted join ("candidate-budget"
        # before "result-budget", discovery_search.py:1020).
        searcher, _cs = _searcher(
            {1: _page((_py(0), _py(1), _py(2), _py(3)), total=100)}, max_results=2
        )
        report = searcher.search(_spec())

        bounds = _bounds(searcher)
        assert bounds.incomplete is True
        assert bounds.bounds == (BOUND_CANDIDATE_BUDGET, BOUND_RESULT_BUDGET)
        assert report.coverage.files_indexed == 2


class TestTransportError:
    """BOUND_TRANSPORT_ERROR: discovery_search.py:845-850."""

    @pytest.mark.parametrize(
        "failure", (CodeSearchError("late boom"), OSError("socket reset"))
    )
    def test_mid_search_failure_reports_bound(self, failure: Exception) -> None:
        searcher, cs = _searcher({1: _full_page(total=1000)}, page_errors={2: failure})
        report = searcher.search(_spec())

        assert cs.page_numbers == [1, 2]  # page 2 was attempted ...
        bounds = _bounds(searcher)
        assert bounds.pages_fetched == 1  # ... but not fetched
        assert bounds.incomplete is True
        assert bounds.bounds == (BOUND_TRANSPORT_ERROR,)
        assert bounds.matches_returned == len(report.matches)

    def test_first_page_failure_is_fail_closed_without_bounds(self) -> None:
        # Lines 846-847: a page-1 failure re-raises and no bounds are
        # fabricated for a search that never produced an observation.
        searcher, cs = _searcher({}, page_errors={1: CodeSearchError("boom")})
        with pytest.raises(CodeSearchError, match="boom"):
            searcher.search(_spec())
        assert cs.page_numbers == [1]
        assert searcher.last_coverage_bounds is None


class TestParserUnavailable:
    """BOUND_PARSER_UNAVAILABLE: discovery_search.py:971-976."""

    def test_ast_parse_failure_reports_bound(self) -> None:
        hit = _hit_for_bytes("Lib/broken.py", BROKEN)
        searcher, _cs = _searcher(
            {1: _page((hit,), total=1)},
            adapters=(PythonAstAdapter(PythonAdapter()),),
            blob_reader=lambda _slug, _sha, _path: BROKEN,
        )
        report = searcher.search(_spec(PredicateKind.CALL, "urlencode"))

        bounds = _bounds(searcher)
        assert bounds.pages_fetched == 1
        assert bounds.incomplete is True
        assert bounds.bounds == (BOUND_PARSER_UNAVAILABLE,)
        assert report.coverage.exclusions.get("parser_unavailable") == 1
        assert report.coverage.files_indexed == 1  # scored via fallback, still flagged

    def test_plain_adapter_on_the_same_content_reports_no_bound(self) -> None:
        # Control: the regex adapter never signals parser unavailability.
        hit = _hit_for_bytes("Lib/broken.py", BROKEN)
        searcher, _cs = _searcher(
            {1: _page((hit,), total=1)},
            adapters=(PythonAdapter(),),
            blob_reader=lambda _slug, _sha, _path: BROKEN,
        )
        report = searcher.search(_spec(PredicateKind.CALL, "urlencode"))

        assert _bounds(searcher) == CoverageBounds(1, len(report.matches), False, ())
        assert report.coverage.exclusions == {}


class TestVerificationFailed:
    """BOUND_VERIFICATION_FAILED: discovery_search.py:944-957 feeding 980-982."""

    def test_provenance_mismatch_on_every_candidate_reports_bound(self) -> None:
        # The blob reader serves bytes whose git blob sha disagrees with the
        # hit's claim: fail-closed, no match is ever fabricated.
        searcher, _cs = _searcher(
            {1: _page((_py(0), _py(1)), total=2)},
            blob_reader=lambda _slug, _sha, _path: b"tampered bytes\n",
        )
        report = searcher.search(_spec())

        bounds = _bounds(searcher)
        assert bounds.incomplete is True
        assert bounds.bounds == (BOUND_VERIFICATION_FAILED,)
        assert report.coverage.exclusions == {"provenance_mismatch": 2}
        assert report.coverage.files_indexed == 0
        assert len(report.matches) == 0
        assert bounds.matches_returned == 0

    def test_partial_verification_still_reports_bound(self) -> None:
        # One candidate verifies, one fails: files_indexed (1) stays below
        # max_results (30), so the observation is still honestly incomplete.
        good_path = "Lib/urllib/parse0.py"
        contents: dict[str, bytes] = {good_path: _content_for(good_path)}

        def selective(_slug: str, _sha: str, path: str) -> bytes:
            return contents.get(path, b"tampered bytes\n")

        searcher, _cs = _searcher(
            {1: _page((_py(0), _py(1)), total=2)}, blob_reader=selective
        )
        report = searcher.search(_spec())

        assert report.coverage.exclusions == {"provenance_mismatch": 1}
        assert report.coverage.files_indexed == 1
        bounds = _bounds(searcher)
        assert bounds == CoverageBounds(1, len(report.matches), True, (BOUND_VERIFICATION_FAILED,))

    def test_undecodable_blob_reports_bound(self) -> None:
        raw = b"\xff\xfe\xfa\xfb"
        hit = _hit_for_bytes("Lib/binary.py", raw)
        searcher, _cs = _searcher(
            {1: _page((hit,), total=1)},
            blob_reader=lambda _slug, _sha, _path: raw,
        )
        report = searcher.search(_spec())

        bounds = _bounds(searcher)
        assert bounds.incomplete is True
        assert bounds.bounds == (BOUND_VERIFICATION_FAILED,)
        assert report.coverage.exclusions == {"decode_failed": 1}
        assert len(report.matches) == 0


class TestUnderEveryCap:
    """Negative: under every cap, no incomplete flag and no bound (lines 1016-1021)."""

    def test_small_complete_result_reports_no_bounds(self) -> None:
        searcher, cs = _searcher({1: _page((_py(0), _py(1)), total=2)})
        report = searcher.search(_spec())

        assert cs.page_numbers == [1]
        bounds = _bounds(searcher)
        assert bounds == CoverageBounds(1, len(report.matches), False, ())
        assert bounds.to_dict() == {
            "pages_fetched": 1,
            "matches_returned": len(report.matches),
            "bounds": [],
        }
        assert report.coverage.incomplete_results is False
        assert report.coverage.exclusions == {}

    def test_zero_hits_on_a_single_page_is_a_complete_answer(self) -> None:
        searcher, _cs = _searcher({1: _page((), total=0)})
        report = searcher.search(_spec())

        assert _bounds(searcher) == CoverageBounds(1, 0, False, ())
        assert len(report.matches) == 0
        assert report.coverage.incomplete_results is False


class TestDeterminism:
    """Same script in, identical report and bounds out (issue #191 SP-4)."""

    def test_repeated_runs_over_identical_scripts_are_identical(self) -> None:
        pages = {1: _page(tuple(_py(i) for i in range(4)), total=100)}

        def run() -> tuple[SearchReport, CoverageBounds]:
            searcher, _cs = _searcher(pages, max_results=2)
            report = searcher.search(_spec())
            return report, _bounds(searcher)

        first_report, first_bounds = run()
        second_report, second_bounds = run()
        assert first_report == second_report
        assert first_bounds == second_bounds
        # A non-trivial capped scenario: two bounds fire, deterministically.
        assert first_bounds.bounds == (BOUND_CANDIDATE_BUDGET, BOUND_RESULT_BUDGET)
        assert first_bounds.incomplete is True

    def test_hit_order_within_and_across_pages_does_not_change_the_report(self) -> None:
        # Full pages (per_page == max_results == 3) so both pages are always
        # traversed; the same six hits are shuffled within and across pages.
        a, b, c = _py(0), _py(1), _py(2)
        x, y, z = _md(0), _md(1), _md(2)
        variants = (
            {1: _page((a, b, x), total=6), 2: _page((c, y, z), total=6)},
            {1: _page((b, a, x), total=6), 2: _page((c, z, y), total=6)},
            {1: _page((c, x, a), total=6), 2: _page((y, b, z), total=6)},
            {1: _page((x, b, c), total=6), 2: _page((a, y, z), total=6)},
        )
        observed: list[tuple[SearchReport, CoverageBounds]] = []
        for pages in variants:
            searcher, cs = _searcher(pages, max_results=3)
            report = searcher.search(_spec())
            assert cs.page_numbers == [1, 2]  # a real two-page traversal
            observed.append((report, _bounds(searcher)))

        assert observed[0] == observed[1] == observed[2] == observed[3]
        assert observed[0][1].pages_fetched == 2
        assert observed[0][1].incomplete is False
        assert observed[0][1].bounds == ()


class TestCoverageBoundsContract:
    """CoverageBounds.__post_init__ (discovery_search.py:740-755) is fail-closed."""

    def test_reasons_require_incomplete_true(self) -> None:
        with pytest.raises(ValueError, match="bound reasons require incomplete=True"):
            CoverageBounds(
                pages_fetched=1, matches_returned=0, incomplete=False, bounds=(BOUND_PAGE_CAP,)
            )

    def test_unknown_reason_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown bound reason"):
            CoverageBounds(1, 0, True, ("stale-page",))

    def test_duplicate_reasons_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="bound reasons must be unique"):
            CoverageBounds(1, 0, True, (BOUND_PAGE_CAP, BOUND_PAGE_CAP))

    def test_negative_counters_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="pages_fetched must be a non-negative integer"):
            CoverageBounds(-1, 0, False)

    def test_capped_run_renders_sorted_json_ready_bounds(self) -> None:
        full = _full_page(total=1000)
        searcher, _cs = _searcher({1: full, 2: full}, max_pages=2)
        searcher.search(_spec())

        rendered = _bounds(searcher).to_dict()
        assert rendered["pages_fetched"] == 2
        assert rendered["bounds"] == ["page-cap"]  # a JSON list, in sorted order


class TestMaxResultsValidation:
    """max_results validation (discovery_search.py:779-786)."""

    @pytest.mark.parametrize(
        "bad",
        (0, -1, MAX_SEARCH_RESULTS + 1, "30", 30.0, 1.5, None, True, False),
    )
    def test_invalid_max_results_raises_the_typed_error(self, bad: object) -> None:
        with pytest.raises(ValueError, match=MAX_RESULTS_MESSAGE) as raised:
            GlobalSearcher(
                code_search=ScriptedCodeSearch({}),
                tree_source=FakeTree(),
                adapters=(PythonAdapter(),),
                max_results=bad,  # type: ignore[arg-type]
            )
        assert str(raised.value) == MAX_RESULTS_MESSAGE

    @pytest.mark.parametrize("good", (1, 30, MAX_SEARCH_RESULTS))
    def test_boundary_values_are_accepted(self, good: int) -> None:
        searcher = GlobalSearcher(
            code_search=ScriptedCodeSearch({}),
            tree_source=FakeTree(),
            adapters=(PythonAdapter(),),
            max_results=good,
        )
        assert searcher.last_coverage_bounds is None
