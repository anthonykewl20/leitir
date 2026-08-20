"""Honest discovery coverage reporting (issue #191).

Scripted-transport coverage fixtures: complete, incomplete, multi-page,
zero-results, and page-cap.  Every fixture is pinned by the sha256 of its
canonical serialization (``test_scripted_fixture_digests_are_pinned``); the
pinned digests are recorded in the delivery PR (contract: "Pin fixtures by
digest").
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re

import pytest

from leitir.adapters import PythonAdapter
from leitir.cli import ExitCode, main
from leitir.discovery_search import (
    CodeSearchError,
    CodeSearchHit,
    CodeSearchPage,
    CoverageBounds,
    GlobalSearcher,
)
from leitir.search import Predicate, PredicateKind, SearchMode, SearchSpec
from leitir.tree import BlobEntry

SHA = "a" * 40

CONTENT = """\
def urlencode(query, doseq=False):
    if doseq:
        for k, v in query:
            pass
    return query
"""


def _content_for(path: str) -> bytes:
    return (CONTENT + f"\n# {path}\n").encode()


def _blob_for(path: str) -> str:
    content = _content_for(path)
    return hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\x00" + content
    ).hexdigest()


def _hit(path: str = "Lib/urllib/parse.py", slug: str = "python/cpython") -> CodeSearchHit:
    return CodeSearchHit(
        slug=slug,
        path=path,
        blob_sha=_blob_for(path),
        commit_sha=SHA,
        html_url=f"https://github.com/{slug}/blob/{SHA}/{path}",
    )


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


# --- scripted fixtures (complete + incomplete + multi-page + zero + cap) ---

TWO_HITS = (_hit(), _hit("Lib/urllib/parse.py", "python/cpython-fork"))


def _mixed_page(python_hits: int, markdown_hits: int, *, total: int) -> CodeSearchPage:
    """A full-ish page mixing adapter-eligible and ineligible hits.

    Only the eligible (``.py``) hits can pass Phase A's candidate budget, so
    pages dominated by ineligible hits traverse to further pages instead of
    stopping on the result budget.
    """

    hits: list[CodeSearchHit] = [_hit(f"Lib/urllib/parse{index}.py") for index in range(python_hits)]
    hits += [
        CodeSearchHit(
            slug="python/cpython",
            path=f"docs/design/module-{index}.md",
            blob_sha=_blob_for(f"docs/design/module-{index}.md"),
            commit_sha=SHA,
            html_url=f"https://github.com/python/cpython/blob/{SHA}/docs/design/module-{index}.md",
        )
        for index in range(markdown_hits)
    ]
    return CodeSearchPage(hits=tuple(hits), total_count=total, incomplete_results=False)


FIXTURES: dict[str, dict[int, CodeSearchPage]] = {
    "complete-single-page": {
        1: CodeSearchPage(hits=TWO_HITS, total_count=2, incomplete_results=False)
    },
    "incomplete-server-flag": {
        1: CodeSearchPage(hits=TWO_HITS, total_count=1000, incomplete_results=True)
    },
    "multi-page-complete": {
        1: _mixed_page(1, 29, total=31),
        2: _mixed_page(0, 5, total=31),
    },
    "zero-results": {
        1: CodeSearchPage(hits=(), total_count=0, incomplete_results=False)
    },
}


def canonical_fixture_digest(pages: dict[int, CodeSearchPage]) -> str:
    payload = {
        str(number): {
            "hits": [
                {
                    "slug": hit.slug,
                    "path": hit.path,
                    "blob_sha": hit.blob_sha,
                    "commit_sha": hit.commit_sha,
                    "html_url": hit.html_url,
                }
                for hit in page.hits
            ],
            "total_count": page.total_count,
            "incomplete_results": page.incomplete_results,
        }
        for number, page in sorted(pages.items())
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


PINNED_FIXTURE_DIGESTS = {
    "complete-single-page": (
        "d4a68a9feac579533abad053a8cf04d23da935eabf9a55f72a67993b752b0002"
    ),
    "incomplete-server-flag": (
        "31486935f185697408a41b3d7fcfdec2ebcd2c05d33d16c9aefe402352ff98bd"
    ),
    "multi-page-complete": (
        "46ab9a64548abe7a0bfe39324c7ddefa901c78c4d6b03d70873341d45c157cc8"
    ),
    "zero-results": (
        "3b1182965fb2353c6961be627dbabc379f50eb0a10b0a761e637cd14a8a055a7"
    ),
}


def _searcher(
    pages: dict[int, CodeSearchPage],
    *,
    max_results: int = 30,
    max_pages: int = 10,
    page_errors: dict[int, Exception] | None = None,
) -> tuple[GlobalSearcher, ScriptedCodeSearch]:
    cs = ScriptedCodeSearch(pages, page_errors=page_errors)
    searcher = GlobalSearcher(
        code_search=cs,
        tree_source=FakeTree(),
        adapters=(PythonAdapter(),),
        blob_reader=lambda slug, sha, path: _content_for(path),
        max_results=max_results,
        max_pages=max_pages,
        clock=lambda: "2026-08-21T00:00:00Z",
    )
    return searcher, cs


def _spec() -> SearchSpec:
    return SearchSpec(
        mode=SearchMode.GLOBAL_DISCOVERY,
        must=(Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),),
    )


def _invoke_global(
    pages: dict[int, CodeSearchPage],
    *,
    max_results: int = 30,
    max_pages: int = 10,
    argv: list[str] | None = None,
) -> tuple[int, str, str, GlobalSearcher]:
    searcher, _cs = _searcher(pages, max_results=max_results, max_pages=max_pages)
    out, err = io.StringIO(), io.StringIO()
    code = main(
        argv
        or [
            "search",
            "--global",
            "--must",
            "identifier:urlencode:python",
        ],
        code_search_factory=lambda _token: ScriptedCodeSearch(pages),
        global_searcher_factory=lambda cs, ts, mr, mp: searcher,
        stdout=out,
        stderr=err,
    )
    return code, out.getvalue(), err.getvalue(), searcher


def test_scripted_fixture_digests_are_pinned() -> None:
    """Contract: scripted fixtures are pinned by digest (recorded in the PR)."""

    computed = {
        name: canonical_fixture_digest(pages) for name, pages in FIXTURES.items()
    }
    assert computed == PINNED_FIXTURE_DIGESTS


def test_provider_coverage_reported() -> None:
    """AC-1/G-0-i: complete scripted result, 1 page -> pages=1, matches=N, complete."""

    code, out, err, searcher = _invoke_global(FIXTURES["complete-single-page"])
    assert code == ExitCode.SUCCESS
    payload = json.loads(out)
    matches = len(payload["matches"])
    assert matches >= 1
    assert (
        f"coverage=bounded-discovery pages=1 matches={matches} incomplete=false"
        in err
    )
    assert "indeterminate" not in err
    bounds = searcher.last_coverage_bounds
    assert bounds == CoverageBounds(
        pages_fetched=1,
        matches_returned=matches,
        incomplete=False,
        bounds=(),
    )

    if os.environ.get("LEITIR_ENABLE_LIVE_E2E") == "1":
        # G-4 live arm: real read-only GitHub code search through the CLI.
        live_out, live_err = io.StringIO(), io.StringIO()
        live_code = main(
            [
                "search",
                "--global",
                "--must",
                "identifier:urlencode:python",
                "--max-results",
                "5",
                "--max-pages",
                "2",
            ],
            stdout=live_out,
            stderr=live_err,
        )
        assert live_code == ExitCode.SUCCESS
        statement = re.search(
            r"coverage=bounded-discovery pages=(\d+) matches=(\d+) "
            r"incomplete=(true|false)",
            live_err.getvalue(),
        )
        assert statement is not None
        pages, reported_matches, incomplete = statement.groups()
        assert int(pages) >= 1
        assert int(reported_matches) >= 0
        # One verified file can yield several span matches, so the count is
        # cross-checked against the machine payload, not the result budget.
        assert int(reported_matches) == len(json.loads(live_out.getvalue())["matches"])
        assert incomplete in ("true", "false")
        if incomplete == "true":
            assert "bound=" in live_err.getvalue()
            assert "results may be incomplete" in live_err.getvalue()
    else:
        pytest.skip("set LEITIR_ENABLE_LIVE_E2E=1 to run live coverage verification")


def test_partial_results_flagged_incomplete() -> None:
    """AC-2/G-0-i: incomplete_results:true -> flag + explanation + provenance."""

    code, out, err, searcher = _invoke_global(FIXTURES["incomplete-server-flag"])
    assert code == ExitCode.SUCCESS
    payload = json.loads(out)
    matches = len(payload["matches"])
    assert (
        f"coverage=bounded-discovery pages=1 matches={matches} incomplete=true"
        in err
    )
    assert "bound=incomplete-results" in err
    assert "results may be incomplete" in err
    assert searcher.last_coverage_bounds is not None
    assert searcher.last_coverage_bounds.incomplete is True
    assert "incomplete-results" in searcher.last_coverage_bounds.bounds


def test_multi_page_complete_reports_pages_fetched() -> None:
    """Multi-page traversal: pages=2, complete, no indeterminate fallback."""

    code, out, err, searcher = _invoke_global(FIXTURES["multi-page-complete"])
    assert code == ExitCode.SUCCESS
    payload = json.loads(out)
    matches = len(payload["matches"])
    assert (
        f"coverage=bounded-discovery pages=2 matches={matches} incomplete=false"
        in err
    )
    assert "indeterminate" not in err
    assert searcher.last_coverage_bounds == CoverageBounds(
        pages_fetched=2, matches_returned=matches, incomplete=False, bounds=()
    )


def test_page_cap_reports_pages_fetched() -> None:
    """SP-3: the page cap states pages fetched and names the cap."""

    full = _mixed_page(1, 29, total=1000)
    code, _out, err, searcher = _invoke_global({1: full, 2: full}, max_pages=2)
    assert code == ExitCode.SUCCESS
    assert "pages=2" in err
    assert "incomplete=true" in err
    assert "bound=page-cap" in err
    assert "results may be incomplete" in err
    bounds = searcher.last_coverage_bounds
    assert bounds is not None
    assert bounds.pages_fetched == 2
    assert bounds.bounds == ("page-cap",)


def test_zero_results_is_a_complete_answer() -> None:
    """SP-2: zero results, one page -> pages=1, matches=0, complete."""

    code, out, err, searcher = _invoke_global(FIXTURES["zero-results"])
    assert code == ExitCode.SUCCESS
    assert json.loads(out)["matches"] == []
    assert (
        "coverage=bounded-discovery pages=1 matches=0 incomplete=false" in err
    )
    assert "indeterminate" not in err
    assert searcher.last_coverage_bounds == CoverageBounds(
        pages_fetched=1, matches_returned=0, incomplete=False, bounds=()
    )


def test_malformed_first_page_is_a_typed_error_without_bounds() -> None:
    """SP-1: malformed transport -> typed error; no coverage fabrication."""

    searcher, cs = _searcher({}, page_errors={1: CodeSearchError("boom")})
    with pytest.raises(CodeSearchError):
        searcher.search(_spec())
    assert cs.page_numbers == [1]
    # No search completed: no bounds are fabricated (fail-closed honesty).
    assert searcher.last_coverage_bounds is None


def test_transport_failure_mid_search_marks_incomplete() -> None:
    """Mid-search transport failure: incomplete with transport-error provenance."""

    page1 = _mixed_page(1, 29, total=1000)  # full page: page 2 is attempted
    searcher, cs = _searcher(
        {1: page1}, page_errors={2: CodeSearchError("late boom")}
    )
    report = searcher.search(_spec())
    assert cs.page_numbers == [1, 2]
    bounds = searcher.last_coverage_bounds
    assert bounds is not None
    assert bounds.pages_fetched == 1  # page 2 was attempted, not fetched
    assert bounds.matches_returned == len(report.matches)
    assert bounds.incomplete is True
    assert "transport-error" in bounds.bounds


def test_sequential_searches_keep_bounds_per_invocation() -> None:
    """SP-4: each rendering reflects its own invocation's bounds."""

    searcher, cs = _searcher(FIXTURES["complete-single-page"])
    first = searcher.search(_spec())
    first_bounds = searcher.last_coverage_bounds
    assert first_bounds is not None

    # Second invocation on the same searcher sees a different script.
    cs.pages = dict(FIXTURES["incomplete-server-flag"])
    second = searcher.search(_spec())
    second_bounds = searcher.last_coverage_bounds
    assert second_bounds is not None

    assert first_bounds.pages_fetched == 1 and first_bounds.incomplete is False
    assert second_bounds.incomplete is True
    assert "incomplete-results" in second_bounds.bounds
    # Coherence: bounds agree with their own report, never the other's.
    assert first_bounds.matches_returned == len(first.matches)
    assert second_bounds.matches_returned == len(second.matches)
