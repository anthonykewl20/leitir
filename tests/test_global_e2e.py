"""Offline e2e gate for global discovery (ADR-001 P5).

Runs without network. Drives the full ``leitir search --global`` flow using
a fake code search port seeded with real fixture data and an in-memory tree.
Proves the CLI wires GlobalSearcher correctly and emits valid JSON with
INDETERMINATE_GLOBAL coverage.
"""

from __future__ import annotations

import hashlib
import io
import json

import fixtures_real as fx

from leitir.adapters import PythonAdapter
from leitir.cli import ExitCode, main
from leitir.discovery_search import (
    CodeSearchHit,
    CodeSearchPage,
    GlobalSearcher,
)
from leitir.tree import BlobEntry

REPRESENTATIVE_CONTENT = """\
def urlencode(query, doseq=False, safe='', encoding=None, errors=None,
              quote_via=quote_plus):
    if doseq:
        for k, v in query:
            if isinstance(v, (str, bytes)):
                v = quote_via(v, safe, encoding, errors)
            else:
                v = quote_via(str(v), safe, encoding, errors)
            l.append(k + '=' + v)
    else:
        if isinstance(query, bytes):
            query = query.decode(encoding, errors)
        query = quote_via(query, safe, encoding, errors)
    return '&'.join(l)
"""
REPRESENTATIVE_BYTES = REPRESENTATIVE_CONTENT.encode()
REPRESENTATIVE_BLOB_SHA = hashlib.sha1(
    b"blob "
    + str(len(REPRESENTATIVE_BYTES)).encode("ascii")
    + b"\x00"
    + REPRESENTATIVE_BYTES
).hexdigest()


class _FakeCodeSearch:
    def __init__(self, page: CodeSearchPage):
        self._page = page
        self.queries: list[str] = []

    def search(self, query: str, *, per_page: int = 10, page: int = 1) -> CodeSearchPage:
        self.queries.append(query)
        return self._page

    def resolve_head_sha(self, slug: str) -> str:
        if slug == fx.REPO_SLUG:
            return fx.COMMIT_SHA
        raise RuntimeError(f"unknown slug {slug}")

    def read_blob_by_path(self, slug: str, commit_sha: str, path: str) -> bytes:
        if slug == fx.REPO_SLUG and path == fx.PATH:
            return REPRESENTATIVE_BYTES
        return b""


class _FakeTree:
    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        return ()

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        return b""


def _page(*hits) -> CodeSearchPage:
    return CodeSearchPage(
        hits=tuple(hits),
        total_count=len(hits),
        incomplete_results=False,
    )


def _hit(**overrides) -> CodeSearchHit:
    base = {
        "slug": fx.REPO_SLUG,
        "path": fx.PATH,
        "blob_sha": REPRESENTATIVE_BLOB_SHA,
        "html_url": f"https://github.com/{fx.REPO_SLUG}/blob/{fx.COMMIT_SHA}/{fx.PATH}",
        "commit_sha": fx.COMMIT_SHA,
    }
    base.update(overrides)
    return CodeSearchHit(**base)


def _invoke(argv, page=None):
    cs = _FakeCodeSearch(page or _page(_hit()))
    out = io.StringIO()
    err = io.StringIO()
    code = main(
        argv,
        tree_source_factory=lambda _token: _FakeTree(),
        code_search_factory=lambda _token: cs,
        global_searcher_factory=lambda code_search, tree_source: GlobalSearcher(
            code_search=code_search,
            tree_source=tree_source,
            adapters=(PythonAdapter(),),
            blob_reader=code_search.read_blob_by_path,
        ),
        stdout=out,
        stderr=err,
    )
    return code, out.getvalue(), err.getvalue(), cs


class TestGlobalHappyPath:
    def test_finds_urlencode_with_real_provenance(self):
        code, out, _, _ = _invoke([
            "search", "--global",
            "--must", "symbol_definition:urlencode:python",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert len(payload["matches"]) > 0
        top = payload["matches"][0]
        assert top["source"]["slug"] == fx.REPO_SLUG
        assert top["source"]["commit_sha"] == fx.COMMIT_SHA
        assert top["source"]["path"] == fx.PATH
        assert top["source"]["blob_sha"] == REPRESENTATIVE_BLOB_SHA

    def test_coverage_is_indeterminate_global(self):
        _, out, _, _ = _invoke([
            "search", "--global",
            "--must", "identifier:urlencode:python",
        ])
        payload = json.loads(out)
        assert payload["coverage"]["status"] == "indeterminate_global"

    def test_permalink_in_output(self):
        _, out, _, _ = _invoke([
            "search", "--global",
            "--must", "symbol_definition:urlencode:python",
        ])
        payload = json.loads(out)
        permalink = payload["matches"][0]["source"]["permalink"]
        assert f"/blob/{fx.COMMIT_SHA}/" in permalink

    def test_stderr_summary_present(self):
        _, _, err, _ = _invoke([
            "search", "--global",
            "--must", "identifier:urlencode:python",
        ])
        assert "coverage=indeterminate_global" in err
        assert "matches=" in err

    def test_query_translated_correctly(self):
        _, _, _, cs = _invoke([
            "search", "--global",
            "--must", "identifier:urlencode:python",
        ])
        assert len(cs.queries) == 1
        assert "urlencode" in cs.queries[0]
        assert "language:python" in cs.queries[0]


class TestGlobalSadPaths:
    def test_no_hits_yields_empty_report(self):
        code, out, err, _ = _invoke(
            ["search", "--global", "--must", "identifier:zzz_absent"],
            page=_page(),
        )
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert payload["matches"] == []
        assert "matches=0" in err

    def test_incomplete_results_threaded(self):
        page = CodeSearchPage(hits=(), total_count=999, incomplete_results=True)
        _, out, _, _ = _invoke(
            ["search", "--global", "--must", "identifier:foo"],
            page=page,
        )
        payload = json.loads(out)
        assert payload["coverage"]["incomplete_results"] is True
        assert payload["coverage"]["files_eligible"] == 999

    def test_global_and_repo_are_mutually_exclusive(self):
        code = main([
            "search", "--global", "--repo", "o/r", "--commit", "a" * 40,
            "--must", "identifier:x",
        ])
        assert code == ExitCode.MALFORMED_USAGE

    def test_no_scope_flag_at_all_is_malformed(self):
        code = main(
            ["search", "--must", "identifier:x"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert code == ExitCode.MALFORMED_USAGE

    def test_api_error_is_infrastructure_failure(self):
        class FailSearch:
            def search(self, query, *, per_page=10, page=1):
                raise RuntimeError("rate limited")

        out = io.StringIO()
        err = io.StringIO()
        code = main(
            ["search", "--global", "--must", "identifier:x"],
            code_search_factory=lambda _token: FailSearch(),
            global_searcher_factory=lambda cs, ts: GlobalSearcher(
                code_search=cs, tree_source=ts, adapters=(PythonAdapter(),),
            ),
            stdout=out,
            stderr=err,
        )
        assert code == ExitCode.INFRASTRUCTURE_FAILURE
        assert "rate limited" in err.getvalue()
