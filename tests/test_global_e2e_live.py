"""Opt-in live gate for global discovery (ADR-001 P5).

Skipped unless LEITIR_ENABLE_LIVE_E2E=1. Drives ``leitir search --global``
against the live GitHub Code Search API and verifies honest coverage reporting.
"""

from __future__ import annotations

import io
import json
import os

import pytest

from leitir.cli import ExitCode, main

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
)


def _invoke(argv):
    out = io.StringIO()
    err = io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


class TestLiveGlobalDiscovery:
    def test_finds_python_symbol(self):
        code, out, err = _invoke([
            "search", "--global",
            "--must", "symbol_definition:urlencode:python",
            "--must", "path:urllib",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert payload["coverage"]["status"] == "indeterminate_global"
        assert len(payload["matches"]) > 0

    def test_coverage_is_honest(self):
        code, out, _ = _invoke([
            "search", "--global",
            "--must", "identifier:urlencode:python",
        ])
        payload = json.loads(out)
        cov = payload["coverage"]
        assert cov["status"] == "indeterminate_global"
        assert cov["files_indexed"] >= 0
        assert cov["files_eligible"] >= 0

    def test_provenance_has_commit_sha(self):
        code, out, _ = _invoke([
            "search", "--global",
            "--must", "symbol_definition:urlencode:python",
            "--must", "path:urllib",
        ])
        payload = json.loads(out)
        if payload["matches"]:
            sha = payload["matches"][0]["source"]["commit_sha"]
            assert len(sha) == 40


class TestLiveGlobalSadPaths:
    def test_no_results_for_absurd_query(self):
        code, out, _ = _invoke([
            "search", "--global",
            "--must", "identifier:zzz_nonexistent_symbol_xyz_999:python",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert payload["coverage"]["status"] == "indeterminate_global"


class TestLiveTransportDirect:
    """Drive GitHubCodeSearchTransport directly against the real GitHub API.

    Proves the transport + retry wiring succeeds on the real happy path (the
    retry path itself is proven against a real local server in
    test_http_retry_real.py; transient failures cannot be forced on live
    GitHub). Loops twice to confirm stability across consecutive calls.
    """

    def _token(self) -> str | None:
        return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

    @pytest.mark.parametrize("iteration", range(2))
    def test_real_code_search_returns_hits(self, iteration):
        from leitir.discovery_search import GitHubCodeSearchTransport

        transport = GitHubCodeSearchTransport(token=self._token())
        page = transport.search("urlencode language:python path:urllib", per_page=5)
        assert page.total_count > 0
        assert len(page.hits) >= 1
        hit = page.hits[0]
        assert "/" in hit.slug
        assert len(hit.blob_sha) == 40

    @pytest.mark.parametrize("iteration", range(2))
    def test_real_resolve_head_sha(self, iteration):
        from leitir.discovery_search import GitHubCodeSearchTransport

        transport = GitHubCodeSearchTransport(token=self._token())
        sha = transport.resolve_head_sha("python/cpython")
        assert len(sha) == 40

    def test_real_404_is_fatal_not_retried(self):
        # Resolving HEAD for a repo that does not exist returns a real 404,
        # which must surface immediately (fatal) rather than be retried.
        from leitir.discovery_search import CodeSearchError, GitHubCodeSearchTransport

        transport = GitHubCodeSearchTransport(token=self._token(), max_attempts=4)
        with pytest.raises(CodeSearchError, match="HTTP 40"):
            transport.resolve_head_sha("leitir/no-such-repo-xyz-999")
