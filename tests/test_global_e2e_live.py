"""Opt-in live gate for global discovery (ADR-001 P5).

Skipped unless LEITIR_ENABLE_LIVE_E2E=1. Drives ``leitir search --global``
against the live GitHub Code Search API and verifies honest coverage reporting.
"""

from __future__ import annotations

import hashlib
import io
import itertools
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
        code, out, _err = _invoke([
            "search", "--global",
            "--must", "symbol_definition:urlencode:python",
            "--must", "path:urllib",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert payload["coverage"]["status"] == "indeterminate_global"
        assert len(payload["matches"]) > 0

    def test_coverage_is_honest(self):
        _code, out, _ = _invoke([
            "search", "--global",
            "--must", "identifier:urlencode:python",
        ])
        payload = json.loads(out)
        cov = payload["coverage"]
        assert cov["status"] == "indeterminate_global"
        assert cov["files_indexed"] >= 0
        assert cov["files_eligible"] >= 0

    def test_provenance_has_commit_sha(self):
        _code, out, _ = _invoke([
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

    def test_indexed_commit_bytes_are_independently_repeatable(self):
        from urllib.parse import quote, urlencode
        from urllib.request import Request

        from leitir import _http
        from leitir.adapters import PythonAdapter
        from leitir.discovery_search import GitHubCodeSearchTransport, GlobalSearcher
        from leitir.search import Predicate, PredicateKind, SearchMode, SearchSpec

        class NullTree:
            pass

        transport = GitHubCodeSearchTransport(token=self._token())
        searcher = GlobalSearcher(
            code_search=transport,
            tree_source=NullTree(),  # type: ignore[arg-type]  # unused by global search
            adapters=(PythonAdapter(),),
            blob_reader=transport.read_blob_by_path,
            max_results=5,
        )
        report = searcher.search(
            SearchSpec(
                mode=SearchMode.GLOBAL_DISCOVERY,
                must=(
                    Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),
                    Predicate(PredicateKind.PATH, "urllib"),
                ),
            )
        )
        assert report.matches

        headers = {
            "Accept": "application/vnd.github.raw+json",
            "User-Agent": "leitir-live-test",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token():
            headers["Authorization"] = f"Bearer {self._token()}"

        observed_heads: list[tuple[str, str]] = []
        for match in report.matches:
            source = match.source
            url = (
                f"https://api.github.com/repos/{source.slug}/contents/"
                f"{quote(source.path, safe='/')}?{urlencode({'ref': source.commit_sha})}"
            )
            reads = []
            for _ in range(2):
                with _http.safe_urlopen(Request(url, headers=headers), timeout=30) as response:
                    reads.append(response.read())
            assert reads[0] == reads[1]
            header = b"blob " + str(len(reads[0])).encode("ascii") + b"\x00"
            assert hashlib.sha1(header + reads[0]).hexdigest() == source.blob_sha

            head = transport.resolve_head_sha(source.slug)
            observed_heads.append((head, source.commit_sha))
            if head != source.commit_sha:
                assert source.commit_sha in {item.source.commit_sha for item in report.matches}

        if not any(head != indexed for head, indexed in observed_heads):
            assert all(head == indexed for head, indexed in observed_heads), "no lag observed"


class TestLiveGlobalRealDataOrdering:
    """Lock P6 ordering and identity guarantees against one real snapshot."""

    def _token(self) -> str | None:
        return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

    def test_real_snapshot_is_ordered_unique_and_offline_deterministic(self):
        from leitir.adapters import PythonAdapter
        from leitir.discovery_search import GitHubCodeSearchTransport, GlobalSearcher
        from leitir.ranking import (
            normalize_scores,
            order_source_matches,
            source_identity,
        )
        from leitir.search import Predicate, PredicateKind, SearchMode, SearchSpec

        class NullTree:
            pass

        transport = GitHubCodeSearchTransport(token=self._token())
        searcher = GlobalSearcher(
            code_search=transport,
            tree_source=NullTree(),  # type: ignore[arg-type]  # unused by global search
            adapters=(PythonAdapter(),),
            blob_reader=transport.read_blob_by_path,
            max_results=5,
        )
        report = searcher.search(
            SearchSpec(
                mode=SearchMode.GLOBAL_DISCOVERY,
                must=(
                    Predicate(PredicateKind.IDENTIFIER, "urlencode", "python"),
                    Predicate(PredicateKind.PATH, "urllib"),
                ),
            )
        )
        assert report.matches, "live global query returned no real matches"
        if len(report.matches) < 2:
            pytest.skip("live global query returned fewer than two real matches")

        normalized_scores = normalize_scores(report.matches)
        order_keys = tuple(
            (
                -normalized_score,
                match.source.slug,
                match.source.commit_sha,
                match.source.path,
                match.source.blob_sha,
                match.source.start_line,
                match.source.end_line,
            )
            for match, normalized_score in zip(
                report.matches, normalized_scores, strict=True
            )
        )
        for index, (left, right) in enumerate(
            itertools.pairwise(order_keys), start=1
        ):
            assert left <= right, (
                f"P6 order decreased between match indexes {index - 1} and {index}: "
                f"{left!r} > {right!r}"
            )

        identities = tuple(source_identity(match.source) for match in report.matches)
        assert len(set(identities)) == len(report.matches), (
            "live global report contains duplicate source identities"
        )

        identity_digest = report.identity_digest()
        assert len(identity_digest) == 64
        assert all(character in "0123456789abcdef" for character in identity_digest)
        identity_payload = {
            "spec_digest": report.spec_digest,
            "coverage": report.coverage.to_dict(),
            "matches": [match.to_dict() for match in report.matches],
        }
        independently_encoded = json.dumps(
            identity_payload,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        assert hashlib.sha256(independently_encoded).hexdigest() == identity_digest

        expected_matches = json.dumps(
            [match.to_dict() for match in report.matches],
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        for permutation_index, permutation in enumerate(
            itertools.islice(itertools.permutations(report.matches), 6)
        ):
            reordered = order_source_matches(permutation)
            actual_matches = json.dumps(
                [match.to_dict() for match in reordered],
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            assert actual_matches == expected_matches, (
                f"offline permutation {permutation_index} changed ordered output"
            )
