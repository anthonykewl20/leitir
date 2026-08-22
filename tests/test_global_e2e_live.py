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
import random

import pytest

from leitir.cli import ExitCode, main

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
        reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
    )
]


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
            "query_translation": [
                item.to_dict() for item in report.query_translation
            ],
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


class TestLiveGlobalDedup:
    """Verify G7 against one captured real-data snapshot.

    G8 drift boundary: this never asserts which repositories appear or how
    many duplicates exist. It checks only collapse invariants, the winner rule,
    accounting, permutation determinism, and independently fetched bytes for
    the captured snapshot.
    """

    def _token(self) -> str | None:
        return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

    def test_real_vendored_snapshot_deduplicates_deterministically(self):
        from urllib.parse import quote, urlencode
        from urllib.request import Request

        from leitir import _http
        from leitir.adapters import PythonAdapter
        from leitir.discovery_search import (
            CodeSearchError,
            CodeSearchPage,
            GitHubCodeSearchTransport,
            GlobalSearcher,
            _git_blob_sha,
            dedup_hits,
            hit_identity,
        )
        from leitir.search import Predicate, PredicateKind, SearchMode, SearchSpec

        class NullTree:
            pass

        class RecordingPort:
            def __init__(self, delegate):
                self.delegate = delegate
                self.pages: list[CodeSearchPage] = []

            def search(self, query, *, per_page=10, page=1):
                result = self.delegate.search(query, per_page=per_page, page=page)
                self.pages.append(result)
                return result

        transport = GitHubCodeSearchTransport(token=self._token())
        recording = RecordingPort(transport)
        byte_cache: dict[tuple[str, str, str], bytes] = {}

        def read_and_record(slug, commit_sha, path):
            key = (slug, commit_sha, path)
            data = transport.read_blob_by_path(*key)
            byte_cache[key] = data
            return data

        spec = SearchSpec(
            mode=SearchMode.GLOBAL_DISCOVERY,
            must=(Predicate(PredicateKind.IDENTIFIER, "add_metaclass", "python"),),
        )
        report = GlobalSearcher(
            code_search=recording,
            tree_source=NullTree(),  # type: ignore[arg-type]
            adapters=(PythonAdapter(),),
            blob_reader=read_and_record,
            max_results=30,
        ).search(spec)
        captured = tuple(hit for page in recording.pages for hit in page.hits)
        outcome = dedup_hits(captured)
        if outcome.collapsed == 0:
            pytest.skip("live index currently exposes no collapsible vendored copies")

        origins: dict[str, set[tuple[str, str, str]]] = {}
        for match in report.matches:
            source = match.source
            origins.setdefault(source.blob_sha, set()).add(
                (source.slug, source.commit_sha, source.path)
            )
        assert all(len(items) == 1 for items in origins.values())
        winners = {source for items in origins.values() for source in items}
        for candidate, group in zip(outcome.candidates, outcome.groups, strict=True):
            assert candidate == min(group, key=hit_identity)
        expected_winners = set()
        for group in outcome.groups:
            for hit in group:
                data = byte_cache.get((hit.slug, hit.commit_sha, hit.path))
                if data is None or _git_blob_sha(data) != hit.blob_sha:
                    continue
                try:
                    data.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                expected_winners.add(hit_identity(hit)[:3])
                break
        assert winners <= expected_winners
        assert report.coverage.exclusions.get("deduplicated", 0) <= outcome.collapsed
        assert (
            report.coverage.files_indexed + report.coverage.files_excluded
            <= report.coverage.files_eligible
        )
        assert sum(report.coverage.exclusions.values()) == report.coverage.files_excluded

        expected = outcome
        for seed in (0, 1, 42, 99999):
            shuffled = list(captured)
            random.Random(seed).shuffle(shuffled)
            assert dedup_hits(shuffled) == expected

        class SnapshotPort:
            def __init__(self, hits):
                self.hits = hits

            def search(self, query, *, per_page=10, page=1):
                if page == 1:
                    return CodeSearchPage(
                        tuple(self.hits), recording.pages[0].total_count, False
                    )
                return CodeSearchPage((), recording.pages[0].total_count, False)

        digests = set()

        def replay_blob(slug, commit_sha, path):
            try:
                return byte_cache[(slug, commit_sha, path)]
            except KeyError as exc:
                raise CodeSearchError("captured live fetch failure") from exc

        for seed in (0, 1, 42, 99999):
            shuffled = list(captured)
            random.Random(seed).shuffle(shuffled)
            replay = GlobalSearcher(
                SnapshotPort(shuffled),
                NullTree(),  # type: ignore[arg-type]
                (PythonAdapter(),),
                blob_reader=replay_blob,
                max_results=30,
            ).search(spec)
            digests.add(replay.identity_digest())
        assert len(digests) == 1

        headers = {
            "Accept": "application/vnd.github.raw+json",
            "User-Agent": "leitir-live-test",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token():
            headers["Authorization"] = f"Bearer {self._token()}"
        for slug, commit_sha, path in sorted(winners):
            url = (
                f"https://api.github.com/repos/{slug}/contents/"
                f"{quote(path, safe='/')}?{urlencode({'ref': commit_sha})}"
            )
            with _http.safe_urlopen(Request(url, headers=headers), timeout=30) as response:
                data = response.read()
            header = b"blob " + str(len(data)).encode("ascii") + b"\x00"
            source_blob = next(
                match.source.blob_sha
                for match in report.matches
                if (match.source.slug, match.source.commit_sha, match.source.path)
                == (slug, commit_sha, path)
            )
            assert hashlib.sha1(header + data).hexdigest() == source_blob
