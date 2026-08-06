"""Opt-in live probe matrix for issue #49 (G6).

The legacy ``GET /search/code`` endpoint differs from GitHub's website code
search.  These probes pin behavioral verdicts rather than drift-prone counts.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub query probes",
)
if os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1":
    pytest.skip(
        "set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub query probes",
        allow_module_level=True,
    )

_API = "https://api.github.com/search/code"
_QUERY_DELAY_SECONDS = 1.0
_RATE_LIMIT_RETRY_SECONDS = 2.0


@dataclass(frozen=True)
class _ProbeResult:
    status: int
    total_count: int | None


class _LegacyCodeSearchProbe:
    def __init__(self) -> None:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            pytest.skip("GH_TOKEN or GITHUB_TOKEN is required for live query probes")
        self._headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "leitir-query-probe",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self._has_called = False
        self._cache: dict[str, _ProbeResult] = {}

    def search(self, query: str) -> _ProbeResult:
        if query in self._cache:
            return self._cache[query]
        if self._has_called:
            time.sleep(_QUERY_DELAY_SECONDS)
        self._has_called = True

        result = self._request(query)
        if result.status != 403:
            self._cache[query] = result
            return result

        time.sleep(_RATE_LIMIT_RETRY_SECONDS)
        result = self._request(query)
        if result.status == 403:
            pytest.skip("search rate-limited")
        self._cache[query] = result
        return result

    def _request(self, query: str) -> _ProbeResult:
        params = urllib.parse.urlencode({"q": query, "per_page": 1})
        request = urllib.request.Request(f"{_API}?{params}", headers=self._headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
            total_count = payload.get("total_count")
            assert isinstance(total_count, int)
            return _ProbeResult(status=200, total_count=total_count)
        except urllib.error.HTTPError as exc:
            return _ProbeResult(status=exc.code, total_count=None)


@pytest.fixture(scope="module")
def probe() -> _LegacyCodeSearchProbe:
    return _LegacyCodeSearchProbe()


def _successful_count(result: _ProbeResult) -> int:
    assert result.status == 200
    assert result.total_count is not None
    return result.total_count


def test_regex_forms_are_not_honored(probe: _LegacyCodeSearchProbe) -> None:
    control_count = _successful_count(probe.search("urlencode"))

    for query in (
        "/urlencode/",
        "regex:urlencode",
        "symbol:urlencode",
        "urlencode(?=x)",
    ):
        result = probe.search(query)
        assert (400 <= result.status < 500) or (
            result.status == 200 and result.total_count != control_count
        )


def test_honored_qualifiers_narrow_results(probe: _LegacyCodeSearchProbe) -> None:
    control_count = _successful_count(probe.search("urlencode"))

    for query in (
        "path:urllib urlencode",
        "urlencode language:python",
        "urlencode doseq",
    ):
        assert _successful_count(probe.search(query)) < control_count


def test_in_comments_and_in_body_are_rejected(
    probe: _LegacyCodeSearchProbe,
) -> None:
    for query in ("urlencode in:comments", "urlencode in:body"):
        assert probe.search(query).status == 422
