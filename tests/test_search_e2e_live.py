"""Opt-in live gate: re-verify the pinned real provenance against GitHub.

Skipped unless LEITIR_ENABLE_LIVE_E2E=1, matching the project's existing
opt-in pattern for network/Docker/model operations. This catches fixture drift
and proves the offline e2e data still matches reality.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request

import pytest

import fixtures_real as fx


pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub verification",
)

_API = "https://api.github.com"
_HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "leitir"}


def _get(url: str) -> dict:
    request = urllib.request.Request(url, headers=_HEADERS)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def test_pinned_commit_still_serves_the_expected_blob():
    headers = dict(_HEADERS)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{_API}/repos/{fx.REPO_SLUG}/contents/{fx.PATH}?ref={fx.COMMIT_SHA}",
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    assert payload["sha"] == fx.BLOB_SHA
    assert payload["size"] == fx.BLOB_SIZE


def test_raw_blob_git_sha_matches_the_pinned_value():
    url = (
        f"https://raw.githubusercontent.com/{fx.REPO_SLUG}/"
        f"{fx.COMMIT_SHA}/{fx.PATH}"
    )
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read()
    blob_sha = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert blob_sha == fx.BLOB_SHA
    for symbol in fx.KNOWN_SYMBOLS:
        assert symbol.encode("utf-8") in data


def test_a_corrupted_commit_sha_is_not_silently_accepted():
    bad_sha = ("0" * 40)
    request = urllib.request.Request(
        f"{_API}/repos/{fx.REPO_SLUG}/contents/{fx.PATH}?ref={bad_sha}",
        headers=_HEADERS,
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(request, timeout=30)
    assert excinfo.value.code in {404, 422}
