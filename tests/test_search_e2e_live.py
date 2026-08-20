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

import fixtures_real as fx
import pytest

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
        reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub verification",
    )
]

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


def test_live_search_pins_latest_stable_tag():
    """Discovery pins donors to immutable release tags by default (issue #189).

    Runs the real transport against a real tagged repository, then verifies
    the returned pin independently: the commit SHA must equal the tag's
    dereferenced commit (the API equivalent of ``git rev-parse <tag>^{commit}``)
    and the tag name must be a stable release tag present in the newest page
    of repository tags.
    """
    import re

    from leitir.discovery_search import GitHubCodeSearchTransport

    slug = "matrix-org/matrix-js-sdk"
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    transport = GitHubCodeSearchTransport(token=token)
    pin = transport.resolve_default_pin(slug)

    assert pin.slug == slug
    assert pin.ref_kind == "tag"
    assert pin.immutable is True
    assert re.fullmatch(r"[vV]?\d+\.\d+\.\d+", pin.ref_name), pin.ref_name
    assert re.fullmatch(r"[0-9a-f]{40}", pin.commit_sha)

    headers = dict(_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    ref_request = urllib.request.Request(
        f"{_API}/repos/{slug}/git/ref/tags/{pin.ref_name}", headers=headers
    )
    with urllib.request.urlopen(ref_request, timeout=30) as response:
        ref_payload = json.load(response)
    obj = ref_payload["object"]
    if obj["type"] == "tag":
        peel_request = urllib.request.Request(
            f"{_API}/repos/{slug}/git/tags/{obj['sha']}", headers=headers
        )
        with urllib.request.urlopen(peel_request, timeout=30) as response:
            obj = json.load(response)["object"]
    assert obj["type"] == "commit"
    assert obj["sha"] == pin.commit_sha

    tags_request = urllib.request.Request(
        f"{_API}/repos/{slug}/tags?per_page=100", headers=headers
    )
    with urllib.request.urlopen(tags_request, timeout=30) as response:
        newest_names = {str(entry["name"]) for entry in json.load(response)}
    assert pin.ref_name in newest_names
