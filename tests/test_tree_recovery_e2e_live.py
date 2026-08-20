"""Opt-in live canary surface: truncated recursive-tree recovery (#197 C-3).

Skipped unless LEITIR_ENABLE_LIVE_E2E=1. Exercises the paginated-walk
recovery that #187 (A1) added to ``GitHubTreeSource.list_blobs_ex`` against
two pinned public fixtures, read-only:

- ``LIVE_CANARY_FIXTURE_REPO``/``_COMMIT`` (workflow default
  ``torvalds/linux@d58772d8…``): the recursive listing is asserted to arrive
  truncated — the precondition that makes this surface a canary. A full
  recovery walk on Linux needs one request per subtree (~5.8k requests,
  OBSERVED 2026-08-20 from the truncated listing's tree count), which cannot
  complete inside a single 5,000-request/hour API window, so the walk itself
  runs on the second fixture below. The owner can still point the walk at
  Linux via ``LIVE_CANARY_RECOVERY_FIXTURE_REPO``/``_COMMIT``.
- ``LIVE_CANARY_RECOVERY_FIXTURE_REPO``/``_COMMIT`` (default
  ``microsoft/TypeScript@b465fdb…``, the same pinned fixture as
  tests/test_tree.py): a genuinely truncated recursive listing whose
  paginated recovery walk (~2k requests) fits a rate-limit window. The
  surface asserts the walk completes, reports ``recovered=True``, and returns
  a strictly larger blob universe than the truncated listing exposed.

Status disclosure (2026-08-21): the ~2k-request recovery walk below has NOT
yet produced a green live run end-to-end; until it does, the workflow
variable ``LEITIR_CANARY_TREE_V2`` stays ``false`` (owner-gated, see the
``truncated-tree-recovery`` job and ``gate`` outputs in
``.github/workflows/live-canary.yml``). Building this surface is the
prerequisite; observing it green is the promotion evidence.

API/host failures propagate as typed tree errors; the canary plugin then
classifies them honestly (infra-failure/configuration-failure) — never a
silent pass.
"""

from __future__ import annotations

import json
import os
from urllib.request import Request

import pytest

from leitir import _http
from leitir.tree import GitHubTreeSource

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub verification",
)

# Workflow-pinned truncation precondition fixture (live-canary.yml
# truncated-tree-recovery job).  Pinned by commit; re-verified live.
TRUNCATION_REPO = os.environ.get("LIVE_CANARY_FIXTURE_REPO", "torvalds/linux")
TRUNCATION_COMMIT = os.environ.get(
    "LIVE_CANARY_FIXTURE_COMMIT", "d58772d8520c7ef247c4b95c9bd76d3a25da9ff5"
)

# Recovery-walk fixture: truncated listing, completable walk.  Same pin as
# tests/test_tree.py::TYPESCRIPT_COMMIT (OBSERVED: 53,309 blobs visible in
# the truncated recursive listing of 55,311 total, 2026-08-18).
RECOVERY_REPO = os.environ.get(
    "LIVE_CANARY_RECOVERY_FIXTURE_REPO", "microsoft/TypeScript"
)
RECOVERY_COMMIT = os.environ.get(
    "LIVE_CANARY_RECOVERY_FIXTURE_COMMIT",
    "b465fdbfe175304d9b977da137b2c178ae1091d3",
)
RECOVERY_TRUNCATED_VISIBLE_BLOBS = 53_309

_EXPECT_TRUNCATED = os.environ.get("LIVE_CANARY_EXPECT_TRUNCATED_TREE", "true")


def _token() -> str | None:
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "leitir-live-canary",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = _token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_recursive_listing(slug: str, commit_sha: str) -> dict[str, object]:
    # Routed through the shared categorized retry seam (_http.make_retry,
    # same default policy as GitHubTreeSource) so transient transport
    # failures retry like every production call instead of failing the
    # canary on first blip. The response body is read inside the retried
    # operation: no bytes are yielded mid-flight, so replay is safe here
    # (unlike read_blob_stream's mid-stream discipline).
    retry = _http.make_retry(
        max_attempts=4,
        base_delay=1.0,
        max_delay=60.0,
        max_rate_limit_delay=300.0,
        sleeper=None,
    )
    url = f"https://api.github.com/repos/{slug}/git/trees/{commit_sha}?recursive=1"

    def _open() -> dict[str, object]:
        with _http.safe_urlopen(
            Request(url, headers=_headers()), timeout=60
        ) as response:
            payload: object = json.load(response)
        if not isinstance(payload, dict):
            raise AssertionError("recursive tree listing must be a JSON object")
        return payload

    return retry(_open)


def test_pinned_fixture_recursive_listing_arrives_truncated() -> None:
    payload = _fetch_recursive_listing(TRUNCATION_REPO, TRUNCATION_COMMIT)
    entries = payload.get("entries") or payload.get("tree") or []
    assert isinstance(entries, list) and entries, "listing must expose entries"
    if _EXPECT_TRUNCATED == "true":
        assert payload.get("truncated") is True, (
            f"{TRUNCATION_REPO}@{TRUNCATION_COMMIT} recursive listing is no "
            "longer truncated; the canary precondition drifted — repin"
        )
    # Provenance (OBSERVED 2026-08-21, authenticated call through
    # leitir._http.safe_urlopen): ``GET /git/trees/{commit}?recursive=1``
    # echoes the *requested* identifier in the response ``sha`` field — here
    # the commit SHA d58772d8…, NOT the commit's underlying tree SHA
    # (e61a1d8e0fd5f82e786b93bb95607378b069eb9b, cross-checked via
    # ``GET /git/commits/{commit}`` and confirmed different). The assertion
    # below therefore pins response-echo consistency against the commit pin.
    assert payload.get("sha") == TRUNCATION_COMMIT


def test_truncated_listing_recovery_walk_completes_with_full_universe() -> None:
    listing = _fetch_recursive_listing(RECOVERY_REPO, RECOVERY_COMMIT)
    assert listing.get("truncated") is True, (
        f"{RECOVERY_REPO}@{RECOVERY_COMMIT} must arrive truncated for the "
        "recovery surface to exercise the paginated fallback"
    )
    visible = {
        entry["path"]
        for entry in (listing.get("entries") or listing.get("tree") or [])
        if isinstance(entry, dict) and entry.get("type") == "blob"
    }

    source = GitHubTreeSource(token=_token())
    blobs, recovered = source.list_blobs_ex(RECOVERY_REPO, RECOVERY_COMMIT)

    # Recovery actually happened via the paginated walk, not a silent sample.
    assert recovered is True
    paths = [blob.path for blob in blobs]
    assert paths == sorted(paths), "recovered universe must be path-sorted"
    assert len(set(paths)) == len(paths), "recovered universe must be unique"
    assert len(blobs) > len(visible), (
        "recovered universe must exceed the truncated listing's visible blobs"
    )
    assert len(blobs) > RECOVERY_TRUNCATED_VISIBLE_BLOBS
    # Every blob visible in the truncated listing must survive recovery.
    assert visible <= set(paths)
    for blob in blobs:
        assert len(blob.blob_sha) == 40
        assert blob.size >= 0
    print(
        f"tree-recovery surface: visible={len(visible)} recovered={len(blobs)} "
        f"fixture={RECOVERY_REPO}@{RECOVERY_COMMIT[:12]}"
    )
