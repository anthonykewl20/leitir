"""Opt-in live re-verification of the immutable search-v1 benchmark pins."""

from __future__ import annotations

import os

import pytest

from leitir.bench import load_manifest
from leitir.tree import GitHubTreeSource

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
        reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
    )
]


def test_all_manifest_sources_are_reachable_and_byte_exact():
    manifest = load_manifest()
    tree = GitHubTreeSource(
        token=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    )
    trees: dict[tuple[str, str], dict[str, str]] = {}
    blobs: dict[tuple[str, str], bytes] = {}

    for task in manifest.tasks:
        scope = task.spec.scopes[0]
        scope_key = (scope.slug, scope.commit_sha)
        if scope_key not in trees:
            trees[scope_key] = {
                entry.path: entry.blob_sha
                for entry in tree.list_blobs(scope.slug, scope.commit_sha)
            }
        expected = task.expected_results[0]
        assert trees[scope_key][expected.path] == expected.blob_sha

        blob_key = (expected.slug, expected.blob_sha)
        if blob_key not in blobs:
            blobs[blob_key] = tree.read_blob(expected.slug, expected.blob_sha)
        data = blobs[blob_key]
        assert GitHubTreeSource.git_blob_sha(data) == expected.blob_sha

        line = data.decode("utf-8").splitlines()[expected.start_line - 1]
        symbol = task.spec.must[-1].value
        assert symbol in line
