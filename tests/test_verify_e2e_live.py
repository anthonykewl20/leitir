"""Opt-in live verification of GitHub's tiny octocat/Hello-World repository."""

from __future__ import annotations

import json
import os

import pytest

from leitir.materialize import materialize_github_repo
from leitir.tree import GitHubTreeSource

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub verification",
)

SHA = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
VITEST_SHA = "c9e59a089d94642eea29a43f2ee1986a5afb99c6"


def test_materializes_and_verifies_pinned_small_repository(tmp_path):
    target = materialize_github_repo(
        tmp_path, "octocat/Hello-World", "octocat", "Hello-World", SHA
    )
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    entries = GitHubTreeSource(token=os.environ.get("GITHUB_TOKEN")).list_blobs(
        "octocat/Hello-World", SHA
    )
    readme = next(entry for entry in entries if entry.path == "README")
    assert manifest["verified"] in (True, "sampled")
    assert GitHubTreeSource.git_blob_sha((target / "README").read_bytes()) == readme.blob_sha


def test_materializes_vitest_archive_with_text_normalization(tmp_path):
    target = materialize_github_repo(
        tmp_path,
        "npm:vitest@2.1.9",
        "vitest-dev",
        "vitest",
        VITEST_SHA,
        tag="v2.1.9",
    )
    manifest = json.loads((target / "leitir-manifest.json").read_text())

    assert manifest["commit_sha"] == VITEST_SHA
    assert manifest["verified"] in (True, "sampled")
