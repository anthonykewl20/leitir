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
