"""Opt-in live materialization of octocat/Hello-World at immutable commit.

The repository is GitHub's tiny public tutorial repository; commit
``7fd1a60b01f91b314f59955a4e4d4e80d8edf11d`` is pinned rather than resolved at
test time.
"""

from __future__ import annotations

import json
import os

import pytest

from leitir.materialize import materialize_github_repo

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub materialization",
)

SHA = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"


def test_materializes_pinned_small_repository(tmp_path):
    target = materialize_github_repo(
        tmp_path, "octocat/Hello-World", "octocat", "Hello-World", SHA
    )
    manifest = json.loads((target / "leitir-manifest.json").read_text())

    assert (target / "README").is_file()
    assert manifest["commit_sha"] == SHA
    assert manifest["repo_url"] == "https://github.com/octocat/Hello-World"
    assert manifest["fetch_method"] == "codeload-tarball"
    assert manifest["verified"] in (True, "sampled")
    assert manifest["verified_at"].endswith("Z")
