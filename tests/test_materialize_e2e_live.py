"""Opt-in live materialization of octocat/Hello-World at immutable commit.

The repository is GitHub's tiny public tutorial repository; commit
``7fd1a60b01f91b314f59955a4e4d4e80d8edf11d`` is pinned rather than resolved at
test time.
"""

from __future__ import annotations

import json
import os

import pytest

import fixtures_resolver as fx
from leitir.materialize import materialize_github_repo, materialize_repo
from leitir.resolver import BitbucketResolver, GitLabResolver
from leitir.search import RepoScope

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub materialization",
)

SHA = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"


def _anonymous_bitbucket_rate_limit(exc):
    current = exc
    while current is not None:
        if getattr(current, "code", None) == 429 or getattr(current, "status", None) == 429:
            return True
        message = str(current).lower()
        if "http 429" in message or "rate limit" in message or "too many requests" in message:
            return True
        current = current.__cause__
    return False


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


def test_materializes_pinned_gitlab_repository(tmp_path):
    target = materialize_repo(
        tmp_path,
        f"gitlab:{fx.GITLAB_SLUG}@{fx.GITLAB_COMMIT_SHA}",
        RepoScope(fx.GITLAB_SLUG, fx.GITLAB_COMMIT_SHA),
        host="gitlab.com",
        resolver=GitLabResolver(),
    )
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["host"] == "gitlab.com"
    assert manifest["verified"] in (True, "sampled")


def test_materializes_pinned_gitlab_subgroup_repository(tmp_path):
    target = materialize_repo(
        tmp_path,
        f"gitlab:{fx.GITLAB_SUBGROUP_SLUG}@{fx.GITLAB_SUBGROUP_COMMIT_SHA}",
        RepoScope(fx.GITLAB_SUBGROUP_SLUG, fx.GITLAB_SUBGROUP_COMMIT_SHA),
        host="gitlab.com",
        resolver=GitLabResolver(),
    )
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert target == tmp_path / "repos" / "gitlab.com" / fx.GITLAB_SUBGROUP_SLUG / fx.GITLAB_SUBGROUP_COMMIT_SHA
    assert manifest["owner"] == "gl-demo-ultimate-cwoolley/cwoolley-gitlab-test-subgroup"
    assert manifest["repo"] == "cwoolley-gitlab-test-project-1"
    assert manifest["verified"] in (True, "sampled")


def test_materializes_pinned_bitbucket_repository(tmp_path):
    try:
        target = materialize_repo(
            tmp_path,
            f"bitbucket:{fx.BITBUCKET_SLUG}@{fx.BITBUCKET_COMMIT_SHA}",
            RepoScope(fx.BITBUCKET_SLUG, fx.BITBUCKET_COMMIT_SHA),
            host="bitbucket.org",
            resolver=BitbucketResolver(),
        )
    except Exception as exc:
        if not os.environ.get("BITBUCKET_TOKEN") and _anonymous_bitbucket_rate_limit(exc):
            pytest.skip("anonymous Bitbucket rate limit (set BITBUCKET_TOKEN)")
        raise
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["host"] == "bitbucket.org"
    assert manifest["verified"] in (True, "sampled")
