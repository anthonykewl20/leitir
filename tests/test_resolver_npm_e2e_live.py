"""Opt-in live npm monorepo resolution and verified materialization."""

from __future__ import annotations

import json
import os

import pytest

from leitir.corpus import materialize_source
from leitir.resolver import Ecosystem, GitHubTagResolver, NpmResolver, PackageRef

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live npm materialization",
)

NAME = "@sveltejs/kit"
VERSION = "2.70.2"
TAG = "@sveltejs/kit@2.70.2"
SLUG = "sveltejs/kit"
SHA = "a297affcec19d6f4d2df8bac1b292d8c34486344"


class RecordingTagResolver(GitHubTagResolver):
    def __init__(self) -> None:
        super().__init__(token=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
        self.calls: list[tuple[str, str]] = []

    def resolve_tag_to_sha(self, slug: str, tag: str) -> str:
        self.calls.append((slug, tag))
        return super().resolve_tag_to_sha(slug, tag)


def test_live_sveltekit_package_uses_name_tag_and_materializes_verified(tmp_path):
    tags = RecordingTagResolver()
    resolved = NpmResolver(tags).resolve(PackageRef(Ecosystem.NPM, NAME, VERSION))

    assert resolved.scope.slug == SLUG
    assert resolved.scope.commit_sha == SHA
    assert resolved.tag == TAG
    assert tags.calls == [(SLUG, TAG)]

    target = materialize_source(
        f"npm:{NAME}@{VERSION}", resolved, root=tmp_path, name=NAME
    )
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert resolved.subpath == "packages/kit"
    assert (target / "packages" / "kit").is_dir()
    assert manifest["commit_sha"] == SHA
    assert manifest["tag"] == TAG
    assert manifest["verified"] in (True, "sampled")
