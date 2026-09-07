"""Opt-in live re-verification of the immutable search-v1 benchmark pins."""

from __future__ import annotations

import hashlib
import json
import os
from urllib.request import Request, urlopen

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


def test_all_manifest_sources_are_reachable_and_byte_exact() -> None:
    manifest = load_manifest()
    tree = GitHubTreeSource(
        token=os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    )
    # This test revalidates the pinned benchmark files, not every unrelated
    # file in a huge repository. Follow the actual Git tree chain to each
    # declared path; full-universe recovery has its own live test.
    trees: dict[tuple[str, str], dict[str, dict[str, str]]] = {}

    def entries(slug: str, ref: str) -> dict[str, dict[str, str]]:
        key = (slug, ref)
        if key not in trees:
            headers = {"User-Agent": "leitir-benchmark-pin-validation"}
            token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            if token:
                headers["Authorization"] = "Bearer " + token
            url = f"https://api.github.com/repos/{slug}/git/trees/{ref}"
            with urlopen(Request(url, headers=headers), timeout=60) as response:
                payload = json.load(response)
            assert payload["truncated"] is False
            trees[key] = {entry["path"]: entry for entry in payload["tree"]}
        return trees[key]
    blobs: dict[tuple[str, str], bytes] = {}

    for task in manifest.tasks:
        scope = task.spec.scopes[0]
        expected = task.expected_results[0]
        ref = scope.commit_sha
        components = expected.path.split("/")
        for component in components[:-1]:
            directory = entries(scope.slug, ref)[component]
            assert directory["type"] == "tree"
            ref = directory["sha"]
        leaf = entries(scope.slug, ref)[components[-1]]
        assert leaf["type"] == "blob"
        assert leaf["sha"] == expected.blob_sha

        blob_key = (expected.slug, expected.blob_sha)
        if blob_key not in blobs:
            blobs[blob_key] = tree.read_blob(expected.slug, expected.blob_sha)
        data = blobs[blob_key]
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == expected.blob_sha

        line = data.decode("utf-8").splitlines()[expected.start_line - 1]
        symbol = task.spec.must[-1].value
        assert symbol in line
        print(f"verified {expected.slug}@{expected.commit_sha}:{expected.path}:{expected.start_line} blob={expected.blob_sha}")
