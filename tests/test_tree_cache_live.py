"""Actual immutable GitHub tree reuse, content identity and rejection."""
from __future__ import annotations

import os
import time
from urllib.request import urlopen

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="real GitHub access requires LEITIR_ENABLE_LIVE_E2E=1")


@pytest.mark.live
def test_real_tree_reuse_keeps_pinned_identity_and_rejects_bad_pins() -> None:
    from leitir.tree import GitHubTreeSource, TreeEnumerationError, TreeReadError

    source = GitHubTreeSource(token=os.environ.get("GITHUB_TOKEN"))
    slug, pin = "pypa/packaging", "85442b8032cb7bae72866dfd7782234a98dd2fb7"
    first = source.list_blobs_ex(slug, pin)
    assert first[0]
    start = time.monotonic()
    second = source.list_blobs_ex(slug, pin)
    assert second is first
    assert time.monotonic() - start < 0.5
    blob = next(item for item in first[0] if item.path == "src/packaging/version.py")
    with urlopen(f"https://raw.githubusercontent.com/{slug}/{pin}/{blob.path}", timeout=60) as response:
        assert source.read_blob(slug, blob.blob_sha) == response.read()
    with pytest.raises(TreeEnumerationError):
        source.list_blobs_ex(slug, "invalid-pin")
    with pytest.raises(TreeReadError):
        source.list_blobs_ex(slug, "0" * 40)
    assert source.list_blobs_ex(slug, pin) is first
