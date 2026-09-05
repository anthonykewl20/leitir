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


@pytest.mark.live
def test_shared_real_tree_source_keeps_hits_atomic_during_eviction() -> None:
    import sys
    import threading
    from pathlib import Path

    import leitir.tree
    from leitir.tree import GitHubTreeSource

    pins = (
        ("pypa/packaging", "85442b8032cb7bae72866dfd7782234a98dd2fb7"),
        ("fmtlib/fmt", "6c285ba88a22e287f8d33a4e15b43c0095160181"),
        ("stretchr/testify", "b747d7c5f853d017ddbc5e623d026d7fc2770a58"),
        ("google/gson", "310ac341f2f92a454b229bf21f70d2d18b2b6db7"),
        ("tj/commander.js", "ba6d13ddb4243e5913367734f8c159089ffe7834"),
    )
    source = GitHubTreeSource(token=os.environ.get("GITHUB_TOKEN"), timeout=15)
    first = source.list_blobs_ex(*pins[0])
    paused, resume, finished = threading.Event(), threading.Event(), threading.Event()
    errors: list[Exception] = []
    returned = []
    path = Path(leitir.tree.__file__).resolve()
    line = next(number for number, text in enumerate(path.read_text().splitlines(), 1)
                if "self._tree_cache.move_to_end(cache_key)" in text)

    def trace(frame, event, arg):
        if event == "line" and frame.f_code.co_filename == str(path) and frame.f_lineno == line:
            paused.set()
            if not resume.wait(30):
                raise TimeoutError("reader resume deadline expired")
        return trace

    def read() -> None:
        sys.settrace(trace)
        try:
            returned.append(source.list_blobs_ex(*pins[0]))
        except Exception as exc:
            errors.append(exc)
        finally:
            sys.settrace(None)

    def evict() -> None:
        try:
            for pin in pins[1:]:
                assert source.list_blobs_ex(*pin)[0]
        except Exception as exc:
            errors.append(exc)
        finally:
            finished.set()

    reader = threading.Thread(target=read, daemon=True)
    writer = threading.Thread(target=evict, daemon=True)
    reader.start()
    try:
        assert paused.wait(10)
        writer.start()
        # With a lock the writer waits. Without one real lookups can evict
        # Packaging between membership and the resumed read. No data/methods
        # are replaced: tracing only selects this valid thread interleaving.
        finished.wait(10)
    finally:
        resume.set()
        reader.join(20)
        if writer.ident is not None:
            writer.join(90)
    assert not reader.is_alive() and not writer.is_alive()
    assert not errors, errors
    assert returned == [first]
    assert len(source._tree_cache) <= 4
