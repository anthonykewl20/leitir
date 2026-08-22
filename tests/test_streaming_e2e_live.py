"""Opt-in live canary surface: streamed, SHA-verified large blob (#197 C-4).

Skipped unless LEITIR_ENABLE_LIVE_E2E=1. Streams a >2 MiB blob pinned by
digest through the hardened ``GitHubTreeSource.read_blob_stream`` (SHA
validation, categorized retry on open, typed failures, bounded total bytes,
prompt response closure — #197) and verifies the git blob SHA incrementally
without ever materializing the blob in memory.

Fixture pins (workflow ``streamed-large-blob`` job defaults; every value
env-overridable): torvalds/linux@d58772d8…, blob
3caee4515ad62aa7b8031b93bccb4e69b9ed0e64 at
drivers/accel/habanalabs/include/gaudi2/asic_reg/gaudi2_blocks_linux_driver.h,
2,456,864 bytes — all OBSERVED live on 2026-08-20 (streamed byte count and
computed git blob SHA matched the pins exactly).
"""

from __future__ import annotations

import hashlib
import os

import pytest

from leitir.tree import STREAM_CHUNK_SIZE, STREAM_MAX_BYTES, GitHubTreeSource

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
        reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live GitHub verification",
    ),
]

FIXTURE_REPO = os.environ.get("LIVE_CANARY_FIXTURE_REPO", "torvalds/linux")
FIXTURE_COMMIT = os.environ.get(
    "LIVE_CANARY_FIXTURE_COMMIT", "d58772d8520c7ef247c4b95c9bd76d3a25da9ff5"
)
FIXTURE_PATH = os.environ.get(
    "LIVE_CANARY_FIXTURE_PATH",
    "drivers/accel/habanalabs/include/gaudi2/asic_reg/gaudi2_blocks_linux_driver.h",
)
FIXTURE_BLOB_SHA = os.environ.get(
    "LIVE_CANARY_FIXTURE_BLOB_SHA", "3caee4515ad62aa7b8031b93bccb4e69b9ed0e64"
)
FIXTURE_SIZE = int(os.environ.get("LIVE_CANARY_FIXTURE_SIZE", "2456864"))
_REQUIRE_SHA_VERIFICATION = os.environ.get(
    "LIVE_CANARY_REQUIRE_STREAM_SHA_VERIFICATION", "true"
)


def _token() -> str | None:
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")


def test_large_blob_streams_chunked_with_verified_digest() -> None:
    assert FIXTURE_SIZE > 2 * 1024 * 1024, "fixture must remain a >2 MiB blob"
    assert FIXTURE_SIZE <= STREAM_MAX_BYTES

    source = GitHubTreeSource(token=_token())
    # The git blob SHA is sha1(b"blob <size>\0" + content); the declared size
    # seeds the header so the digest can be verified incrementally, keeping
    # memory bounded at one chunk regardless of blob size.
    digest = hashlib.sha1(b"blob %d\x00" % FIXTURE_SIZE)  # noqa: UP031
    received = 0
    chunks = 0

    for chunk in source.read_blob_stream(FIXTURE_REPO, FIXTURE_BLOB_SHA):
        assert isinstance(chunk, bytes)
        assert 0 < len(chunk) <= STREAM_CHUNK_SIZE
        received += len(chunk)
        chunks += 1
        digest.update(chunk)

    assert received == FIXTURE_SIZE, "streamed byte count must match the pin"
    assert chunks >= 2, "blob must arrive in stream chunks, not one read"
    assert received <= STREAM_MAX_BYTES
    if _REQUIRE_SHA_VERIFICATION == "true":
        assert digest.hexdigest() == FIXTURE_BLOB_SHA, (
            "streamed content failed git blob SHA verification"
        )
    print(
        f"streamed-large-blob surface: bytes={received} chunks={chunks} "
        f"path={FIXTURE_PATH}@{FIXTURE_COMMIT[:12]} "
        f"digest_verified={_REQUIRE_SHA_VERIFICATION == 'true'}"
    )
