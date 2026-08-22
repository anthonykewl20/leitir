from __future__ import annotations

import base64
import io
import os

import _http_server as hs
import pytest

from leitir.resolver import CodebergResolver, ResolutionError

SHA = "a" * 40

# Scripted Gitea symlink fixtures pinned to the live-probed codeberg.org
# shape (issue #219): for a symlink entry the contents API returns
# ``content``/``encoding`` null and carries the link target in ``target``
# with the entry's own blob SHA in ``sha``. The digest below is the real Git
# blob SHA of b".tmux/.tmux.conf" (observed at
# codeberg.org/xoo/.dotfiles @ acec3647d251e7581f5e5f07120810c5a8aaf1e8).
SYMLINK_PATH = "tmux/.tmux.conf"
SYMLINK_TARGET = b".tmux/.tmux.conf"
SYMLINK_BLOB_SHA = "ad7697978653b125fa5fe54ec8651366975c516e"


def _resolver(base_url, **kwargs):
    return CodebergResolver(base_url=base_url, sleeper=lambda _: None, **kwargs)


def _symlink_contents_payload(
    *,
    target: str | None = ".tmux/.tmux.conf",
    blob_sha: str = SYMLINK_BLOB_SHA,
    size: int = len(SYMLINK_TARGET),
) -> dict:
    payload = {
        "name": ".tmux.conf",
        "path": SYMLINK_PATH,
        "sha": blob_sha,
        "type": "symlink",
        "size": size,
        "encoding": None,
        "content": None,
        "download_url": f"https://codeberg.org/owner/repo/raw/{SYMLINK_PATH}",
    }
    if target is not None:
        payload["target"] = target
    return payload


def _git_blob_payload(
    *,
    data: bytes = SYMLINK_TARGET,
    blob_sha: str = SYMLINK_BLOB_SHA,
) -> dict:
    return {
        "content": base64.b64encode(data).decode("ascii"),
        "encoding": "base64",
        "sha": blob_sha,
        "size": len(data),
    }


def test_resolves_ref_and_commit_through_gitea_api():
    with hs.scripted_server([(200, {}, hs.json_body([{"sha": SHA.upper()}]))]) as server:
        assert _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "release/1") == SHA
    assert server.state.request_paths == ["/repos/owner/repo/commits?sha=release%2F1&limit=1"]


def test_404_and_malformed_metadata_fail_closed():
    with hs.scripted_server([(404, {}, b"")]) as server:
        with pytest.raises(ResolutionError, match="HTTP 404"):
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "missing")
    with hs.scripted_server([(200, {}, hs.json_body([{"sha": "short"}]))]) as server:
        with pytest.raises(ResolutionError, match="malformed commit metadata"):
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "main")


def test_archive_and_recursive_tree_endpoints():
    payload = {"tree": [{"type": "blob", "path": "a.py", "sha": "b" * 40, "size": 3, "mode": "100644"}]}
    with hs.scripted_server([(200, {}, hs.json_body(payload))]) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert CodebergResolver().archive_url("owner/repo", SHA) == f"https://codeberg.org/owner/repo/archive/{SHA}.tar.gz"
    assert entries[0].path == "a.py"
    assert server.state.request_paths == [f"/repos/owner/repo/git/trees/{SHA}?recursive=true"]


def test_environment_token_is_bearer_and_redacted(monkeypatch, capsys):
    captured = {}

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return io.BytesIO(hs.json_body([{"sha": SHA}]))

    monkeypatch.setenv("CODEBERG_TOKEN", "never-print-this")
    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    assert CodebergResolver().resolve_tag_to_sha("owner/repo", "main") == SHA
    assert captured["Authorization"] == "Bearer never-print-this"
    assert "never-print-this" not in capsys.readouterr().err


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification")
def test_live_pinned_commit_resolves():
    sha = "db760a61d52ac179f8f308f089b4741c072f17ce"
    assert CodebergResolver().resolve_tag_to_sha("forgejo/forgejo", sha) == sha


def test_read_blob_at_commit_symlink_returns_verified_target_bytes():
    # G-0 recreated per the issue #219 contract: an honest symlink re-read
    # must return the blob's exact bytes (the link target), digest-verified
    # against the blob SHA the contents response itself carries — never a
    # ResolutionError. The verified target arm needs no extra round-trip.
    with hs.scripted_server(
        [(200, {}, hs.json_body(_symlink_contents_payload()))]
    ) as server:
        data = _resolver(server.base_url).read_blob_at_commit(
            "owner/repo", SHA, SYMLINK_PATH
        )
    assert data == SYMLINK_TARGET
    assert server.state.request_paths == [
        f"/repos/owner/repo/contents/{SYMLINK_PATH}?ref={SHA}"
    ]


def test_read_blob_at_commit_symlink_without_target_uses_verified_git_blob_fallback():
    # AC-1 fallback arm: a Gitea version that omits ``target`` still serves
    # the blob through the git-blob API; the returned bytes must pass
    # response-identity, size, and recomputed-digest verification.
    with hs.scripted_server(
        [
            (200, {}, hs.json_body(_symlink_contents_payload(target=None))),
            (200, {}, hs.json_body(_git_blob_payload())),
        ]
    ) as server:
        data = _resolver(server.base_url).read_blob_at_commit(
            "owner/repo", SHA, SYMLINK_PATH
        )
    assert data == SYMLINK_TARGET
    assert server.state.request_paths == [
        f"/repos/owner/repo/contents/{SYMLINK_PATH}?ref={SHA}",
        f"/repos/owner/repo/git/blobs/{SYMLINK_BLOB_SHA}",
    ]


def test_read_blob_at_commit_symlink_target_lies_falls_back_to_verified_channel():
    # Fail-closed fast path: a contents payload whose declared target is
    # byte-consistent on size but does not digest-match the blob SHA its
    # own response declares is never trusted — the re-read falls through
    # to the digest-verified git-blob channel instead (the digest check is
    # the sole trigger here).
    with hs.scripted_server(
        [
            (
                200,
                {},
                hs.json_body(
                    _symlink_contents_payload(target="x" * len(SYMLINK_TARGET))
                ),
            ),
            (200, {}, hs.json_body(_git_blob_payload())),
        ]
    ) as server:
        data = _resolver(server.base_url).read_blob_at_commit(
            "owner/repo", SHA, SYMLINK_PATH
        )
    assert data == SYMLINK_TARGET
    assert server.state.request_paths == [
        f"/repos/owner/repo/contents/{SYMLINK_PATH}?ref={SHA}",
        f"/repos/owner/repo/git/blobs/{SYMLINK_BLOB_SHA}",
    ]


def test_read_blob_at_commit_symlink_surrogate_target_falls_back_to_verified_channel():
    # A JSON-decoded target carrying lone surrogates cannot round-trip to
    # the blob's raw bytes — the fast path must defer to the digest-verified
    # git-blob channel rather than crash with an untyped UnicodeEncodeError.
    with hs.scripted_server(
        [
            (200, {}, hs.json_body(_symlink_contents_payload(target="\ud800x"))),
            (200, {}, hs.json_body(_git_blob_payload())),
        ]
    ) as server:
        data = _resolver(server.base_url).read_blob_at_commit(
            "owner/repo", SHA, SYMLINK_PATH
        )
    assert data == SYMLINK_TARGET
    assert server.state.request_paths[-1] == (
        f"/repos/owner/repo/git/blobs/{SYMLINK_BLOB_SHA}"
    )


def test_read_blob_at_commit_symlink_target_size_lies_falls_back_to_verified_channel():
    # A declared size that disagrees with the target bytes is the same
    # self-inconsistency: never accept the target on its own — the
    # asserted request sequence proves the verified git-blob channel
    # produced the bytes.
    with hs.scripted_server(
        [
            (200, {}, hs.json_body(_symlink_contents_payload(size=4))),
            (200, {}, hs.json_body(_git_blob_payload())),
        ]
    ) as server:
        data = _resolver(server.base_url).read_blob_at_commit(
            "owner/repo", SHA, SYMLINK_PATH
        )
    assert data == SYMLINK_TARGET
    assert server.state.request_paths == [
        f"/repos/owner/repo/contents/{SYMLINK_PATH}?ref={SHA}",
        f"/repos/owner/repo/git/blobs/{SYMLINK_BLOB_SHA}",
    ]


@pytest.mark.parametrize("status", [404, 500])
def test_read_blob_at_commit_symlink_fallback_channel_failure_fails_closed(status):
    # SP-1: the contents response is a symlink entry without ``target`` and
    # the fallback channel also fails — the re-read must fail closed with a
    # typed ResolutionError, never silently accept or skip.
    with hs.scripted_server(
        [
            (200, {}, hs.json_body(_symlink_contents_payload(target=None))),
            (status, {}, b""),
        ]
    ) as server:
        with pytest.raises(ResolutionError):
            _resolver(server.base_url).read_blob_at_commit(
                "owner/repo", SHA, SYMLINK_PATH
            )


def test_read_blob_at_commit_symlink_fallback_digest_disagreement_rejects():
    # SP-2: the fallback channel serves bytes whose recomputed Git blob SHA
    # disagrees with the SHA the response echoes — typed rejection naming
    # the mismatch; the disagreement is never treated as a clearance.
    lying = _git_blob_payload(data=b"tampered link target")
    with hs.scripted_server(
        [
            (200, {}, hs.json_body(_symlink_contents_payload(target=None))),
            (200, {}, hs.json_body(lying)),
        ]
    ) as server:
        with pytest.raises(
            ResolutionError, match="content does not match the declared blob SHA"
        ):
            _resolver(server.base_url).read_blob_at_commit(
                "owner/repo", SHA, SYMLINK_PATH
            )


def test_read_blob_at_commit_symlink_fallback_response_sha_mismatch_rejects():
    # Response-identity check mirroring GitHubTreeSource.read_blob: the
    # git-blob channel must echo the requested blob SHA.
    echoed = _git_blob_payload(blob_sha="c" * 40)
    with hs.scripted_server(
        [
            (200, {}, hs.json_body(_symlink_contents_payload(target=None))),
            (200, {}, hs.json_body(echoed)),
        ]
    ) as server:
        with pytest.raises(
            ResolutionError, match="response SHA does not match requested blob"
        ):
            _resolver(server.base_url).read_blob_at_commit(
                "owner/repo", SHA, SYMLINK_PATH
            )


def test_read_blob_at_commit_symlink_fallback_size_disagreement_rejects():
    # Size check mirroring GitHubTreeSource.read_blob: the declared size
    # must equal the decoded content length.
    bad_size = _git_blob_payload()
    bad_size["size"] = 4
    with hs.scripted_server(
        [
            (200, {}, hs.json_body(_symlink_contents_payload(target=None))),
            (200, {}, hs.json_body(bad_size)),
        ]
    ) as server:
        with pytest.raises(ResolutionError, match="size does not match decoded content"):
            _resolver(server.base_url).read_blob_at_commit(
                "owner/repo", SHA, SYMLINK_PATH
            )


def test_read_blob_at_commit_symlink_fallback_transient_failures_retry_then_fail_typed():
    # SP-3: pin the git-blobs fallback channel's retry — the contents
    # request succeeds (symlink entry without target), but the fallback
    # channel keeps failing transiently until the explicitly pinned four
    # attempts are exhausted, then the typed ResolutionError. No hang, no
    # partial pass.
    with hs.scripted_server(
        [
            (200, {}, hs.json_body(_symlink_contents_payload(target=None))),
            (502, {}, b""),
        ]
    ) as server:
        with pytest.raises(ResolutionError, match="HTTP 502"):
            _resolver(server.base_url, max_attempts=4).read_blob_at_commit(
                "owner/repo", SHA, SYMLINK_PATH
            )
    assert server.state.served_count == 5


def test_read_blob_at_commit_symlink_malformed_blob_payload_rejects():
    # SP-1 (malformed payload variant): a non-object git-blob response is a
    # typed rejection.
    with hs.scripted_server(
        [
            (200, {}, hs.json_body(_symlink_contents_payload(target=None))),
            (200, {}, hs.json_body([1, 2, 3])),
        ]
    ) as server:
        with pytest.raises(ResolutionError, match="malformed blob metadata"):
            _resolver(server.base_url).read_blob_at_commit(
                "owner/repo", SHA, SYMLINK_PATH
            )


def test_read_blob_at_commit_regular_file_re_read_is_unchanged():
    # C-4: regular (non-symlink) re-reads keep today's behavior exactly —
    # base64 contents decode straight through with no extra round-trip and
    # no digest cross-check on this path.
    payload = {
        "name": "a.py",
        "path": "a.py",
        "sha": "d" * 40,
        "type": "file",
        "size": 5,
        "encoding": "base64",
        "content": base64.b64encode(b"proof").decode("ascii"),
    }
    with hs.scripted_server([(200, {}, hs.json_body(payload))]) as server:
        data = _resolver(server.base_url).read_blob_at_commit("owner/repo", SHA, "a.py")
    assert data == b"proof"
    assert server.state.request_paths == [f"/repos/owner/repo/contents/a.py?ref={SHA}"]


def test_read_blob_at_commit_non_symlink_without_content_keeps_typed_error():
    # C-4 error taxonomy: a non-symlink entry without base64 content keeps
    # the pre-existing malformed-content rejection.
    payload = {
        "name": "a.py",
        "path": "a.py",
        "sha": "d" * 40,
        "type": "file",
        "size": 5,
        "encoding": None,
        "content": None,
    }
    with hs.scripted_server([(200, {}, hs.json_body(payload))]) as server:
        with pytest.raises(
            ResolutionError, match="malformed content metadata"
        ):
            _resolver(server.base_url).read_blob_at_commit("owner/repo", SHA, "a.py")


@pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification")
def test_live_symlink_reread_returns_digest_verified_target():
    # G-3/G-4 scripted corroboration at the resolver boundary: the pinned
    # public fixture carries an in-tree symlink whose blob bytes are the
    # link target; the re-read must return exactly those bytes.
    resolver = CodebergResolver(timeout=30)
    data = resolver.read_blob_at_commit(
        "xoo/.dotfiles", "acec3647d251e7581f5e5f07120810c5a8aaf1e8", "tmux/.tmux.conf"
    )
    assert data == b".tmux/.tmux.conf"
