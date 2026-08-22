from __future__ import annotations

import base64
import gzip
import io
import os
import tarfile

import _http_server as hs
import fixtures_resolver as fx
import pytest

from leitir.resolver import (
    BitbucketResolver,
    Ecosystem,
    GoResolver,
    PackageRef,
    ResolutionError,
    TagAbsentError,
)

SHA = "a" * 40


def _anonymous_rate_limit(exc):
    current = exc
    while current is not None:
        if getattr(current, "code", None) == 429 or getattr(current, "status", None) == 429:
            return True
        message = str(current).lower()
        if "http 429" in message or "rate limit" in message or "too many requests" in message:
            return True
        current = current.__cause__
    return False


def _resolver(base_url, **kwargs):
    resolver = BitbucketResolver(base_url=base_url, sleeper=lambda _: None, **kwargs)
    resolver.archive_url = lambda _slug, _sha: f"{base_url}/repositories/owner/repo/get/{SHA}.tar.gz"  # type: ignore[method-assign]
    return resolver


def test_resolves_ref_to_lowercase_commit_sha():
    with hs.scripted_server([(200, {}, hs.json_body({"hash": SHA.upper()}))]) as server:
        assert _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "release/1") == SHA
    assert server.state.request_paths == ["/repositories/owner/repo/commit/release%2F1"]


def test_commit_sha_input_is_verified_through_api():
    with hs.scripted_server([(200, {}, hs.json_body({"hash": SHA}))]) as server:
        assert _resolver(server.base_url).resolve_ref_to_sha("owner/repo", SHA) == SHA
    assert server.state.served_count == 1


def test_pseudo_version_commit_prefix_is_expanded_through_api():
    with hs.scripted_server([(200, {}, hs.json_body({"hash": SHA}))]) as server:
        assert _resolver(server.base_url).resolve_commit_to_sha(
            "owner/repo", "abcdef123456"
        ) == SHA
    assert server.state.request_paths == [
        "/repositories/owner/repo/commit/abcdef123456"
    ]


def test_404_is_wrapped_without_retry():
    sleeps = []
    with hs.scripted_server([(404, {}, b"")]) as server:
        resolver = BitbucketResolver(base_url=server.base_url, sleeper=sleeps.append)
        with pytest.raises(TagAbsentError, match="HTTP 404"):
            resolver.resolve_tag_to_sha("owner/repo", "missing")
    assert sleeps == []


def test_non_404_stays_resolution_error():
    with hs.scripted_server([(403, {}, b"")]) as server:
        with pytest.raises(ResolutionError, match="HTTP 403") as caught:
            _resolver(server.base_url, max_attempts=1).resolve_tag_to_sha(
                "owner/repo", "main"
            )
    assert not isinstance(caught.value, TagAbsentError)


def test_go_subpath_tag_advances_after_absent_candidate():
    responses = [
        (404, {}, b""),
        (200, {}, hs.json_body({"hash": SHA})),
    ]
    with hs.scripted_server(responses) as repository, hs.scripted_server(
        [(200, {}, hs.json_body({}))]
    ) as proxy:
        hosted = _resolver(repository.base_url)
        resolver = GoResolver(
            hosted,
            base_url=proxy.base_url,
            repository_resolvers={"bitbucket.org": hosted},
        )
        result = resolver.resolve(
            PackageRef(
                Ecosystem.GO,
                "bitbucket.org/owner/repo/submodule",
                "v1.0.0",
            )
        )

    assert result.scope.slug == "owner/repo"
    assert result.subpath == "submodule"
    assert result.tag == "v1.0.0"
    assert repository.state.served_count == 2


def test_rate_limit_retries():
    sleeps = []
    responses = [
        (429, {"Retry-After": "0"}, b""),
        (200, {}, hs.json_body({"hash": SHA})),
    ]
    with hs.scripted_server(responses) as server:
        resolver = BitbucketResolver(base_url=server.base_url, sleeper=sleeps.append)
        assert resolver.resolve_tag_to_sha("owner/repo", "main") == SHA
    assert sleeps == [0.0]


@pytest.mark.parametrize("payload", [{}, {"hash": "short"}, [], {"hash": 1}])
def test_malformed_commit_metadata_is_honest(payload):
    with hs.scripted_server([(200, {}, hs.json_body(payload))]) as server:
        with pytest.raises(ResolutionError, match="malformed commit metadata"):
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "main")


def test_archive_url_uses_download_endpoint_and_pinned_sha():
    url = BitbucketResolver().archive_url("owner/repo", SHA)
    assert url == f"https://bitbucket.org/owner/repo/get/{SHA}.tar.gz"


def _fixture_archive(root, contents, symlinks=frozenset()):
    """Deterministic tar.gz fixture: sorted members, mtimes zeroed."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(contents):
            content = contents[path]
            info = tarfile.TarInfo(f"{root}/{path}")
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            if path in symlinks:
                info.type = tarfile.SYMTYPE
                info.linkname = content.decode()
                info.mode = 0o777
                tar.addfile(info)
                continue
            info.size = len(content)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(content))
    return gzip.compress(raw.getvalue(), mtime=0)


def test_tree_listing_hashes_host_native_file_content():
    payload = {
        "values": [
            {"type": "commit_file", "path": "a.py", "size": 5, "attributes": []}
        ]
    }
    routes = {
        f"/repositories/owner/repo/src/{SHA}/": (200, {}, hs.json_body(payload)),
        f"/repositories/owner/repo/get/{SHA}.tar.gz": (
            200,
            {},
            _fixture_archive("single-root", {"a.py": b"hello"}),
        ),
        # K=3 spot check raw read (K collapses to 1 for a one-file repo).
        f"/repositories/owner/repo/src/{SHA}/a.py": (200, {}, b"hello"),
    }
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert [(entry.path, entry.size, entry.mode) for entry in entries] == [("a.py", 5, "100644")]
    assert entries[0].blob_sha == "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0"
    assert server.state.served_count == 3  # listing + archive + 1 spot-check read


def test_environment_token_uses_bearer_only_for_https_api_host(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return io.BytesIO(hs.json_body({"hash": SHA}))

    monkeypatch.setenv("BITBUCKET_TOKEN", "secret-value")
    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    assert BitbucketResolver().resolve_tag_to_sha("owner/repo", "main") == SHA
    assert captured["Authorization"] == "Bearer secret-value"


def test_bearer_token_authenticates_api_and_archive(monkeypatch):
    monkeypatch.setenv("BITBUCKET_TOKEN", "secret-value")
    resolver = BitbucketResolver()
    assert resolver._headers("https://api.bitbucket.org/2.0/repositories/x/y")["Authorization"] == "Bearer secret-value"
    assert resolver._headers(resolver.archive_url("owner/repo", SHA))["Authorization"] == "Bearer secret-value"


def test_username_selects_basic_auth_for_api_and_archive(monkeypatch):
    monkeypatch.setenv("BITBUCKET_TOKEN", "app-password")
    monkeypatch.setenv("BITBUCKET_USERNAME", "bitbucket-user")
    resolver = BitbucketResolver()
    expected = "Basic " + base64.b64encode(b"bitbucket-user:app-password").decode()
    assert resolver._headers("https://api.bitbucket.org/2.0/repositories/x/y")["Authorization"] == expected
    assert resolver._headers(resolver.archive_url("owner/repo", SHA))["Authorization"] == expected


def test_token_is_never_rendered_on_failure(monkeypatch, capsys):
    monkeypatch.setenv("BITBUCKET_TOKEN", "never-print-this")
    with hs.scripted_server([(404, {}, b"")]) as server:
        with pytest.raises(ResolutionError) as caught:
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "main")
    assert "never-print-this" not in str(caught.value)
    assert "never-print-this" not in capsys.readouterr().err


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
)
def test_live_ref_resolves_to_pinned_commit():
    resolver = BitbucketResolver()
    try:
        actual = resolver.resolve_tag_to_sha(fx.BITBUCKET_SLUG, fx.BITBUCKET_REF)
    except Exception as exc:
        if not os.environ.get("BITBUCKET_TOKEN") and _anonymous_rate_limit(exc):
            pytest.skip("anonymous Bitbucket rate limit (set BITBUCKET_TOKEN)")
        raise
    assert actual == fx.BITBUCKET_COMMIT_SHA
