from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
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
    }
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert [(entry.path, entry.size, entry.mode) for entry in entries] == [("a.py", 5, "100644")]
    assert entries[0].blob_sha == "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0"
    assert server.state.served_count == 2  # one listing page + one archive download


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


# ---------------------------------------------------------------------------
# Issue #195: page-bounded enumeration with archive-derived digests. Fixtures
# are deterministic and pinned by digest; expected entry tuples were captured
# from BASELINE list_blobs (commit 8aa08e2c) against the same fixtures.

_BB_FIXTURE_ROOT = "bb-fixture-root"
_BB_ROOT_PAYLOAD_SHA256 = "17f96416d15b761699777f89ed6fbe05e9bdb0c16f5c365399eb6bffb1d08594"
_BB_PKG_PAYLOAD_SHA256 = "d6fd3e22a2c7cb8ef1230ba9d7e950712cf3ac194131e4e25fe2af12d5a551c9"
# Pin the UNCOMPRESSED tar stream: gzip.compress output bytes vary with the
# platform zlib (Python 3.11/3.12 and Windows emit different, equally valid
# deflate streams), while the tar member bytes/order are identical everywhere.
_BB_ARCHIVE_TAR_SHA256 = "d25612df6396b8c100b35bf3024ca2b3e89efa215e060c84944976d3aea93e1b"


def _bb_blob_sha(content: bytes) -> str:
    from leitir.tree import GitHubTreeSource

    return GitHubTreeSource.git_blob_sha(content)


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


def _bb_fixture_paths():
    return [
        *[f"file_{i:03d}.txt" for i in range(30)],
        *[f"pkg/file_{i:03d}.txt" for i in range(29)],
        "pkg/link.txt",
    ]


def _bb_fixture_content(path):
    if path == "pkg/link.txt":
        return b"file_000.txt"
    return f"leitir bitbucket fixture {path}\n".encode()


def _bb_fixture_repo():
    """Deterministic 60-file repo across two directories plus one symlink."""
    contents = {path: _bb_fixture_content(path) for path in _bb_fixture_paths()}
    root_values = [
        {
            "type": "commit_file",
            "path": path,
            "size": len(contents[path]),
            "attributes": [],
        }
        for path in _bb_fixture_paths()
        if "/" not in path
    ]
    root_values.append({"type": "commit_directory", "path": "pkg"})
    pkg_values = [
        {
            "type": "commit_file",
            "path": path,
            "size": len(contents[path]),
            "attributes": ["link"] if path == "pkg/link.txt" else [],
        }
        for path in _bb_fixture_paths()
        if path.startswith("pkg/")
    ]
    routes = {
        f"/repositories/owner/repo/src/{SHA}/": (
            200,
            {},
            hs.json_body({"values": root_values}),
        ),
        f"/repositories/owner/repo/src/{SHA}/pkg/": (
            200,
            {},
            hs.json_body({"values": pkg_values}),
        ),
        f"/repositories/owner/repo/get/{SHA}.tar.gz": (
            200,
            {},
            _fixture_archive(_BB_FIXTURE_ROOT, contents, frozenset({"pkg/link.txt"})),
        ),
    }
    # Per-file raw reads (baseline behavior only; page-bounded enumeration
    # must never request these).
    for path, content in contents.items():
        routes[f"/repositories/owner/repo/src/{SHA}/{path}"] = (200, {}, content)
    return routes, contents


def test_bitbucket_enumeration_makes_no_per_file_requests():
    routes, _ = _bb_fixture_repo()
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    listing_pages = {
        f"/repositories/owner/repo/src/{SHA}/",
        f"/repositories/owner/repo/src/{SHA}/pkg/",
    }
    per_file = [
        path
        for path in server.state.request_paths
        if not path.endswith(".tar.gz") and path not in listing_pages
    ]
    assert per_file == []
    assert server.state.request_paths == [
        f"/repositories/owner/repo/src/{SHA}/",
        f"/repositories/owner/repo/src/{SHA}/pkg/",
        f"/repositories/owner/repo/get/{SHA}.tar.gz",
    ]
    assert server.state.served_count <= 4  # 2 directory pages + 1 archive + slack
    assert len(entries) == 60


def test_bitbucket_entries_are_byte_identical_to_baseline_capture():
    routes, _ = _bb_fixture_repo()
    assert (
        hashlib.sha256(routes[f"/repositories/owner/repo/src/{SHA}/"][2]).hexdigest()
        == _BB_ROOT_PAYLOAD_SHA256
    )
    assert (
        hashlib.sha256(routes[f"/repositories/owner/repo/src/{SHA}/pkg/"][2]).hexdigest()
        == _BB_PKG_PAYLOAD_SHA256
    )
    assert (
        hashlib.sha256(
            gzip.decompress(routes[f"/repositories/owner/repo/get/{SHA}.tar.gz"][2])
        ).hexdigest()
        == _BB_ARCHIVE_TAR_SHA256
    )
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert [
        (entry.path, entry.blob_sha, entry.size, entry.mode) for entry in entries
    ] == _BITBUCKET_BASELINE_ENTRIES


def test_bitbucket_repeated_enumeration_is_cached_and_identical():
    routes, _ = _bb_fixture_repo()
    with hs.routed_server(routes) as server:
        resolver = _resolver(server.base_url)
        first = resolver.list_blobs("owner/repo", SHA)
        second = resolver.list_blobs("owner/repo", SHA)
    assert second == first
    assert server.state.served_count == 3  # second call served from cache


def test_bitbucket_size_mismatch_between_listing_and_archive_fails_closed():
    routes, _ = _bb_fixture_repo()
    root = json.loads(routes[f"/repositories/owner/repo/src/{SHA}/"][2])
    root["values"][0]["size"] = 999
    routes[f"/repositories/owner/repo/src/{SHA}/"] = (200, {}, hs.json_body(root))
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="size mismatch between listing and archive"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_bitbucket_missing_size_field_is_typed_error():
    routes, _ = _bb_fixture_repo()
    root = json.loads(routes[f"/repositories/owner/repo/src/{SHA}/"][2])
    del root["values"][0]["size"]
    routes[f"/repositories/owner/repo/src/{SHA}/"] = (200, {}, hs.json_body(root))
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="lacks integer size field"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_bitbucket_link_attribute_disagreement_fails_closed():
    routes, _ = _bb_fixture_repo()
    root = json.loads(routes[f"/repositories/owner/repo/src/{SHA}/"][2])
    root["values"][0]["attributes"] = ["link"]  # regular archive member, claimed link
    routes[f"/repositories/owner/repo/src/{SHA}/"] = (200, {}, hs.json_body(root))
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="attributes disagree with archive entry kind"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_bitbucket_archive_missing_blob_fails_closed():
    routes, _ = _bb_fixture_repo()
    root = json.loads(routes[f"/repositories/owner/repo/src/{SHA}/"][2])
    root["values"].append(
        {"type": "commit_file", "path": "ghost.txt", "size": 3, "attributes": []}
    )
    routes[f"/repositories/owner/repo/src/{SHA}/"] = (200, {}, hs.json_body(root))
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="missing listed blob: ghost.txt"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_bitbucket_archive_unlisted_blob_fails_closed():
    contents = {"a.txt": b"hello\n", "extra.txt": b"ghost\n"}
    root_values = [
        {"type": "commit_file", "path": "a.txt", "size": 6, "attributes": []}
    ]
    routes = {
        f"/repositories/owner/repo/src/{SHA}/": (
            200,
            {},
            hs.json_body({"values": root_values}),
        ),
        f"/repositories/owner/repo/get/{SHA}.tar.gz": (
            200,
            {},
            _fixture_archive("extra-root", contents),
        ),
    }
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="unlisted blob: extra.txt"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_bitbucket_malformed_values_is_typed_error():
    routes = {
        f"/repositories/owner/repo/src/{SHA}/": (200, {}, hs.json_body({"values": {}})),
    }
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="malformed tree metadata"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


_BITBUCKET_BASELINE_ENTRIES = [
    ('file_000.txt', '8b6dba364d1329fb8bb52745871c6f870693a545', 38, '100644'),
    ('file_001.txt', '7c4fe32fe1c936bcd718d09314c61918ac73a819', 38, '100644'),
    ('file_002.txt', '7c746363e1b6c705a4036f3f3fd3f4b48c8bb8b7', 38, '100644'),
    ('file_003.txt', '655270f694870a5a294f858e3f390a17bf900e44', 38, '100644'),
    ('file_004.txt', '9cc0ebe822f438ddba570357283e2a5407f66ef9', 38, '100644'),
    ('file_005.txt', '73be424e2b8edf048a798f4fee87852044f53bc0', 38, '100644'),
    ('file_006.txt', '093262c940836cd931e39c3ecf3d7bd10db2f877', 38, '100644'),
    ('file_007.txt', '14bac5a0225b9d8d13b7850d459190b48364b50b', 38, '100644'),
    ('file_008.txt', '93b3f02baf31c3b3fc49db529424bd3370167b2b', 38, '100644'),
    ('file_009.txt', '1115522a33623f7a4a0f5d142a574aca518b37c9', 38, '100644'),
    ('file_010.txt', '9d0cfd7a78a2664f65508c1a0fbc9303197047c3', 38, '100644'),
    ('file_011.txt', 'bdd257d68411527cf41fb40b798ec6331b4a4687', 38, '100644'),
    ('file_012.txt', '06fcc702cc9e226e3983917e6a35e68117215b9c', 38, '100644'),
    ('file_013.txt', '2c9c1aaf9893d9c8603477948480536e2dbcffa1', 38, '100644'),
    ('file_014.txt', '82cf6dacc2899a221e1c8eebb2b1fa56a8a2056e', 38, '100644'),
    ('file_015.txt', 'b85c93c04da2fee31c4095a61fa95c092c6d18a7', 38, '100644'),
    ('file_016.txt', '7466f999144282a46a65c6a2c7f87bc6d095e232', 38, '100644'),
    ('file_017.txt', 'b6316562e52742e32cf62c32d14669ed3ed0f59e', 38, '100644'),
    ('file_018.txt', '9e639ec9e4fcd548d959f81c911cd9cc8419b5a4', 38, '100644'),
    ('file_019.txt', 'd3a42eeda172326f338b6e521ccfa06f1e1abaa4', 38, '100644'),
    ('file_020.txt', '2e31a8f669a5318355d800b5456df81cf5d9d8f7', 38, '100644'),
    ('file_021.txt', '3ba2eb2c6284992bb1815caffe2b313232f6a118', 38, '100644'),
    ('file_022.txt', '8c50a87bbe9e08ad7086e5f130847fbdd87bb211', 38, '100644'),
    ('file_023.txt', '9ba49d5f738a81e35979e42028d1960f362fb097', 38, '100644'),
    ('file_024.txt', 'd661a84832b0c5080ea69e10dd1a07fe5498423f', 38, '100644'),
    ('file_025.txt', '964ec665923974ed2bcce73370dade7abfcbe0d2', 38, '100644'),
    ('file_026.txt', '8cb347dbc53018c4c600c9d695e863af868e4821', 38, '100644'),
    ('file_027.txt', '3d6ef467fcb69b4f1d6aad44dcfe0a75abf86208', 38, '100644'),
    ('file_028.txt', '68072764d1a6f04d6e3febd5e4cc1bdf00bc2108', 38, '100644'),
    ('file_029.txt', '7cdc887f038c9f917ae001d3f35c34795602d7af', 38, '100644'),
    ('pkg/file_000.txt', '36bea12d94b664436ee22aed4da904976ec3fdfb', 42, '100644'),
    ('pkg/file_001.txt', '39f51ebfb2ffd1428fbce840a36a15b8f58b77f4', 42, '100644'),
    ('pkg/file_002.txt', '35d091403885bab0c524f362ab53ba2199b387f3', 42, '100644'),
    ('pkg/file_003.txt', 'e4c4888fb462f600eecce79c69a7ff97b6419e7d', 42, '100644'),
    ('pkg/file_004.txt', '7f87e2e1c15c5b356a5e26f9a8e8373de413b0d3', 42, '100644'),
    ('pkg/file_005.txt', '7d70832d4c293ed22a8fc80df3f2179643be7d8d', 42, '100644'),
    ('pkg/file_006.txt', 'ce58d7dcc718a862c06156772a6203f641dc3bfe', 42, '100644'),
    ('pkg/file_007.txt', 'd36854aa3996e8b8077a610d3e90a406bd9029fc', 42, '100644'),
    ('pkg/file_008.txt', '2345e8578a59ae53d4f91dbe9b0b39d796bfa696', 42, '100644'),
    ('pkg/file_009.txt', '2640f72eb394cb5e77ef36a538aa7f3f80df3787', 42, '100644'),
    ('pkg/file_010.txt', '15f579f9a0b1195c36eaabb7b409f865d070a419', 42, '100644'),
    ('pkg/file_011.txt', '859852e45b0534c2c6eed0c72c85102292ff8b26', 42, '100644'),
    ('pkg/file_012.txt', '6c3f2185af8acd6032ee8cecad0fd1bde492a24c', 42, '100644'),
    ('pkg/file_013.txt', '50199ed53be1f57e2937c1fa96223682ce3cbf8d', 42, '100644'),
    ('pkg/file_014.txt', '48c91200297aeaea83fe9af0b5826635323dc947', 42, '100644'),
    ('pkg/file_015.txt', '3744a9db19511522e4ba47d1e3a64fc83fc1a9fa', 42, '100644'),
    ('pkg/file_016.txt', 'd6d24c3fe87f5970369c26f3f5ae6b82cc1528bb', 42, '100644'),
    ('pkg/file_017.txt', '24663ac7366bb7518e1c4b2b6faed65829c3aba4', 42, '100644'),
    ('pkg/file_018.txt', '4ce5efe87d41e0f16832e1e9fe308e2cc637a1d2', 42, '100644'),
    ('pkg/file_019.txt', '02e4784619af586d602e353b4216ce3f997a85e5', 42, '100644'),
    ('pkg/file_020.txt', 'e37593c22e0a7dbc5e511698a0e398d9915755cb', 42, '100644'),
    ('pkg/file_021.txt', 'f871a16e172f27decf064148ece87bd177bc88c6', 42, '100644'),
    ('pkg/file_022.txt', 'f76ece8ccb192039696c7b28fe69b011a40cdb13', 42, '100644'),
    ('pkg/file_023.txt', '4710db456c3d5ebf93c122b6d9748ebc366a1abf', 42, '100644'),
    ('pkg/file_024.txt', 'e917ee29ceeb21e01d3832e6dc570289c8f29380', 42, '100644'),
    ('pkg/file_025.txt', '3a0d189c75e8ac85e6438d5f9686d9583ebf4ae4', 42, '100644'),
    ('pkg/file_026.txt', '94efa54bdee32759214263fabee40ad920ece766', 42, '100644'),
    ('pkg/file_027.txt', '88fd12a6cf29509212025f3f795090d949faa68c', 42, '100644'),
    ('pkg/file_028.txt', '8d06c1c2f1e1b05930ee8b117e53a262547a3b6e', 42, '100644'),
    ('pkg/link.txt', '67a39b521f3455b2572fc82699c32d2f0537ff5e', 12, '120000'),
]


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
