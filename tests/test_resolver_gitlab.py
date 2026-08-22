from __future__ import annotations

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
    Ecosystem,
    GitLabResolver,
    GoResolver,
    PackageRef,
    ResolutionError,
    TagAbsentError,
)

SHA = "a" * 40


def _resolver(base_url, **kwargs):
    return GitLabResolver(base_url=base_url, sleeper=lambda _: None, **kwargs)


def test_resolves_ref_to_lowercase_commit_sha():
    with hs.scripted_server([(200, {}, hs.json_body({"id": SHA.upper()}))]) as server:
        assert _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "release/1") == SHA
    assert server.state.request_paths == ["/projects/owner%2Frepo/repository/commits/release%2F1"]


def test_resolves_subgroup_project_ref_with_encoded_full_path():
    with hs.scripted_server([(200, {}, hs.json_body({"id": SHA.upper()}))]) as server:
        assert _resolver(server.base_url).resolve_tag_to_sha(
            "group/subgroup/project", "main"
        ) == SHA
    assert server.state.request_paths == [
        "/projects/group%2Fsubgroup%2Fproject/repository/commits/main"
    ]


def test_commit_sha_input_is_verified_through_api():
    with hs.scripted_server([(200, {}, hs.json_body({"id": SHA}))]) as server:
        assert _resolver(server.base_url).resolve_ref_to_sha("owner/repo", SHA) == SHA
    assert server.state.served_count == 1


def test_pseudo_version_commit_prefix_is_expanded_through_api():
    with hs.scripted_server([(200, {}, hs.json_body({"id": SHA}))]) as server:
        assert _resolver(server.base_url).resolve_commit_to_sha(
            "owner/repo", "abcdef123456"
        ) == SHA
    assert server.state.request_paths == [
        "/projects/owner%2Frepo/repository/commits/abcdef123456"
    ]


def test_404_is_wrapped_without_retry():
    sleeps = []
    with hs.scripted_server([(404, {}, b"")]) as server:
        resolver = GitLabResolver(base_url=server.base_url, sleeper=sleeps.append)
        with pytest.raises(TagAbsentError, match="HTTP 404"):
            resolver.resolve_tag_to_sha("owner/repo", "missing")
    assert sleeps == []


def test_non_404_stays_resolution_error():
    with hs.scripted_server([(500, {}, b"")]) as server:
        with pytest.raises(ResolutionError, match="HTTP 500") as caught:
            _resolver(server.base_url, max_attempts=1).resolve_tag_to_sha(
                "owner/repo", "main"
            )
    assert not isinstance(caught.value, TagAbsentError)


def test_go_nested_module_advances_after_absent_repository_candidate():
    responses = [
        (404, {}, b""),
        (200, {}, hs.json_body({"id": SHA})),
    ]
    with hs.scripted_server(responses) as repository, hs.scripted_server(
        [(200, {}, hs.json_body({}))]
    ) as proxy:
        hosted = _resolver(repository.base_url)
        resolver = GoResolver(
            hosted,
            base_url=proxy.base_url,
            repository_resolvers={"gitlab.com": hosted},
        )
        result = resolver.resolve(
            PackageRef(
                Ecosystem.GO,
                "gitlab.com/group/project/submodule",
                "v1.0.0",
            )
        )

    assert result.scope.slug == "group/project"
    assert result.subpath == "submodule"
    assert repository.state.served_count == 2


def test_rate_limit_retries():
    sleeps = []
    responses = [
        (429, {"Retry-After": "0"}, b""),
        (200, {}, hs.json_body({"id": SHA})),
    ]
    with hs.scripted_server(responses) as server:
        resolver = GitLabResolver(base_url=server.base_url, sleeper=sleeps.append)
        assert resolver.resolve_tag_to_sha("owner/repo", "main") == SHA
    assert sleeps == [0.0]


@pytest.mark.parametrize("payload", [{}, {"id": "short"}, [], {"id": 1}])
def test_malformed_commit_metadata_is_honest(payload):
    with hs.scripted_server([(200, {}, hs.json_body(payload))]) as server:
        with pytest.raises(ResolutionError, match="malformed commit metadata"):
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "main")


def test_archive_url_uses_project_api_and_pinned_sha():
    url = GitLabResolver().archive_url("owner/repo", SHA)
    assert url == "https://gitlab.com/api/v4/projects/owner%2Frepo/repository/archive.tar.gz?sha=" + SHA


def test_tree_listing_maps_gitlab_blobs():
    content = b"content"
    payload = [
        {
            "id": _gitlab_blob_sha(content),
            "path": "src/a.py",
            "type": "blob",
            "mode": "100644",
        }
    ]
    routes = {
        "/projects/owner%2Frepo/repository/tree": (200, {}, hs.json_body(payload)),
        "/projects/owner%2Frepo/repository/archive.tar.gz": (
            200,
            {},
            _fixture_archive("single-root", {"src/a.py": content}),
        ),
    }
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert [(entry.path, entry.blob_sha, entry.size, entry.mode) for entry in entries] == [
        ("src/a.py", _gitlab_blob_sha(content), 7, "100644")
    ]
    assert server.state.served_count == 2  # one tree page + one archive download


def test_environment_token_uses_private_token_only_for_https_host(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return io.BytesIO(hs.json_body({"id": SHA}))

    monkeypatch.setenv("GITLAB_TOKEN", "secret-value")
    monkeypatch.setattr("leitir._http.safe_urlopen", fake_urlopen)
    assert GitLabResolver().resolve_tag_to_sha("owner/repo", "main") == SHA
    assert captured["Private-token"] == "secret-value"


def test_token_is_never_rendered_on_failure(monkeypatch, capsys):
    monkeypatch.setenv("GITLAB_TOKEN", "never-print-this")
    with hs.scripted_server([(404, {}, b"")]) as server:
        with pytest.raises(ResolutionError) as caught:
            _resolver(server.base_url).resolve_tag_to_sha("owner/repo", "main")
    assert "never-print-this" not in str(caught.value)
    assert "never-print-this" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Issue #195: page-bounded enumeration. Fixtures are deterministic (sorted
# members, zeroed mtimes, gzip mtime 0) and pinned by digest; the expected
# entry tuples were captured by running BASELINE list_blobs (commit 8aa08e2c)
# against these same fixtures, so byte-identical parity is asserted directly.

_GITLAB_FIXTURE_ROOT = "gitlab-fixture-root"
_GITLAB_TREE_PAYLOAD_SHA256 = "643ab2c84f28b7a34ec06ddb6026ab1501ea9b6a26a1b507b4c06bab8aa1661f"
# Pin the UNCOMPRESSED tar stream: gzip.compress output bytes vary with the
# platform zlib (Python 3.11/3.12 and Windows emit different, equally valid
# deflate streams), while the tar member bytes/order are identical everywhere.
_GITLAB_ARCHIVE_TAR_SHA256 = "bab1839a5fd83d319c46500c1820b2539f3f957acbfa7d5eaaf24ae368f731f7"
_GITLAB_AC1_ENTRIES_SHA256 = "4c9e448bafe0efb5d5bd9db21d3f64f397bc6284caa46903c333b3b2b2dda728"
_AC1_TOTAL = 2500
_AC1_PER_PAGE = 100


def _gitlab_blob_sha(content: bytes) -> str:
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


def _gitlab_fixture_paths():
    paths = [(f"src/file_{i:03d}.py", "100644") for i in range(58)]
    paths.append(("bin/tool", "100755"))
    paths.append(("docs/link.md", "120000"))
    return paths


def _gitlab_fixture_content(path):
    if path == "bin/tool":
        return b"#!/bin/sh\necho leitir fixture tool\n"
    if path == "docs/link.md":
        return b"../src/file_000.py"
    return f"# leitir gitlab fixture {path}\n".encode()


def _gitlab_fixture_repo(omit_archive=frozenset(), substitute_archive=None):
    """Deterministic 60-blob repo: 58 regular files, 1 executable, 1 symlink.

    ``omit_archive`` drops paths from the ARCHIVE only (export-ignore
    shape); ``substitute_archive`` replaces a member's archived bytes
    (export-subst shape). The tree listing and per-blob probes always
    describe the pristine content, exactly like a gitattributes repo.
    """
    contents = {
        path: _gitlab_fixture_content(path) for path, _ in _gitlab_fixture_paths()
    }
    items = [
        {
            "id": _gitlab_blob_sha(contents[path]),
            "name": path.rsplit("/", 1)[-1],
            "type": "blob",
            "path": path,
            "mode": mode,
        }
        for path, mode in _gitlab_fixture_paths()
    ]
    archived = {
        path: content
        for path, content in contents.items()
        if path not in omit_archive
    }
    if substitute_archive:
        archived = {
            path: substitute_archive.get(path, content)
            for path, content in archived.items()
        }
    routes = {
        "/projects/owner%2Frepo/repository/tree": (200, {}, hs.json_body(items)),
        "/projects/owner%2Frepo/repository/archive.tar.gz": (
            200,
            {},
            _fixture_archive(
                _GITLAB_FIXTURE_ROOT, archived, frozenset({"docs/link.md"})
            ),
        ),
    }
    # Per-blob size probes: the baseline channel. Clean enumerations never
    # request these; the bounded divergence fallback does, one per
    # divergent path (issue #195 remediation).
    for item in items:
        routes[f"/projects/owner%2Frepo/repository/blobs/{item['id']}"] = (
            200,
            {},
            hs.json_body({"size": len(contents[item["path"]])}),
        )
    return routes, contents


def test_gitlab_request_count_is_page_bounded():
    routes, _ = _gitlab_fixture_repo()
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    blob_probes = [
        path for path in server.state.request_paths if "/repository/blobs/" in path
    ]
    assert blob_probes == []
    assert server.state.request_paths == [
        "/projects/owner%2Frepo/repository/tree",
        "/projects/owner%2Frepo/repository/archive.tar.gz",
    ]
    assert server.state.served_count <= 3  # 1 tree page + 1 archive + slack
    assert len(entries) == 60


def test_gitlab_entries_are_byte_identical_to_baseline_capture():
    routes, _ = _gitlab_fixture_repo()
    assert (
        hashlib.sha256(routes["/projects/owner%2Frepo/repository/tree"][2]).hexdigest()
        == _GITLAB_TREE_PAYLOAD_SHA256
    )
    assert (
        hashlib.sha256(
            gzip.decompress(routes["/projects/owner%2Frepo/repository/archive.tar.gz"][2])
        ).hexdigest()
        == _GITLAB_ARCHIVE_TAR_SHA256
    )
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert [
        (entry.path, entry.blob_sha, entry.size, entry.mode) for entry in entries
    ] == _GITLAB_BASELINE_ENTRIES


def test_gitlab_repeated_enumeration_is_cached_and_identical():
    routes, _ = _gitlab_fixture_repo()
    with hs.routed_server(routes) as server:
        resolver = _resolver(server.base_url)
        first = resolver.list_blobs("owner/repo", SHA)
        second = resolver.list_blobs("owner/repo", SHA)
    assert second == first
    assert server.state.served_count == 2  # second call served from cache


def _ac1_content(path):
    return f"# ac1 fixture {path}\n".encode()


def test_gitlab_2500_file_enumeration_is_page_bounded():
    contents = {
        f"src/file_{i:04d}.py": _ac1_content(f"src/file_{i:04d}.py")
        for i in range(_AC1_TOTAL)
    }
    pages = []
    for page in range(_AC1_TOTAL // _AC1_PER_PAGE):
        items = [
            {
                "id": _gitlab_blob_sha(contents[path]),
                "name": path.rsplit("/", 1)[-1],
                "type": "blob",
                "path": path,
                "mode": "100644",
            }
            for path in sorted(contents)[
                page * _AC1_PER_PAGE : (page + 1) * _AC1_PER_PAGE
            ]
        ]
        pages.append((200, {}, hs.json_body(items)))
    pages.append((200, {}, hs.json_body([])))  # terminal empty page 26
    archive = (200, {}, _fixture_archive("ac1-root", contents))
    tree_pages = _AC1_TOTAL // _AC1_PER_PAGE + 1
    with hs.scripted_server([*pages, archive]) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
        served = server.state.served_count
    assert len(entries) == _AC1_TOTAL
    assert served <= tree_pages + 2  # tree pages + 1 archive + retry slack
    assert (
        sum(1 for path in server.state.request_paths if "archive.tar.gz" in path) == 1
    )
    digest = hashlib.sha256(
        json.dumps(
            [[entry.path, entry.blob_sha, entry.size, entry.mode] for entry in entries]
        ).encode()
    ).hexdigest()
    assert digest == _GITLAB_AC1_ENTRIES_SHA256


def _tree_page_number(path):
    from urllib.parse import parse_qs, urlparse

    return int(parse_qs(urlparse(path).query).get("page", ["1"])[0])


def test_gitlab_rate_limit_mid_walk_resumes_without_refetching_pages():
    contents = {
        f"src/file_{i:04d}.py": _ac1_content(f"src/file_{i:04d}.py")
        for i in range(250)
    }
    paths = sorted(contents)

    def page_response(paths_on_page):
        items = [
            {
                "id": _gitlab_blob_sha(contents[path]),
                "name": path.rsplit("/", 1)[-1],
                "type": "blob",
                "path": path,
                "mode": "100644",
            }
            for path in paths_on_page
        ]
        return (200, {}, hs.json_body(items))

    page1 = page_response(paths[:100])
    page2 = page_response(paths[100:200])
    page3 = page_response(paths[200:])
    archive = (200, {}, _fixture_archive("resume-root", contents))
    with hs.scripted_server(
        [page1, page2, (429, {"Retry-After": "0"}, b"")]
    ) as server:
        resolver = GitLabResolver(
            base_url=server.base_url, sleeper=lambda _: None, max_attempts=1
        )
        with pytest.raises(ResolutionError, match="HTTP 429"):
            resolver.list_blobs("owner/repo", SHA)
        assert server.state.served_count == 3
        # The limit lifts; the retry resumes from the cached pages.
        server.state.responses = [page1, page2, page3, archive]
        server.state.index = 2
        entries = resolver.list_blobs("owner/repo", SHA)
    assert len(entries) == 250
    tree_pages = [_tree_page_number(path) for path in server.state.request_paths if "/tree?" in path]
    assert tree_pages.count(1) == 1  # resumed from cache, not refetched
    assert tree_pages.count(2) == 1
    pages_total = 3
    retry_slack = 2  # one failed request + the single archive download
    assert server.state.served_count <= pages_total + retry_slack


def test_gitlab_single_digest_divergence_falls_back_to_baseline_probe():
    # CCR-amended SP-2 (issue #195 remediation): one tampered listing id is
    # one divergent path — re-verified on the baseline per-blob channel, the
    # entry byte-identical to what the baseline per-blob enumeration built.
    routes, _ = _gitlab_fixture_repo()
    tree = json.loads(routes["/projects/owner%2Frepo/repository/tree"][2])
    tree[0]["id"] = "0" * 40  # listing id disagrees with the archive digest
    routes["/projects/owner%2Frepo/repository/tree"] = (200, {}, hs.json_body(tree))
    routes[f"/projects/owner%2Frepo/repository/blobs/{'0' * 40}"] = (
        200,
        {},
        hs.json_body({"size": 40}),  # the baseline probe's size for src/file_000.py
    )
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    baseline_first = _GITLAB_BASELINE_ENTRIES[2]  # src/file_000.py, sorted position
    assert baseline_first == (
        "src/file_000.py",
        "21b10b1efa0e3e30d572dbabc2c3c1fa6edd236b",
        40,
        "100644",
    )
    assert [
        (entry.path, entry.blob_sha, entry.size, entry.mode) for entry in entries
    ][2] == ("src/file_000.py", "0" * 40, 40, "100644")
    blob_probes = [
        path for path in server.state.request_paths if "/repository/blobs/" in path
    ]
    assert blob_probes == [f"/projects/owner%2Frepo/repository/blobs/{'0' * 40}"]


def test_gitlab_archive_missing_blob_fails_closed():
    # The ghost path is divergent (export-ignore shape) but the baseline
    # channel refuses it too: no probe route exists, so the fallback's
    # per-blob fetch fails closed with a typed error (CCR-amended SP-2).
    routes, _ = _gitlab_fixture_repo()
    tree = json.loads(routes["/projects/owner%2Frepo/repository/tree"][2])
    tree.append(
        {
            "id": "f" * 40,
            "name": "ghost.py",
            "type": "blob",
            "path": "src/ghost.py",
            "mode": "100644",
        }
    )
    routes["/projects/owner%2Frepo/repository/tree"] = (200, {}, hs.json_body(tree))
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="HTTP 404"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert (
        f"/projects/owner%2Frepo/repository/blobs/{'f' * 40}"
        in server.state.request_paths
    )


def test_gitlab_archive_unlisted_blob_fails_closed():
    contents = {"a.txt": b"hello\n", "extra.txt": b"ghost\n"}
    tree = [
        {
            "id": _gitlab_blob_sha(contents["a.txt"]),
            "name": "a.txt",
            "type": "blob",
            "path": "a.txt",
            "mode": "100644",
        }
    ]
    routes = {
        "/projects/owner%2Frepo/repository/tree": (200, {}, hs.json_body(tree)),
        "/projects/owner%2Frepo/repository/archive.tar.gz": (
            200,
            {},
            _fixture_archive("extra-root", contents),
        ),
    }
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="unlisted blob: extra.txt"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_gitlab_symlink_mode_disagreement_fails_closed():
    contents = {"a.txt": b"hello\n", "link.txt": b"a.txt"}
    tree = [
        {
            "id": _gitlab_blob_sha(contents[path]),
            "name": path,
            "type": "blob",
            "path": path,
            "mode": "100644",  # listing claims regular; archive member is a symlink
        }
        for path in sorted(contents)
    ]
    routes = {
        "/projects/owner%2Frepo/repository/tree": (200, {}, hs.json_body(tree)),
        "/projects/owner%2Frepo/repository/archive.tar.gz": (
            200,
            {},
            _fixture_archive("mode-root", contents, frozenset({"link.txt"})),
        ),
    }
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="mode disagrees"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_gitlab_malformed_tree_page_is_typed_error():
    routes = {
        "/projects/owner%2Frepo/repository/tree": (200, {}, hs.json_body({"values": []})),
    }
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="malformed tree metadata"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_gitlab_export_ignored_path_falls_back_exactly_like_baseline():
    # .gitattributes export-ignore: the archive omits src/file_030.py but the
    # tree listing still carries it. The bounded fallback re-verifies that
    # ONE path on the baseline per-blob channel; every entry — including the
    # fallback one — is byte-identical to the baseline capture.
    routes, _ = _gitlab_fixture_repo(omit_archive=frozenset({"src/file_030.py"}))
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert [
        (entry.path, entry.blob_sha, entry.size, entry.mode) for entry in entries
    ] == _GITLAB_BASELINE_ENTRIES
    blob_probes = [
        path for path in server.state.request_paths if "/repository/blobs/" in path
    ]
    assert len(blob_probes) == 1  # exactly one baseline-channel probe
    assert blob_probes[0].endswith(
        _gitlab_blob_sha(b"# leitir gitlab fixture src/file_030.py\n")
    )


def test_gitlab_export_subst_content_falls_back_exactly_like_baseline():
    # .gitattributes export-subst: the archived bytes for src/file_031.py are
    # substituted (here also a different length); the listing id still names
    # the pristine blob. The fallback takes size from the baseline probe, so
    # every entry stays byte-identical to the baseline capture.
    substituted = b"$Id: expanded by export-subst beyond original length\x1a\n"
    routes, _ = _gitlab_fixture_repo(
        substitute_archive={"src/file_031.py": substituted}
    )
    assert len(substituted) != 40  # sizes genuinely differ between channels
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert [
        (entry.path, entry.blob_sha, entry.size, entry.mode) for entry in entries
    ] == _GITLAB_BASELINE_ENTRIES
    blob_probes = [
        path for path in server.state.request_paths if "/repository/blobs/" in path
    ]
    assert len(blob_probes) == 1


def _divergent_fixture_repo(total, archived):
    """Repo with ``total`` listed files and an archive carrying only the
    first ``archived`` of them (export-ignore at scale)."""
    contents = {
        f"src/file_{i:04d}.py": f"# divergence fixture {i}\n".encode()
        for i in range(total)
    }
    items = [
        {
            "id": _gitlab_blob_sha(contents[path]),
            "name": path.rsplit("/", 1)[-1],
            "type": "blob",
            "path": path,
            "mode": "100644",
        }
        for path in sorted(contents)
    ]
    routes = {
        "/projects/owner%2Frepo/repository/tree": (200, {}, hs.json_body(items)),
        "/projects/owner%2Frepo/repository/archive.tar.gz": (
            200,
            {},
            _fixture_archive(
                "divergence-root", dict(list(sorted(contents.items()))[:archived])
            ),
        ),
    }
    for item in items:
        routes[f"/projects/owner%2Frepo/repository/blobs/{item['id']}"] = (
            200,
            {},
            hs.json_body({"size": len(contents[item["path"]])}),
        )
    return routes, contents


def test_gitlab_fallback_cap_thirty_three_divergent_paths_fails_closed():
    # 34 listed files, 1 archived → 33 divergent > cap 32 → the archive
    # channel is judged inconsistent: typed error BEFORE any per-path fetch
    # (fail-closed, no request storm).
    routes, _ = _divergent_fixture_repo(total=34, archived=1)
    with hs.routed_server(routes) as server:
        with pytest.raises(
            ResolutionError, match=r"diverges from tree listing on 33 paths \(limit 32\)"
        ):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)
    blob_probes = [
        path for path in server.state.request_paths if "/repository/blobs/" in path
    ]
    assert blob_probes == []  # the cap fires before any fallback fetch
    assert server.state.served_count == 2  # one tree page + one archive


def test_gitlab_fallback_cap_boundary_thirty_two_divergent_paths_succeeds():
    # Exactly at the cap: 34 listed, 2 archived → 32 divergent paths, each
    # re-verified on the baseline channel — enumeration succeeds with
    # baseline-identical entries.
    routes, contents = _divergent_fixture_repo(total=34, archived=2)
    with hs.routed_server(routes) as server:
        entries = _resolver(server.base_url).list_blobs("owner/repo", SHA)
    assert [
        (entry.path, entry.blob_sha, entry.size, entry.mode) for entry in entries
    ] == [
        (path, _gitlab_blob_sha(content), len(content), "100644")
        for path, content in sorted(contents.items())
    ]
    blob_probes = [
        path for path in server.state.request_paths if "/repository/blobs/" in path
    ]
    assert len(blob_probes) == 32


def test_gitlab_archive_member_count_cap_is_typed_error(monkeypatch):
    monkeypatch.setattr("leitir.resolver._ARCHIVE_MAX_MEMBERS", 2)
    content = {"a.txt": b"hello\n", "b.txt": b"world\n", "c.txt": b"extra\n"}
    routes = _gitlab_archive_routes(content)
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="too many members"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_gitlab_archive_member_size_cap_is_typed_error(monkeypatch):
    monkeypatch.setattr("leitir.resolver._ARCHIVE_MAX_MEMBER_BYTES", 4)
    content = {"a.txt": b"hello\n"}
    routes = _gitlab_archive_routes(content)
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="member exceeds size limit"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_gitlab_archive_total_size_cap_is_typed_error(monkeypatch):
    monkeypatch.setattr("leitir.resolver._ARCHIVE_MAX_TOTAL_BYTES", 8)
    content = {"a.txt": b"hello\n", "b.txt": b"world\n"}
    routes = _gitlab_archive_routes(content)
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="total size limit"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_gitlab_duplicate_archive_path_is_typed_error():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for _ in range(2):
            info = tarfile.TarInfo("dup-root/a.txt")
            info.size = 6
            info.mtime = 0
            tar.addfile(info, io.BytesIO(b"hello\n"))
    routes = {
        "/projects/owner%2Frepo/repository/tree": (
            200,
            {},
            hs.json_body(
                [
                    {
                        "id": _gitlab_blob_sha(b"hello\n"),
                        "name": "a.txt",
                        "type": "blob",
                        "path": "a.txt",
                        "mode": "100644",
                    }
                ]
            ),
        ),
        "/projects/owner%2Frepo/repository/archive.tar.gz": (
            200,
            {},
            gzip.compress(raw.getvalue(), mtime=0),
        ),
    }
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="duplicate path: a.txt"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def test_gitlab_non_gzip_archive_is_typed_error():
    # The archive channel is pinned to tar.gz (materialize parity); an xz
    # stream must surface as a typed ResolutionError, never an untyped
    # LZMAError escape.
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:xz", format=tarfile.PAX_FORMAT) as tar:
        info = tarfile.TarInfo("xz-root/a.txt")
        info.size = 6
        info.mtime = 0
        tar.addfile(info, io.BytesIO(b"hello\n"))
    routes = {
        "/projects/owner%2Frepo/repository/tree": (
            200,
            {},
            hs.json_body([]),
        ),
        "/projects/owner%2Frepo/repository/archive.tar.gz": (
            200,
            {},
            raw.getvalue(),
        ),
    }
    with hs.routed_server(routes) as server:
        with pytest.raises(ResolutionError, match="malformed source archive"):
            _resolver(server.base_url).list_blobs("owner/repo", SHA)


def _gitlab_archive_routes(content):
    tree = [
        {
            "id": _gitlab_blob_sha(data),
            "name": path,
            "type": "blob",
            "path": path,
            "mode": "100644",
        }
        for path, data in sorted(content.items())
    ]
    return {
        "/projects/owner%2Frepo/repository/tree": (200, {}, hs.json_body(tree)),
        "/projects/owner%2Frepo/repository/archive.tar.gz": (
            200,
            {},
            _fixture_archive("caps-root", content),
        ),
    }


_GITLAB_BASELINE_ENTRIES = [
    ('bin/tool', 'f88329aab41da89224bd7dd2fd11129e9129af35', 35, '100755'),
    ('docs/link.md', 'e1f30f92592987ced63c0ec4c81c2181271a59c9', 18, '120000'),
    ('src/file_000.py', '21b10b1efa0e3e30d572dbabc2c3c1fa6edd236b', 40, '100644'),
    ('src/file_001.py', '3f16e1cdfbdf24b0333946e0dd7a0954f2c5a82c', 40, '100644'),
    ('src/file_002.py', '24fd04dd3de4d4ede1121532dc895279381fc63a', 40, '100644'),
    ('src/file_003.py', '4171f3146eaac2abf091e3007d2e05442072dacb', 40, '100644'),
    ('src/file_004.py', '7ca7fd6c261c1e4c376c85b4c187d2b8ffc2bb1f', 40, '100644'),
    ('src/file_005.py', '4b5f41a826a55ef2b9d6960a50951847c4d9da16', 40, '100644'),
    ('src/file_006.py', '2e212402361de2d3b68977e6f8ca27c72970eacb', 40, '100644'),
    ('src/file_007.py', '3f784a59877ec0ea9a612196a9da3d4d20d11c71', 40, '100644'),
    ('src/file_008.py', 'a5bd0900510fc352f277e27fad64120d7d4ca32e', 40, '100644'),
    ('src/file_009.py', 'b0dcfcac33dfaac47fac41b8e3a47a677c30fc5e', 40, '100644'),
    ('src/file_010.py', '1115c1bbe9bef4729ee1d5c278b158436cc9c51a', 40, '100644'),
    ('src/file_011.py', 'ccf0ad58429198246f329dd62420169958db2ce0', 40, '100644'),
    ('src/file_012.py', 'c9635cab156112aee1b8473602a95040b827aef7', 40, '100644'),
    ('src/file_013.py', '3132e6bf088cb63f0a56ded534158724350dc4ae', 40, '100644'),
    ('src/file_014.py', 'e6010a820ee1e97952347be083bfad52ea7b661c', 40, '100644'),
    ('src/file_015.py', '61e1a2ef096520d38cc16333c873a0fa1f61e3f1', 40, '100644'),
    ('src/file_016.py', 'df8a0a863f9cef2bb2a239777435f9479f58a90f', 40, '100644'),
    ('src/file_017.py', '6dd8624cdfa46f351e4591e1252ebbb1c0c4f661', 40, '100644'),
    ('src/file_018.py', '60d7ce27980cd1af9e5d72add1f490da69b44f6f', 40, '100644'),
    ('src/file_019.py', '526d21fbfe721d4619d240459191cb37b89d0134', 40, '100644'),
    ('src/file_020.py', '022276f29b6b5f460f32c4e44c05da70cb103fe7', 40, '100644'),
    ('src/file_021.py', '4eb2fa32cccddb6f222513b4d56a007842e4a6ca', 40, '100644'),
    ('src/file_022.py', '09797bbc65a9a76c6185354549445ab182cdd935', 40, '100644'),
    ('src/file_023.py', '8e9759bb94c35170304fa5a99841fe0a02adac00', 40, '100644'),
    ('src/file_024.py', '644c8ac6b5f7b5c8c1f39c352754c08b6a9c4de4', 40, '100644'),
    ('src/file_025.py', '8d670fd2f17c37c9ecb09c4e8399b06a33ebac3f', 40, '100644'),
    ('src/file_026.py', '315e4b629a93a4e812d6581c9d4e2014c8ffb44f', 40, '100644'),
    ('src/file_027.py', '5575047a12b454da95dd50f705a555438eaefbea', 40, '100644'),
    ('src/file_028.py', 'dd493c1ef82ab6cf03f1920f86c358bd6cb607b6', 40, '100644'),
    ('src/file_029.py', '346808f2fbea31b2f3301d39948525810d908f72', 40, '100644'),
    ('src/file_030.py', '4a7620a66e3f91bab66f0d47ffbe2412b0efd1d6', 40, '100644'),
    ('src/file_031.py', 'f1311416d7fd6bcd40e3d1a698222824e7a2e814', 40, '100644'),
    ('src/file_032.py', '9aa663293ed3ec5d3233d80e2052379951c1e063', 40, '100644'),
    ('src/file_033.py', '3ead835ac808937f0c2b9f680c1269b143091e25', 40, '100644'),
    ('src/file_034.py', '103b4bd9b8d9b0506426bb0804d7cfa97983a00c', 40, '100644'),
    ('src/file_035.py', '98d78d257d996be40ee4ba888c5c8bb8c1a0846e', 40, '100644'),
    ('src/file_036.py', 'db5bc22a5506b920796d17f79a25ebcb7b85b0c1', 40, '100644'),
    ('src/file_037.py', 'c9c89d41c1ed7cccc18d649b4b1549daffd6bce7', 40, '100644'),
    ('src/file_038.py', '34806bb66195f6536dd9a709d257d546d45adf07', 40, '100644'),
    ('src/file_039.py', '74c80e4f294d05f019a9b580fab7259b54b62df1', 40, '100644'),
    ('src/file_040.py', '1ba33cd1c9b57a8d5f7ca35d18678de8356fa7e8', 40, '100644'),
    ('src/file_041.py', '5841cf2cf3eb386480011be8bc6118b9565771d0', 40, '100644'),
    ('src/file_042.py', 'e0c09d46fa50d845c6057223a56e00cef63ff729', 40, '100644'),
    ('src/file_043.py', '21588fc62842e588c771f1abbc1c3f4e279cfe0d', 40, '100644'),
    ('src/file_044.py', 'b68bcd1279758d49a3aeedfa31092d0aa95891a8', 40, '100644'),
    ('src/file_045.py', 'b34bdbf653e61536e918ef245c79896d7642d197', 40, '100644'),
    ('src/file_046.py', 'acf4aa20e762aab85558429f76ab50861fad4b29', 40, '100644'),
    ('src/file_047.py', 'cabf48e9fa1ce41b72d0b3b1c2e14372bc1ef57b', 40, '100644'),
    ('src/file_048.py', '635c40982a6b9f0e399c764758d5abfc1131bed3', 40, '100644'),
    ('src/file_049.py', 'f2df5c8ffc6ec6334c9fc5b7a8c8189975498479', 40, '100644'),
    ('src/file_050.py', '54e9f4ba10c30458b44bbb56f7aeee7ccde3bdec', 40, '100644'),
    ('src/file_051.py', '8f21fec71bc234157e93d371834f84dde2fb6702', 40, '100644'),
    ('src/file_052.py', 'fbb57e164b416558162c41b7a0738d96a0a9e3fa', 40, '100644'),
    ('src/file_053.py', '1babb3f7b9174b60466a9e531e83e4ab4d1b806f', 40, '100644'),
    ('src/file_054.py', '1615575d25e6320265ec079f74f7a182dd1bef48', 40, '100644'),
    ('src/file_055.py', '939af439fc90d5cf6ee6e7d5982cb8b216d12af7', 40, '100644'),
    ('src/file_056.py', '10d19d324dd6b11c0f5fff1159d5126461421259', 40, '100644'),
    ('src/file_057.py', '044ea0e983ff6e45522cd136a1ebad77c184c15e', 40, '100644'),
]


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
)
def test_live_ref_resolves_to_pinned_commit():
    resolver = GitLabResolver()
    assert resolver.resolve_tag_to_sha(fx.GITLAB_SLUG, fx.GITLAB_REF) == fx.GITLAB_COMMIT_SHA


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live verification",
)
def test_live_subgroup_ref_resolves_to_pinned_commit():
    resolver = GitLabResolver()
    assert resolver.resolve_tag_to_sha(
        fx.GITLAB_SUBGROUP_SLUG, fx.GITLAB_SUBGROUP_REF
    ) == fx.GITLAB_SUBGROUP_COMMIT_SHA
