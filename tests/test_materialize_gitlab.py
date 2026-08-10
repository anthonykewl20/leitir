from __future__ import annotations

import io
import json
import tarfile

import _http_server as hs
import pytest

from leitir.cli import ExitCode, main
from leitir.materialize import MaterializationError, materialize_repo
from leitir.resolver import Ecosystem, GitLabResolver, PackageRef, ResolvedPackage
from leitir.search import RepoScope
from leitir.tree import GitHubTreeSource

SHA = "a" * 40
CONTENT = b"host-native proof\n"


def _tarball(content: bytes = CONTENT) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"demo-{SHA}/README.md")
        member.size = len(content)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _resolver(server) -> GitLabResolver:
    resolver = GitLabResolver(base_url=server.base_url, max_attempts=1)
    resolver.archive_url = lambda _slug, _sha: f"{server.base_url}/archive"  # type: ignore[method-assign]
    return resolver


def _tree(content: bytes = CONTENT) -> list[object]:
    return [
        {"id": GitHubTreeSource.git_blob_sha(content), "path": "README.md", "type": "blob", "mode": "100644"}
    ]


def test_cli_materializes_verified_gitlab_repository(tmp_path):
    responses = [
        (200, {}, _tarball()),
        (200, {}, hs.json_body(_tree())),
        (200, {}, hs.json_body({"size": len(CONTENT)})),
    ]
    with hs.scripted_server(responses) as server:
        resolver = _resolver(server)
        multi = type("Resolver", (), {"_repository_resolvers": {"gitlab.com": resolver}})()
        out, err = io.StringIO(), io.StringIO()
        code = main(
            ["get", f"gitlab:owner/demo@{SHA}", "--root", str(tmp_path)],
            resolver_factory=lambda _token: multi,
            code_search_factory=lambda _token: object(),
            stdout=out,
            stderr=err,
        )
    assert code == ExitCode.SUCCESS, err.getvalue()
    target = tmp_path / "repos/gitlab.com/owner/demo" / SHA
    assert out.getvalue().strip() == str(target)
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["host"] == "gitlab.com"
    assert manifest["repo_url"] == "https://gitlab.com/owner/demo"
    assert manifest["fetch_method"] == "gitlab-archive"
    assert manifest["verified"] is True
    assert server.state.request_paths[0] == "/archive"


def test_cli_materializes_go_package_through_resolved_gitlab_host(tmp_path):
    responses = [
        (200, {}, _tarball()),
        (200, {}, hs.json_body(_tree())),
        (200, {}, hs.json_body({"size": len(CONTENT)})),
    ]
    with hs.scripted_server(responses) as server:
        hosted = _resolver(server)

        class Resolver:
            _repository_resolvers = {"gitlab.com": hosted}

            def resolve(self, ref):
                assert ref == PackageRef(Ecosystem.GO, "gitlab.com/owner/demo", "v1.0.0")
                return ResolvedPackage(
                    ref,
                    RepoScope("owner/demo", SHA),
                    "v1.0.0",
                    "https://pkg.go.dev/gitlab.com/owner/demo@v1.0.0",
                    host="gitlab.com",
                )

        out, err = io.StringIO(), io.StringIO()
        code = main(
            ["get", "go:gitlab.com/owner/demo@v1.0.0", "--root", str(tmp_path)],
            resolver_factory=lambda _token: Resolver(),
            code_search_factory=lambda _token: object(),
            stdout=out,
            stderr=err,
        )
    target = tmp_path / "repos/gitlab.com/owner/demo" / SHA
    assert code == ExitCode.SUCCESS, err.getvalue()
    assert out.getvalue().strip() == str(target)
    assert json.loads((target / "leitir-manifest.json").read_text())["host"] == "gitlab.com"


def test_cli_materializes_verified_gitlab_subgroup_repository(tmp_path):
    responses = [
        (200, {}, _tarball()),
        (200, {}, hs.json_body(_tree())),
        (200, {}, hs.json_body({"size": len(CONTENT)})),
    ]
    slug = "group/subgroup/demo"
    with hs.scripted_server(responses) as server:
        resolver = _resolver(server)
        multi = type("Resolver", (), {"_repository_resolvers": {"gitlab.com": resolver}})()
        out, err = io.StringIO(), io.StringIO()
        code = main(
            ["get", f"gitlab:{slug}@{SHA}", "--root", str(tmp_path)],
            resolver_factory=lambda _token: multi,
            code_search_factory=lambda _token: object(),
            stdout=out,
            stderr=err,
        )
    target = tmp_path / "repos/gitlab.com/group/subgroup/demo" / SHA
    assert code == ExitCode.SUCCESS, err.getvalue()
    assert out.getvalue().strip() == str(target)
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["owner"] == "group/subgroup"
    assert manifest["repo"] == "demo"
    assert manifest["repo_url"] == f"https://gitlab.com/{slug}"
    assert manifest["verified"] is True
    assert server.state.request_paths[1:] == [
        f"/projects/group%2Fsubgroup%2Fdemo/repository/tree?ref={SHA}&recursive=true&per_page=100&page=1",
        f"/projects/group%2Fsubgroup%2Fdemo/repository/blobs/{GitHubTreeSource.git_blob_sha(CONTENT)}",
    ]


def test_gitlab_archive_404_cleans_target(tmp_path):
    with hs.scripted_server([(404, {}, b"missing")]) as server:
        with pytest.raises(MaterializationError, match="HTTP 404"):
            materialize_repo(
                tmp_path,
                f"gitlab:owner/demo@{SHA}",
                RepoScope("owner/demo", SHA),
                host="gitlab.com",
                resolver=_resolver(server),
            )
    assert not (tmp_path / "repos/gitlab.com/owner/demo" / SHA).exists()


def test_gitlab_verification_mismatch_fails_closed(tmp_path):
    expected = b"expected\n"
    responses = [
        (200, {}, _tarball(b"tampered\n")),
        (200, {}, hs.json_body(_tree(expected))),
        (200, {}, hs.json_body({"size": len(expected)})),
        (200, {}, expected),
    ]
    with hs.scripted_server(responses) as server:
        with pytest.raises(MaterializationError, match="VerificationError"):
            materialize_repo(
                tmp_path,
                f"gitlab:owner/demo@{SHA}",
                RepoScope("owner/demo", SHA),
                host="gitlab.com",
                resolver=_resolver(server),
            )
    target = tmp_path / "repos/gitlab.com/owner/demo" / SHA
    assert not target.exists()
    assert not list(target.parent.glob(f".{SHA}.tmp-*"))


def test_gitlab_token_is_never_logged_during_materialization(tmp_path, monkeypatch, capsys):
    token = "gitlab-materialize-secret"
    monkeypatch.setenv("GITLAB_TOKEN", token)
    with hs.scripted_server([(404, {}, b"")]) as server:
        with pytest.raises(MaterializationError) as caught:
            materialize_repo(
                tmp_path,
                f"gitlab:owner/demo@{SHA}",
                RepoScope("owner/demo", SHA),
                host="gitlab.com",
                resolver=_resolver(server),
            )
    assert token not in str(caught.value)
    assert token not in capsys.readouterr().err
