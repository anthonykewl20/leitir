from __future__ import annotations

import io
import json
import tarfile

import pytest

import _http_server as hs
from leitir.cli import ExitCode, main
from leitir.materialize import MaterializationError, materialize_repo
from leitir.resolver import BitbucketResolver
from leitir.search import RepoScope

SHA = "b" * 40
CONTENT = b"host-native proof\n"


def _tarball(content: bytes = CONTENT) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"owner-demo-{SHA[:12]}/README.md")
        member.size = len(content)
        member.mode = 0o644
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _resolver(server) -> BitbucketResolver:
    resolver = BitbucketResolver(base_url=server.base_url, max_attempts=1)
    resolver.archive_url = lambda _slug, _sha: f"{server.base_url}/archive"  # type: ignore[method-assign]
    return resolver


def _listing() -> dict[str, object]:
    return {"values": [{"type": "commit_file", "path": "README.md", "size": len(CONTENT)}]}


def test_cli_materializes_verified_bitbucket_repository(tmp_path):
    responses = [
        (200, {}, _tarball()),
        (200, {}, hs.json_body(_listing())),
        (200, {}, CONTENT),
    ]
    with hs.scripted_server(responses) as server:
        resolver = _resolver(server)
        multi = type("Resolver", (), {"_repository_resolvers": {"bitbucket.org": resolver}})()
        out, err = io.StringIO(), io.StringIO()
        code = main(
            ["get", f"bitbucket:owner/demo@{SHA}", "--root", str(tmp_path)],
            resolver_factory=lambda _token: multi,
            code_search_factory=lambda _token: object(),
            stdout=out,
            stderr=err,
        )
    assert code == ExitCode.SUCCESS, err.getvalue()
    target = tmp_path / "repos/bitbucket.org/owner/demo" / SHA
    assert out.getvalue().strip() == str(target)
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["host"] == "bitbucket.org"
    assert manifest["repo_url"] == "https://bitbucket.org/owner/demo"
    assert manifest["fetch_method"] == "bitbucket-archive"
    assert manifest["verified"] is True
    assert server.state.request_paths[0] == "/archive"


def test_bitbucket_archive_404_cleans_target(tmp_path):
    with hs.scripted_server([(404, {}, b"missing")]) as server:
        with pytest.raises(MaterializationError, match="HTTP 404"):
            materialize_repo(
                tmp_path,
                f"bitbucket:owner/demo@{SHA}",
                RepoScope("owner/demo", SHA),
                host="bitbucket.org",
                resolver=_resolver(server),
            )
    assert not (tmp_path / "repos/bitbucket.org/owner/demo" / SHA).exists()


def test_bitbucket_verification_mismatch_fails_closed(tmp_path):
    responses = [
        (200, {}, _tarball(b"tampered\n")),
        (200, {}, hs.json_body(_listing())),
        (200, {}, CONTENT),
        (200, {}, CONTENT),
    ]
    with hs.scripted_server(responses) as server:
        with pytest.raises(MaterializationError, match="VerificationError"):
            materialize_repo(
                tmp_path,
                f"bitbucket:owner/demo@{SHA}",
                RepoScope("owner/demo", SHA),
                host="bitbucket.org",
                resolver=_resolver(server),
            )
    target = tmp_path / "repos/bitbucket.org/owner/demo" / SHA
    assert not target.exists()
    assert not list(target.parent.glob(f".{SHA}.tmp-*"))


def test_bitbucket_token_is_never_logged_during_materialization(tmp_path, monkeypatch, capsys):
    token = "bitbucket-materialize-secret"
    monkeypatch.setenv("BITBUCKET_TOKEN", token)
    with hs.scripted_server([(404, {}, b"")]) as server:
        with pytest.raises(MaterializationError) as caught:
            materialize_repo(
                tmp_path,
                f"bitbucket:owner/demo@{SHA}",
                RepoScope("owner/demo", SHA),
                host="bitbucket.org",
                resolver=_resolver(server),
            )
    assert token not in str(caught.value)
    assert token not in capsys.readouterr().err
