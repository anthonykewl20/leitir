"""Offline coverage for corpus Git blob verification."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from leitir.cli import ExitCode, main
from leitir.materialize import MaterializationError, materialize_github_repo, read_valid_manifest
from leitir.tree import GitHubTreeSource

from _http_server import json_body, routed_server

SHA = "d" * 40


def _tarball(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for path, content in files.items():
            member = tarfile.TarInfo(f"demo-{SHA}/{path}")
            member.size = len(content)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _tree(files: dict[str, bytes], *, overrides: dict[str, str] | None = None) -> bytes:
    overrides = overrides or {}
    return json_body(
        {
            "tree": [
                {
                    "path": path,
                    "type": "blob",
                    "size": len(content),
                    "mode": "100644",
                    "sha": overrides.get(path, GitHubTreeSource.git_blob_sha(content)),
                }
                for path, content in files.items()
            ]
        }
    )


def _routes(files: dict[str, bytes], tree: bytes):
    return {
        f"/acme/demo/tar.gz/{SHA}": (200, {}, _tarball(files)),
        f"/repos/acme/demo/git/trees/{SHA}": (200, {}, tree),
    }


def _materialize(root: Path, base_url: str, **options: object) -> Path:
    return materialize_github_repo(
        root,
        "acme/demo",
        "acme",
        "demo",
        SHA,
        base_url=base_url,
        tree_base_url=base_url,
        max_attempts=1,
        **options,  # type: ignore[arg-type]
    )


def test_matching_tree_is_fully_verified(tmp_path):
    files = {"README.md": b"proof\n", "src/demo.py": b"answer = 42\n"}
    with routed_server(_routes(files, _tree(files))) as server:
        target = _materialize(tmp_path, server.base_url)
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["verified"] is True
    assert manifest["verified_at"].endswith("Z")


def test_over_cap_uses_deterministic_sample(tmp_path):
    files = {"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"}
    ranked = sorted(
        files,
        key=lambda path: hashlib.sha256(f"{SHA}\0{path}".encode()).digest(),
    )
    # A bad digest outside the one-file sample proves the sample path is stable.
    overrides = {ranked[1]: "0" * 40}
    with routed_server(_routes(files, _tree(files, overrides=overrides))) as server:
        target = _materialize(
            tmp_path,
            server.base_url,
            verification_max_files=1,
            verification_max_bytes=100,
        )
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["verified"] == "sampled"


def test_digest_mismatch_is_hard_failure_and_cleans_staging(tmp_path):
    files = {"proof.txt": b"proof"}
    routes = _routes(files, _tree(files, overrides={"proof.txt": "0" * 40}))
    with routed_server(routes) as server:
        with pytest.raises(MaterializationError, match="VerificationError"):
            _materialize(tmp_path, server.base_url)
    target = tmp_path / "repos/github.com/acme/demo" / SHA
    assert not target.exists()
    assert not list(target.parent.glob(f".{SHA}.tmp-*"))


def test_missing_extracted_regular_file_is_a_mismatch(tmp_path):
    archive_files = {"present.txt": b"present"}
    tree_files = {**archive_files, "missing.txt": b"missing"}
    routes = {
        f"/acme/demo/tar.gz/{SHA}": (200, {}, _tarball(archive_files)),
        f"/repos/acme/demo/git/trees/{SHA}": (200, {}, _tree(tree_files)),
    }
    with routed_server(routes) as server:
        with pytest.raises(MaterializationError, match="VerificationError"):
            _materialize(tmp_path, server.base_url)
    assert not (tmp_path / "repos/github.com/acme/demo" / SHA).exists()


def test_unenumerable_tree_is_hard_failure(tmp_path):
    files = {"proof.txt": b"proof"}
    routes = _routes(files, b"")
    routes[f"/repos/acme/demo/git/trees/{SHA}"] = (503, {}, b"unavailable")
    with routed_server(routes) as server:
        with pytest.raises(MaterializationError, match="TreeReadError"):
            _materialize(tmp_path, server.base_url)
    assert not (tmp_path / "repos/github.com/acme/demo" / SHA).exists()


def test_cli_uses_api_base_url_for_verification(tmp_path, monkeypatch):
    files = {"proof.txt": b"proof"}
    with routed_server(_routes(files, _tree(files))) as server:
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        out, err = io.StringIO(), io.StringIO()
        code = main(
            ["get", f"acme/demo@{SHA}", "--root", str(tmp_path)],
            stdout=out,
            stderr=err,
        )
    assert code == ExitCode.SUCCESS, err.getvalue()
    manifest = json.loads((Path(out.getvalue().strip()) / "leitir-manifest.json").read_text())
    assert manifest["verified"] is True


def test_no_verify_records_explicit_false_without_tree_request(tmp_path, monkeypatch):
    files = {"proof.txt": b"proof"}
    routes = {f"/acme/demo/tar.gz/{SHA}": (200, {}, _tarball(files))}
    with routed_server(routes) as server:
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        out, err = io.StringIO(), io.StringIO()
        code = main(
            ["fetch", f"acme/demo@{SHA}", "--root", str(tmp_path), "--no-verify"],
            stdout=out,
            stderr=err,
        )
        paths = server.state.request_paths
    assert code == ExitCode.SUCCESS, err.getvalue()
    target = tmp_path / "repos/github.com/acme/demo" / SHA
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["verified"] is False
    assert manifest["verified_at"] is None
    assert paths == [f"/acme/demo/tar.gz/{SHA}"]


def test_legacy_manifest_without_verification_fields_still_loads(tmp_path):
    target = tmp_path / "legacy"
    target.mkdir()
    payload = {
        "spec": "acme/demo",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
        "tag": None,
        "repo_url": "https://github.com/acme/demo",
        "fetched_at": "2026-08-03T00:00:00Z",
        "fetch_method": "codeload-tarball",
    }
    (target / "leitir-manifest.json").write_text(json.dumps(payload))
    assert read_valid_manifest(target, "acme", "demo", SHA) == payload


def test_no_verify_upgrades_cached_legacy_manifest_to_explicit_false(tmp_path):
    target = tmp_path / "repos/github.com/acme/demo" / SHA
    target.mkdir(parents=True)
    payload = {
        "spec": "acme/demo",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
        "tag": None,
        "repo_url": "https://github.com/acme/demo",
        "fetched_at": "2026-08-03T00:00:00Z",
        "fetch_method": "codeload-tarball",
    }
    (target / "leitir-manifest.json").write_text(json.dumps(payload))
    result = materialize_github_repo(
        tmp_path, "acme/demo", "acme", "demo", SHA, verify=False
    )
    manifest = json.loads((result / "leitir-manifest.json").read_text())
    assert manifest["verified"] is False
    assert manifest["verified_at"] is None
