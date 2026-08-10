from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import tarfile

import pytest
from _http_server import scripted_server

from leitir.corpus import materialize_source
from leitir.materialize import MANIFEST_NAME, materialize_artifact, materialize_github_repo
from leitir.parity import ArtifactInfo, ChecksumMismatchError, RegistryArtifactFetcher
from leitir.resolver import Ecosystem, GitHubTagResolver, NpmResolver, PackageRef, ResolvedPackage
from leitir.search import RepoScope

SHA = "e" * 40


def _tar(root: str, files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, content in sorted(files.items()):
            member = tarfile.TarInfo(f"{root}/{name}")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _artifact(data: bytes) -> ArtifactInfo:
    digest = hashlib.sha512(data).digest()
    checksum = "sha512-" + base64.b64encode(digest).decode()
    return ArtifactInfo(
        "npm-tarball",
        "https://registry.example/demo.tgz",
        "sha512",
        digest.hex(),
        checksum,
    )


def _resolved(artifact: ArtifactInfo | None) -> ResolvedPackage:
    return ResolvedPackage(
        PackageRef(Ecosystem.NPM, "demo", "1.0.0"),
        RepoScope("example/demo", SHA),
        "v1.0.0",
        "https://www.npmjs.com/package/demo/v/1.0.0",
        artifact=artifact,
    )


def test_materialize_verified_artifact_manifest(tmp_path):
    data = _tar("package", {"index.js": b"module.exports = 1\n"})
    artifact = _artifact(data)

    target = materialize_artifact(
        tmp_path,
        "npm:demo@1.0.0",
        RepoScope("example/demo", SHA),
        artifact,
        fetcher=RegistryArtifactFetcher(get_bytes=lambda _url: data),
    )

    manifest = json.loads((target / MANIFEST_NAME).read_text())
    assert (target / "index.js").read_bytes() == b"module.exports = 1\n"
    assert manifest["source"] == "registry-artifact"
    assert manifest["artifact_kind"] == "npm-tarball"
    assert manifest["artifact_checksum"] == artifact.checksum
    assert manifest["verified"] is True
    assert manifest["verified_at"]
    assert manifest["has_tests"] is None


def test_git_materialization_does_not_reuse_artifact_cache(tmp_path):
    artifact_data = _tar("package", {"index.js": b"artifact\n"})
    artifact = _artifact(artifact_data)
    materialize_artifact(
        tmp_path,
        "npm:demo@1.0.0",
        RepoScope("example/demo", SHA),
        artifact,
        fetcher=RegistryArtifactFetcher(get_bytes=lambda _url: artifact_data),
    )
    git_data = _tar(f"demo-{SHA}", {"index.js": b"git\n"})

    with scripted_server([(200, {}, git_data)]) as server:
        target = materialize_github_repo(
            tmp_path,
            "example/demo",
            "example",
            "demo",
            SHA,
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
        )

    manifest = json.loads((target / MANIFEST_NAME).read_text())
    assert server.state.served_count == 1
    assert (target / "index.js").read_bytes() == b"git\n"
    assert manifest["source"] == "git-commit"


def test_checksum_mismatch_leaves_nothing_shelved(tmp_path):
    data = _tar("package", {"index.js": b"wrong"})
    artifact = ArtifactInfo(
        "npm-tarball",
        "https://registry.example/demo.tgz",
        "sha512",
        "0" * 128,
        "sha512-invalid",
    )

    with pytest.raises(ChecksumMismatchError):
        materialize_artifact(
            tmp_path,
            "npm:demo@1.0.0",
            RepoScope("example/demo", SHA),
            artifact,
            fetcher=RegistryArtifactFetcher(get_bytes=lambda _url: data),
        )

    assert not (tmp_path / "repos").exists()


def test_no_artifact_falls_back_to_git_and_records_unknown_parity(tmp_path):
    git_archive = _tar(f"demo-{SHA}", {"index.js": b"git\n"})
    with scripted_server([(200, {}, git_archive)]) as server:
        target = materialize_source(
            "npm:demo@1.0.0",
            _resolved(None),
            root=tmp_path,
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
        )

    manifest = json.loads((target / MANIFEST_NAME).read_text())
    assert manifest["source"] == "git-commit"
    assert manifest["parity"] == "unknown"
    assert "artifact_kind" not in manifest
    assert "artifact_checksum" not in manifest


def test_artifact_tree_is_shelved_and_compared_with_git(tmp_path):
    artifact_data = _tar("package", {"index.js": b"artifact\n"})
    git_archive = _tar(
        f"demo-{SHA}",
        {"index.js": b"git\n", "git.txt": b"only\n", "Tests/test.js": b"test\n"},
    )
    with scripted_server([(200, {}, git_archive)]) as server:
        target = materialize_source(
            "npm:demo@1.0.0",
            _resolved(_artifact(artifact_data)),
            root=tmp_path,
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
            parity_fetcher=RegistryArtifactFetcher(
                get_bytes=lambda _url: artifact_data
            ),
        )

    manifest = json.loads((target / MANIFEST_NAME).read_text())
    assert (target / "index.js").read_bytes() == b"artifact\n"
    assert manifest["source"] == "registry-artifact"
    assert manifest["parity"] == "drift"
    assert manifest["files_compared"] == 1
    assert manifest["only_in_git"] == 2
    assert manifest["only_in_artifact"] == 0
    assert manifest["has_tests"] is True


def test_artifact_records_unknown_tests_when_git_tree_cannot_be_fetched(tmp_path):
    artifact_data = _tar("package", {"index.js": b"artifact\n"})
    with scripted_server([(429, {"Retry-After": "0"}, b"")]) as server:
        target = materialize_source(
            "npm:demo@1.0.0",
            _resolved(_artifact(artifact_data)),
            root=tmp_path,
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
            parity_fetcher=RegistryArtifactFetcher(get_bytes=lambda _url: artifact_data),
        )
    manifest = json.loads((target / MANIFEST_NAME).read_text())
    assert manifest["parity"] == "unknown"
    assert manifest["has_tests"] is None


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live artifact materialization",
)
def test_live_npm_materializes_registry_artifact(tmp_path):
    resolved = NpmResolver(GitHubTagResolver()).resolve(
        PackageRef(Ecosystem.NPM, "is-number", "7.0.0")
    )
    target = materialize_source("npm:is-number@7.0.0", resolved, root=tmp_path)
    manifest = json.loads((target / MANIFEST_NAME).read_text())
    assert manifest["source"] == "registry-artifact"
    assert manifest["artifact_checksum"]
