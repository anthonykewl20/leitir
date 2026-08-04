from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile

from leitir.corpus import materialize_source
from leitir.materialize import MANIFEST_NAME
from leitir.parity import ArtifactInfo, RegistryArtifactFetcher
from leitir.resolver import Ecosystem, PackageRef, ResolvedPackage
from leitir.search import RepoScope

from _http_server import scripted_server

SHA = "f" * 40


def _tar(root: str, content: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"{root}/source.txt")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _artifact(data: bytes) -> ArtifactInfo:
    digest = hashlib.sha512(data).digest()
    encoded = base64.b64encode(digest).decode()
    return ArtifactInfo(
        "npm-tarball",
        "https://registry.example/demo.tgz",
        "sha512",
        digest.hex(),
        f"sha512-{encoded}",
    )


def _resolved(artifact: ArtifactInfo | None) -> ResolvedPackage:
    return ResolvedPackage(
        PackageRef(Ecosystem.NPM, "demo", "1.0.0"),
        RepoScope("example/demo", SHA),
        "v1.0.0",
        "https://www.npmjs.com/package/demo/v/1.0.0",
        artifact=artifact,
    )


def test_artifact_is_preferred_over_git_archive(tmp_path):
    artifact_data = _tar("package", b"artifact")
    with scripted_server([(503, {}, b"unavailable")]) as server:
        target = materialize_source(
            "npm:demo@1.0.0",
            _resolved(_artifact(artifact_data)),
            root=tmp_path,
            parity_fetcher=RegistryArtifactFetcher(
                get_bytes=lambda _url: artifact_data
            ),
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
        )

    manifest = json.loads((target / MANIFEST_NAME).read_text())
    assert (target / "source.txt").read_bytes() == b"artifact"
    assert manifest["source"] == "registry-artifact"
    assert manifest["parity"] == "unknown"


def test_artifact_retrieval_failure_falls_back_to_git(tmp_path):
    artifact_data = _tar("package", b"artifact")
    git_data = _tar(f"demo-{SHA}", b"git")

    def fail(_url: str) -> bytes:
        raise OSError("registry unavailable")

    with scripted_server([(200, {}, git_data)]) as server:
        target = materialize_source(
            "npm:demo@1.0.0",
            _resolved(_artifact(artifact_data)),
            root=tmp_path,
            parity_fetcher=RegistryArtifactFetcher(
                get_bytes=fail, max_attempts=1
            ),
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
        )

    manifest = json.loads((target / MANIFEST_NAME).read_text())
    assert (target / "source.txt").read_bytes() == b"git"
    assert manifest["source"] == "git-commit"
    assert manifest["parity"] == "unknown"
