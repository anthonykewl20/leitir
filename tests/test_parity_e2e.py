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
from leitir.parity import RegistryArtifactFetcher, artifact_from_metadata
from leitir.resolver import Ecosystem, GitHubTagResolver, NpmResolver, PackageRef, ResolvedPackage
from leitir.search import RepoScope

SHA = "d" * 40


def _tar(root: str, content: bytes = b"same") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"{root}/same.txt")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def test_package_materialization_records_real_parity(tmp_path):
    git_archive = _tar(f"demo-{SHA}")
    artifact_bytes = _tar("package")
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(artifact_bytes).digest()).decode()
    metadata = {
        "versions": {
            "1.0": {
                "dist": {
                    "tarball": "https://registry.example/demo.tgz",
                    "integrity": integrity,
                }
            }
        }
    }
    artifact = artifact_from_metadata("npm", "demo", "1.0", metadata)
    assert artifact is not None
    resolved = ResolvedPackage(
        PackageRef(Ecosystem.NPM, "demo", "1.0"),
        RepoScope("acme/demo", SHA),
        "v1.0",
        "https://www.npmjs.com/package/demo/v/1.0",
        artifact=artifact,
    )
    fetcher = RegistryArtifactFetcher(get_bytes=lambda _url: artifact_bytes)

    with scripted_server([(200, {}, git_archive)]) as server:
        target = materialize_source(
            "npm:demo@1.0",
            resolved,
            root=tmp_path,
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
            parity_fetcher=fetcher,
        )

    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["parity"] == "exact"
    assert manifest["files_compared"] == 1
    assert manifest["only_in_git"] == manifest["only_in_artifact"] == 0


def test_repository_materialization_records_unknown(tmp_path):
    with scripted_server([(200, {}, _tar(f"demo-{SHA}"))]) as server:
        target = materialize_source(
            "acme/demo",
            RepoScope("acme/demo", SHA),
            root=tmp_path,
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
        )
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["parity"] == "unknown"


@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live parity verification",
)
def test_live_npm_registry_artifact_parity(tmp_path):
    resolved = NpmResolver(GitHubTagResolver()).resolve(
        PackageRef(Ecosystem.NPM, "is-number", "7.0.0")
    )
    target = materialize_source("npm:is-number@7.0.0", resolved, root=tmp_path)
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["parity"] in {"drift", "exact"}
    assert manifest["files_compared"] > 0
