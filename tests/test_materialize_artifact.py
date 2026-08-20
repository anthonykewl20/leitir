from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import tarfile
import zipfile
from pathlib import Path

import pytest
from _http_server import scripted_server

from leitir.corpus import materialize_source
from leitir.materialize import (
    MANIFEST_NAME,
    VerificationError,
    _go_zip_h1,
    materialize_artifact,
    materialize_github_repo,
    materialize_go_module_zip,
)
from leitir.parity import ArtifactInfo, ChecksumMismatchError, RegistryArtifactFetcher
from leitir.resolver import Ecosystem, GitHubTagResolver, NpmResolver, PackageRef, ResolvedPackage
from leitir.search import RepoScope

SHA = "e" * 40
_GO_MODULE_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "go_module"
    / "github.com-mmcloughlin-avo-v0.6.0.zip"
)


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


def _go_zip(module: str, version: str, *, root: str | None = None) -> bytes:
    output = io.BytesIO()
    root = root or f"{module}@{version}"
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(f"{root}/", b"")
        archive.writestr(f"{root}/go.mod", f"module {module}\n".encode())
        archive.writestr(f"{root}/demo.go", b"package demo\n")
        archive.writestr(f"{root}/LICENSE", b"SPDX-License-Identifier: MIT\n")
    return output.getvalue()


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


def test_go_module_zip_shelves_authenticated_proxy_artifact(tmp_path, monkeypatch):
    module = "example.com/demo"
    version = "v1.2.3"
    data = _go_zip(module, version)

    class SumDB:
        def __init__(self, *args, **kwargs):
            pass

        def verify(self, requested_module, requested_version, *, escaped_module=None):
            assert (requested_module, requested_version) == (module, version)
            assert escaped_module == module
            return _go_zip_h1(data)

    monkeypatch.setattr("leitir.sumdb.SumDBClient", SumDB)
    with scripted_server([(200, {}, data)]) as server:
        target = materialize_go_module_zip(
            tmp_path,
            f"go:{module}@{version}",
            RepoScope("module/" + "b" * 40, "b" * 40),
            module,
            version,
            server.base_url,
        )

    manifest = json.loads((target / MANIFEST_NAME).read_text())
    assert (target / "demo.go").read_bytes() == b"package demo\n"
    assert target.parts[-2:] == ("module", "b" * 40)
    assert not (target / ("b" * 40)).exists()
    assert manifest["source"] == "go-module-zip"
    assert manifest["module_path"] == module
    assert manifest["module_version"] == version
    assert manifest["zip_sha256"] == hashlib.sha256(data).hexdigest()
    assert manifest["sumdb_h1"] == _go_zip_h1(data)
    assert {
        field: manifest[field]
        for field in ("license_identifier", "license_method", "license_confidence")
    } == {
        "license_identifier": "MIT",
        "license_method": "license-file",
        "license_confidence": "high",
    }


def test_go_zip_h1_matches_sumdb_golden_module_fixture() -> None:
    """Pin Go's canonical zip hashing against offline proxy bytes."""

    data = _GO_MODULE_FIXTURE.read_bytes()
    assert hashlib.sha256(data).hexdigest() == (
        "dd9c1abdff8a58ae41dc6ed32283adc6cca4983266e42d109c82d0d5105292bf"
    )
    assert _go_zip_h1(data) == "h1:QH6FU8SKoTLaVs80GA8TJuLNkUYl4VokHKlPhVDg4YY="


def test_go_module_zip_uses_escaped_wire_path_and_root(tmp_path, monkeypatch):
    module = "github.com/BurntSushi/toml"
    version = "v1.2.0"
    escaped_module = "github.com/!burnt!sushi/toml"
    data = _go_zip(module, version, root=f"{escaped_module}@{version}")

    class SumDB:
        def __init__(self, *args, **kwargs):
            pass

        def verify(self, requested_module, requested_version, *, escaped_module=None):
            assert (requested_module, requested_version) == (module, version)
            assert escaped_module == "github.com/!burnt!sushi/toml"
            return _go_zip_h1(data)

    monkeypatch.setattr("leitir.sumdb.SumDBClient", SumDB)
    with scripted_server([(200, {}, data)]) as server:
        target = materialize_go_module_zip(
            tmp_path,
            f"go:{module}@{version}",
            RepoScope("module/" + "d" * 40, "d" * 40),
            module,
            version,
            server.base_url,
        )

    manifest = json.loads((target / MANIFEST_NAME).read_text())
    assert server.state.request_paths == [f"/github.com/!burnt!sushi/toml/@v/{version}.zip"]
    assert (target / "demo.go").read_bytes() == b"package demo\n"
    assert manifest["module_path"] == module


def test_materialize_source_uses_go_zip_and_refreshes_its_cache(tmp_path, monkeypatch):
    module = "example.com/demo"
    version = "v1.2.3"
    data = _go_zip(module, version)
    source_id = "f" * 40
    resolved = ResolvedPackage(
        PackageRef(Ecosystem.GO, module, version),
        RepoScope(f"module/{source_id}", source_id),
        version,
        f"https://pkg.go.dev/{module}@{version}",
        host="go-module-zip",
        go_module_zip=True,
        go_proxy_url="http://127.0.0.1",
    )

    class SumDB:
        def __init__(self, *args, **kwargs):
            pass

        def verify(self, *args, **kwargs):
            return _go_zip_h1(data)

    monkeypatch.setattr("leitir.sumdb.SumDBClient", SumDB)
    fetched: list[None] = []
    with scripted_server([(200, {}, data)]) as server:
        resolved = ResolvedPackage(
            resolved.ref,
            resolved.scope,
            resolved.tag,
            resolved.registry_url,
            host=resolved.host,
            go_module_zip=True,
            go_proxy_url=server.base_url,
        )
        first = materialize_source(
            f"go:{module}@{version}", resolved, root=tmp_path, on_fetch=lambda: fetched.append(None)
        )
        second = materialize_source(
            f"go:{module}@{version}", resolved, root=tmp_path, on_fetch=lambda: fetched.append(None)
        )

    assert first == second
    assert server.state.request_paths == [f"/{module}/@v/{version}.zip"]
    assert fetched == [None]
    assert json.loads((first / MANIFEST_NAME).read_text())["source"] == "go-module-zip"


@pytest.mark.parametrize("option", [{"sumdb_url": object()}, {"timeout": "30"}])
def test_go_zip_materialization_rejects_invalid_fetch_option_types(tmp_path, option):
    module = "example.com/demo"
    version = "v1.2.3"
    source_id = "a" * 40
    resolved = ResolvedPackage(
        PackageRef(Ecosystem.GO, module, version),
        RepoScope(f"module/{source_id}", source_id),
        version,
        f"https://pkg.go.dev/{module}@{version}",
        host="go-module-zip",
        go_module_zip=True,
        go_proxy_url="https://proxy.example",
    )

    with pytest.raises(TypeError, match="fetch options"):
        materialize_source(f"go:{module}@{version}", resolved, root=tmp_path, **option)

    assert not (tmp_path / "repos").exists()


@pytest.mark.parametrize(
    ("member", "limits"),
    [
        ("duplicate", {"ARCHIVE_MAX_MEMBERS": 0}),
        ("bad\nname", {}),
        ("large", {"ARCHIVE_MAX_MEMBER_BYTES": 1}),
        ("total", {"ARCHIVE_MAX_TOTAL_BYTES": 1}),
    ],
)
def test_go_zip_h1_rejects_malformed_or_limit_exceeding_members(
    monkeypatch, member, limits
):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr(member, b"payload")
    for name, value in limits.items():
        monkeypatch.setattr(f"leitir.materialize.{name}", value)

    with pytest.raises(VerificationError, match="malformed"):
        _go_zip_h1(data.getvalue())


def test_go_module_zip_rejects_an_unexpected_authenticated_root(tmp_path, monkeypatch):
    module = "example.com/demo"
    version = "v1.2.3"
    data = _go_zip(module, version, root="unexpected")

    class SumDB:
        def __init__(self, *args, **kwargs):
            pass

        def verify(self, *args, **kwargs):
            return _go_zip_h1(data)

    monkeypatch.setattr("leitir.sumdb.SumDBClient", SumDB)
    with scripted_server([(200, {}, data)]) as server:
        with pytest.raises(VerificationError, match="unexpected module root"):
            materialize_go_module_zip(
                tmp_path,
                f"go:{module}@{version}",
                RepoScope("module/" + "1" * 40, "1" * 40),
                module,
                version,
                server.base_url,
            )

    assert not (tmp_path / "repos").exists()


def test_go_module_sumdb_mismatch_leaves_nothing_shelved(tmp_path, monkeypatch):
    module = "example.com/demo"
    version = "v1.2.3"
    data = _go_zip(module, version)

    class SumDB:
        def __init__(self, *args, **kwargs):
            pass

        def verify(self, *args, **kwargs):
            return "h1:invalid"

    monkeypatch.setattr("leitir.sumdb.SumDBClient", SumDB)
    with scripted_server([(200, {}, data)]) as server:
        with pytest.raises(VerificationError, match="sumdb h1"):
            materialize_go_module_zip(
                tmp_path,
                f"go:{module}@{version}",
                RepoScope("module/" + "c" * 40, "c" * 40),
                module,
                version,
                server.base_url,
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


@pytest.mark.live
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
