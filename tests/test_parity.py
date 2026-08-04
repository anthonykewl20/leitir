from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import zipfile

import pytest

from leitir.materialize import UnsafeArchiveError
from leitir.parity import (
    ChecksumMismatchError,
    RegistryArtifactFetcher,
    artifact_from_metadata,
    compare_trees,
    package_parity,
)


def _tar(files: dict[str, bytes], root: str = "package") -> bytes:
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


def _zip(files: dict[str, bytes], root: str = "demo-1.0") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(f"{root}/", b"")
        for name, content in sorted(files.items()):
            archive.writestr(f"{root}/{name}", content)
    return output.getvalue()


@pytest.mark.parametrize("ecosystem", ["npm", "pypi", "crates"])
def test_registry_metadata_artifact_fetch_and_checksum(ecosystem, tmp_path):
    data = _zip({"same.txt": b"same"}) if ecosystem == "pypi" else _tar({"same.txt": b"same"})
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = base64.b64encode(hashlib.sha512(data).digest()).decode()
    metadata = {
        "npm": {
            "versions": {
                "1.0": {
                    "dist": {
                        "tarball": "https://registry.example/demo.tgz",
                        "integrity": f"sha512-{sha512}",
                    }
                }
            }
        },
        "pypi": {
            "urls": [
                {
                    "packagetype": "sdist",
                    "url": "https://registry.example/demo.zip",
                    "digests": {"sha256": sha256},
                }
            ]
        },
        "crates": {
            "version": {
                "checksum": sha256,
                "download_url": "https://registry.example/demo.crate",
            }
        },
    }[ecosystem]
    git = tmp_path / "git"
    git.mkdir()
    (git / "same.txt").write_bytes(b"same")
    fetcher = RegistryArtifactFetcher(
        get_json=lambda _url: metadata,
        get_bytes=lambda _url: data,
    )

    result = package_parity(ecosystem, "demo", "1.0", git, fetcher=fetcher)

    assert result.parity == "exact"
    assert result.files_compared == 1
    assert result.artifact_kind is not None
    assert result.checksum is not None


def test_compare_reports_byte_and_file_set_drift(tmp_path):
    git, artifact = tmp_path / "git", tmp_path / "artifact"
    git.mkdir()
    artifact.mkdir()
    (git / "different.txt").write_bytes(b"git")
    (artifact / "different.txt").write_bytes(b"artifact")
    (git / "git-only.txt").write_bytes(b"git")
    (artifact / "artifact-only.txt").write_bytes(b"artifact")

    result = compare_trees(git, artifact)

    assert result.parity == "drift"
    assert (result.files_compared, result.only_in_git, result.only_in_artifact) == (1, 1, 1)


def test_file_set_difference_alone_is_drift(tmp_path):
    git, artifact = tmp_path / "git", tmp_path / "artifact"
    git.mkdir()
    artifact.mkdir()
    (git / "same.txt").write_bytes(b"same")
    (artifact / "same.txt").write_bytes(b"same")
    (git / "only.txt").write_bytes(b"only")
    assert compare_trees(git, artifact).parity == "drift"


def test_no_source_artifact_is_unknown(tmp_path):
    fetcher = RegistryArtifactFetcher(get_json=lambda _url: {"urls": []})
    result = package_parity("pypi", "demo", "1.0", tmp_path, fetcher=fetcher)
    assert result.parity == "unknown"
    assert (result.files_compared, result.only_in_git, result.only_in_artifact) == (0, 0, 0)


def test_checksum_mismatch_fails_closed(tmp_path):
    data = _tar({"same.txt": b"same"})
    artifact = artifact_from_metadata(
        "crates",
        "demo",
        "1.0",
        {"version": {"checksum": "0" * 64, "download_url": "https://example.test/demo"}},
    )
    assert artifact is not None
    with pytest.raises(ChecksumMismatchError):
        package_parity(
            "crates",
            "demo",
            "1.0",
            tmp_path,
            artifact=artifact,
            fetcher=RegistryArtifactFetcher(get_bytes=lambda _url: data),
        )


def test_tar_path_traversal_is_rejected(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        member = tarfile.TarInfo("package/../../escape")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    payload = data.getvalue()
    checksum = hashlib.sha256(payload).hexdigest()
    artifact = artifact_from_metadata(
        "crates",
        "demo",
        "1.0",
        {"version": {"checksum": checksum, "download_url": "https://example.test/demo"}},
    )
    assert artifact is not None
    with pytest.raises(UnsafeArchiveError):
        package_parity(
            "crates",
            "demo",
            "1.0",
            tmp_path,
            artifact=artifact,
            fetcher=RegistryArtifactFetcher(get_bytes=lambda _url: payload),
        )


@pytest.mark.parametrize(
    ("environment", "url", "token"),
    [
        ({"NPM_TOKEN": "npm-secret"}, "https://registry.npmjs.org/demo.tgz", "npm-secret"),
        ({"PYPI_TOKEN": "pypi-secret"}, "https://pypi.org/packages/demo.tar.gz", "pypi-secret"),
        ({"CARGO_TOKEN": "cargo-secret"}, "https://static.crates.io/crates/demo.crate", "cargo-secret"),
    ],
)
def test_registry_artifact_authentication(monkeypatch, environment, url, token):
    captured = {}

    class Response(io.BytesIO):
        def geturl(self):
            return url

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return Response(b"artifact")

    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert RegistryArtifactFetcher()._request_bytes(url) == b"artifact"
    assert captured["Authorization"] == f"Bearer {token}"


def test_registry_artifact_is_anonymous_without_token(monkeypatch):
    captured = {}

    class Response(io.BytesIO):
        def geturl(self):
            return "https://registry.npmjs.org/demo.tgz"

    def fake_urlopen(request, timeout):
        captured.update(request.header_items())
        return Response(b"artifact")

    monkeypatch.delenv("NPM_TOKEN", raising=False)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    RegistryArtifactFetcher()._request_bytes("https://registry.npmjs.org/demo.tgz")
    assert "Authorization" not in captured
