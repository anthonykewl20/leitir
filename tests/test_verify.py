"""Offline coverage for corpus Git blob verification."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path
import sys

import pytest

from leitir.cli import ExitCode, main
from leitir.materialize import (
    MaterializationError,
    VerificationError,
    _verify_extracted_tree,
    materialize_github_repo,
    read_valid_manifest,
)
from leitir.tree import BlobEntry, GitHubTreeSource

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
        paths = server.state.request_paths
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["verified"] is True
    assert manifest["verified_at"].endswith("Z")
    assert manifest["verification_notes"] == []
    assert paths == [
        f"/acme/demo/tar.gz/{SHA}",
        f"/repos/acme/demo/git/trees/{SHA}",
    ]


def test_crlf_archive_variant_is_verified_via_pinned_contents(tmp_path):
    blob = b"first line\nsecond line\n"
    archive_files = {"docs/proof.txt": blob.replace(b"\n", b"\r\n")}
    routes = _routes(archive_files, _tree({"docs/proof.txt": blob}))
    routes["/repos/acme/demo/contents/docs/proof.txt"] = (200, {}, blob)

    with routed_server(routes) as server:
        target = _materialize(tmp_path, server.base_url)
        paths = server.state.request_paths

    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["verified"] is True
    assert manifest["verification_notes"] == ["text-normalized: 1 file(s)"]
    assert paths == [
        f"/acme/demo/tar.gz/{SHA}",
        f"/repos/acme/demo/git/trees/{SHA}",
        "/repos/acme/demo/contents/docs/proof.txt",
    ]


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
    blob = b"proof\n"
    files = {"proof.txt": b"pr00f\n"}
    routes = _routes(files, _tree({"proof.txt": blob}))
    routes["/repos/acme/demo/contents/proof.txt"] = (200, {}, blob)
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


class _FakeTreeSource:
    def __init__(self, entries: tuple[BlobEntry, ...], blobs: dict[str, bytes]) -> None:
        self.entries = entries
        self.blobs = blobs

    def list_blobs(self, _slug: str, _commit_sha: str) -> tuple[BlobEntry, ...]:
        return self.entries

    def read_blob(self, _slug: str, blob_sha: str) -> bytes:
        return self.blobs[blob_sha]


class _FakeGitHubTreeSource(GitHubTreeSource):
    def __init__(self, entries: tuple[BlobEntry, ...], blobs: dict[str, bytes]) -> None:
        self.entries = entries
        self.blobs = blobs

    def list_blobs(self, _slug: str, _commit_sha: str) -> tuple[BlobEntry, ...]:
        return self.entries

    def read_blob(self, _slug: str, blob_sha: str) -> bytes:
        return self.blobs[blob_sha]

    def read_blob_at_commit(self, _slug: str, _commit_sha: str, path: str) -> bytes:
        entry = next(entry for entry in self.entries if entry.path == path)
        return self.blobs[entry.blob_sha]


def _verify_direct(staging: Path, source: object) -> bool | str:
    status, _normalized = _verify_extracted_tree(
        staging,
        "acme",
        "demo",
        SHA,
        source,
        max_files=100,
        max_bytes=1024,
    )
    return status


def test_matching_symbolic_link_is_verified(tmp_path):
    target = "realfile"
    (tmp_path / "realfile").write_bytes(b"proof")
    (tmp_path / "link").symlink_to(target)
    entries = (
        BlobEntry("realfile", GitHubTreeSource.git_blob_sha(b"proof"), 5, "100644"),
        BlobEntry("link", GitHubTreeSource.git_blob_sha(target.encode()), len(target), "120000"),
    )

    assert _verify_direct(tmp_path, _FakeGitHubTreeSource(entries, {})) is True


def test_tampered_symbolic_link_is_rejected(tmp_path):
    expected_target = "realfile"
    (tmp_path / "realfile").write_bytes(b"proof")
    (tmp_path / "link").symlink_to("other")
    link_sha = GitHubTreeSource.git_blob_sha(expected_target.encode())
    entries = (
        BlobEntry("realfile", GitHubTreeSource.git_blob_sha(b"proof"), 5, "100644"),
        BlobEntry("link", link_sha, len(expected_target), "120000"),
    )
    source = _FakeGitHubTreeSource(entries, {link_sha: expected_target.encode()})

    with pytest.raises(VerificationError):
        _verify_direct(tmp_path, source)


def test_non_github_symbolic_link_digest_mismatch_is_sampled(tmp_path):
    expected_target = b"realfile"
    (tmp_path / "link").symlink_to("other")
    link_sha = GitHubTreeSource.git_blob_sha(expected_target)
    entries = (BlobEntry("link", link_sha, len(expected_target), "120000"),)

    assert _verify_direct(tmp_path, _FakeTreeSource(entries, {link_sha: b"followed"})) == "sampled"


@pytest.mark.parametrize("variant", ["missing", "extra"])
def test_symbolic_link_universe_mismatch_is_sampled(tmp_path, variant):
    target = "realfile"
    (tmp_path / "realfile").write_bytes(b"proof")
    if variant == "extra":
        (tmp_path / "extra").symlink_to(target)
    entries = (
        BlobEntry("realfile", GitHubTreeSource.git_blob_sha(b"proof"), 5, "100644"),
        BlobEntry("link", GitHubTreeSource.git_blob_sha(target.encode()), len(target), "120000"),
    )

    assert _verify_direct(tmp_path, _FakeTreeSource(entries, {})) == "sampled"


def test_symbolic_link_eol_difference_is_rejected(tmp_path):
    extracted_target = "realfile\r"
    expected_target = b"realfile\n"
    (tmp_path / "link").symlink_to(extracted_target)
    link_sha = GitHubTreeSource.git_blob_sha(expected_target)
    entries = (BlobEntry("link", link_sha, len(expected_target), "120000"),)

    with pytest.raises(VerificationError, match="symbolic-link blob digest mismatch"):
        _verify_direct(tmp_path, _FakeGitHubTreeSource(entries, {link_sha: expected_target}))


def test_non_utf8_symbolic_link_target_verifies(tmp_path):
    if sys.platform == "win32":
        pytest.skip(
            "non-UTF-8 filenames are not representable on Windows via the standard Python API"
        )
    raw_target = b"target-\xff"
    os.symlink(raw_target, os.fsencode(tmp_path / "link"))
    entries = (
        BlobEntry(
            "link",
            GitHubTreeSource.git_blob_sha(raw_target),
            len(raw_target),
            "120000",
        ),
    )

    assert _verify_direct(tmp_path, _FakeTreeSource(entries, {})) is True


def test_mode_less_tree_verification_is_never_fully_claimed(tmp_path):
    content = b"proof"
    (tmp_path / "proof.txt").write_bytes(content)
    entries = (
        BlobEntry("proof.txt", GitHubTreeSource.git_blob_sha(content), len(content)),
        BlobEntry("missing.txt", GitHubTreeSource.git_blob_sha(b"missing"), 7),
    )

    assert _verify_direct(tmp_path, _FakeTreeSource(entries, {})) == "sampled"


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
