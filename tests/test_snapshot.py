from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from leitir.cli import ExitCode, main
from leitir.corpus import load_sources, write_sources
from leitir.materialize import MANIFEST_NAME, UnsafeArchiveError
from leitir.snapshot import (
    SnapshotError,
    SnapshotVerificationError,
    export_corpus,
    import_corpus,
    tree_sha,
)
from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields

SHA_A = "1" * 40
SHA_B = "2" * 40


def _manifest(owner: str, repo: str, sha: str, spec: str, *, artifact: bool) -> dict[str, object]:
    source = "registry-artifact" if artifact else "git-commit"
    payload: dict[str, object] = {
        "spec": spec,
        "host": "github.com",
        "owner": owner,
        "repo": repo,
        "commit_sha": sha,
        "tag": None,
        "repo_url": f"https://github.com/{owner}/{repo}",
        "fetched_at": "2026-01-02T03:04:05Z",
        "fetch_method": source if artifact else "codeload-tarball",
        "subpath": None,
        "verified": True,
        "verified_at": "2026-01-02T03:04:05Z",
        "verification_notes": [],
        "source": source,
        "version_source": "explicit",
    }
    if artifact:
        payload.update(artifact_kind="npm-tarball", artifact_checksum="sha512:fixture")
    return payload


def make_corpus(root: Path) -> list[dict[str, object]]:
    definitions = [
        ("alpha", "one", SHA_A, "npm:one@1.0.0", True, b"alpha\x00bytes\n"),
        ("beta", "two", SHA_B, "beta/two@" + SHA_B, False, b"beta\n"),
    ]
    entries: list[dict[str, object]] = []
    for owner, repo, sha, spec, artifact, content in definitions:
        relative = f"repos/github.com/{owner}/{repo}/{sha}"
        target = root / relative
        target.mkdir(parents=True)
        (target / "src").mkdir()
        (target / "src" / "data.bin").write_bytes(content)
        manifest = _manifest(owner, repo, sha, spec, artifact=artifact)
        digest, scope = compute_materialized_tree_hash(target)
        manifest.update(manifest_digest_fields(digest, scope=scope))
        (target / MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        entries.append(
            {
                "name": repo,
                "host": "github.com",
                "owner": owner,
                "repo": repo,
                "commit_sha": sha,
                "path": relative,
                "fetched_at": "2026-01-02T03:04:05Z",
                "verified": True,
            }
        )
    write_sources(root, entries)
    (root / "POINTERS.md").write_bytes(b"# exact pointers\n")
    return entries


def _replace_archive_member(path: Path, member_name: str, data: bytes) -> None:
    with tarfile.open(path, "r:gz") as source:
        members = source.getmembers()
        contents = {
            member.name: source.extractfile(member).read()
            for member in members
            if member.isreg()
        }
    with tarfile.open(path, "w:gz") as output:
        for member in members:
            if member.name == member_name:
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
            elif member.isreg():
                output.addfile(member, io.BytesIO(contents[member.name]))
            else:
                output.addfile(member)


def test_export_import_round_trip_is_byte_identical(tmp_path):
    source = tmp_path / "source"
    expected_entries = make_corpus(source)
    expected = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    }
    lock, tarball = export_corpus(tmp_path / "corpus.lock", root=source)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    assert tarball.name == "corpus.tar.gz"
    assert payload["format_version"] == 1
    assert payload["corpus_version"] == 2
    assert [record["tree_sha"] for record in payload["sources"]] == [
        tree_sha(source / record["path"]) for record in payload["sources"]
    ]
    fresh = tmp_path / "fresh"
    import_corpus(lock, root=fresh)
    actual = {
        path.relative_to(fresh).as_posix(): path.read_bytes()
        for path in fresh.rglob("*")
        if path.is_file()
    }
    assert actual == expected
    assert load_sources(fresh) == expected_entries


@pytest.mark.parametrize("field", ["tree_sha", "artifact_checksum"])
def test_lock_tampering_is_fail_closed(tmp_path, field):
    source = tmp_path / "source"
    make_corpus(source)
    lock, _tarball = export_corpus(tmp_path / "corpus.lock", root=source)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    record = payload["sources"][0]
    record[field] = "0" * 64
    lock.write_text(json.dumps(payload), encoding="utf-8")
    destination = tmp_path / "destination"
    with pytest.raises(SnapshotVerificationError):
        import_corpus(lock, root=destination)
    assert not destination.exists()


def test_tarball_content_tampering_is_fail_closed(tmp_path):
    source = tmp_path / "source"
    make_corpus(source)
    lock, tarball = export_corpus(tmp_path / "corpus.lock", root=source)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    member = f"leitir-corpus-v1/{payload['sources'][0]['path']}/src/data.bin"
    _replace_archive_member(tarball, member, b"tampered")
    destination = tmp_path / "destination"
    with pytest.raises(SnapshotVerificationError):
        import_corpus(lock, root=destination)
    assert not destination.exists()


def test_tarball_pointers_tampering_is_fail_closed(tmp_path):
    source = tmp_path / "source"
    make_corpus(source)
    lock, tarball = export_corpus(tmp_path / "corpus.lock", root=source)
    _replace_archive_member(tarball, "leitir-corpus-v1/POINTERS.md", b"tampered pointers\n")
    destination = tmp_path / "destination"
    with pytest.raises(SnapshotVerificationError, match="POINTERS.md checksum mismatch"):
        import_corpus(lock, root=destination)
    assert not destination.exists()


def test_snapshot_tarball_reuses_safe_extraction_guards(tmp_path):
    source = tmp_path / "source"
    make_corpus(source)
    lock, tarball = export_corpus(tmp_path / "corpus.lock", root=source)
    with tarfile.open(tarball, "r:gz") as source_archive:
        members = source_archive.getmembers()
        contents = {
            member.name: source_archive.extractfile(member).read()
            for member in members
            if member.isreg()
        }
    with tarfile.open(tarball, "w:gz") as archive:
        for member in members:
            if member.isreg():
                archive.addfile(member, io.BytesIO(contents[member.name]))
            else:
                archive.addfile(member)
        unsafe = tarfile.TarInfo("leitir-corpus-v1/../escape")
        unsafe.size = 1
        archive.addfile(unsafe, io.BytesIO(b"x"))
    destination = tmp_path / "destination"
    with pytest.raises(UnsafeArchiveError):
        import_corpus(lock, root=destination)
    assert not destination.exists()


def test_missing_tarball_has_clear_error(tmp_path):
    source = tmp_path / "source"
    make_corpus(source)
    lock, tarball = export_corpus(tmp_path / "corpus.lock", root=source)
    tarball.unlink()
    with pytest.raises(SnapshotError, match="snapshot tarball not found"):
        import_corpus(lock, root=tmp_path / "destination")


def test_snapshot_cli_outputs_machine_readable_paths_and_summary(tmp_path):
    source = tmp_path / "source"
    make_corpus(source)
    lock = tmp_path / "saved.lock"
    stdout = io.StringIO()
    stderr = io.StringIO()
    assert main(["export", "--root", str(source), "-o", str(lock)], stdout=stdout, stderr=stderr) == ExitCode.SUCCESS
    assert json.loads(stdout.getvalue())["lock"] == str(lock)
    assert "exported" in stderr.getvalue()
    stdout = io.StringIO()
    stderr = io.StringIO()
    destination = tmp_path / "destination"
    assert main(["import", str(lock), "--root", str(destination)], stdout=stdout, stderr=stderr) == ExitCode.SUCCESS
    assert json.loads(stdout.getvalue())["sources"] == 2
    assert "imported 2 source(s)" in stderr.getvalue()
