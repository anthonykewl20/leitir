"""Offline tests for SHA-pinned codeload materialization."""

from __future__ import annotations

import hashlib
import io
import json
import multiprocessing
import os
import shutil
import tarfile
import tempfile
import threading
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path

import pytest
from _http_server import json_body, scripted_server

import leitir.materialize as materialize_module
from leitir.materialize import (
    MaterializationError,
    UnsafeArchiveError,
    VerificationError,
    _extract_tarball,
    _verify_extracted_tree,
    materialize_github_repo,
    read_valid_manifest,
)
from leitir.resolver import CodebergResolver, ResolutionError
from leitir.tree import BlobEntry, GitHubTreeSource, TreeReadError
from leitir.trust import compute_trust

SHA = "a" * 40


def _concurrent_materialize_worker(
    root: str,
    base_url: str | None,
    started: multiprocessing.synchronize.Event,
    release: multiprocessing.synchronize.Event,
    lock_attempted: multiprocessing.synchronize.Event | None,
    queue: multiprocessing.queues.Queue,
) -> None:
    fetched = False

    def fetch_started() -> None:
        nonlocal fetched
        fetched = True
        if lock_attempted is None:
            started.set()
            if not release.wait(10):
                raise TimeoutError("timed out waiting to release first materialization")

    if lock_attempted is not None:
        real_target_lock = materialize_module._target_lock

        @contextmanager
        def observed_target_lock(*args: object, **kwargs: object):
            lock_attempted.set()
            with real_target_lock(*args, **kwargs):  # type: ignore[arg-type]
                yield

        materialize_module._target_lock = observed_target_lock

    try:
        if base_url is None:
            with scripted_server([(200, {}, _tarball())]) as server:
                result = _materialize(
                    Path(root), server.base_url, on_fetch=fetch_started
                )
        else:
            result = _materialize(Path(root), base_url, on_fetch=fetch_started)
        queue.put((str(result), fetched))
    except BaseException as exc:
        queue.put(repr(exc))


def _materialization_waiter(root: str) -> None:
    with scripted_server([]) as server:
        _materialize(Path(root), server.base_url)


def _snapshot(path: Path) -> set[str]:
    return {
        item.relative_to(path).as_posix()
        for item in path.rglob("*")
    }


def _extract_then_clean(data: bytes, staging: Path) -> None:
    try:
        _extract_tarball(data, staging, "pkg", SHA)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _tarball(*, traversal: bool = False) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        root = tarfile.TarInfo(f"demo-{SHA}/")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        archive.addfile(root)
        content = b"pinned source\n"
        source = tarfile.TarInfo(f"demo-{SHA}/src/example.py")
        source.size = len(content)
        source.mode = 0o644
        archive.addfile(source, io.BytesIO(content))
        if traversal:
            evil = tarfile.TarInfo("../evil.txt")
            evil.size = 4
            archive.addfile(evil, io.BytesIO(b"evil"))
    return data.getvalue()


def _materialize(root: Path, base_url: str, **options: object) -> Path:
    return materialize_github_repo(
        root,
        "example/demo#v1",
        "example",
        "demo",
        SHA,
        tag="v1",
        base_url=base_url,
        max_attempts=1,
        verify=False,
        **options,  # type: ignore[arg-type]
    )


def test_download_extracts_directly_into_sha_directory(tmp_path):
    with scripted_server([(200, {"Content-Type": "application/gzip"}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)

    assert target == tmp_path / "repos/github.com/example/demo" / SHA
    assert (target / "src/example.py").read_text() == "pinned source\n"
    assert not (target / f"demo-{SHA}").exists()
    assert server.state.request_paths == [f"/example/demo/tar.gz/{SHA}"]


def test_manifest_records_immutable_provenance(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)
    manifest = json.loads((target / "leitir-manifest.json").read_text())

    assert manifest == {
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "fetched_at": manifest["fetched_at"],
        "has_tests": False,
        "host": "github.com",
        "license_confidence": "low",
        "license_identifier": None,
        "license_method": "unknown",
        # Issue #194: the flat per-file digest map, plus the aggregate at
        # full scope anchoring it. The digest value itself is unchanged from
        # the pre-map below-cap computation (byte-identical anchor).
        "materialized_file_digests": {
            "src/example.py": "073bd3c4ab4735908691f35310ecc19e8c1ba1bb993fd74f6738e4d0f8dcef72"
        },
        "materialized_file_digests_algorithm": "per-file-sha256-v1",
        "materialized_tree_hash": "h1:cOO2Q95wvMIfJHy3T7u15v8K/y5EH8GT0x24FCEgzEU=",
        "materialized_tree_hash_algorithm": "dirhash-h1-sha256-v1",
        "materialized_tree_hash_scope": "full",
        "owner": "example",
        "parity": "unknown",
        "repo": "demo",
        "repo_url": "https://github.com/example/demo",
        "source": "git-commit",
        "spec": "example/demo#v1",
        "subpath": None,
        "tag": "v1",
        "verified": False,
        "verified_at": None,
        "verification_notes": [],
    }
    assert manifest["fetched_at"].endswith("Z")
    assert "published_at" not in manifest
    assert manifest["verified"] is False
    assert manifest["verified_at"] is None


def test_missing_source_timestamp_has_unknown_age_evidence(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)
    manifest = json.loads((target / "leitir-manifest.json").read_text())

    age = next(
        factor for factor in compute_trust(manifest, target).breakdown
        if factor["factor"] == "age"
    )
    assert age["score"] == 50
    assert age["evidence"]["state"] == "unknown"


def test_unverified_shelf_without_tree_hash_is_rejected(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)
    path = target / "leitir-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    for field in (
        "materialized_tree_hash",
        "materialized_tree_hash_algorithm",
        "materialized_tree_hash_scope",
    ):
        manifest.pop(field)
    path.write_text(json.dumps(manifest), encoding="utf-8")

    assert read_valid_manifest(target, "example", "demo", SHA) is None


def test_duplicate_manifest_key_is_rejected_like_any_other_malformed_manifest(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)
    path = target / "leitir-manifest.json"
    path.write_text('{"owner":"example","owner":"attacker"}', encoding="utf-8")

    assert read_valid_manifest(target, "example", "demo", SHA) is None


def test_read_valid_manifest_rejects_a_final_component_symlink(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)
    manifest = target / "leitir-manifest.json"
    outside = tmp_path / "outside-manifest.json"
    outside.write_bytes(manifest.read_bytes())
    manifest.unlink()
    manifest.symlink_to(outside)

    assert read_valid_manifest(target, "example", "demo", SHA) is None


@pytest.mark.parametrize("ecosystem", ["npm", "pypi", "crates", "go"])
def test_manifest_producer_populates_age_field_for_each_ecosystem(tmp_path, ecosystem):
    published = "2020-01-02T03:04:05Z"
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _materialize(
            tmp_path,
            server.base_url,
            manifest_fields={"ecosystem": ecosystem, "published_at": published},
        )
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["ecosystem"] == ecosystem
    assert manifest["published_at"] == published
    age = next(
        factor for factor in compute_trust(manifest, target).breakdown
        if factor["factor"] == "age"
    )
    assert age["evidence"]["state"] == "known"
    assert age["evidence"]["source"] == "published_at"


def test_resolved_package_timestamp_is_threaded_into_materialized_manifest(tmp_path):
    from leitir.corpus import materialize_source
    from leitir.resolver import Ecosystem, PackageRef, ResolvedPackage
    from leitir.search import RepoScope

    published = "2026-08-08T03:04:05Z"
    resolved = ResolvedPackage(
        ref=PackageRef(Ecosystem.PYPI, "demo", "1.0.0"),
        scope=RepoScope("example/demo", SHA),
        tag="v1.0.0",
        registry_url="https://pypi.org/project/demo/1.0.0/",
        published_at=published,
    )
    with scripted_server([(200, {}, _tarball())]) as server:
        target = materialize_source(
            "pypi:demo@1.0.0",
            resolved,
            root=tmp_path,
            base_url=server.base_url,
            verify=False,
        )

    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["published_at"] == published
    age = next(
        factor
        for factor in compute_trust(manifest, target).breakdown
        if factor["factor"] == "age"
    )
    assert age["evidence"]["state"] == "known"
    assert age["evidence"]["days_at_fetch"] < 100


def test_manifest_producer_rejects_malformed_age_field(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        with pytest.raises(MaterializationError, match="timezone-aware"):
            _materialize(
                tmp_path,
                server.base_url,
                manifest_fields={"published_at": "2020-01-02T03:04:05"},
            )


def test_existing_valid_manifest_is_idempotent(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        first = _materialize(tmp_path, server.base_url)
        second = _materialize(tmp_path, server.base_url)

    assert second == first
    assert server.state.served_count == 1


def test_http_failure_cleans_partial_target_and_uses_domain_error(tmp_path):
    with scripted_server([(404, {}, b"missing")]) as server:
        with pytest.raises(MaterializationError, match="HTTP 404"):
            _materialize(tmp_path, server.base_url)

    target = tmp_path / "repos/github.com/example/demo" / SHA
    assert not target.exists()
    assert not list(target.parent.glob(f".{SHA}.tmp-*"))
    # Failed materialization must not leave orphan empty parent directories.
    assert not (tmp_path / "repos").exists()


def test_transient_http_failure_is_retried(tmp_path):
    with scripted_server([(500, {}, b"retry"), (200, {}, _tarball())]) as server:
        target = materialize_github_repo(
            tmp_path,
            "example/demo",
            "example",
            "demo",
            SHA,
            base_url=server.base_url,
            max_attempts=2,
            sleeper=lambda _delay: None,
            verify=False,
        )

    assert (target / "src/example.py").is_file()
    assert server.state.served_count == 2


def test_invalid_tarball_cleans_partial_target(tmp_path):
    with scripted_server([(200, {}, b"not a tarball")]) as server:
        with pytest.raises(MaterializationError, match="ReadError"):
            _materialize(tmp_path, server.base_url)
    assert not (tmp_path / "repos/github.com/example/demo" / SHA).exists()


def test_target_symlink_to_external_cache_is_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / "corpus/repos/github.com/example/demo" / SHA
    target.parent.mkdir(parents=True)
    target.symlink_to(outside, target_is_directory=True)
    with scripted_server([(200, {}, _tarball())]) as server:
        with pytest.raises(MaterializationError, match="symbolic link"):
            _materialize(tmp_path / "corpus", server.base_url)
    assert list(outside.iterdir()) == []


def test_parent_symlink_escape_write_is_rejected(tmp_path):
    corpus = tmp_path / "corpus"
    outside = tmp_path / "outside"
    outside.mkdir()
    corpus.mkdir()
    (corpus / "repos").symlink_to(outside, target_is_directory=True)
    with scripted_server([(200, {}, _tarball())]) as server:
        with pytest.raises(MaterializationError, match="symbolic link"):
            _materialize(corpus, server.base_url)
    assert list(outside.iterdir()) == []


def test_deep_parent_symlink_chain_is_rejected(tmp_path):
    corpus = tmp_path / "corpus"
    outside = tmp_path / "outside"
    outside.mkdir()
    (corpus / "repos/github.com/example").mkdir(parents=True)
    (corpus / "repos/github.com/example/demo").symlink_to(
        outside, target_is_directory=True
    )
    with scripted_server([(200, {}, _tarball())]) as server:
        with pytest.raises(MaterializationError, match="symbolic link"):
            _materialize(corpus, server.base_url)
    assert list(outside.iterdir()) == []


def test_target_lock_rejects_symlinked_parent_before_sweeping_debris(
    tmp_path: Path,
) -> None:
    """Issue #205 SP: confinement protects the sweep from an escaping parent."""
    sha = "9" * 40
    root = (tmp_path / "corpus").absolute()
    outside = (tmp_path / "outside").absolute()
    outside_shelf = outside / "github.com/example/demo"
    outside_shelf.mkdir(parents=True)
    debris = outside_shelf / f".{sha}.tmp-escape"
    original = b"must not be removed"
    debris.write_bytes(original)
    corpus_repos = root / "repos"
    root.mkdir()
    try:
        corpus_repos.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    target = materialize_module.target_path(root, "example", "demo", sha)
    before = sorted(path.relative_to(outside) for path in outside.rglob("*"))
    with pytest.raises(MaterializationError, match="symbolic link"):
        with materialize_module._target_lock(root, target, sha):
            pass

    assert debris.read_bytes() == original
    assert sorted(path.relative_to(outside) for path in outside.rglob("*")) == before


def test_abandoned_staging_is_cleaned_under_target_lock(tmp_path):
    parent = tmp_path / "repos/github.com/example/demo"
    parent.mkdir(parents=True)
    stale = parent / f".{SHA}.tmp-999999-abandoned"
    stale.mkdir()
    (stale / "partial").write_bytes(b"partial")
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)
    assert target.is_dir()
    assert not stale.exists()


def test_concurrent_materializations_publish_once_without_cache_gap(tmp_path):
    started = multiprocessing.Event()
    release = multiprocessing.Event()
    second_lock_attempted = multiprocessing.Event()

    queue = multiprocessing.Queue()
    # A spawned worker must import the test module before it can run its target.
    # Keep unrelated socket-server setup out of that startup path. Fork workers
    # retain the original child-local server path so Linux behavior is unchanged.
    spawn_server = (
        scripted_server([(200, {}, _tarball())])
        if multiprocessing.get_start_method() == "spawn"
        else nullcontext(None)
    )
    with spawn_server as server:
        base_url = server.base_url if server is not None else None
        first_args = (str(tmp_path), base_url, started, release, None, queue)
        second_args = (
            str(tmp_path),
            base_url,
            started,
            release,
            second_lock_attempted,
            queue,
        )
        first = multiprocessing.Process(
            target=_concurrent_materialize_worker, args=first_args
        )
        second = multiprocessing.Process(
            target=_concurrent_materialize_worker, args=second_args
        )
        first.start()
        assert started.wait(10)
        second.start()
        assert second_lock_attempted.wait(10)
        release.set()
        first.join(10)
        second.join(10)
        assert first.exitcode == second.exitcode == 0
        if server is not None:
            assert server.state.served_count == 1
    results = [queue.get(timeout=2), queue.get(timeout=2)]
    target = tmp_path / "repos/github.com/example/demo" / SHA
    assert sorted(results) == [(str(target), False), (str(target), True)]
    assert (target / "src/example.py").read_bytes() == b"pinned source\n"
    assert not list(target.parent.glob(f".{SHA}.tmp-*"))


def test_killed_waiter_cannot_destroy_valid_cache(tmp_path):
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)

    with materialize_module._target_lock(tmp_path, target, SHA):
        process = multiprocessing.Process(target=_materialization_waiter, args=(str(tmp_path),))
        process.start()
        time.sleep(0.1)
        process.terminate()
        process.join(5)
    assert process.exitcode is not None and process.exitcode != 0
    assert (target / "src/example.py").read_bytes() == b"pinned source\n"
    assert json.loads((target / "leitir-manifest.json").read_text())["commit_sha"] == SHA


def test_path_traversal_member_is_rejected(tmp_path):
    with scripted_server([(200, {}, _tarball(traversal=True))]) as server:
        with pytest.raises(MaterializationError, match="UnsafeArchiveError"):
            _materialize(tmp_path, server.base_url)

    assert not (tmp_path / "evil.txt").exists()
    assert not (tmp_path / "repos/github.com/example/demo" / SHA).exists()


def test_device_file_is_rejected(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        device = tarfile.TarInfo(f"demo-{SHA}/device")
        device.type = tarfile.CHRTYPE
        archive.addfile(device)
    with scripted_server([(200, {}, data.getvalue())]) as server:
        with pytest.raises(MaterializationError, match="UnsafeArchiveError"):
            _materialize(tmp_path, server.base_url)


def test_escaping_symlink_is_rejected(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        link = tarfile.TarInfo(f"demo-{SHA}/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        archive.addfile(link)
    with scripted_server([(200, {}, data.getvalue())]) as server:
        with pytest.raises(MaterializationError, match="UnsafeArchiveError"):
            _materialize(tmp_path, server.base_url)


def test_chained_symlink_escape_is_rejected(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        root = tarfile.TarInfo(f"demo-{SHA}/")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, target in (
            ("a", "."),
            ("b", "a/.."),
            ("c", "b/.."),
            ("leak.py", "c/etc/passwd"),
        ):
            link = tarfile.TarInfo(f"demo-{SHA}/{name}")
            link.type = tarfile.SYMTYPE
            link.linkname = target
            archive.addfile(link)

    with pytest.raises(UnsafeArchiveError, match="symbolic link escapes its target"):
        _extract_tarball(data.getvalue(), tmp_path / "out", "demo", SHA)


def test_chained_symlink_escape_creates_nothing_outside_staging(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        root = tarfile.TarInfo("pkg/")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        for name, target in (("a", "."), ("b", "a/.."), ("b/payload", "owned")):
            link = tarfile.TarInfo(f"pkg/{name}")
            link.type = tarfile.SYMTYPE
            link.linkname = target
            archive.addfile(link)

    parent = tmp_path / "parent"
    parent.mkdir()
    before = _snapshot(parent)
    with pytest.raises(UnsafeArchiveError, match="symbolic link escapes its target"):
        _extract_then_clean(data.getvalue(), parent / "staging")

    assert _snapshot(parent) == before
    assert not (parent / "payload").exists()


def test_relocated_nested_symlink_escape_creates_nothing_outside_staging(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        inside = tarfile.TarInfo("pkg/inside/")
        inside.type = tarfile.DIRTYPE
        inside.mode = 0o755
        archive.addfile(inside)
        for name, target in (
            ("x/y/a", "../../inside"),
            ("x/y/a/b", "../../outside"),
            ("x/y/a/b/pwn", "marker"),
        ):
            link = tarfile.TarInfo(f"pkg/{name}")
            link.type = tarfile.SYMTYPE
            link.linkname = target
            archive.addfile(link)

    parent = tmp_path / "parent"
    parent.mkdir()
    (parent / "outside").mkdir()
    before = _snapshot(parent)
    with pytest.raises(UnsafeArchiveError, match="symbolic link escapes its target"):
        _extract_then_clean(data.getvalue(), parent / "staging")

    assert _snapshot(parent) == before
    assert not (parent / "outside/pwn").exists()


def test_benign_symlink_extracts_within_target(tmp_path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        content = b"safe"
        member = tarfile.TarInfo(f"demo-{SHA}/realfile")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
        link = tarfile.TarInfo(f"demo-{SHA}/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "realfile"
        archive.addfile(link)

    destination = tmp_path / "out"
    _extract_tarball(data.getvalue(), destination, "demo", SHA)

    assert (destination / "link").is_symlink()
    assert (destination / "link").read_bytes() == b"safe"


class _ModeBearingTreeSource:
    """Non-GitHub TreeSource whose listing carries full blob modes."""

    def __init__(
        self,
        entries: tuple[BlobEntry, ...],
        blobs: dict[str, bytes],
        *,
        at_commit_fails: bool = False,
    ) -> None:
        self.entries = entries
        self.blobs = blobs
        self.at_commit_fails = at_commit_fails

    def list_blobs(self, _slug: str, _commit_sha: str) -> tuple[BlobEntry, ...]:
        return self.entries

    def read_blob(self, _slug: str, blob_sha: str) -> bytes:
        return self.blobs[blob_sha]

    def read_blob_at_commit(self, _slug: str, _commit_sha: str, path: str) -> bytes:
        if self.at_commit_fails:
            raise TreeReadError("tree source read failed")
        entry = next(entry for entry in self.entries if entry.path == path)
        return self.blobs[entry.blob_sha]


class _ReadBlobOnlyTreeSource:
    """Legacy injected TreeSource without commit-pinned re-read support."""

    def __init__(self, entries: tuple[BlobEntry, ...], blobs: dict[str, bytes]) -> None:
        self.entries = entries
        self.blobs = blobs

    def list_blobs(self, _slug: str, _commit_sha: str) -> tuple[BlobEntry, ...]:
        return self.entries

    def read_blob(self, _slug: str, blob_sha: str) -> bytes:
        return self.blobs[blob_sha]


class _GitHubSymlinkTreeSource(GitHubTreeSource):
    """GitHub-flavored source pinning the existing commit-pinned re-read path."""

    def __init__(self, entries: tuple[BlobEntry, ...], blobs: dict[str, bytes]) -> None:
        self.entries = entries
        self.blobs = blobs

    def list_blobs(self, _slug: str, _commit_sha: str) -> tuple[BlobEntry, ...]:
        return self.entries

    def read_blob_at_commit(self, _slug: str, _commit_sha: str, path: str) -> bytes:
        entry = next(entry for entry in self.entries if entry.path == path)
        return self.blobs[entry.blob_sha]


class _ListOnlyTreeSource:
    """Mode-bearing TreeSource that can enumerate but not re-read blobs."""

    def __init__(self, entries: tuple[BlobEntry, ...]) -> None:
        self.entries = entries

    def list_blobs(self, _slug: str, _commit_sha: str) -> tuple[BlobEntry, ...]:
        return self.entries


class _RereadOrderPinningSource(_ModeBearingTreeSource):
    """Pin the re-read arm order: read_blob must never be consulted."""

    def read_blob(self, _slug: str, _blob_sha: str) -> bytes:
        raise AssertionError(
            "read_blob must not be consulted while read_blob_at_commit is offered"
        )


def _verify_staging(staging: Path, source: object) -> bool | str:
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


def _tampered_link_fixture(tmp_path):
    expected_target = b"realfile"
    (tmp_path / "realfile").write_bytes(b"proof")
    (tmp_path / "link").symlink_to("other")
    link_sha = GitHubTreeSource.git_blob_sha(expected_target)
    entries = (
        BlobEntry("realfile", GitHubTreeSource.git_blob_sha(b"proof"), 5, "100644"),
        BlobEntry("link", link_sha, len(expected_target), "120000"),
    )
    return entries, link_sha, expected_target


def test_tampered_symlink_content_non_github_rejected(tmp_path):
    # G-0 / AC-1 / SP-1: a hostile archive alters one symlink target while
    # the (non-GitHub) tree source can enumerate modes. The commit-pinned
    # re-check still mismatches, so verification must fail closed with a
    # typed error naming the path instead of downgrading to "sampled".
    entries, link_sha, expected_target = _tampered_link_fixture(tmp_path)
    source = _ModeBearingTreeSource(entries, {link_sha: expected_target})

    with pytest.raises(
        VerificationError, match="symbolic-link blob digest mismatch: link"
    ):
        _verify_staging(tmp_path, source)


def test_tampered_symlink_recheck_via_read_blob_rejected(tmp_path):
    # AC-1 (fallback arm) / SP-1: same tamper against a legacy injected
    # TreeSource that only offers read_blob — the blob re-read must still
    # reject instead of downgrading to "sampled".
    entries, link_sha, expected_target = _tampered_link_fixture(tmp_path)
    source = _ReadBlobOnlyTreeSource(entries, {link_sha: expected_target})

    with pytest.raises(
        VerificationError, match="symbolic-link blob digest mismatch: link"
    ):
        _verify_staging(tmp_path, source)


def test_symlink_reread_failure_is_typed_rejection(tmp_path):
    # SP-3: when the re-read helper itself fails (e.g. network), the typed
    # error must propagate — a failed re-read can never become a pass or a
    # sampled downgrade.
    entries, link_sha, _expected_target = _tampered_link_fixture(tmp_path)
    source = _ModeBearingTreeSource(entries, {}, at_commit_fails=True)

    with pytest.raises(TreeReadError):
        _verify_staging(tmp_path, source)


@pytest.mark.parametrize("variant", ["missing", "extra"])
def test_symlink_universe_mismatch_rejected(tmp_path, variant):
    # AC-2 / SP-2: with modes available, an archive that drops or adds a
    # symlink relative to the expected universe must be rejected by name,
    # never silently repaired or downgraded to "sampled".
    target = "realfile"
    (tmp_path / "realfile").write_bytes(b"proof")
    link_sha = GitHubTreeSource.git_blob_sha(target.encode())
    entries = [BlobEntry("realfile", GitHubTreeSource.git_blob_sha(b"proof"), 5, "100644")]
    if variant == "missing":
        entries.append(BlobEntry("link", link_sha, len(target), "120000"))
        expected_name = r"missing extracted symbolic link: link"
    else:
        (tmp_path / "extra").symlink_to(target)
        expected_name = r"unexpected extracted symbolic link: extra"

    with pytest.raises(VerificationError, match=expected_name):
        _verify_staging(tmp_path, _ModeBearingTreeSource(tuple(entries), {link_sha: target.encode()}))


def test_mode_less_source_keeps_sampled_ingest(tmp_path):
    # AC-3 / C-3 / SP-4: a host that genuinely cannot enumerate modes keeps
    # the explicit sampled outcome — no mode fabrication, no crash, no
    # false full verification even with a consistent symlink on disk.
    content = b"proof"
    (tmp_path / "proof.txt").write_bytes(content)
    (tmp_path / "link").symlink_to("proof.txt")
    entries = (BlobEntry("proof.txt", GitHubTreeSource.git_blob_sha(content), len(content)),)

    assert _verify_staging(tmp_path, _ModeBearingTreeSource(entries, {})) == "sampled"


def test_matching_non_github_symlink_verifies_fully(tmp_path):
    # C-2 counterweight: an honest non-GitHub archive with an intact symlink
    # still verifies fully — fail-closed must not become false rejects.
    target = "realfile"
    (tmp_path / "realfile").write_bytes(b"proof")
    (tmp_path / "link").symlink_to(target)
    link_sha = GitHubTreeSource.git_blob_sha(target.encode())
    entries = (
        BlobEntry("realfile", GitHubTreeSource.git_blob_sha(b"proof"), 5, "100644"),
        BlobEntry("link", link_sha, len(target), "120000"),
    )

    assert _verify_staging(tmp_path, _ModeBearingTreeSource(entries, {})) is True


def test_github_symlink_tamper_still_rejected(tmp_path):
    # AC-4 / C-4: the existing GitHub commit-pinned re-read + reject
    # behavior is unchanged by the unified mismatch handling.
    entries, link_sha, expected_target = _tampered_link_fixture(tmp_path)
    source = _GitHubSymlinkTreeSource(entries, {link_sha: expected_target})

    with pytest.raises(
        VerificationError, match="symbolic-link blob digest mismatch: link"
    ):
        _verify_staging(tmp_path, source)


def test_symlink_enumeration_glitch_cleared_by_commit_pinned_reread(tmp_path):
    # Review residual (positive arm): the listing vouches a digest that does
    # not match the bytes extracted to disk (an enumeration glitch). The
    # commit-pinned re-read returns exactly the extracted bytes, so the
    # mismatch is cleared and verification completes fully. The at-commit
    # arm is selected — read_blob is never consulted while it is offered.
    target = b"realfile"
    (tmp_path / "realfile").write_bytes(b"proof")
    (tmp_path / "link").symlink_to("realfile")
    glitched_sha = GitHubTreeSource.git_blob_sha(b"stale listing digest")
    entries = (
        BlobEntry("realfile", GitHubTreeSource.git_blob_sha(b"proof"), 5, "100644"),
        BlobEntry("link", glitched_sha, len(target), "120000"),
    )
    source = _RereadOrderPinningSource(entries, {glitched_sha: target})

    assert _verify_staging(tmp_path, source) is True


def test_symlink_mismatch_without_any_reread_method_fails_closed(tmp_path):
    # Review residual (else arm): a mode-bearing source offering neither
    # read_blob_at_commit nor read_blob can neither confirm nor clear a
    # symlink digest mismatch — the mismatch must fail closed with a typed
    # error instead of a downgrade to "sampled".
    entries, _link_sha, _expected_target = _tampered_link_fixture(tmp_path)
    source = _ListOnlyTreeSource(entries)

    with pytest.raises(
        VerificationError, match="cannot re-read symbolic link blob: link"
    ):
        _verify_staging(tmp_path, source)


def _gitea_trees_payload(rows: list[dict]) -> dict:
    return {"tree": rows}


def _gitea_symlink_contents_payload(
    target: str, blob_sha: str, *, with_target: bool = True
) -> dict:
    payload = {
        "name": "link",
        "path": "link",
        "sha": blob_sha,
        "type": "symlink",
        "size": len(target),
        "encoding": None,
        "content": None,
    }
    if with_target:
        payload["target"] = target
    return payload


def _codeberg_shelf_responses(
    link_blob_sha: str,
    contents_response: tuple,
    fallback_response: tuple | None = None,
) -> list[tuple]:
    target = "realfile"
    trees = _gitea_trees_payload(
        [
            {
                "type": "blob",
                "path": "realfile",
                "sha": GitHubTreeSource.git_blob_sha(b"proof"),
                "size": 5,
                "mode": "100644",
            },
            {
                "type": "blob",
                "path": "link",
                "sha": link_blob_sha,
                "size": len(target),
                "mode": "120000",
            },
        ]
    )
    responses = [
        (200, {}, json.dumps(trees).encode("utf-8")),
        contents_response,
    ]
    if fallback_response is not None:
        responses.append(fallback_response)
    return responses


def test_codeberg_symlink_enumeration_glitch_cleared_by_digest_verified_reread(tmp_path):
    # AC-2 / C-2 (issue #219): a Codeberg shelf whose tree listing vouches a
    # stale digest for an intact on-disk symlink (an enumeration glitch).
    # The commit-pinned re-read now succeeds for symlink paths and returns
    # digest-verified bytes equal to the extracted ones, so the mismatch is
    # cleared and the outcome is identical to the no-glitch run — full
    # verification, never a downgrade to "sampled".
    (tmp_path / "realfile").write_bytes(b"proof")
    (tmp_path / "link").symlink_to("realfile")
    glitched_sha = GitHubTreeSource.git_blob_sha(b"stale listing digest")
    honest_sha = GitHubTreeSource.git_blob_sha(b"realfile")
    contents = _gitea_symlink_contents_payload("realfile", honest_sha)
    responses = _codeberg_shelf_responses(glitched_sha, (200, {}, json_body(contents)))

    with scripted_server(responses) as server:
        resolver = CodebergResolver(
            base_url=server.base_url, sleeper=lambda _: None
        )
        assert _verify_staging(tmp_path, resolver) is True
    assert server.state.request_paths == [
        f"/repos/acme/demo/git/trees/{SHA}?recursive=true",
        f"/repos/acme/demo/contents/link?ref={SHA}",
    ]


def test_codeberg_symlink_tamper_rejected_naming_path(tmp_path):
    # AC-3 / C-3 (issue #219): a genuinely tampered Codeberg symlink. The
    # listing digest is honest, the extracted bytes are not; the re-read
    # returns digest-verified bytes, which differ from the
    # extracted ones, so verification rejects with the path-naming
    # VerificationError instead of surfacing a ResolutionError.
    (tmp_path / "realfile").write_bytes(b"proof")
    (tmp_path / "link").symlink_to("other")  # tampered target
    honest_sha = GitHubTreeSource.git_blob_sha(b"realfile")
    contents = _gitea_symlink_contents_payload("realfile", honest_sha)
    responses = _codeberg_shelf_responses(honest_sha, (200, {}, json_body(contents)))

    with scripted_server(responses) as server:
        resolver = CodebergResolver(
            base_url=server.base_url, sleeper=lambda _: None
        )
        with pytest.raises(
            VerificationError, match="Git symbolic-link blob digest mismatch: link"
        ):
            _verify_staging(tmp_path, resolver)


def test_codeberg_symlink_glitch_cleared_via_git_blob_fallback_channel(tmp_path):
    # AC-2 via the no-``target`` contents shape (older Gitea): the re-read
    # takes the digest-verified git-blob fallback channel and still clears
    # the enumeration glitch — full verification, never a downgrade.
    import base64

    (tmp_path / "realfile").write_bytes(b"proof")
    (tmp_path / "link").symlink_to("realfile")
    glitched_sha = GitHubTreeSource.git_blob_sha(b"stale listing digest")
    honest_sha = GitHubTreeSource.git_blob_sha(b"realfile")
    contents = _gitea_symlink_contents_payload(
        "realfile", honest_sha, with_target=False
    )
    git_blob = {
        "content": base64.b64encode(b"realfile").decode("ascii"),
        "encoding": "base64",
        "sha": honest_sha,
        "size": len(b"realfile"),
    }
    responses = _codeberg_shelf_responses(
        glitched_sha,
        (200, {}, json.dumps(contents).encode("utf-8")),
        (200, {}, json.dumps(git_blob).encode("utf-8")),
    )

    with scripted_server(responses) as server:
        resolver = CodebergResolver(base_url=server.base_url, sleeper=lambda _: None)
        assert _verify_staging(tmp_path, resolver) is True
    assert server.state.request_paths == [
        f"/repos/acme/demo/git/trees/{SHA}?recursive=true",
        f"/repos/acme/demo/contents/link?ref={SHA}",
        f"/repos/acme/demo/git/blobs/{honest_sha}",
    ]


def test_codeberg_symlink_glitch_reread_channel_failure_fails_closed(tmp_path):
    # SP-1 at the materialize boundary (issue #219): a glitch listing whose
    # re-read channel fails can neither clear nor confirm the mismatch — the
    # typed ResolutionError propagates and verification fails closed (no
    # clearance, no "sampled" downgrade).
    (tmp_path / "realfile").write_bytes(b"proof")
    (tmp_path / "link").symlink_to("realfile")
    glitched_sha = GitHubTreeSource.git_blob_sha(b"stale listing digest")
    responses = _codeberg_shelf_responses(glitched_sha, (500, {}, b""))

    with scripted_server(responses) as server:
        resolver = CodebergResolver(
            base_url=server.base_url, sleeper=lambda _: None
        )
        with pytest.raises(ResolutionError, match="HTTP 500"):
            _verify_staging(tmp_path, resolver)


def test_oversized_archive_member_is_rejected(tmp_path, monkeypatch):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        member = tarfile.TarInfo(f"demo-{SHA}/large")
        member.size = 2
        archive.addfile(member, io.BytesIO(b"xx"))
    monkeypatch.setattr(materialize_module, "ARCHIVE_MAX_MEMBER_BYTES", 1)

    with pytest.raises(UnsafeArchiveError, match="archive member exceeds size limit"):
        _extract_tarball(data.getvalue(), tmp_path / "out", "demo", SHA)


def test_archive_member_count_is_enforced_during_iteration(tmp_path, monkeypatch):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name in ("one", "two"):
            member = tarfile.TarInfo(f"demo-{SHA}/{name}")
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
    monkeypatch.setattr(materialize_module, "ARCHIVE_MAX_MEMBERS", 1)

    with pytest.raises(UnsafeArchiveError, match="archive contains too many members"):
        _extract_tarball(data.getvalue(), tmp_path / "out", "demo", SHA)


def test_compressed_download_size_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(materialize_module, "ARCHIVE_MAX_COMPRESSED_BYTES", 4)
    with scripted_server([(200, {}, b"12345")]) as server:
        with pytest.raises(MaterializationError, match="compressed size limit"):
            _materialize(tmp_path, server.base_url)


class _ShortReadResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    def read(self, _size: int) -> bytes:
        return self.chunks.pop(0) if self.chunks else b""


def test_bounded_read_accepts_streaming_short_reads_under_limit():
    response = _ShortReadResponse([b"ab", b"c", b"de"])
    assert materialize_module._read_bounded(response, 5) == b"abcde"


def test_bounded_read_rejects_streaming_short_reads_over_limit():
    response = _ShortReadResponse([b"ab", b"cd", b"ef"])
    with pytest.raises(MaterializationError, match="compressed size limit"):
        materialize_module._read_bounded(response, 5)


@pytest.mark.parametrize("token", ["bad\x00token", "bad\x7ftoken"])
def test_codeload_token_control_character_is_rejected_without_disclosure(
    tmp_path, token
):
    with pytest.raises(ValueError) as error:
        materialize_github_repo(
            tmp_path,
            "example/demo",
            "example",
            "demo",
            SHA,
            token=token,
            verify=False,
        )
    assert token not in str(error.value)


# --- Issue #194: full-coverage load-time verification (per-file digest map) ---

_ABOVE_CAP_FILES = 1_010
_ABOVE_CAP_FILE_BYTES = 67_000  # 1010 * 67000 > 64 MiB aggregate byte cap
# SHA-256 over the canonical compact JSON of the fixture shelf's per-file
# digest map (sorted keys). Pinning it keeps the fixture byte-stable.
ABOVE_CAP_MAP_DIGEST = (
    "216e635366fe847ccbcf0ba69fbec43f108d11c2ba170cd8fce134314081925b"
)


def _above_cap_content(index: int) -> bytes:
    pattern = f"{index:04d}-pinned-source\n".encode("ascii")
    return (pattern * (_ABOVE_CAP_FILE_BYTES // len(pattern) + 1))[:_ABOVE_CAP_FILE_BYTES]


def _above_cap_tarball() -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        root = tarfile.TarInfo(f"demo-{SHA}/")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        archive.addfile(root)
        for index in range(_ABOVE_CAP_FILES):
            content = _above_cap_content(index)
            member = tarfile.TarInfo(f"demo-{SHA}/file_{index:04d}.bin")
            member.size = len(content)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(content))
    return data.getvalue()


def _above_cap_tree_source() -> tuple[object, dict[str, bytes]]:
    entries = []
    blobs = {}
    for index in range(_ABOVE_CAP_FILES):
        content = _above_cap_content(index)
        blob_sha = GitHubTreeSource.git_blob_sha(content)
        entries.append(
            BlobEntry(f"file_{index:04d}.bin", blob_sha, len(content), "100644")
        )
        blobs[blob_sha] = content
    return _ModeBearingTreeSource(tuple(entries), blobs), blobs


def _legacy_sampled_window(contents: dict[str, bytes]) -> set[str]:
    """Mirror the legacy treehash sampled selection for the fixture shelf.

    Entries are ordered by SHA-256 of ``<digest_hex>\\0<path>`` and selected
    greedily while both caps permit; with 1010 uniform files the 1000-file
    cap binds first, so exactly ten fixture paths fall outside the window.
    """
    import hashlib as _hashlib

    from leitir import treehash as _treehash

    ordered = sorted(
        contents,
        key=lambda path: _hashlib.sha256(
            _hashlib.sha256(contents[path]).hexdigest().encode("ascii")
            + b"\0"
            + path.encode("utf-8")
        ).digest(),
    )
    selected: list[str] = []
    selected_bytes = 0
    for path in ordered:
        if len(selected) >= _treehash.MAX_FILES:
            break
        if selected_bytes + len(contents[path]) <= _treehash.MAX_BYTES:
            selected.append(path)
            selected_bytes += len(contents[path])
    if not selected and ordered:
        selected.append(ordered[0])
    return set(selected)


def _materialize_above_cap(root: Path) -> Path:
    source, _blobs = _above_cap_tree_source()
    with scripted_server([(200, {}, _above_cap_tarball())]) as server:
        return materialize_github_repo(
            root,
            "example/demo#v1",
            "example",
            "demo",
            SHA,
            tag="v1",
            base_url=server.base_url,
            max_attempts=1,
            verify=True,
            tree_source=source,
        )


def test_above_cap_shelf_load_verifies_every_file(tmp_path):
    # G-0 (issue #194): a shelf above both verification caps must still be
    # FULLY anchored at load time via the per-file digest map. Corrupting a
    # file outside the legacy sampled window is detected on load. Before the
    # map existed, the load anchor was the sampled aggregate digest and such
    # corruption loaded clean (this test failed at the contract baseline).
    import hashlib as _hashlib

    target = _materialize_above_cap(tmp_path)
    manifest = json.loads((target / "leitir-manifest.json").read_text())

    # C-1: the manifest records a flat per-file SHA-256 digest map.
    file_digests = manifest["materialized_file_digests"]
    assert manifest["materialized_file_digests_algorithm"] == "per-file-sha256-v1"
    assert len(file_digests) == _ABOVE_CAP_FILES
    assert file_digests[f"file_{0:04d}.bin"] == _hashlib.sha256(
        _above_cap_content(0)
    ).hexdigest()

    # C-5 / AC-2: caps no longer bound the load-time trust level.
    assert manifest["materialized_tree_hash_scope"] == "full"

    # C-4: `sampled` survives only as the ingest-time cross-check label.
    assert manifest["verified"] == "sampled"

    # Pin the fixture's map digest (deterministic content -> stable digest).
    import hashlib as _map_digest

    canonical = json.dumps(file_digests, sort_keys=True, separators=(",", ":"))
    assert _map_digest.sha256(canonical.encode("utf-8")).hexdigest() == ABOVE_CAP_MAP_DIGEST

    # AC-2: a healthy above-cap shelf loads with full-coverage verification.
    from leitir.materialize import verify_materialized_integrity

    verify_materialized_integrity(target, manifest)  # no raise
    assert read_valid_manifest(target, "example", "demo", SHA) is not None

    # AC-1 / SP-1: corrupt a file OUTSIDE the legacy sampled window.
    contents = {
        f"file_{index:04d}.bin": _above_cap_content(index)
        for index in range(_ABOVE_CAP_FILES)
    }
    window = _legacy_sampled_window(contents)
    victim = sorted(set(contents) - window)[0]
    assert victim not in window
    (target / victim).write_bytes(b"tampered bytes\n")

    with pytest.raises(VerificationError, match=victim):
        verify_materialized_integrity(target, manifest)
    # The load gate rejects the shelf outright; it never loads-and-warns.
    assert read_valid_manifest(target, "example", "demo", SHA) is None


def _strip_map_fields(manifest: dict) -> dict:
    for field in (
        "materialized_file_digests",
        "materialized_file_digests_algorithm",
    ):
        manifest.pop(field, None)
    return manifest


def _healthy_mapped_shelf(tmp_path: Path) -> tuple[Path, dict]:
    with scripted_server([(200, {}, _tarball())]) as server:
        target = _materialize(tmp_path, server.base_url)
    return target, json.loads((target / "leitir-manifest.json").read_text())


def test_legacy_manifest_without_map_loads_via_existing_path(tmp_path):
    # AC-3 / C-3: a manifest with the map fields stripped (the pre-#194
    # shape) loads through the unchanged aggregate path. The shelf is
    # below-cap so the full-scope aggregate still verifies byte-identically.
    target, manifest = _healthy_mapped_shelf(tmp_path)
    path = target / "leitir-manifest.json"
    legacy = _strip_map_fields(manifest)
    path.write_text(json.dumps(legacy, indent=2, sort_keys=True), encoding="utf-8")

    from leitir.materialize import verify_materialized_integrity

    verify_materialized_integrity(target, legacy)  # no raise
    loaded = read_valid_manifest(target, "example", "demo", SHA)
    assert loaded is not None
    assert loaded["materialized_tree_hash_scope"] == "full"
    assert "materialized_file_digests" not in loaded


_SAMPLED_CAP_FILES = 1_001  # one file above the real 1000-file cap


def _sampled_cap_tarball() -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        root = tarfile.TarInfo(f"demo-{SHA}/")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        archive.addfile(root)
        for index in range(_SAMPLED_CAP_FILES):
            content = f"tiny-{index:04d}\n".encode("ascii")
            member = tarfile.TarInfo(f"demo-{SHA}/file_{index:04d}.txt")
            member.size = len(content)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(content))
    return data.getvalue()


def _materialize_sampled_cap(root: Path) -> Path:
    with scripted_server([(200, {}, _sampled_cap_tarball())]) as server:
        return materialize_github_repo(
            root,
            "example/demo#v1",
            "example",
            "demo",
            SHA,
            tag="v1",
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
        )


def test_legacy_sampled_manifest_keeps_honest_label_next_to_mapped_shelf(tmp_path):
    # AC-3 / SP-3: an old-style above-cap manifest (sampled aggregate, no
    # map) keeps its honest sampled label; a sibling map-carrying shelf in
    # the same corpus reports full. Per-shelf labels, no global downgrade.
    from leitir import treehash
    from leitir.materialize import verify_materialized_integrity

    target = _materialize_sampled_cap(tmp_path)
    manifest = json.loads((target / "leitir-manifest.json").read_text())

    sampled_digest, sampled_scope = treehash.compute_materialized_tree_hash(target)
    assert sampled_scope == treehash.SAMPLED  # 1001 files > real file cap
    legacy = _strip_map_fields(dict(manifest))
    legacy.update(
        treehash.manifest_digest_fields(sampled_digest, scope=sampled_scope)
    )
    (target / "leitir-manifest.json").write_text(
        json.dumps(legacy, indent=2, sort_keys=True), encoding="utf-8"
    )

    loaded_legacy = read_valid_manifest(target, "example", "demo", SHA)
    assert loaded_legacy is not None
    assert loaded_legacy["materialized_tree_hash_scope"] == "sampled"
    verify_materialized_integrity(target, legacy)  # legacy path accepts it

    # The mapped sibling keeps its full label in the same corpus root.
    sibling_sha = "b" * 40
    sibling_data = io.BytesIO()
    with tarfile.open(fileobj=sibling_data, mode="w:gz") as archive:
        root_member = tarfile.TarInfo(f"demo2-{sibling_sha}/")
        root_member.type = tarfile.DIRTYPE
        root_member.mode = 0o755
        archive.addfile(root_member)
        content = b"pinned source\n"
        source = tarfile.TarInfo(f"demo2-{sibling_sha}/src/example.py")
        source.size = len(content)
        source.mode = 0o644
        archive.addfile(source, io.BytesIO(content))
    with scripted_server([(200, {}, sibling_data.getvalue())]) as server:
        sibling = materialize_github_repo(
            tmp_path,
            "example/demo2#v1",
            "example",
            "demo2",
            sibling_sha,
            tag="v1",
            base_url=server.base_url,
            max_attempts=1,
            verify=False,
        )
    loaded_mapped = read_valid_manifest(sibling, "example", "demo2", sibling_sha)
    assert loaded_mapped is not None
    assert loaded_mapped["materialized_tree_hash_scope"] == "full"
    assert loaded_mapped["materialized_file_digests"]["src/example.py"] == (
        __import__("hashlib").sha256(b"pinned source\n").hexdigest()
    )


def test_mapped_sampled_cap_shelf_upgrades_to_full_coverage(tmp_path):
    # C-5: the same 1001-file shelf, materialized by the current producer,
    # carries the map and reports full despite being above the caps.
    target = _materialize_sampled_cap(tmp_path)
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    assert manifest["materialized_tree_hash_scope"] == "full"
    assert len(manifest["materialized_file_digests"]) == _SAMPLED_CAP_FILES
    # The aggregate still equals the legacy forced-full computation.
    from leitir import treehash

    assert manifest["materialized_tree_hash"] == (
        treehash.compute_materialized_tree_hash(target, _force_full=True)[0]
    )
    assert read_valid_manifest(target, "example", "demo", SHA) is not None


def test_malformed_map_is_fail_closed_reject(tmp_path):
    # AC-4: malformed or truncated map -> typed reject, never ignore.
    from leitir.materialize import verify_materialized_integrity

    target, manifest = _healthy_mapped_shelf(tmp_path)
    path = target / "leitir-manifest.json"

    for corruption in (
        {"materialized_file_digests": "truncated"},
        {"materialized_file_digests": ["a", "b"]},
        {"materialized_file_digests": {"src/example.py": "not-hex"}},
        {"materialized_file_digests": None, "materialized_file_digests_algorithm": "per-file-sha256-v1"},
        {"materialized_file_digests": {"src/example.py": "0" * 64}},
    ):
        tampered = dict(manifest)
        tampered.update(corruption)
        with pytest.raises(VerificationError):
            verify_materialized_integrity(target, tampered)
        path.write_text(json.dumps(tampered, indent=2, sort_keys=True), encoding="utf-8")
        assert read_valid_manifest(target, "example", "demo", SHA) is None

    # Restore: the healthy manifest loads again (no lasting damage).
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    assert read_valid_manifest(target, "example", "demo", SHA) is not None


def test_map_consistent_file_tamper_breaks_the_anchor(tmp_path):
    # SP-2 at the manifest load gate: corrupt the file AND rewrite its map
    # entry. The stored full-scope aggregate no longer matches the map, so
    # the load rejects instead of trusting the attacker-rewritten map.
    import hashlib

    from leitir.materialize import verify_materialized_integrity

    target, manifest = _healthy_mapped_shelf(tmp_path)
    (target / "src/example.py").write_bytes(b"attacker bytes\n")
    tampered = dict(manifest)
    tampered["materialized_file_digests"] = {
        "src/example.py": hashlib.sha256(b"attacker bytes\n").hexdigest()
    }
    (target / "leitir-manifest.json").write_text(
        json.dumps(tampered, indent=2, sort_keys=True), encoding="utf-8"
    )

    with pytest.raises(VerificationError, match="anchored"):
        verify_materialized_integrity(target, tampered)
    assert read_valid_manifest(target, "example", "demo", SHA) is None


def test_update_manifest_refuses_tampered_mapped_shelf(tmp_path):
    # Manifest updates must never merge fields over a broken anchor.
    from leitir.materialize import ManifestIntegrityError, update_manifest

    target, manifest = _healthy_mapped_shelf(tmp_path)
    (target / "src/example.py").write_bytes(b"bitrot\n")
    with pytest.raises(ManifestIntegrityError):
        update_manifest(target, {"parity": "exact"})
    rewritten = json.loads((target / "leitir-manifest.json").read_text())
    assert rewritten["parity"] == manifest["parity"]  # unchanged


def test_update_manifest_never_backfills_a_stripped_anchor_on_mapped_shelf(tmp_path):
    # SP-2: stripping materialized_tree_hash from a map-carrying manifest is
    # tampering, not a legacy shelf; the provenance backfill path must not
    # repair it.
    from leitir.materialize import ManifestIntegrityError, update_manifest

    target, manifest = _healthy_mapped_shelf(tmp_path)
    stripped = dict(manifest)
    for field in (
        "materialized_tree_hash",
        "materialized_tree_hash_algorithm",
        "materialized_tree_hash_scope",
    ):
        stripped.pop(field)
    (target / "leitir-manifest.json").write_text(
        json.dumps(stripped, indent=2, sort_keys=True), encoding="utf-8"
    )
    with pytest.raises(ManifestIntegrityError):
        update_manifest(target, {"parity": "exact"})


def test_io_error_mid_verify_is_typed_and_never_partially_accepted(
    tmp_path, monkeypatch
):
    # SP-4: an IO failure during load verification surfaces as a typed
    # error; the shelf is rejected outright, not partially verified.
    import os as _os

    from leitir.materialize import verify_materialized_integrity

    target, manifest = _healthy_mapped_shelf(tmp_path)
    real_open = _os.open

    def denied(path, flags, mode=0o777):
        if Path(path) == target / "src/example.py":
            raise PermissionError("disk failing")
        return real_open(path, flags, mode)

    monkeypatch.setattr(_os, "open", denied)
    with pytest.raises(VerificationError):
        verify_materialized_integrity(target, manifest)
    assert read_valid_manifest(target, "example", "demo", SHA) is None


def test_map_writing_failure_fails_materialization(tmp_path, monkeypatch):
    # C-1 error contract: if the map cannot be computed, materialization
    # fails; no mapless shelf is published.
    def broken(_root: Path) -> dict:
        raise RuntimeError("scan exploded")

    monkeypatch.setattr(materialize_module, "full_coverage_manifest_fields", broken)
    with scripted_server([(200, {}, _tarball())]) as server:
        with pytest.raises(MaterializationError):
            _materialize(tmp_path, server.base_url)
    assert not (tmp_path / "repos").exists()


def test_manifest_size_bound_is_enforced_on_write(tmp_path, monkeypatch):
    # The in-manifest map must stay loadable: an over-bound manifest fails
    # materialization instead of stranding an unreadable shelf.
    monkeypatch.setattr(materialize_module, "MANIFEST_MAX_BYTES", 4)
    with scripted_server([(200, {}, _tarball())]) as server:
        with pytest.raises(MaterializationError, match="maximum serialized size"):
            _materialize(tmp_path, server.base_url)
    assert not (tmp_path / "repos").exists()


def _canonical_manifest_bytes(payload: dict) -> bytes:
    # Exactly _write_manifest's serialization: indent=2, sorted keys, LF.
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


@pytest.mark.parametrize("overflow", [-1, 0, 1])
def test_manifest_size_bound_transition(tmp_path, monkeypatch, overflow):
    # Dual-review remediation: pin the MANIFEST_MAX_BYTES transition exactly.
    # At bound-1/bound the manifest is writable AND loadable through
    # update_manifest; at bound+1 both sides fail loudly and typed — the
    # write side (_write_manifest) as MaterializationError, the read side
    # (update_manifest's bounded read) as ManifestIntegrityError.
    from leitir.materialize import (
        MANIFEST_NAME,
        ManifestIntegrityError,
        _write_manifest,
        update_manifest,
    )

    target, manifest = _healthy_mapped_shelf(tmp_path)
    manifest_path = target / MANIFEST_NAME
    # A "pad" string field is ignored by the map verification and the load
    # gate; each pad byte adds exactly one byte to the canonical form, so
    # the serialized size is controllable to the byte.
    base = dict(manifest, pad="")
    bound = len(_canonical_manifest_bytes(base)) + 8
    total = bound + overflow
    payload = dict(manifest, pad="x" * (total - len(_canonical_manifest_bytes(base))))
    data = _canonical_manifest_bytes(payload)
    assert len(data) == total  # exact transition point under test
    manifest_path.write_bytes(data)

    monkeypatch.setattr(materialize_module, "MANIFEST_MAX_BYTES", bound)

    if overflow <= 0:
        _write_manifest(manifest_path, payload)  # at-or-under bound: writable
        assert manifest_path.read_bytes() == data
        # Shrinking the pad field keeps the merged write under the bound.
        merged = update_manifest(target, {"pad": "y"})
        assert merged["pad"] == "y"
        assert read_valid_manifest(target, "example", "demo", SHA) is not None
    else:
        with pytest.raises(MaterializationError, match="maximum serialized size"):
            _write_manifest(manifest_path, payload)
        with pytest.raises(
            ManifestIntegrityError, match="maximum serialized size"
        ):
            update_manifest(target, {"pad": "y"})
        # Refused without writing: the shelf is left byte-identical, and the
        # load gate independently treats the over-bound manifest as a miss.
        assert manifest_path.read_bytes() == data
        assert read_valid_manifest(target, "example", "demo", SHA) is None


def test_update_manifest_rejects_duplicate_key_manifest(tmp_path):
    # Dual-review remediation: update_manifest must parse with the load
    # gate's duplicate-key-rejecting parser. A duplicated key (here: a
    # second "materialized_tree_hash") must never be last-wins decoded
    # into a clean, rewritten manifest.
    from leitir.materialize import MANIFEST_NAME, ManifestIntegrityError, update_manifest

    target, manifest = _healthy_mapped_shelf(tmp_path)
    canonical = json.dumps(manifest, indent=2, sort_keys=True)
    marker = '"materialized_tree_hash":'
    assert marker in canonical
    # json.dumps cannot emit duplicate keys; splice a second occurrence of
    # the anchor key directly after the first so last-wins decoding would
    # verify against the attacker's digest.
    lines = canonical.splitlines()
    insert_at = next(i for i, line in enumerate(lines) if marker in line) + 1
    duplicated = (
        "\n".join(
            [
                *lines[:insert_at],
                f'  "materialized_tree_hash": "h1:{"B" * 43}=",',
                *lines[insert_at:],
            ]
        )
        + "\n"
    )
    (target / MANIFEST_NAME).write_text(duplicated, encoding="utf-8")

    # Plain json.loads would take the attacker's last value silently.
    assert json.loads(duplicated)["materialized_tree_hash"] == "h1:" + "B" * 43 + "="
    with pytest.raises(ManifestIntegrityError, match="malformed"):
        update_manifest(target, {"parity": "exact"})
    # No laundering: the duplicated-key manifest is left untouched.
    assert (target / MANIFEST_NAME).read_text(encoding="utf-8") == duplicated


def test_manifest_fields_deterministic_across_independent_trees(tmp_path):
    # AC-5: same input -> byte-identical manifest fields (sorted, stable),
    # independent of insertion or iteration order.
    from leitir.treehash import full_coverage_manifest_fields

    files = {f"dir{i}/file{j}.txt": f"{i}-{j}".encode() for i in range(5) for j in range(5)}
    root_a = _extract_tree(tmp_path / "a", files)
    root_b = _extract_tree(tmp_path / "b", dict(reversed(list(files.items()))))
    fields_a = full_coverage_manifest_fields(root_a)
    fields_b = full_coverage_manifest_fields(root_b)
    assert fields_a == fields_b
    assert (
        json.dumps(fields_a, sort_keys=True) == json.dumps(fields_b, sort_keys=True)
    )


def _extract_tree(root: Path, files: dict[str, bytes]) -> Path:
    root.mkdir(parents=True)
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return root


def test_write_manifest_replace_failure_never_closes_recycled_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G-0 / SP-1 (issue #200): a failing ``os.replace`` must not double-close.

    The pre-consolidation except path closed the descriptor a second time
    after ``os.fdopen``'s context exit had already closed it.  Descriptor
    numbers are recycled lowest-first, so this canary ``os.open`` inside the
    injected failure receives the same number: a double-close would close a
    live descriptor owned by whoever recycled it.
    """
    from leitir.materialize import MANIFEST_NAME, _write_manifest

    target = tmp_path / MANIFEST_NAME
    # A canary FILE: os.open() on a directory is a PermissionError on Windows.
    canary = tmp_path / "canary.dat"
    canary.write_bytes(b"canary")
    recycled: list[int] = []

    def replace_failure(src: object, dst: object) -> None:
        recycled.append(os.open(canary, os.O_RDONLY))
        raise OSError("injected replace failure")

    monkeypatch.setattr(os, "replace", replace_failure)

    with pytest.raises(OSError, match="injected replace failure"):
        _write_manifest(target, {"schema": 2})

    # Temp litter is never left behind, even on the failure path.
    assert list(tmp_path.glob(f".{MANIFEST_NAME}.tmp-*")) == []
    # The recycled (canary) descriptor must still be open: the except path
    # closed nothing.  On the buggy baseline this fstat raised EBADF.
    assert recycled, "os.replace was invoked"
    os.fstat(recycled[0])
    os.close(recycled[0])


def test_write_manifest_fdopen_failure_closes_fd_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SP-2 (issue #200): an ``os.fdopen`` failure must not leak the fd."""
    from leitir.materialize import MANIFEST_NAME, _write_manifest

    created: list[int] = []
    closed: list[int] = []
    real_mkstemp = tempfile.mkstemp
    real_close = os.close

    def spy_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        fd, name = real_mkstemp(*args, **kwargs)  # type: ignore[arg-types]
        created.append(fd)
        return fd, name

    def spy_close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    def fdopen_failure(fd: int, *args: object, **kwargs: object) -> object:
        raise OSError("injected fdopen failure")

    monkeypatch.setattr(tempfile, "mkstemp", spy_mkstemp)
    monkeypatch.setattr(os, "close", spy_close)
    monkeypatch.setattr(os, "fdopen", fdopen_failure)

    target = tmp_path / MANIFEST_NAME
    with pytest.raises(OSError, match="injected fdopen failure"):
        _write_manifest(target, {"schema": 2})

    assert closed == created
    assert list(tmp_path.glob(f".{MANIFEST_NAME}.tmp-*")) == []


def test_stale_old_backup_dirs_are_swept_under_target_lock(tmp_path: Path) -> None:
    """Issue #205 C-5/AC-5/SP-2: crash-orphaned ``.old-`` backups are GC'd.

    A crash between the two ``os.replace`` calls orphans a ``.{sha}.old-``
    backup next to the shelf. While the verified target still exists, the
    target-lock sweep removes both staging temps and stale backups for THIS
    commit sha only — another source's debris is never ours to delete (hy3
    P1 remediation: backup staleness is target-relative).
    """

    sha = "a" * 40
    foreign_sha = "b" * 40
    root = (tmp_path / "corpus").absolute()
    target = materialize_module.target_path(root, "acme", "widget", sha)
    target.parent.mkdir(parents=True, exist_ok=True)
    # The verified generation is present, so the leftover backup is stale.
    target.mkdir()
    stale_tmp = target.parent / f".{sha}.tmp-1"
    stale_old = target.parent / f".{sha}.old-2"
    foreign_old = target.parent / f".{foreign_sha}.old-3"
    for directory in (stale_tmp, stale_old, foreign_old):
        directory.mkdir()

    with materialize_module._target_lock(root, target, sha):
        pass

    assert not stale_tmp.exists()
    assert not stale_old.exists()
    assert foreign_old.exists()


def test_target_lock_sweep_preserves_sole_survivor_backup(tmp_path: Path) -> None:
    """hy3 P1: the sweep never deletes the sole surviving generation.

    After ``os.replace(target, backup)`` succeeded but the process died
    before ``os.replace(staging, target)`` and before any rollback, the
    ``.{sha}.old-*`` backup is the only remaining verified shelf — the
    state ``cli.py``'s gc documents as "the only valid cache generation"
    and restores under this same per-target lock. The sweep must leave it
    in place; only the always-removable ``.{sha}.tmp-*`` staging debris
    (and never another sha's files) is swept.
    """

    sha = "d" * 40
    foreign_sha = "e" * 40
    root = (tmp_path / "corpus").absolute()
    target = materialize_module.target_path(root, "acme", "widget", sha)
    target.parent.mkdir(parents=True, exist_ok=True)
    # The target was moved away by the interrupted swap: it does not exist.
    survivor_backup = target.parent / f".{sha}.old-1"
    crash_staging = target.parent / f".{sha}.tmp-2"
    foreign_old = target.parent / f".{foreign_sha}.old-3"
    for directory in (survivor_backup, crash_staging, foreign_old):
        directory.mkdir()

    with materialize_module._target_lock(root, target, sha):
        pass

    assert survivor_backup.exists()
    assert not crash_staging.exists()
    assert foreign_old.exists()


def test_target_lock_sweep_skips_cleanly_when_shelf_parent_is_absent(
    tmp_path: Path,
) -> None:
    """Issue #205 SP-4: a sweep that cannot run skips, never blocks or crashes."""

    sha = "c" * 40
    root = (tmp_path / "corpus").absolute()
    target = materialize_module.target_path(root, "acme", "widget", sha)

    with materialize_module._target_lock(root, target, sha):
        pass

    assert not target.parent.exists()


def test_target_lock_sweep_skips_when_shelf_lock_is_contended(
    tmp_path: Path,
) -> None:
    """Issue #205 SP-4: contention skips cleanup without waiting or deleting."""
    sha = "f" * 40
    root = (tmp_path / "corpus").absolute()
    target = materialize_module.target_path(root, "acme", "widget", sha)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.mkdir()
    stale_tmp = target.parent / f".{sha}.tmp-contended"
    stale_old = target.parent / f".{sha}.old-contended"
    stale_tmp.mkdir()
    stale_old.mkdir()

    relative_target = target.relative_to(root)
    identity = os.path.normcase(str(relative_target)).encode("utf-8")
    lock_path = root / ".locks" / f"{hashlib.sha256(identity).hexdigest()}.lock"
    completed = threading.Event()
    errors: list[BaseException] = []

    def sweep() -> None:
        try:
            materialize_module._sweep_target_debris(lock_path, target, sha)
        except BaseException as exc:  # pragma: no cover - assertion below reports it
            errors.append(exc)
        finally:
            completed.set()

    worker = threading.Thread(target=sweep)
    with materialize_module._file_lock(lock_path):
        worker.start()
        worker.join(timeout=10.0)
        assert completed.is_set(), "contended stale sweep waited for the shelf lock"
    worker.join(timeout=10.0)
    assert not worker.is_alive()
    assert errors == []
    assert stale_tmp.exists()
    assert stale_old.exists()


def test_target_lock_composes_with_contended_sweep_lock(tmp_path: Path) -> None:
    """Issue #205 SP: a contended sweep does not prevent the body from running."""
    sha = "8" * 40
    root = (tmp_path / "corpus").absolute()
    target = materialize_module.target_path(root, "acme", "widget", sha)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.mkdir()
    stale_tmp = target.parent / f".{sha}.tmp-composed"
    stale_tmp.write_bytes(b"survive contention")

    relative_target = target.relative_to(root)
    identity = os.path.normcase(str(relative_target)).encode("utf-8")
    lock_path = root / ".locks" / f"{hashlib.sha256(identity).hexdigest()}.lock"
    held = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    def holder() -> None:
        try:
            with materialize_module._file_lock(lock_path):
                held.set()
                if not release.wait(10):
                    raise TimeoutError("timed out waiting to release composed lock")
        except BaseException as exc:  # pragma: no cover - assertion below reports it
            errors.append(exc)

    worker = threading.Thread(target=holder)
    worker.start()
    assert held.wait(10), "worker did not acquire the shelf lock"
    timer = threading.Timer(0.1, release.set)
    timer.start()
    body_ran = False
    try:
        with materialize_module._target_lock(root, target, sha):
            body_ran = True
    finally:
        release.set()
        timer.cancel()
        worker.join(timeout=10)

    assert not worker.is_alive()
    assert errors == []
    assert body_ran
    assert stale_tmp.read_bytes() == b"survive contention"


def test_http_server_harness_threads_join_cleanly() -> None:
    """Issue #205 C-3/AC-3: test-server joins are asserted, not discarded.

    Every harness server thread must be confirmed dead before its context
    manager returns; the started/joined counters must stay in lockstep, so a
    lingering server thread fails the suite instead of accruing sockets.
    """

    from _http_server import routed_server, server_thread_stats

    before = server_thread_stats()
    with scripted_server([(200, {}, b"ok")]):
        pass
    with routed_server({"/ping": (200, {}, b"pong")}):
        pass
    after = server_thread_stats()
    assert after["started"] - before["started"] == 2
    assert after["joined"] - before["joined"] == 2
