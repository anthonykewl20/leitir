"""Offline tests for SHA-pinned codeload materialization."""

from __future__ import annotations

import io
import json
import multiprocessing
import shutil
import tarfile
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path

import pytest
from _http_server import scripted_server

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
