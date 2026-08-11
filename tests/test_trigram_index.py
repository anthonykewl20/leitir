from __future__ import annotations

import hashlib
import json
import tarfile
import threading
from pathlib import Path

import pytest

from leitir.adapters.registry import build_adapters
from leitir.cli import ExitCode, main
from leitir.corpus import write_sources
from leitir.doctor import check_search_indexes
from leitir.engine import ScopedSearcher
from leitir.index.builder import ShelfRef, build_shelf_index
from leitir.index.query import IndexedSearcher, predicate_literal_runs
from leitir.materialize import VerificationError
from leitir.search import CoverageStatus, Predicate, PredicateKind, RepoScope, SearchMode, SearchSpec
from leitir.tree import BlobEntry
from leitir.treehash import TREE_HASH_ALGORITHM, compute_materialized_tree_hash

SHA = "a" * 40


def _blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data, usedforsecurity=False).hexdigest()


class LocalTree:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.by_sha = {_blob_sha(data): data for data in files.values()}

    def list_blobs_ex(self, slug: str, commit_sha: str) -> tuple[tuple[BlobEntry, ...], bool]:
        return self.list_blobs(slug, commit_sha), False

    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        return tuple(
            BlobEntry(path, _blob_sha(data), len(data))
            for path, data in sorted(self.files.items())
        )

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        return self.by_sha[blob_sha]

    def read_blob_stream(self, slug: str, blob_sha: str):
        yield self.read_blob(slug, blob_sha)


def _corpus(root: Path, files: dict[str, bytes]) -> ShelfRef:
    target = root / "repos/github.com/example/demo" / SHA
    target.mkdir(parents=True)
    for relative, data in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    tree_hash, scope = compute_materialized_tree_hash(target)
    manifest = {
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "fetched_at": "2026-01-01T00:00:00Z",
        "host": "github.com",
        "materialized_tree_hash": tree_hash,
        "materialized_tree_hash_algorithm": TREE_HASH_ALGORITHM,
        "materialized_tree_hash_scope": scope,
        "owner": "example",
        "parity": "exact",
        "repo": "demo",
        "repo_url": "https://github.com/example/demo",
        "source": "git-commit",
        "spec": f"example/demo@{SHA}",
        "verified": False,
    }
    (target / "leitir-manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    write_sources(
        root,
        [
            {
                "commit_sha": SHA,
                "fetched_at": "2026-01-01T00:00:00Z",
                "host": "github.com",
                "name": "example/demo",
                "owner": "example",
                "path": f"repos/github.com/example/demo/{SHA}",
                "repo": "demo",
            }
        ],
    )
    return ShelfRef("github.com", "example", "demo", SHA)


def _spec(value: str = "needle", kind: PredicateKind = PredicateKind.EXACT_TEXT) -> SearchSpec:
    return SearchSpec(
        SearchMode.SCOPED_EXHAUSTIVE,
        must=(Predicate(kind, value),),
        scopes=(RepoScope("example/demo", SHA),),
    )


def _searchers(root: Path, files: dict[str, bytes], *, require: bool = False, limit: int = 1000):
    adapters = build_adapters()
    scoped = ScopedSearcher(LocalTree(files), adapters)
    indexed = IndexedSearcher(root, scoped, adapters, require_index=require, fallback_file_limit=limit)
    return scoped, indexed


def test_cli_indexed_search_has_exhaustive_recall_and_order(tmp_path, monkeypatch, capsys):
    files = {"z.py": b"needle = 1\n", "a.py": b"# needle\n", "skip.txt": b"needle\n"}
    _corpus(tmp_path, files)
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")

    assert main(["index", "--root", str(tmp_path)]) == ExitCode.SUCCESS
    capsys.readouterr()
    code = main(
        ["search", "--repo", "example/demo", "--commit", SHA, "--must", "exact_text:needle", "--index", "--root", str(tmp_path)],
        tree_source_factory=lambda _token: LocalTree(files),
    )
    output = json.loads(capsys.readouterr().out)

    assert code == ExitCode.SUCCESS
    assert output["coverage"]["status"] == "complete_for_declared_universe"
    assert [match["source"]["path"] for match in output["matches"]] == ["a.py", "z.py"]


def test_indexed_and_exhaustive_reports_have_identical_source_identities(tmp_path):
    files = {"z.py": b"needle = 1\n", "a.py": b"# needle\n", "other.rs": b"fn other() {}\n"}
    shelf = _corpus(tmp_path, files)
    build_shelf_index(tmp_path, shelf)
    scoped, indexed = _searchers(tmp_path, files)

    exhaustive = scoped.search(_spec())
    report = indexed.search(_spec())

    identity = lambda match: tuple(match.source.to_dict().items())
    assert tuple(map(identity, report.matches)) == tuple(map(identity, exhaustive.matches))
    assert report.coverage.files_eligible == exhaustive.coverage.files_eligible
    assert report.coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE


@pytest.mark.parametrize("tamper", ["index", "manifest-schema", "source", "source-manifest", "symlink"])
def test_tampered_index_shelf_is_partial_or_required_index_rejects(tmp_path, tamper):
    files = {"a.py": b"needle = 1\n"}
    shelf = _corpus(tmp_path, files)
    path = build_shelf_index(tmp_path, shelf)
    if tamper == "index":
        path.write_bytes(path.read_bytes() + b" ")
    elif tamper == "manifest-schema":
        manifest_path = path.parent / "manifest.json"
        payload = json.loads(manifest_path.read_text())
        payload["schema_version"] = 999
        manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    elif tamper == "source":
        (tmp_path / "repos/github.com/example/demo" / SHA / "a.py").write_bytes(b"changed\n")
    elif tamper == "source-manifest":
        source_manifest = tmp_path / "repos/github.com/example/demo" / SHA / "leitir-manifest.json"
        payload = json.loads(source_manifest.read_text())
        payload["fetched_at"] = "2026-02-02T00:00:00Z"
        source_manifest.write_text(json.dumps(payload), encoding="utf-8")
    else:
        path.unlink()
        path.symlink_to(path.parent / "manifest.json")

    _scoped, indexed = _searchers(tmp_path, files)
    assert indexed.search(_spec()).coverage.status is CoverageStatus.PARTIAL
    _scoped, required = _searchers(tmp_path, files, require=True)
    with pytest.raises(VerificationError):
        required.search(_spec())


@pytest.mark.parametrize(
    ("field", "value"),
    [("source", "registry-artifact"), ("parity", "drift"), ("parity", "unknown"), ("materialized_tree_hash_scope", "sampled")],
)
def test_ineligible_shelf_cannot_build(tmp_path, field, value):
    shelf = _corpus(tmp_path, {"a.py": b"needle\n"})
    manifest_path = tmp_path / "repos/github.com/example/demo" / SHA / "leitir-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest[field] = value
    if field == "source":
        manifest["fetch_method"] = "registry-artifact"
        manifest["verified"] = True
        manifest["verified_at"] = "2026-01-01T00:00:00Z"
        manifest["artifact_kind"] = "sdist"
        manifest["artifact_checksum"] = "sha256:abc"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(VerificationError):
        build_shelf_index(tmp_path, shelf)


@pytest.mark.parametrize("field", ["source", "parity", "materialized_tree_hash_scope"])
def test_missing_eligibility_field_cannot_build(tmp_path, field):
    shelf = _corpus(tmp_path, {"a.py": b"needle\n"})
    manifest_path = tmp_path / "repos/github.com/example/demo" / SHA / "leitir-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    del manifest[field]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(VerificationError):
        build_shelf_index(tmp_path, shelf)


def test_malformed_source_manifest_cannot_build(tmp_path):
    shelf = _corpus(tmp_path, {"a.py": b"needle\n"})
    manifest_path = tmp_path / "repos/github.com/example/demo" / SHA / "leitir-manifest.json"
    manifest_path.write_text("{", encoding="utf-8")

    with pytest.raises(VerificationError):
        build_shelf_index(tmp_path, shelf)


def test_missing_index_is_not_lazily_built_and_fallback_is_partial(tmp_path):
    files = {"a.py": b"needle\n"}
    _corpus(tmp_path, files)
    _scoped, indexed = _searchers(tmp_path, files)

    report = indexed.search(_spec())

    assert report.coverage.status is CoverageStatus.PARTIAL
    assert not (tmp_path / ".search-index").exists()


def test_no_literal_bounded_scan_is_partial_but_exhaustive_fallback_can_complete(tmp_path):
    files = {"a.py": b"one\n", "b.py": b"two\n"}
    shelf = _corpus(tmp_path, files)
    build_shelf_index(tmp_path, shelf)
    _scoped, bounded = _searchers(tmp_path, files, limit=1)
    _scoped, exhaustive = _searchers(tmp_path, files, limit=2)
    spec = _spec("^.*$", PredicateKind.REGEX)

    partial = bounded.search(spec)
    complete = exhaustive.search(spec)

    assert partial.coverage.status is CoverageStatus.PARTIAL
    assert partial.coverage.files_indexed == 1
    assert complete.coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
    assert complete.coverage.files_indexed == complete.coverage.files_eligible == 2
    _scoped, required = _searchers(tmp_path, files, require=True, limit=1)
    with pytest.raises(VerificationError):
        required.search(spec)


def test_regex_literal_extraction_is_sound_for_optional_and_alternation():
    optional = Predicate(PredicateKind.REGEX, "(?:needle)?hay")
    alternation = Predicate(PredicateKind.REGEX, "needle|haystack")

    assert b"needle" not in predicate_literal_runs(optional)
    assert predicate_literal_runs(alternation) == ()


def test_top_level_unknown_schema_is_refused_and_doctor_reports_it(tmp_path):
    files = {"a.py": b"needle\n"}
    shelf = _corpus(tmp_path, files)
    build_shelf_index(tmp_path, shelf)
    catalog_path = tmp_path / ".search-index/manifest.json"
    catalog = json.loads(catalog_path.read_text())
    catalog["schema_version"] = 999
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")

    _scoped, indexed = _searchers(tmp_path, files)

    assert indexed.search(_spec()).coverage.status is CoverageStatus.PARTIAL
    diagnostic = check_search_indexes(tmp_path)
    assert diagnostic.status == "error"
    assert "schema" in diagnostic.summary


def test_doctor_reports_stale_index_bytes(tmp_path):
    shelf = _corpus(tmp_path, {"a.py": b"needle\n"})
    index_path = build_shelf_index(tmp_path, shelf)
    index_path.write_bytes(index_path.read_bytes() + b" ")

    diagnostic = check_search_indexes(tmp_path)

    assert diagnostic.status == "warn"
    assert diagnostic.json_data == {"invalid": 1, "valid": 0}


def test_doctor_reports_index_shelf_omitted_from_catalog(tmp_path):
    shelf = _corpus(tmp_path, {"a.py": b"needle\n"})
    build_shelf_index(tmp_path, shelf)
    catalog_path = tmp_path / ".search-index/manifest.json"
    catalog = json.loads(catalog_path.read_text())
    catalog["shelves"] = []
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")

    diagnostic = check_search_indexes(tmp_path)

    assert diagnostic.status == "warn"
    assert "missing from top-level" in (diagnostic.detail or "")


def test_explicit_rebuild_repairs_but_search_never_does(tmp_path):
    files = {"a.py": b"needle\n"}
    shelf = _corpus(tmp_path, files)
    index_path = build_shelf_index(tmp_path, shelf)
    index_path.write_bytes(b"{}\n")
    _scoped, indexed = _searchers(tmp_path, files)

    assert indexed.search(_spec()).coverage.status is CoverageStatus.PARTIAL
    assert index_path.read_bytes() == b"{}\n"
    build_shelf_index(tmp_path, shelf)
    assert indexed.search(_spec()).coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE


def test_snapshot_export_excludes_index_and_gc_preserves_it(tmp_path):
    from leitir.cli import _gc_abandoned_staging
    from leitir.snapshot import export_corpus

    shelf = _corpus(tmp_path, {"a.py": b"needle\n"})
    index_path = build_shelf_index(tmp_path, shelf)
    lock, archive = export_corpus(tmp_path.parent / f"{tmp_path.name}.lock", root=tmp_path)

    with tarfile.open(archive, "r:gz") as bundle:
        assert all(".search-index" not in name for name in bundle.getnames())
    assert _gc_abandoned_staging(tmp_path) == 0
    assert index_path.exists()
    lock.unlink()
    archive.unlink()


def test_repeated_builds_publish_byte_identical_artifacts(tmp_path):
    shelf = _corpus(tmp_path, {"b.py": b"needle two\n", "a.py": b"needle one\n"})
    build_shelf_index(tmp_path, shelf)
    index_root = tmp_path / ".search-index"
    first = {
        path.relative_to(index_root).as_posix(): path.read_bytes()
        for path in sorted(index_root.rglob("*.json"))
    }

    build_shelf_index(tmp_path, shelf)
    second = {
        path.relative_to(index_root).as_posix(): path.read_bytes()
        for path in sorted(index_root.rglob("*.json"))
    }

    assert second == first


def test_index_root_symlink_path_escape_is_rejected(tmp_path):
    shelf = _corpus(tmp_path, {"a.py": b"needle\n"})
    outside = tmp_path.parent / f"{tmp_path.name}-outside-index"
    outside.mkdir()
    (tmp_path / ".search-index").symlink_to(outside, target_is_directory=True)

    with pytest.raises(VerificationError, match="symbolic link"):
        build_shelf_index(tmp_path, shelf)

    assert list(outside.iterdir()) == []
    (tmp_path / ".search-index").unlink()
    outside.rmdir()


def test_candidate_verification_retains_target_lock_against_writer(tmp_path):
    from leitir.adapters import PythonAdapter
    from leitir.materialize import _target_lock

    files = {"a.py": b"needle\n"}
    shelf = _corpus(tmp_path, files)
    build_shelf_index(tmp_path, shelf)
    target = tmp_path / "repos/github.com/example/demo" / SHA
    scoring = threading.Event()
    release = threading.Event()
    writer_acquired = threading.Event()

    class BlockingPythonAdapter(PythonAdapter):
        def find_matches_ex(self, content, predicates, *, whole_file=False):
            scoring.set()
            assert release.wait(timeout=2)
            return super().find_matches_ex(content, predicates, whole_file=whole_file)

    adapters = (BlockingPythonAdapter(),)
    indexed = IndexedSearcher(tmp_path, ScopedSearcher(LocalTree(files), adapters), adapters)
    reports = []
    reader = threading.Thread(target=lambda: reports.append(indexed.search(_spec())))
    reader.start()
    assert scoring.wait(timeout=2)

    def write_after_lock():
        with _target_lock(tmp_path, target, SHA):
            writer_acquired.set()

    writer = threading.Thread(target=write_after_lock)
    writer.start()
    assert not writer_acquired.wait(timeout=0.05)
    release.set()
    reader.join(timeout=2)
    writer.join(timeout=2)

    assert writer_acquired.is_set()
    assert reports[0].coverage.status is CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE
