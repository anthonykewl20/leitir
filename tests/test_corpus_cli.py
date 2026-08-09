"""Unit coverage for the M2 corpus CLI boundary."""

from __future__ import annotations

import io
import hashlib
import json
import threading
from contextlib import contextmanager

import pytest

from leitir.cli import ExitCode, _ensure_local_gitignore, main, parse_corpus_spec
from leitir.corpus import record_trust, write_sources
from leitir.search import RepoScope
from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields

SHA = "a" * 40


@pytest.mark.parametrize(
    ("raw", "ecosystem", "name", "version", "kind"),
    [
        ("owner/repo", None, "owner/repo", None, "head"),
        ("owner/repo@v1", None, "owner/repo", None, "tag"),
        (f"owner/repo@{SHA}", None, "owner/repo", None, "sha"),
        ("owner/repo#main", None, "owner/repo", None, "branch"),
        ("pypi:requests@2.0", "pypi", "requests", "2.0", None),
        ("pypi:requests", "pypi", "requests", None, None),
        ("crates:serde@1.0", "crates", "serde", "1.0", None),
        ("crates:serde", "crates", "serde", None, None),
        (
            "go:github.com/acme/demo@v1.0.0",
            "go",
            "github.com/acme/demo",
            "v1.0.0",
            None,
        ),
        ("go:github.com/acme/demo", "go", "github.com/acme/demo", None, None),
    ],
)
def test_parse_m2_specs(raw, ecosystem, name, version, kind):
    parsed = parse_corpus_spec(raw)
    assert (parsed.ecosystem, parsed.name, parsed.version, parsed.ref_kind) == (
        ecosystem,
        name,
        version,
        kind,
    )


@pytest.mark.parametrize(
    "raw", ["https://github.com.attacker.example/o/r", "o/r#", "pypi:"]
)
def test_unknown_specs_name_supported_forms(raw):
    with pytest.raises(ValueError, match="supported forms"):
        parse_corpus_spec(raw)


def test_gitignore_append_is_idempotent_and_preserves_rules(tmp_path):
    ignore = tmp_path / ".gitignore"
    ignore.write_text("dist/\n# keep this\n", encoding="utf-8")
    assert "appended" in _ensure_local_gitignore(tmp_path)
    first = ignore.read_text(encoding="utf-8")
    assert first == "dist/\n# keep this\n.leitir-refs/\n"
    assert "already covers" in _ensure_local_gitignore(tmp_path)
    assert ignore.read_text(encoding="utf-8") == first


def test_gitignore_is_created_when_missing(tmp_path):
    assert "created" in _ensure_local_gitignore(tmp_path)
    assert (tmp_path / ".gitignore").read_text(encoding="utf-8") == ".leitir-refs/\n"


def _fabricate(root):
    relative = f"repos/github.com/acme/demo/{SHA}"
    source = root / relative
    source.mkdir(parents=True)
    digest, scope = compute_materialized_tree_hash(source)
    (source / "leitir-manifest.json").write_text(
        json.dumps(
            {
                "version": "1.2.3",
                "host": "github.com",
                "owner": "acme",
                "repo": "demo",
                "commit_sha": SHA,
                "fetch_method": "codeload-tarball",
                "spec": f"acme/demo@{SHA}",
                "repo_url": "https://github.com/acme/demo",
                "fetched_at": "2026-08-03T00:00:00Z",
                "verified": False,
                "verified_at": None,
                **manifest_digest_fields(digest, scope=scope),
            }
        ),
        encoding="utf-8",
    )
    entry = {
        "name": "demo",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
        "path": relative,
        "fetched_at": "2026-08-03T00:00:00Z",
    }
    write_sources(root, [entry])
    return source, entry


def _write_valid_fake_manifest(target, sha, **fields):
    digest, scope = compute_materialized_tree_hash(target)
    payload = {
        "spec": f"acme/demo@{sha}",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": sha,
        "fetch_method": "codeload-tarball",
        "repo_url": "https://github.com/acme/demo",
        "fetched_at": "2026-08-04T00:00:00Z",
        **manifest_digest_fields(digest, scope=scope),
        **fields,
    }
    if payload.get("verified") in (True, "sampled", "archive-only"):
        payload.setdefault("verified_at", "2026-08-04T00:00:00Z")
    (target / "leitir-manifest.json").write_text(json.dumps(payload), encoding="utf-8")


def test_materialize_source_metadata_update_blocks_racing_publisher(
    tmp_path, monkeypatch
):
    import leitir.corpus

    target = tmp_path / f"repos/github.com/acme/demo/{SHA}"
    target.mkdir(parents=True)
    (target / "payload.txt").write_text("generation", encoding="utf-8")
    _write_valid_fake_manifest(target, SHA, verified=True)
    writer_lock = threading.Lock()
    contender_started = threading.Event()
    contender_acquired = threading.Event()
    threads = []

    @contextmanager
    def process_lock(_root, _target, _sha):
        with writer_lock:
            yield

    def fake_materialize(*_args, **_kwargs):
        return target

    real_update = leitir.corpus.update_manifest

    def checked_update(path, fields):
        assert writer_lock.locked()

        def contender():
            contender_started.set()
            with process_lock(tmp_path, target, SHA):
                contender_acquired.set()

        thread = threading.Thread(target=contender)
        thread.start()
        assert contender_started.wait(timeout=2)
        assert not contender_acquired.wait(timeout=0.05)
        threads.append(thread)
        return real_update(path, fields)

    def checked_upsert(_root, _entry):
        # Pointer regeneration can lock multiple targets and therefore runs
        # only after this target's writer lock is released.
        assert not writer_lock.locked()

    monkeypatch.setattr(leitir.corpus, "_target_lock", process_lock)
    monkeypatch.setattr(leitir.corpus, "materialize_repo", fake_materialize)
    monkeypatch.setattr(leitir.corpus, "update_manifest", checked_update)
    monkeypatch.setattr(leitir.corpus, "_upsert", checked_upsert)

    result = leitir.corpus.materialize_source(
        f"acme/demo@{SHA}", RepoScope("acme/demo", SHA), root=tmp_path
    )

    for thread in threads:
        thread.join(timeout=2)
    assert result == target
    assert contender_acquired.is_set()
    manifest = json.loads((target / "leitir-manifest.json").read_text(encoding="utf-8"))
    assert "entry_points" in manifest


def _fabricate_package(
    root, *, sha=SHA, ecosystem="pypi", name="six", version="1.17.0"
):
    relative = f"repos/github.com/acme/{name}/{sha}"
    source = root / relative
    source.mkdir(parents=True)
    digest, scope = compute_materialized_tree_hash(source)
    (source / "leitir-manifest.json").write_text(
        json.dumps(
            {
                "spec": f"{ecosystem}:{name}",
                "ecosystem": ecosystem,
                "version": version,
                "host": "github.com",
                "owner": "acme",
                "repo": name,
                "commit_sha": sha,
                "fetch_method": "codeload-tarball",
                "repo_url": f"https://github.com/acme/{name}",
                "fetched_at": "2026-08-03T00:00:00Z",
                **manifest_digest_fields(digest, scope=scope),
            }
        ),
        encoding="utf-8",
    )
    entry = {
        "name": name,
        "host": "github.com",
        "owner": "acme",
        "repo": name,
        "commit_sha": sha,
        "path": relative,
        "fetched_at": "2026-08-03T00:00:00Z",
    }
    return source, entry


def _fabricate_repo(root, *, sha=SHA, tag=None):
    relative = f"repos/github.com/owner/repo/{sha}"
    source = root / relative
    source.mkdir(parents=True)
    manifest = {
        "spec": "owner/repo",
        "host": "github.com",
        "owner": "owner",
        "repo": "repo",
        "commit_sha": sha,
        "fetch_method": "codeload-tarball",
        "repo_url": "https://github.com/owner/repo",
        "fetched_at": "2026-08-03T00:00:00Z",
    }
    digest, scope = compute_materialized_tree_hash(source)
    manifest.update(manifest_digest_fields(digest, scope=scope))
    if tag is not None:
        manifest["tag"] = tag
    (source / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    entry = {
        "name": "repo",
        "host": "github.com",
        "owner": "owner",
        "repo": "repo",
        "commit_sha": sha,
        "path": relative,
        "fetched_at": "2026-08-03T00:00:00Z",
    }
    return source, entry


class _TrustResult:
    def as_dict(self):
        return {"trust_score": 100}


@pytest.fixture
def fake_trust(monkeypatch):
    monkeypatch.setattr(
        "leitir.trust.compute_trust", lambda _manifest, _target: _TrustResult()
    )


def test_record_trust_matches_package_version_by_resolved_identity(
    tmp_path, fake_trust
):
    source, entry = _fabricate_package(tmp_path)
    write_sources(tmp_path, [entry])

    matched, _result, target = record_trust("pypi:six@1.17.0", tmp_path)

    assert matched == entry
    assert target == source


def test_record_trust_bare_name_still_matches(tmp_path, fake_trust):
    source, entry = _fabricate_package(tmp_path)
    write_sources(tmp_path, [entry])

    matched, _result, target = record_trust("six", tmp_path)

    assert matched == entry
    assert target == source


def test_record_trust_holds_target_lock_through_compute_and_manifest_update(
    tmp_path, monkeypatch
):
    import leitir.corpus

    _source, entry = _fabricate_package(tmp_path)
    write_sources(tmp_path, [entry])
    active = False

    @contextmanager
    def tracking_lock(_root, _target, _sha):
        nonlocal active
        assert not active
        active = True
        try:
            yield
        finally:
            active = False

    class Result:
        score = 100
        breakdown = []

        @staticmethod
        def as_dict():
            assert active
            return {"trust_score": 100, "trust_breakdown": []}

    monkeypatch.setattr(leitir.corpus, "_target_lock", tracking_lock)
    monkeypatch.setattr(
        "leitir.trust.compute_trust", lambda _manifest, _target: Result()
    )

    record_trust("six", tmp_path)

    assert not active


def test_record_trust_missing_identity_raises(tmp_path, fake_trust):
    _source, entry = _fabricate_package(tmp_path)
    write_sources(tmp_path, [entry])

    with pytest.raises(ValueError, match="source is not materialized"):
        record_trust("pypi:missing@1.0.0", tmp_path)


def test_record_trust_ambiguous_identity_raises(tmp_path, fake_trust):
    _source, first = _fabricate_package(tmp_path)
    _source, second = _fabricate_package(tmp_path, sha="b" * 40, version="2.0.0")
    write_sources(tmp_path, [first, second])

    with pytest.raises(ValueError, match="source spec is ambiguous"):
        record_trust("pypi:six", tmp_path)


@pytest.mark.parametrize("spec", [f"owner/repo@{SHA}", f"github:owner/repo@{SHA}"])
def test_record_trust_matches_repo_commit_sha(tmp_path, fake_trust, spec):
    source, entry = _fabricate_repo(tmp_path)
    write_sources(tmp_path, [entry])

    matched, _result, target = record_trust(spec, tmp_path)

    assert matched == entry
    assert target == source


def test_record_trust_matches_repo_tag(tmp_path, fake_trust):
    source, entry = _fabricate_repo(tmp_path, tag="v1.0")
    write_sources(tmp_path, [entry])

    matched, _result, target = record_trust("owner/repo@v1.0", tmp_path)

    assert matched == entry
    assert target == source


def test_record_trust_missing_repo_raises(tmp_path, fake_trust):
    _source, entry = _fabricate_repo(tmp_path)
    write_sources(tmp_path, [entry])

    with pytest.raises(ValueError, match="source is not materialized"):
        record_trust(f"other/repo@{SHA}", tmp_path)


def _invoke(argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_list_human_and_json(tmp_path, monkeypatch):
    monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
    source, entry = _fabricate(tmp_path)
    code, out, _ = _invoke(["list"])
    assert code == ExitCode.SUCCESS
    assert "demo 1.2.3" in out
    assert f"acme/demo@{SHA}" in out
    assert str(source) in out
    assert "2026-08-03T00:00:00Z" in out
    assert "unverified" in out

    code, out, _ = _invoke(["list", "--json"])
    assert code == ExitCode.SUCCESS
    assert json.loads(out) == [dict(entry, verification="unverified")]


@pytest.mark.parametrize(
    ("verified", "label"),
    [(True, "verified"), ("sampled", "sampled"), (False, "unverified")],
)
def test_list_renders_each_verification_state(tmp_path, monkeypatch, verified, label):
    monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
    source, entry = _fabricate(tmp_path)
    manifest_path = source / "leitir-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update(
        verified=verified,
        verified_at="2026-08-03T00:00:00Z" if verified in (True, "sampled") else None,
    )
    if verified in (True, "sampled"):
        digest, scope = compute_materialized_tree_hash(source)
        manifest.update(manifest_digest_fields(digest, scope=scope))
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    code, out, _ = _invoke(["list"])
    assert code == ExitCode.SUCCESS
    assert label in out
    code, out, _ = _invoke(["list", "--json"])
    assert code == ExitCode.SUCCESS
    assert json.loads(out) == [dict(entry, verification=label)]


def _legacy_upgrade_shelf(root, name, *, verified=True, digest=False):
    target = root / "repos" / "github.com" / "acme" / name / SHA
    target.mkdir(parents=True)
    (target / "payload.txt").write_text(name, encoding="utf-8")
    manifest = {"verified": verified}
    if digest:
        value, scope = compute_materialized_tree_hash(target)
        manifest.update(manifest_digest_fields(value, scope=scope))
    path = target / "leitir-manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return target, path


def test_upgrade_cache_backfills_verified_shelves_and_is_idempotent(tmp_path):
    legacy, legacy_manifest = _legacy_upgrade_shelf(tmp_path, "legacy")
    _existing, existing_manifest = _legacy_upgrade_shelf(
        tmp_path, "existing", digest=True
    )
    _unverified, unverified_manifest = _legacy_upgrade_shelf(
        tmp_path, "unverified", verified=False
    )

    code, out, err = _invoke(["upgrade-cache", "--root", str(tmp_path)])

    assert code == ExitCode.SUCCESS
    assert (
        out
        == "Upgraded 1 shelves, skipped 1 (already had digest), failed 0 (see warnings)\n"
    )
    assert err == ""
    upgraded = json.loads(legacy_manifest.read_text(encoding="utf-8"))
    digest, scope = compute_materialized_tree_hash(legacy)
    assert upgraded == {
        "verified": True,
        **manifest_digest_fields(digest, scope=scope),
    }
    assert "materialized_tree_hash" not in json.loads(
        unverified_manifest.read_text(encoding="utf-8")
    )

    code, out, _err = _invoke(["upgrade-cache", "--root", str(tmp_path)])
    assert code == ExitCode.SUCCESS
    assert (
        out
        == "Upgraded 0 shelves, skipped 2 (already had digest), failed 0 (see warnings)\n"
    )
    assert existing_manifest.exists()


def test_upgrade_cache_laundered_bytes_documented_semantics(tmp_path):
    target, manifest_path = _legacy_upgrade_shelf(tmp_path, "legacy")
    (target / "payload.txt").write_text("tampered", encoding="utf-8")

    code, _out, _err = _invoke(["upgrade-cache", "--root", str(tmp_path)])

    assert code == ExitCode.SUCCESS
    upgraded = json.loads(manifest_path.read_text(encoding="utf-8"))
    digest, scope = compute_materialized_tree_hash(target)
    assert upgraded["materialized_tree_hash"] == digest
    assert upgraded["materialized_tree_hash_scope"] == scope


def test_upgrade_cache_dry_run_does_not_write(tmp_path):
    _target, manifest_path = _legacy_upgrade_shelf(tmp_path, "legacy")
    original = manifest_path.read_bytes()

    code, out, err = _invoke(["upgrade-cache", "--root", str(tmp_path), "--dry-run"])

    assert code == ExitCode.SUCCESS
    assert (
        out
        == "Upgraded 1 shelves, skipped 0 (already had digest), failed 0 (see warnings)\n"
    )
    assert err == ""
    assert manifest_path.read_bytes() == original


def test_upgrade_cache_hash_failure_is_reported_without_writing(tmp_path, monkeypatch):
    target, manifest_path = _legacy_upgrade_shelf(tmp_path, "legacy")
    try:
        (target / "unsupported\nname").write_bytes(b"data")
    except OSError:
        pytest.skip("filesystem does not allow newline in filename")
    original = manifest_path.read_bytes()
    warnings: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        "leitir.cli.logger.warning", lambda *args: warnings.append(args)
    )

    code, out, _err = _invoke(["upgrade-cache", "--root", str(tmp_path)])

    assert code == ExitCode.CORPUS_FAILURE
    assert (
        out
        == "Upgraded 0 shelves, skipped 0 (already had digest), failed 1 (see warnings)\n"
    )
    assert manifest_path.read_bytes() == original
    assert warnings and warnings[0][1] == target


def test_remove_and_clean_fabricated_corpus(tmp_path, monkeypatch):
    monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
    source, _ = _fabricate(tmp_path)
    code, out, err = _invoke(["remove", f"acme/demo@{SHA}"])
    assert code == ExitCode.SUCCESS
    assert out == ""
    assert "removed" in err
    assert not source.exists()

    _fabricate(tmp_path)
    (tmp_path / "POINTERS.md").write_text("stale", encoding="utf-8")
    code, out, err = _invoke(["clean", "--repos"])
    assert code == ExitCode.SUCCESS
    assert out == ""
    assert not (tmp_path / "repos").exists()
    assert not (tmp_path / "sources.json").exists()
    assert not (tmp_path / "POINTERS.md").exists()


def test_import_requires_and_forwards_trusted_lock_digest(tmp_path, monkeypatch):
    import leitir.snapshot

    lock = tmp_path / "corpus.lock"
    lock.write_bytes(b"trusted lock bytes")
    trusted = hashlib.sha256(lock.read_bytes()).hexdigest()
    seen: dict[str, object] = {}

    def fake_import(path, **options):
        seen.update(path=path, options=options)
        return []

    monkeypatch.setattr(leitir.snapshot, "import_corpus", fake_import)
    destination = tmp_path / "destination"
    code, out, err = _invoke(
        [
            "import",
            str(lock),
            "--root",
            str(destination),
            "--lock-sha256",
            trusted,
        ]
    )

    assert code == ExitCode.SUCCESS, err
    assert seen == {
        "path": str(lock),
        "options": {"root": destination, "expected_lock_sha256": trusted},
    }
    assert json.loads(out)["sources"] == 0


def test_import_without_trusted_lock_digest_is_rejected_as_usage_error(tmp_path):
    from leitir.cli import build_parser

    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["import", str(tmp_path / "corpus.lock")])
    assert exc.value.code == ExitCode.MALFORMED_USAGE


def test_import_rejects_coordinated_lock_tamper_against_trusted_digest(tmp_path):
    from leitir.snapshot import export_corpus

    corpus = tmp_path / "corpus"
    _fabricate(corpus)
    lock, _tarball = export_corpus(tmp_path / "snapshot.lock", root=corpus)
    trusted = hashlib.sha256(lock.read_bytes()).hexdigest()
    payload = json.loads(lock.read_text(encoding="utf-8"))
    payload["sources"][0]["tree_sha"] = "0" * 40
    lock.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    code, out, err = _invoke(
        [
            "import",
            str(lock),
            "--root",
            str(tmp_path / "destination"),
            "--lock-sha256",
            trusted,
        ]
    )

    assert code == ExitCode.CORPUS_FAILURE
    assert out == ""
    assert "lock SHA-256 mismatch" in err
    assert not (tmp_path / "destination").exists()


def test_gc_removes_abandoned_staging_and_backup_under_target_lock(tmp_path):
    parent = tmp_path / "repos" / "github.com" / "acme" / "demo"
    staging = parent / f".{SHA}.tmp-999999-abandoned"
    backup = parent / f".{SHA}.old-abandoned"
    staging.mkdir(parents=True)
    backup.mkdir()
    (parent / SHA).mkdir()
    (staging / "partial").write_bytes(b"partial")

    code, out, err = _invoke(["gc", "--root", str(tmp_path)])

    assert code == ExitCode.SUCCESS, err
    assert json.loads(out) == {"removed": 2, "root": str(tmp_path)}
    assert not staging.exists()
    assert not backup.exists()


def test_gc_restores_sole_valid_backup_when_target_is_absent(tmp_path):
    parent = tmp_path / "repos" / "github.com" / "acme" / "demo"
    backup = parent / f".{SHA}.old-only-valid-copy"
    backup.mkdir(parents=True)
    (backup / "proof").write_bytes(b"valid cache generation")
    _write_valid_fake_manifest(backup, SHA, verified=True)

    code, out, err = _invoke(["gc", "--root", str(tmp_path)])

    assert code == ExitCode.SUCCESS, err
    assert json.loads(out)["removed"] == 0
    assert not backup.exists()
    assert (parent / SHA / "proof").read_bytes() == b"valid cache generation"


def test_gc_removes_staging_then_restores_valid_backup_in_one_run(tmp_path):
    parent = tmp_path / "repos" / "github.com" / "acme" / "demo"
    staging = parent / f".{SHA}.tmp-interrupted"
    backup = parent / f".{SHA}.old-interrupted"
    staging.mkdir(parents=True)
    (staging / "partial").write_bytes(b"partial")
    backup.mkdir()
    (backup / "proof").write_bytes(b"valid cache generation")
    _write_valid_fake_manifest(backup, SHA, verified=True)

    code, out, err = _invoke(["gc", "--root", str(tmp_path)])

    assert code == ExitCode.SUCCESS, err
    assert json.loads(out)["removed"] == 1
    assert not staging.exists() and not backup.exists()
    assert (parent / SHA / "proof").read_bytes() == b"valid cache generation"


def test_gc_does_not_restore_corrupt_sole_backup(tmp_path):
    parent = tmp_path / "repos" / "github.com" / "acme" / "demo"
    backup = parent / f".{SHA}.old-corrupt-copy"
    backup.mkdir(parents=True)
    proof = backup / "proof"
    proof.write_bytes(b"valid cache generation")
    _write_valid_fake_manifest(backup, SHA, verified=True)
    proof.write_bytes(b"tampered")

    code, out, err = _invoke(["gc", "--root", str(tmp_path)])

    assert code == ExitCode.SUCCESS, err
    assert json.loads(out)["removed"] == 0
    assert not (parent / SHA).exists()
    assert proof.read_bytes() == b"tampered"


def test_gc_does_not_sweep_matching_user_directory(tmp_path):
    user_directory = tmp_path / "user-data" / f".{SHA}.tmp-looks-abandoned"
    user_directory.mkdir(parents=True)
    proof = user_directory / "proof"
    proof.write_bytes(b"keep")

    code, out, err = _invoke(["gc", "--root", str(tmp_path)])

    assert code == ExitCode.SUCCESS, err
    assert json.loads(out)["removed"] == 0
    assert proof.read_bytes() == b"keep"


def test_gc_ignores_candidate_removed_while_waiting_for_lock(tmp_path, monkeypatch):
    import contextlib
    import leitir.materialize

    parent = tmp_path / "repos" / "github.com" / "acme" / "demo"
    staging = parent / f".{SHA}.tmp-racing"
    staging.mkdir(parents=True)
    real_lock = leitir.materialize._file_lock

    @contextlib.contextmanager
    def removing_lock(path):
        with real_lock(path):
            staging.rmdir()
            yield

    monkeypatch.setattr(leitir.materialize, "_file_lock", removing_lock)
    code, out, err = _invoke(["gc", "--root", str(tmp_path)])

    assert code == ExitCode.SUCCESS, err
    assert json.loads(out)["removed"] == 0


def test_gc_refuses_matching_symlink_without_deleting_outside_root(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    proof = outside / "proof"
    proof.write_bytes(b"keep")
    parent = tmp_path / "repos" / "github.com" / "acme" / "demo"
    parent.mkdir(parents=True)
    (parent / f".{SHA}.tmp-999999-abandoned").symlink_to(
        outside, target_is_directory=True
    )

    code, out, err = _invoke(["gc", "--root", str(tmp_path)])

    assert code == ExitCode.CORPUS_FAILURE
    assert out == ""
    assert "refusing symbolic-link staging candidate" in err
    assert proof.read_bytes() == b"keep"


def test_gc_refuses_symlink_corpus_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(outside, target_is_directory=True)

    code, out, err = _invoke(["gc", "--root", str(linked_root)])

    assert code == ExitCode.CORPUS_FAILURE
    assert out == ""
    assert "corpus root is a symbolic link" in err


def test_api_holds_target_lock_from_load_time_verify_through_tree_read(
    tmp_path, monkeypatch
):
    import leitir.apisurface
    import leitir.corpus
    import leitir.materialize

    corpus = tmp_path / "corpus"
    source = corpus / f"repos/github.com/acme/demo/{SHA}"
    source.mkdir(parents=True)
    (source / "demo.py").write_text("def public():\n    pass\n", encoding="utf-8")
    entry = {
        "name": "acme/demo",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
        "path": f"repos/github.com/acme/demo/{SHA}",
        "fetched_at": "2026-08-04T00:00:00Z",
    }
    write_sources(corpus, [entry])
    manifest = {
        "version": "1.0.0",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
    }
    held = False

    @contextmanager
    def tracked_lock(root, target, commit_sha):
        nonlocal held
        assert (root, target, commit_sha) == (corpus, source, SHA)
        held = True
        try:
            yield
        finally:
            held = False

    def verified_manifest(*_args, **_kwargs):
        assert held
        return manifest

    def extract(path, _language):
        assert held
        assert (path / "demo.py").read_text(encoding="utf-8").startswith("def public")
        return {"schema_version": 1, "symbols": [], "methods": []}

    monkeypatch.setattr(
        leitir.corpus, "materialize_source", lambda *_args, **_kwargs: source
    )
    monkeypatch.setattr(leitir.materialize, "_target_lock", tracked_lock)
    monkeypatch.setattr(leitir.materialize, "read_valid_manifest", verified_manifest)
    monkeypatch.setattr(leitir.apisurface, "extract_api_surface", extract)

    code, _out, err = _invoke(["api", f"acme/demo@{SHA}", "--root", str(corpus)])

    assert code == ExitCode.SUCCESS, err
    assert held is False


def test_lock_emits_machine_json_and_progress_on_stderr(tmp_path, monkeypatch):
    import leitir.corpus

    project = tmp_path / "project"
    project.mkdir()
    corpus = tmp_path / "corpus"
    seen = {}

    def fake_lock(directory, resolver, **options):
        seen.update(directory=directory, resolver=resolver, options=options)
        options["on_resolve"]("npm:a@1.0.0")
        options["on_fetch"]("npm:a@1.0.0")
        return [{"spec": "npm:a@1.0.0", "path": "/cache/a", "graph": "complete"}]

    resolver = object()
    monkeypatch.setattr(leitir.corpus, "lock_project", fake_lock)
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["lock", "--cwd", str(project), "--root", str(corpus)],
        resolver_factory=lambda _token: resolver,
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.SUCCESS
    assert json.loads(out.getvalue()) == {
        "cwd": str(project),
        "dependencies": [
            {"spec": "npm:a@1.0.0", "path": "/cache/a", "graph": "complete"}
        ],
    }
    assert "resolving npm:a@1.0.0" in err.getvalue()
    assert "materializing npm:a@1.0.0" in err.getvalue()
    assert seen["directory"] == project
    assert seen["resolver"] is resolver


def test_lock_best_effort_emits_failures_and_reports_each_one(tmp_path, monkeypatch):
    import leitir.corpus

    project = tmp_path / "project"
    project.mkdir()

    def fake_lock(directory, resolver, **options):
        options["on_failure"]("npm:z@1.0.0", "unavailable")
        options["failures"].append({"spec": "npm:z@1.0.0", "error": "unavailable"})
        return [{"spec": "npm:a@1.0.0", "path": "/cache/a", "graph": "complete"}]

    monkeypatch.setattr(leitir.corpus, "lock_project", fake_lock)
    out, err = io.StringIO(), io.StringIO()
    code = main(
        [
            "lock",
            "--best-effort",
            "--cwd",
            str(project),
            "--root",
            str(tmp_path / "corpus"),
        ],
        resolver_factory=lambda _token: object(),
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.SUCCESS
    assert json.loads(out.getvalue())["failures"] == [
        {"spec": "npm:z@1.0.0", "error": "unavailable"}
    ]
    assert "leitir: failed npm:z@1.0.0: unavailable" in err.getvalue()


def test_lock_best_effort_returns_failure_when_nothing_materialized(
    tmp_path, monkeypatch
):
    import leitir.corpus

    project = tmp_path / "project"
    project.mkdir()

    def fake_lock(directory, resolver, **options):
        options["on_failure"]("npm:z@1.0.0", "unavailable")
        options["failures"].append({"spec": "npm:z@1.0.0", "error": "unavailable"})
        return []

    monkeypatch.setattr(leitir.corpus, "lock_project", fake_lock)
    out, err = io.StringIO(), io.StringIO()
    code = main(
        [
            "lock",
            "--best-effort",
            "--cwd",
            str(project),
            "--root",
            str(tmp_path / "corpus"),
        ],
        resolver_factory=lambda _token: object(),
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.CORPUS_FAILURE
    assert json.loads(out.getvalue())["dependencies"] == []
    assert json.loads(out.getvalue())["failures"] == [
        {"spec": "npm:z@1.0.0", "error": "unavailable"}
    ]


def test_sbom_emits_machine_json_and_progress_on_stderr(tmp_path, monkeypatch):
    import leitir.sbom

    corpus = tmp_path / "corpus"
    project = tmp_path / "project"
    project.mkdir()
    seen = {}

    def fake_generate(root, directory, format):
        seen.update(root=root, directory=directory, format=format)
        return {"bomFormat": "CycloneDX"}

    monkeypatch.setattr(leitir.sbom, "generate_sbom", fake_generate)
    code, out, err = _invoke(
        ["sbom", "--format", "cyclonedx", "--cwd", str(project), "--root", str(corpus)]
    )
    assert code == ExitCode.SUCCESS
    assert json.loads(out) == {"bomFormat": "CycloneDX"}
    assert "generated cyclonedx SBOM" in err
    assert seen == {"root": corpus, "directory": project, "format": "cyclonedx"}


def test_sbom_holds_all_target_locks_through_generation(tmp_path, monkeypatch):
    import leitir.materialize
    import leitir.sbom

    corpus = tmp_path / "corpus"
    project = tmp_path / "project"
    project.mkdir()
    source, entry = _fabricate(corpus)
    active = set()

    @contextmanager
    def tracking_lock(_root, target, _sha):
        active.add(target)
        try:
            yield
        finally:
            active.remove(target)

    def fake_generate(_root, _directory, _format):
        assert active == {source}
        return {"bomFormat": "CycloneDX"}

    write_sources(corpus, [entry])
    monkeypatch.setattr(leitir.materialize, "_target_lock", tracking_lock)
    monkeypatch.setattr(leitir.sbom, "generate_sbom", fake_generate)

    code, _out, err = _invoke(
        ["sbom", "--format", "cyclonedx", "--cwd", str(project), "--root", str(corpus)]
    )

    assert code == ExitCode.SUCCESS, err
    assert not active


def test_diff_reverifies_and_reads_both_targets_under_ordered_locks(
    tmp_path, monkeypatch
):
    import leitir.cli
    import leitir.corpus
    import leitir.diff
    import leitir.materialize

    corpus = tmp_path / "corpus"
    target = corpus / f"repos/github.com/acme/demo/{SHA}"
    target.mkdir(parents=True)
    (target / "payload.txt").write_text("generation", encoding="utf-8")
    _write_valid_fake_manifest(target, SHA, verified=True)
    active = set()

    @contextmanager
    def tracking_lock(_root, path, _sha):
        active.add(path)
        try:
            yield
        finally:
            active.remove(path)

    class Report:
        @staticmethod
        def to_json():
            return json.dumps({"schema_version": 1})

    def fake_diff(spec_a, spec_b, **options):
        assert active == {target}
        assert options["materializer"](spec_a) == target
        assert options["materializer"](spec_b) == target
        return Report()

    fake_diff.__module__ = "leitir.diff"
    monkeypatch.setattr(
        leitir.cli,
        "_resolve_corpus_spec",
        lambda *_args: (RepoScope("acme/demo", SHA), None, None, None),
    )
    monkeypatch.setattr(
        leitir.corpus, "materialize_source", lambda *_args, **_kwargs: target
    )
    monkeypatch.setattr(leitir.materialize, "_target_lock", tracking_lock)
    monkeypatch.setattr(leitir.diff, "diff_packages", fake_diff)

    code, out, err = _invoke(
        [
            "diff",
            f"acme/demo@{SHA}",
            f"acme/demo@{SHA}",
            "--json",
            "--root",
            str(corpus),
        ]
    )

    assert code == ExitCode.SUCCESS, err
    assert json.loads(out) == {"schema_version": 1}
    assert not active


def test_get_json_emits_materialization_metadata(tmp_path, monkeypatch):
    import leitir.corpus

    corpus = tmp_path / "corpus"
    spec = f"acme/demo@{SHA}"
    other_sha = "b" * 40
    other_spec = f"acme/demo@{other_sha}"

    def fake_materialize(raw, resolved, **options):
        source = corpus / f"repos/github.com/acme/demo/{resolved.commit_sha}"
        source.mkdir(parents=True)
        _write_valid_fake_manifest(
            source,
            resolved.commit_sha,
            source="git-commit",
            verified="sampled",
        )
        return source

    monkeypatch.setattr(leitir.corpus, "materialize_source", fake_materialize)
    code, out, err = _invoke(["get", spec, other_spec, "--root", str(corpus), "--json"])

    assert code == ExitCode.SUCCESS
    assert json.loads(out) == {
        "schema_version": 1,
        "results": [
            {
                "spec": spec,
                "path": str(corpus / f"repos/github.com/acme/demo/{SHA}"),
                "commit_sha": SHA,
                "source": "git-commit",
                "verified": "sampled",
            },
            {
                "spec": other_spec,
                "path": str(corpus / f"repos/github.com/acme/demo/{other_sha}"),
                "commit_sha": other_sha,
                "source": "git-commit",
                "verified": "sampled",
            },
        ],
    }
    assert "resolving" in err


def test_get_case_aliases_dedupe_to_one_target_lock_on_posix(tmp_path, monkeypatch):
    import leitir.corpus
    import leitir.materialize
    from leitir.resolver import MultiResolver

    corpus = tmp_path / "corpus"
    calls = 0
    locks = 0

    def fake_materialize(raw, resolved, **options):
        nonlocal calls
        calls += 1
        source = corpus / f"repos/github.com/ACME/DEMO/{SHA}"
        source.mkdir(parents=True, exist_ok=True)
        _write_valid_fake_manifest(
            source,
            SHA,
            owner="ACME",
            repo="DEMO",
            repo_url="https://github.com/ACME/DEMO",
            source="git-commit",
            verified=True,
        )
        return source

    real_lock = leitir.materialize._target_lock

    @contextmanager
    def counting_lock(root, target, commit_sha):
        nonlocal locks
        locks += 1
        with real_lock(root, target, commit_sha):
            yield

    monkeypatch.setattr(leitir.corpus, "materialize_source", fake_materialize)
    monkeypatch.setattr(leitir.materialize, "_target_lock", counting_lock)
    monkeypatch.setattr(
        MultiResolver,
        "published_at_for_commit",
        lambda self, slug, commit_sha: "2026-08-08T00:00:00Z",
    )

    code, out, err = _invoke(
        [
            "get",
            f"github:ACME/DEMO@{SHA}",
            f"github:acme/demo@{SHA}",
            "--root",
            str(corpus),
            "--json",
        ]
    )

    assert code == ExitCode.SUCCESS, err
    assert len(json.loads(out)["results"]) == 2
    assert calls == 1
    assert locks == 1


def test_api_materializes_extracts_and_prints_cache_path(tmp_path, monkeypatch):
    import leitir.corpus

    corpus = tmp_path / "corpus"

    def fake_materialize(spec, resolved, **options):
        source = corpus / f"repos/github.com/acme/demo/{SHA}"
        source.mkdir(parents=True, exist_ok=True)
        (source / "demo.py").write_text(
            "def public(value: int):\n    pass\n", encoding="utf-8"
        )
        _write_valid_fake_manifest(source, SHA, version="1.0.0")
        write_sources(
            corpus,
            [
                {
                    "name": "acme/demo",
                    "host": "github.com",
                    "owner": "acme",
                    "repo": "demo",
                    "commit_sha": SHA,
                    "path": f"repos/github.com/acme/demo/{SHA}",
                    "fetched_at": "2026-08-04T00:00:00Z",
                }
            ],
        )
        return source

    monkeypatch.setattr(leitir.corpus, "materialize_source", fake_materialize)
    code, out, err = _invoke(["api", f"acme/demo@{SHA}", "--root", str(corpus)])

    expected = corpus / f"api/github.com/acme/demo/1.0.0/index.json"
    assert code == ExitCode.SUCCESS
    assert out.strip().splitlines() == [
        str(expected),
        "function demo.public(value: int)",
    ]
    assert "resolving" in err and "extracting API surface" in err
    payload = json.loads(expected.read_text(encoding="utf-8"))
    assert payload["methods"] == ["ast"]
    assert payload["symbols"][0]["qualified_name"] == "demo.public"

    code, out, _ = _invoke(["api", f"acme/demo@{SHA}", "--root", str(corpus), "--json"])
    summary = json.loads(out)
    assert code == ExitCode.SUCCESS
    assert summary == {
        "schema_version": 1,
        "index_path": str(expected),
        "symbols": 1,
        "by_kind": {"function": 1, "class": 0, "method": 0, "constant": 0},
        "method": "ast",
        "top_symbols": [
            {
                "kind": "function",
                "name": "public",
                "qualified_name": "demo.public",
                "path": "demo.py",
                "line": 1,
                "signature": "(value: int)",
                "docstring": None,
            }
        ],
    }


def test_examples_materializes_ensures_api_and_prints_cache_path(tmp_path, monkeypatch):
    import leitir.corpus

    corpus = tmp_path / "corpus"

    def fake_materialize(spec, resolved, **options):
        source = corpus / f"repos/github.com/acme/demo/{SHA}"
        (source / "examples").mkdir(parents=True, exist_ok=True)
        (source / "demo.py").write_text(
            "def public(value: int):\n    pass\n", encoding="utf-8"
        )
        (source / "examples" / "use.py").write_text("public(1)\n", encoding="utf-8")
        _write_valid_fake_manifest(
            source, SHA, version="1.0.0", entry_points=["examples/"]
        )
        write_sources(
            corpus,
            [
                {
                    "name": "acme/demo",
                    "host": "github.com",
                    "owner": "acme",
                    "repo": "demo",
                    "commit_sha": SHA,
                    "path": f"repos/github.com/acme/demo/{SHA}",
                    "fetched_at": "2026-08-04T00:00:00Z",
                }
            ],
        )
        return source

    monkeypatch.setattr(leitir.corpus, "materialize_source", fake_materialize)
    code, out, err = _invoke(["examples", f"acme/demo@{SHA}", "--root", str(corpus)])

    expected = corpus / "examples/github.com/acme/demo/1.0.0/index.json"
    assert code == ExitCode.SUCCESS
    assert out.strip() == str(expected)
    assert "extracting API surface" in err and "extracting examples" in err
    payload = json.loads(expected.read_text(encoding="utf-8"))
    assert payload["snippets"][0]["path"] == "examples/use.py"
    pointers = (corpus / "POINTERS.md").read_text(encoding="utf-8")
    assert "api/github.com/acme/demo/1.0.0/index.json" in pointers
    assert "examples/github.com/acme/demo/1.0.0/index.json" in pointers

    code, out, _ = _invoke(
        ["examples", f"acme/demo@{SHA}", "--root", str(corpus), "--json"]
    )
    summary = json.loads(out)
    assert code == ExitCode.SUCCESS
    assert summary["schema_version"] == 1
    assert summary["index_path"] == str(expected)
    assert summary["count"] == 1
    assert summary["snippets"][0]["path"] == "examples/use.py"
