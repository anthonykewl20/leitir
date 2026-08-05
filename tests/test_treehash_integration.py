"""Offline integration coverage for load-time materialized-tree integrity."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from leitir.cli import ExitCode, _corpus_list, main
from leitir.corpus import write_sources
from leitir.materialize import (
    MANIFEST_NAME,
    ManifestIntegrityError,
    read_valid_manifest,
    update_manifest,
)
from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields

SHA = "a" * 40


def _shelf(root: Path, *, digest: bool = True) -> tuple[Path, dict[str, object]]:
    relative = f"repos/github.com/acme/demo/{SHA}"
    target = root / relative
    target.mkdir(parents=True)
    (target / "payload.txt").write_bytes(b"trusted\n")
    manifest: dict[str, object] = {
        "spec": f"acme/demo@{SHA}",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "repo_url": "https://github.com/acme/demo",
        "fetched_at": "2026-08-05T00:00:00Z",
        "verified": True,
        "verified_at": "2026-08-05T00:00:00Z",
    }
    if digest:
        value, scope = compute_materialized_tree_hash(target)
        manifest.update(manifest_digest_fields(value, scope=scope))
    (target / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    entry = {
        "name": "demo",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
        "path": relative,
        "fetched_at": "2026-08-05T00:00:00Z",
    }
    write_sources(root, [entry])
    return target, manifest


def _read(target: Path):
    return read_valid_manifest(target, "acme", "demo", SHA)


def test_load_time_hash_accepts_restored_tree_and_rejects_tampering(tmp_path):
    target, manifest = _shelf(tmp_path)
    assert _read(target) == manifest

    (target / "payload.txt").write_bytes(b"Trusted\n")
    assert _read(target) is None

    (target / "payload.txt").write_bytes(b"trusted\n")
    assert _read(target) == manifest


def test_existing_full_digest_without_scope_loads(tmp_path):
    target, manifest = _shelf(tmp_path)
    del manifest["materialized_tree_hash_scope"]
    (target / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    assert _read(target) == manifest


def test_update_manifest_tamper_is_atomic_and_typed(tmp_path):
    target, manifest = _shelf(tmp_path)
    original_bytes = (target / MANIFEST_NAME).read_bytes()
    (target / "payload.txt").write_bytes(b"tampered\n")

    with pytest.raises(ManifestIntegrityError):
        update_manifest(target, {"new_field": "must-not-persist"})

    assert (target / MANIFEST_NAME).read_bytes() == original_bytes
    assert json.loads(original_bytes) == manifest


def test_verified_legacy_shelf_is_rejected(tmp_path):
    target, _manifest = _shelf(tmp_path, digest=False)
    assert _read(target) is None


def test_update_manifest_backfills_valid_legacy_shelf(tmp_path):
    target, _manifest = _shelf(tmp_path, digest=False)

    updated = update_manifest(target, {"trust_score": 80})

    digest, scope = compute_materialized_tree_hash(target)
    assert updated["materialized_tree_hash"] == digest
    assert updated["materialized_tree_hash_scope"] == scope
    assert updated["materialized_tree_hash_algorithm"] == "dirhash-h1-sha256-v1"
    assert _read(target) == updated


def test_update_manifest_does_not_backfill_unverified_legacy_shelf(tmp_path):
    target, manifest = _shelf(tmp_path, digest=False)
    manifest["verified"] = False
    manifest["verified_at"] = None
    (target / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")

    updated = update_manifest(target, {"trust_score": 80})

    assert "materialized_tree_hash" not in updated
    assert updated["trust_score"] == 80


def test_update_manifest_backfill_is_idempotent(tmp_path, monkeypatch):
    target, _manifest = _shelf(tmp_path, digest=False)
    update_manifest(target, {"trust_score": 80})

    def unexpected_compute(_target):
        raise AssertionError("digest was recomputed")

    monkeypatch.setattr(
        "leitir.materialize.compute_materialized_tree_hash", unexpected_compute
    )
    updated = update_manifest(target, {"trust_score": 90})
    assert updated["trust_score"] == 90


def test_update_manifest_refuses_backfill_for_invalid_legacy_provenance(tmp_path):
    target, manifest = _shelf(tmp_path, digest=False)
    manifest["commit_sha"] = "b" * 40
    (target / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")

    updated = update_manifest(target, {"trust_score": 80})

    assert "materialized_tree_hash" not in updated
    assert updated["trust_score"] == 80


def test_update_manifest_backfills_symlink_bearing_shelf(tmp_path):
    target, _manifest = _shelf(tmp_path, digest=False)
    (target / "payload-link").symlink_to("payload.txt")

    updated = update_manifest(target, {"trust_score": 80})

    digest, scope = compute_materialized_tree_hash(target)
    assert updated["materialized_tree_hash"] == digest
    assert updated["materialized_tree_hash_scope"] == scope


def test_update_manifest_hash_failure_warns_and_preserves_legacy_path(
    tmp_path, monkeypatch
):
    target, _manifest = _shelf(tmp_path, digest=False)
    (target / "unsupported\nname").write_bytes(b"data")
    warnings: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        "leitir.materialize.logger.warning", lambda *args: warnings.append(args)
    )

    updated = update_manifest(target, {"trust_score": 80})

    assert "materialized_tree_hash" not in updated
    assert updated["trust_score"] == 80
    assert warnings and warnings[0][1] == target


def test_corpus_list_json_excludes_tampered_shelf(tmp_path):
    target, _manifest = _shelf(tmp_path)
    (target / "payload.txt").write_bytes(b"tampered\n")
    out = io.StringIO()

    _corpus_list(tmp_path, as_json=True, out=out)

    assert json.loads(out.getvalue()) == []


def test_corpus_list_warns_when_verified_legacy_shelf_is_filtered(tmp_path, capsys):
    target, manifest = _shelf(tmp_path, digest=False)
    (target / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")

    code = main(["list", "--root", str(tmp_path), "--json"])
    captured = capsys.readouterr()

    assert code == ExitCode.SUCCESS
    assert json.loads(captured.out) == []
    assert (
        "1 corpus entries were excluded because they failed manifest validation. "
        "Run `leitir upgrade-cache` to migrate legacy verified shelves, or "
        "inspect with `--json` for per-entry diagnostics."
    ) in captured.err


def test_manifest_algorithm_is_validated_on_load(tmp_path):
    target, manifest = _shelf(tmp_path)
    manifest["materialized_tree_hash_algorithm"] = "future-v2"
    (target / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    assert _read(target) is None
