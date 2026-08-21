"""ADR-0018 detached manifest-authentication vectors and boundary tests."""

from __future__ import annotations

import base64
import builtins
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from leitir.cli import ExitCode, main
from leitir.manifest_auth import (
    AUTH_RECORD_NAME,
    TRUSTED_KEYS_SCHEMA_VERSION,
    ManifestAuthBadSignatureError,
    ManifestAuthExtraMissingError,
    ManifestAuthKeyExpiredError,
    ManifestAuthKeyRevokedError,
    ManifestAuthKeysInShelfError,
    ManifestAuthMalformedError,
    ManifestAuthNoKeysError,
    ManifestAuthProjectionMismatchError,
    ManifestAuthUnknownKeyError,
    canonical_json,
    derive_projection,
    load_trusted_keys,
    require_detached_projection_auth,
    require_manifest_auth,
    sign_projection,
)
from leitir.materialize import manifest_digest_fields, target_path
from leitir.treehash import compute_materialized_tree_hash

_FIXTURES = Path(__file__).parent / "fixtures" / "manifest_auth"
_HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None
_HAS_NO_FOLLOW = hasattr(os, "O_NOFOLLOW")


def _vectors() -> dict[str, object]:
    return json.loads((_FIXTURES / "vectors.json").read_text(encoding="utf-8"))


def _sidecar_path(shelf: Path) -> Path:
    return shelf.parent / f"{shelf.name}.{AUTH_RECORD_NAME}"


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY or not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require cryptography and O_NOFOLLOW")
def test_committed_vectors_cover_valid_tampered_wrong_key_and_malformed(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from leitir.manifest_auth import sign_projection

    vectors = _vectors()
    manifest = vectors["manifest"]
    assert isinstance(manifest, dict)
    assert sign_projection(derive_projection(manifest), Ed25519PrivateKey.from_private_bytes(bytes(range(32)))) == vectors["valid"]
    public_key = base64.b64decode(str(vectors["public_key_b64"]), validate=True)
    trusted_keys = {str(vectors["key_id"]): public_key}
    shelf = tmp_path / "shelf"
    shelf.mkdir()

    _sidecar_path(shelf).write_bytes(canonical_json(vectors["valid"]))
    require_manifest_auth(manifest, shelf, trusted_keys=trusted_keys)

    _sidecar_path(shelf).write_bytes(canonical_json(vectors["tampered_projection"]))
    with pytest.raises(ManifestAuthProjectionMismatchError):
        require_manifest_auth(manifest, shelf, trusted_keys=trusted_keys)

    _sidecar_path(shelf).write_bytes(canonical_json(vectors["wrong_key"]))
    with pytest.raises(ManifestAuthUnknownKeyError):
        require_manifest_auth(manifest, shelf, trusted_keys=trusted_keys)

    _sidecar_path(shelf).write_text(str(vectors["malformed"]), encoding="utf-8")
    with pytest.raises(Exception, match="duplicate JSON key"):
        require_manifest_auth(manifest, shelf, trusted_keys=trusted_keys)


def test_projection_is_closed_and_excludes_volatile_observations() -> None:
    manifest = _vectors()["manifest"]
    assert isinstance(manifest, dict)
    projection = derive_projection(manifest)
    changed = dict(manifest, fetched_at="later", verified_at="later", trust={"score": 99})
    assert derive_projection(changed) == projection
    assert set(projection) == {
        "host",
        "owner",
        "repo",
        "commit_sha",
        "source",
        "materialized_tree_hash_algorithm",
        "materialized_tree_hash",
        "materialized_tree_hash_scope",
    }
    assert canonical_json(projection) == canonical_json(dict(reversed(list(projection.items()))))


def test_trusted_keys_inside_authenticated_shelf_are_rejected(tmp_path: Path) -> None:
    shelf = tmp_path / "shelf"
    shelf.mkdir()
    keys = shelf / "trusted-keys.json"
    keys.write_text('{"keys":[]}', encoding="utf-8")

    with pytest.raises(ManifestAuthKeysInShelfError) as caught:
        load_trusted_keys(keys, shelf_context=shelf)
    assert caught.value.code == "manifest_auth_keys_in_shelf_v1"


@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_trusted_keys_are_a_no_follow_trust_anchor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys = tmp_path / "trusted-keys.json"
    keys.write_text(
        json.dumps({"keys": [{"key_id": "key", "public_key_b64": base64.b64encode(bytes(range(32))).decode("ascii"), "note": "test"}]}),
        encoding="utf-8",
    )
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)

    with pytest.raises(ManifestAuthMalformedError, match="cannot read trusted keys"):
        load_trusted_keys(keys)


@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_load_trusted_keys_accepts_the_closed_valid_schema(tmp_path: Path) -> None:
    keys = tmp_path / "trusted-keys.json"
    public_key = bytes(range(32))
    keys.write_text(
        json.dumps({"keys": [{"key_id": "key", "public_key_b64": base64.b64encode(public_key).decode("ascii"), "note": "test"}]}),
        encoding="utf-8",
    )

    assert load_trusted_keys(keys) == {"key": public_key}


@pytest.mark.parametrize(
    "payload",
    [
        {"keys": []},
        {"keys": [{"key_id": "key", "public_key_b64": "not base64", "note": "test"}]},
        {"keys": [{"key_id": "key", "public_key_b64": base64.b64encode(b"too short").decode("ascii"), "note": "test"}]},
        {"keys": [{"key_id": "key", "public_key_b64": base64.b64encode(bytes(range(32))).decode("ascii"), "note": "test"}, {"key_id": "key", "public_key_b64": base64.b64encode(bytes(range(32))).decode("ascii"), "note": "duplicate"}]},
    ],
)
@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_load_trusted_keys_rejects_empty_or_malformed_closed_schema(tmp_path: Path, payload: object) -> None:
    keys = tmp_path / "trusted-keys.json"
    keys.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises((ManifestAuthNoKeysError, ManifestAuthMalformedError)):
        load_trusted_keys(keys)


@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_authorization_records_validate_with_the_provider_seam(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeInvalidSignature(Exception):
        pass

    class FakePublicKey:
        @classmethod
        def from_public_bytes(cls, value: bytes) -> FakePublicKey:
            assert len(value) == 32
            return cls()

        def verify(self, signature: bytes, canonical: bytes) -> None:
            assert len(signature) == 64
            assert canonical.endswith(b"\n")
            if signature == b"x" * 64:
                raise FakeInvalidSignature()

        def public_bytes(self, *, encoding: object, format: object) -> bytes:
            return bytes(range(32))

    class FakePrivateKey:
        def public_key(self) -> FakePublicKey:
            return FakePublicKey()

        def sign(self, canonical: bytes) -> bytes:
            assert canonical.endswith(b"\n")
            return b"s" * 64

    class FakeSerialization:
        class Encoding:
            Raw = object()

        class PublicFormat:
            Raw = object()

    monkeypatch.setattr("leitir.manifest_auth._provider", lambda: (FakePrivateKey, FakePublicKey, FakeInvalidSignature, FakeSerialization))
    vectors = _vectors()
    manifest = vectors["manifest"]
    record = vectors["valid"]
    assert isinstance(manifest, dict) and isinstance(record, dict)
    public_key = base64.b64decode(str(vectors["public_key_b64"]), validate=True)
    trusted = {str(vectors["key_id"]): public_key}
    shelf = tmp_path / "shelf"
    shelf.mkdir()
    _sidecar_path(shelf).write_bytes(canonical_json(record))

    require_manifest_auth(manifest, shelf, trusted_keys=trusted)
    detached = tmp_path / "detached.json"
    detached.write_bytes(canonical_json(record))
    require_detached_projection_auth(record["projection"], detached, trusted_keys=trusted)  # type: ignore[arg-type]
    assert sign_projection(record["projection"], FakePrivateKey())["signature"] == base64.b64encode(b"s" * 64).decode("ascii")  # type: ignore[arg-type]

    bad_signature = dict(record, signature=base64.b64encode(b"x" * 64).decode("ascii"))
    _sidecar_path(shelf).write_bytes(canonical_json(bad_signature))
    with pytest.raises(ManifestAuthBadSignatureError):
        require_manifest_auth(manifest, shelf, trusted_keys=trusted)
    with pytest.raises(ManifestAuthNoKeysError):
        require_manifest_auth(manifest, shelf, trusted_keys={})


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY or not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require cryptography and O_NOFOLLOW")
def test_no_keys_and_tree_projection_tamper_fail_closed(tmp_path: Path) -> None:
    vectors = _vectors()
    manifest = vectors["manifest"]
    assert isinstance(manifest, dict)
    shelf = tmp_path / "shelf"
    shelf.mkdir()
    _sidecar_path(shelf).write_bytes(canonical_json(vectors["valid"]))
    with pytest.raises(ManifestAuthNoKeysError):
        require_manifest_auth(manifest, shelf, trusted_keys={})

    public_key = base64.b64decode(str(vectors["public_key_b64"]), validate=True)
    changed = dict(manifest, materialized_tree_hash="h1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
    with pytest.raises(ManifestAuthProjectionMismatchError):
        require_manifest_auth(changed, shelf, trusted_keys={str(vectors["key_id"]): public_key})


def test_extra_missing_is_typed_and_module_import_does_not_import_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    environment = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))
    completed = subprocess.run(
        [sys.executable, "-c", "import leitir.manifest_auth, sys; assert not any(name == 'cryptography' or name.startswith('cryptography.') for name in sys.modules)"],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    original_import = builtins.__import__

    def reject_provider(name: str, *args: object, **kwargs: object) -> object:
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("provider intentionally unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_provider)
    from leitir.manifest_auth import _provider

    with pytest.raises(ManifestAuthExtraMissingError):
        _provider()


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY or not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require cryptography and O_NOFOLLOW")
def test_get_require_manifest_auth_accepts_signed_cache_and_rejects_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from leitir.manifest_auth import key_id_for_public_key, sign_projection

    sha = "b" * 40
    root = tmp_path / "corpus"
    shelf = target_path(root, "acme", "widget", sha)
    shelf.mkdir(parents=True)
    (shelf / "proof.txt").write_text("proof\n", encoding="utf-8")
    digest, scope = compute_materialized_tree_hash(shelf)
    manifest: dict[str, object] = {
        "commit_sha": sha,
        "fetch_method": "codeload-tarball",
        "fetched_at": "2026-08-15T00:00:00Z",
        "host": "github.com",
        "owner": "acme",
        "repo": "widget",
        "repo_url": "https://github.com/acme/widget",
        "source": "git-commit",
        "spec": "acme/widget",
        "verified": False,
        "verified_at": None,
    }
    manifest.update(manifest_digest_fields(digest, scope=scope))
    (shelf / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    from leitir.materialize import read_valid_manifest

    assert read_valid_manifest(shelf, "acme", "widget", sha) == manifest
    from leitir.corpus import write_sources

    write_sources(
        root,
        [{"name": "acme/widget", "host": "github.com", "owner": "acme", "repo": "widget", "commit_sha": sha, "path": str(shelf.relative_to(root)), "fetched_at": "2026-08-15T00:00:00Z"}],
    )
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    record = sign_projection(derive_projection(manifest), private_key)
    _sidecar_path(shelf).write_bytes(canonical_json(record))
    trusted_keys = tmp_path / "trusted-keys.json"
    trusted_keys.write_text(json.dumps({"keys": [{"key_id": key_id_for_public_key(public_key), "public_key_b64": base64.b64encode(public_key).decode("ascii"), "note": "fixture"}]}), encoding="utf-8")
    monkeypatch.setattr("leitir.corpus.materialize_source", lambda *_args, **_kwargs: shelf)

    def invoke() -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        result = main(["get", f"acme/widget@{sha}", "--root", str(root), "--require-manifest-auth", "--trusted-keys", str(trusted_keys), "--json"], stdout=out, stderr=err)
        return result, out.getvalue(), err.getvalue()

    code, out, err = invoke()
    assert code == ExitCode.SUCCESS, err
    assert json.loads(out)["results"][0]["path"] == str(shelf)
    tampered = dict(record, signature="B" + str(record["signature"])[1:])
    _sidecar_path(shelf).write_bytes(canonical_json(tampered))
    code, out, err = invoke()
    assert code == ExitCode.CORPUS_FAILURE
    assert out == ""
    assert json.loads(err.splitlines()[-1].removeprefix("leitir: error: "))["error"] == "manifest_auth_bad_signature_v1"


# --- Issue #207: trusted-key lifecycle (expiry + revocation), ADR-0022 ---

_LIFECYCLE_NOW = datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC)


def _fixed_clock(moment: datetime = _LIFECYCLE_NOW):
    def clock() -> datetime:
        return moment

    return clock


def _lifecycle_row(key_id: str, seed: int = 0, **lifecycle: object) -> dict[str, object]:
    row: dict[str, object] = {
        "key_id": key_id,
        "public_key_b64": base64.b64encode(bytes(range(seed, seed + 32))).decode("ascii"),
        "note": f"lifecycle fixture {key_id}",
    }
    row.update(lifecycle)
    return row


def _write_trusted_keys(tmp_path: Path, payload: object, name: str = "trusted-keys.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_v2_schema_loads_and_filters_expired_and_revoked_keys(tmp_path: Path) -> None:
    """AC-2/AC-3 load side: lifecycle keys stay in the file, leave the active mapping, and keep distinct states."""
    keys = _write_trusted_keys(
        tmp_path,
        {
            "schema_version": TRUSTED_KEYS_SCHEMA_VERSION,
            "keys": [
                _lifecycle_row("expired-key", 0, expires_at="2020-01-01T00:00:00Z"),
                _lifecycle_row("revoked-key", 32, revoked_at="2021-06-01T00:00:00Z", revocation_reason="key-compromise"),
                _lifecycle_row("valid-key", 64, expires_at="2030-01-01T00:00:00Z"),
                _lifecycle_row("undated-key", 96),
            ],
        },
    )

    loaded = load_trusted_keys(keys, clock=_fixed_clock())

    assert loaded == {"valid-key": bytes(range(64, 96)), "undated-key": bytes(range(96, 128))}
    assert list(loaded) == sorted(loaded)
    assert loaded.lifecycle_for("expired-key") is not None and loaded.lifecycle_for("expired-key").state == "expired"
    assert loaded.lifecycle_for("revoked-key") is not None and loaded.lifecycle_for("revoked-key").state == "revoked"
    assert loaded.lifecycle_for("valid-key") is not None and loaded.lifecycle_for("valid-key").state == "active"
    assert loaded.lifecycle_for("undated-key") is None


@pytest.mark.parametrize(
    "rows",
    [
        [_lifecycle_row("only-key", 0, expires_at="2020-01-01T00:00:00Z")],
        [_lifecycle_row("only-key", 0, revoked_at="2020-01-01T00:00:00Z", revocation_reason="key-compromise")],
    ],
    ids=["all-expired", "all-revoked"],
)
@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_v2_all_keys_expired_or_revoked_fails_closed(tmp_path: Path, rows: list[dict[str, object]]) -> None:
    """SP-1: a trust root with no active keys fails closed instead of degrading."""
    keys = _write_trusted_keys(tmp_path, {"schema_version": TRUSTED_KEYS_SCHEMA_VERSION, "keys": rows})

    with pytest.raises(ManifestAuthNoKeysError, match="no active trusted keys configured"):
        load_trusted_keys(keys, clock=_fixed_clock())


@pytest.mark.parametrize(
    ("moment", "active"),
    [
        (datetime(2026, 8, 20, 11, 59, 59, tzinfo=UTC), True),
        (datetime(2026, 8, 20, 12, 0, 0, tzinfo=UTC), False),
        (datetime(2026, 8, 20, 12, 0, 1, tzinfo=UTC), False),
    ],
    ids=["one-second-before", "boundary-instant", "one-second-after"],
)
@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_v2_expiry_boundary_is_documented_and_deterministic(tmp_path: Path, moment: datetime, active: bool) -> None:
    """SP-2: validity is strictly ``now < expires_at``; the boundary instant is already expired; injected clock only."""
    keys = _write_trusted_keys(
        tmp_path,
        {"schema_version": TRUSTED_KEYS_SCHEMA_VERSION, "keys": [_lifecycle_row("boundary-key", 0, expires_at="2026-08-20T12:00:00Z")]},
    )

    if active:
        assert set(load_trusted_keys(keys, clock=_fixed_clock(moment))) == {"boundary-key"}
    else:
        with pytest.raises(ManifestAuthNoKeysError):
            load_trusted_keys(keys, clock=_fixed_clock(moment))


@pytest.mark.parametrize(
    "row",
    [
        dict(_lifecycle_row("bad", 0), expires_at="2026-08-01 00:00:00Z"),
        dict(_lifecycle_row("bad", 0), expires_at="2026-08-01T00:00:00+02:00"),
        dict(_lifecycle_row("bad", 0), expires_at="1750000000"),
        dict(_lifecycle_row("bad", 0), expires_at=1750000000),
        dict(_lifecycle_row("bad", 0), expires_at="2026-02-30T00:00:00Z"),
        dict(_lifecycle_row("bad", 0), expires_at="2026-08-01T25:00:00Z"),
        dict(_lifecycle_row("bad", 0), expires_at="2026-08-01T00:00:00"),
        dict(_lifecycle_row("bad", 0), expires_at=""),
        dict(_lifecycle_row("bad", 0), expires_at=None),
        dict(_lifecycle_row("bad", 0), revoked_at="2020-01-01T00:00:00Z"),
        dict(_lifecycle_row("bad", 0), revocation_reason="key-compromise"),
        dict(_lifecycle_row("bad", 0), revoked_at="2020-01-01T00:00:00Z", revocation_reason=""),
        dict(_lifecycle_row("bad", 0), revoked_at="2020-01-01T00:00:00Z", revocation_reason="ok", created_at="2020-01-01T00:00:00Z"),
    ],
    ids=[
        "space-separator",
        "non-utc-offset",
        "epoch-string",
        "epoch-integer",
        "impossible-date",
        "impossible-hour",
        "missing-zulu",
        "empty-timestamp",
        "null-timestamp",
        "revoked-without-reason",
        "reason-without-revoked",
        "empty-reason",
        "unknown-lifecycle-field",
    ],
)
@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_v2_malformed_lifecycle_fields_fail_closed(tmp_path: Path, row: dict[str, object]) -> None:
    """AC-5/C-5 + SP-4: malformed lifecycle data rejects as typed malformed, never best-effort parses."""
    keys = _write_trusted_keys(tmp_path, {"schema_version": TRUSTED_KEYS_SCHEMA_VERSION, "keys": [row, _lifecycle_row("witness", 32)]})

    with pytest.raises(ManifestAuthMalformedError):
        load_trusted_keys(keys, clock=_fixed_clock())


@pytest.mark.parametrize(
    "declared",
    [3, 1, 0, "2", 2.0, True, None],
    ids=["future-int", "v1-as-int", "zero", "string", "float", "bool", "null"],
)
@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_v2_unknown_schema_version_fails_closed(tmp_path: Path, declared: object) -> None:
    """Unknown schema versions reject: only v1 files (no marker) and integer ``schema_version: 2`` load."""
    keys = _write_trusted_keys(tmp_path, {"schema_version": declared, "keys": [_lifecycle_row("k", 0)]})

    with pytest.raises(ManifestAuthMalformedError, match="schema_version"):
        load_trusted_keys(keys, clock=_fixed_clock())


@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_v1_strictness_is_unchanged_and_mixed_rows_reject(tmp_path: Path) -> None:
    """SP-3: one schema per file — v1 files stay strictly v1; v2 files accept v1-shaped rows."""
    v1_with_lifecycle_field = _write_trusted_keys(tmp_path, {"keys": [dict(_lifecycle_row("k", 0), expires_at="2030-01-01T00:00:00Z")]}, "v1-lifecycle.json")
    with pytest.raises(ManifestAuthMalformedError):
        load_trusted_keys(v1_with_lifecycle_field, clock=_fixed_clock())

    v2_without_lifecycle_fields = _write_trusted_keys(tmp_path, {"schema_version": 2, "keys": [_lifecycle_row("k", 0)]}, "v2-plain.json")
    assert set(load_trusted_keys(v2_without_lifecycle_fields, clock=_fixed_clock())) == {"k"}


@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_v1_files_load_without_reading_the_clock(tmp_path: Path) -> None:
    """C-1 + no hidden wall-clock reads: the v1 path never consults a clock."""

    def forbidden_clock() -> datetime:
        raise AssertionError("v1 loads must not read a clock")

    keys = _write_trusted_keys(tmp_path, {"keys": [_lifecycle_row("k", 0)]})
    assert set(load_trusted_keys(keys, clock=forbidden_clock)) == {"k"}


@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_naive_injected_clock_fails_closed(tmp_path: Path) -> None:
    """A clock returning naive datetimes is an integrity failure, not a silent local-time comparison."""
    keys = _write_trusted_keys(
        tmp_path,
        {"schema_version": TRUSTED_KEYS_SCHEMA_VERSION, "keys": [_lifecycle_row("k", 0, expires_at="2030-01-01T00:00:00Z")]},
    )

    with pytest.raises(ManifestAuthMalformedError, match="timezone-aware"):
        load_trusted_keys(keys, clock=lambda: datetime(2026, 8, 20, 12, 0, 0))


@pytest.mark.skipif(not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require O_NOFOLLOW")
def test_expired_revoked_and_unknown_keys_refuse_with_distinct_typed_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-2/AC-3 verify side: expired, revoked (reason surfaced), and unknown keys are distinct refusals."""
    class FakeInvalidSignature(Exception):
        pass

    class FakePublicKey:
        @classmethod
        def from_public_bytes(cls, value: bytes) -> FakePublicKey:
            assert len(value) == 32
            return cls()

        def verify(self, signature: bytes, canonical: bytes) -> None:
            assert len(signature) == 64 and canonical.endswith(b"\n")

    class FakePrivateKey:
        def public_key(self) -> FakePublicKey:
            return FakePublicKey()

        def sign(self, canonical: bytes) -> bytes:
            return b"s" * 64

    class FakeSerialization:
        class Encoding:
            Raw = object()

        class PublicFormat:
            Raw = object()

    monkeypatch.setattr("leitir.manifest_auth._provider", lambda: (FakePrivateKey, FakePublicKey, FakeInvalidSignature, FakeSerialization))
    keys = _write_trusted_keys(
        tmp_path,
        {
            "schema_version": TRUSTED_KEYS_SCHEMA_VERSION,
            "keys": [
                _lifecycle_row("expired-key", 0, expires_at="2020-01-01T00:00:00Z"),
                _lifecycle_row("revoked-key", 32, revoked_at="2020-01-01T00:00:00Z", revocation_reason="key-compromise"),
                _lifecycle_row("both-key", 128, expires_at="2020-01-01T00:00:00Z", revoked_at="2020-02-01T00:00:00Z", revocation_reason="later-compromise"),
                _lifecycle_row("valid-key", 64),
            ],
        },
    )
    trusted = load_trusted_keys(keys, clock=_fixed_clock())
    vectors = _vectors()
    manifest = vectors["manifest"]
    assert isinstance(manifest, dict)
    shelf = tmp_path / "shelf"
    shelf.mkdir()

    def record_for(key_id: str) -> None:
        _sidecar_path(shelf).write_bytes(canonical_json(dict(vectors["valid"], key_id=key_id)))

    record_for("valid-key")
    require_manifest_auth(manifest, shelf, trusted_keys=trusted)

    record_for("expired-key")
    with pytest.raises(ManifestAuthKeyExpiredError) as expired:
        require_manifest_auth(manifest, shelf, trusted_keys=trusted)
    assert expired.value.code == "manifest_auth_key_expired_v1"
    assert not isinstance(expired.value, (ManifestAuthKeyRevokedError, ManifestAuthUnknownKeyError))

    record_for("revoked-key")
    with pytest.raises(ManifestAuthKeyRevokedError) as revoked:
        require_manifest_auth(manifest, shelf, trusted_keys=trusted)
    assert revoked.value.code == "manifest_auth_key_revoked_v1"
    assert "key-compromise" in str(revoked.value)
    assert not isinstance(revoked.value, (ManifestAuthKeyExpiredError, ManifestAuthUnknownKeyError))

    record_for("both-key")
    with pytest.raises(ManifestAuthKeyRevokedError) as both:
        require_manifest_auth(manifest, shelf, trusted_keys=trusted)
    assert "later-compromise" in str(both.value)
    assert not isinstance(both.value, ManifestAuthKeyExpiredError), "revocation must outrank expiry when both apply"

    record_for("never-configured-key")
    with pytest.raises(ManifestAuthUnknownKeyError):
        require_manifest_auth(manifest, shelf, trusted_keys=trusted)

    detached = tmp_path / "detached.json"
    detached.write_bytes(canonical_json(dict(vectors["valid"], key_id="expired-key")))
    with pytest.raises(ManifestAuthKeyExpiredError):
        require_detached_projection_auth(vectors["valid"]["projection"], detached, trusted_keys=trusted)
    detached.write_bytes(canonical_json(dict(vectors["valid"], key_id="revoked-key")))
    with pytest.raises(ManifestAuthKeyRevokedError):
        require_detached_projection_auth(vectors["valid"]["projection"], detached, trusted_keys=trusted)


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY or not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require cryptography and O_NOFOLLOW")
def test_v2_full_lifecycle_ceremony_with_real_provider(tmp_path: Path) -> None:
    """C-2/C-3/C-4 end to end: sign, expire, revoke, and observe distinct fail-closed refusals."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from leitir.manifest_auth import key_id_for_public_key

    def public_bytes_of(seed: int) -> bytes:
        private = Ed25519PrivateKey.from_private_bytes(bytes(range(seed, seed + 32)))
        return private.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    def row_for(seed: int, **lifecycle: object) -> dict[str, object]:
        return {
            "key_id": key_id_for_public_key(public_bytes_of(seed)),
            "public_key_b64": base64.b64encode(public_bytes_of(seed)).decode("ascii"),
            "note": f"ceremony key {seed}",
            **lifecycle,
        }

    retiring = row_for(0, expires_at="2026-08-20T12:00:00Z")
    current = row_for(32)
    manifest = _vectors()["manifest"]
    assert isinstance(manifest, dict)
    shelf = tmp_path / "shelf"
    shelf.mkdir()
    retiring_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    record = sign_projection(derive_projection(manifest), retiring_key)

    before_expiry = _write_trusted_keys(tmp_path, {"schema_version": 2, "keys": [retiring, current]}, "before.json")
    trusted = load_trusted_keys(before_expiry, clock=_fixed_clock(_LIFECYCLE_NOW - timedelta(seconds=1)))
    _sidecar_path(shelf).write_bytes(canonical_json(record))
    require_manifest_auth(manifest, shelf, trusted_keys=trusted)

    after_expiry = _write_trusted_keys(tmp_path, {"schema_version": 2, "keys": [retiring, current]}, "after.json")
    trusted = load_trusted_keys(after_expiry, clock=_fixed_clock(_LIFECYCLE_NOW))
    assert set(trusted) == {current["key_id"]}
    with pytest.raises(ManifestAuthKeyExpiredError):
        require_manifest_auth(manifest, shelf, trusted_keys=trusted)

    revoked = dict(retiring, revoked_at="2026-08-20T11:00:00Z", revocation_reason="key-compromise")
    del revoked["expires_at"]
    after_revocation = _write_trusted_keys(tmp_path, {"schema_version": 2, "keys": [revoked, current]}, "revoked.json")
    trusted = load_trusted_keys(after_revocation, clock=_fixed_clock(_LIFECYCLE_NOW))
    with pytest.raises(ManifestAuthKeyRevokedError, match="key-compromise"):
        require_manifest_auth(manifest, shelf, trusted_keys=trusted)

    detached = tmp_path / "detached.json"
    detached.write_bytes(canonical_json(record))
    with pytest.raises(ManifestAuthKeyRevokedError):
        require_detached_projection_auth(record["projection"], detached, trusted_keys=trusted)


@pytest.mark.skipif(not _HAS_CRYPTOGRAPHY or not _HAS_NO_FOLLOW, reason="auth trust-anchor reads require cryptography and O_NOFOLLOW")
def test_lifecycle_fixture_files_are_pinned_by_digest(tmp_path: Path) -> None:
    """Contract pin: the four canonical fixture files are regenerated deterministically and pinned by SHA-256."""

    def serialized(payload: object) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from leitir.manifest_auth import key_id_for_public_key

    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    key_id = key_id_for_public_key(public)
    base_row = {"key_id": key_id, "public_key_b64": base64.b64encode(public).decode("ascii"), "note": "pinned fixture"}
    fixtures = {
        "v1": {"keys": [base_row]},
        "v2-valid": {"schema_version": 2, "keys": [dict(base_row, expires_at="2030-01-01T00:00:00Z")]},
        "v2-expired": {"schema_version": 2, "keys": [dict(base_row, expires_at="2020-01-01T00:00:00Z")]},
        "v2-revoked": {"schema_version": 2, "keys": [dict(base_row, revoked_at="2020-01-01T00:00:00Z", revocation_reason="key-compromise")]},
    }
    digests = {name: hashlib.sha256(serialized(payload)).hexdigest() for name, payload in fixtures.items()}
    assert digests == {
        "v1": "0291a9c5168fed666b365fe82c7f88f8404117490c6a02266284bea64c58dbef",
        "v2-valid": "3ea8299cda386de9f2f6821b6163800b92ed125d7e8333a948af1d020954b995",
        "v2-expired": "769fc64ac3a9759e9fb876131486fdb1762d8968dde76c23008949a6b6e5314b",
        "v2-revoked": "f343398c48ddc0c9fc86d741e2ad4eb27adf7bef891db83d3a22553c38b1c4f6",
    }

    for name, payload in fixtures.items():
        path = _write_trusted_keys(tmp_path, payload, f"{name}.json")
        if name == "v2-expired" or name == "v2-revoked":
            with pytest.raises(ManifestAuthNoKeysError):
                load_trusted_keys(path, clock=_fixed_clock())
        else:
            assert set(load_trusted_keys(path, clock=_fixed_clock())) == {key_id}
