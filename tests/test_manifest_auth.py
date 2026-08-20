"""ADR-0018 detached manifest-authentication vectors and boundary tests."""

from __future__ import annotations

import base64
import builtins
import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.cli import ExitCode, main
from leitir.manifest_auth import (
    AUTH_RECORD_NAME,
    ManifestAuthBadSignatureError,
    ManifestAuthExtraMissingError,
    ManifestAuthKeysInShelfError,
    ManifestAuthMalformedError,
    ManifestAuthNoKeysError,
    ManifestAuthPlatformCapabilityError,
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
from leitir.safeio import NoFollowUnavailableError
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

    # A platform lacking O_NOFOLLOW is a capability gap, not tamper evidence
    # (issue #204 C-2/AC-4): the typed capability error must be distinct from
    # the malformed/tamper classification and must name the platform gap.
    with pytest.raises(ManifestAuthPlatformCapabilityError, match="O_NOFOLLOW") as caught:
        load_trusted_keys(keys)
    assert caught.value.code == "manifest_auth_platform_capability_v1"
    assert not isinstance(caught.value, ManifestAuthMalformedError)


def _provider_seam(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install the fake Ed25519 provider used by the seam test (no extra)."""

    class FakeInvalidSignature(Exception):
        pass

    class FakePublicKey:
        @classmethod
        def from_public_bytes(cls, value: bytes) -> FakePublicKey:
            return cls()

        def verify(self, signature: bytes, canonical: bytes) -> None:
            raise FakeInvalidSignature()

        def public_bytes(self, *, encoding: object, format: object) -> bytes:
            return bytes(range(32))

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

    monkeypatch.setattr(
        "leitir.manifest_auth._provider",
        lambda: (FakePrivateKey, FakePublicKey, FakeInvalidSignature, FakeSerialization),
    )


def _patched_record_read(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    def _unavailable(path: Path, *, maximum_bytes: int, no_follow: bool = True) -> bytes:
        raise exc

    monkeypatch.setattr("leitir.manifest_auth.read_regular_file", _unavailable)


def test_record_reads_on_a_no_follow_platform_are_capability_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _provider_seam(monkeypatch)
    _patched_record_read(
        monkeypatch, NoFollowUnavailableError("platform does not support O_NOFOLLOW")
    )
    vectors = _vectors()
    manifest = vectors["manifest"]
    record = vectors["valid"]
    assert isinstance(manifest, dict) and isinstance(record, dict)
    trusted = {str(vectors["key_id"]): bytes(range(32))}
    shelf = tmp_path / "shelf"
    shelf.mkdir()

    with pytest.raises(ManifestAuthPlatformCapabilityError, match="O_NOFOLLOW") as caught:
        require_manifest_auth(manifest, shelf, trusted_keys=trusted)
    assert caught.value.code == "manifest_auth_platform_capability_v1"
    assert not isinstance(caught.value, ManifestAuthMalformedError)

    detached = tmp_path / "detached.json"
    with pytest.raises(ManifestAuthPlatformCapabilityError, match="O_NOFOLLOW"):
        require_detached_projection_auth(record["projection"], detached, trusted_keys=trusted)  # type: ignore[arg-type]


def test_genuine_read_failures_remain_malformed_not_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SP-4: real integrity-relevant read failures keep the existing
    # malformed classification; only the O_NOFOLLOW capability gap is distinct.
    keys = tmp_path / "trusted-keys.json"
    keys.write_text('{"keys": []}', encoding="utf-8")
    _patched_record_read(monkeypatch, OSError("not a regular file"))
    with pytest.raises(ManifestAuthMalformedError) as caught:
        load_trusted_keys(keys)
    assert not isinstance(caught.value, ManifestAuthPlatformCapabilityError)

    _patched_record_read(monkeypatch, UnicodeError("undecodable"))
    with pytest.raises(ManifestAuthMalformedError):
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
