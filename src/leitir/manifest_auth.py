"""Optional detached Ed25519 authorization for materialized manifests.

This module deliberately has no cryptography-provider import at module load time.
The default Leitir installation therefore remains stdlib-only; callers that opt
into verification must install the separately hash-locked ``auth`` extra.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from leitir.safeio import read_regular_file

AUTH_SCHEMA_VERSION = "leitir-manifest-auth-v1"
AUTH_RECORD_NAME = "leitir-manifest-auth.json"
TRUSTED_KEYS_DEFAULT = Path("~/.leitir/trusted-keys.json")
_PROJECTION_FIELDS = frozenset({"host", "owner", "repo", "commit_sha", "source", "materialized_tree_hash_algorithm", "materialized_tree_hash", "materialized_tree_hash_scope"})
_RECORD_FIELDS = frozenset({"schema_version", "key_id", "projection", "projection_digest", "algorithm", "signature"})
_KEY_FIELDS = frozenset({"key_id", "public_key_b64", "note"})
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht", "go-module-zip"})
_SOURCES = frozenset({"git-commit", "registry-artifact", "go-module-zip"})
_MAX_AUTH_INPUT_BYTES = 1 << 20


class ManifestAuthError(Exception):
    """Base class for fail-closed manifest-authentication failures."""

    code = "manifest_auth_error_v1"

    def to_json(self) -> str:
        return json.dumps({"error": self.code, "message": str(self)}, sort_keys=True)


class ManifestAuthExtraMissingError(ManifestAuthError):
    code = "manifest_auth_extra_missing_v1"


class ManifestAuthNoKeysError(ManifestAuthError):
    code = "manifest_auth_no_keys_configured_v1"


class ManifestAuthKeysInShelfError(ManifestAuthError):
    code = "manifest_auth_keys_in_shelf_v1"


class ManifestAuthMalformedError(ManifestAuthError):
    code = "manifest_auth_malformed_v1"


class ManifestAuthUnknownKeyError(ManifestAuthError):
    code = "manifest_auth_unknown_key_id_v1"


class ManifestAuthWrongAlgorithmError(ManifestAuthError):
    code = "manifest_auth_wrong_algorithm_v1"


class ManifestAuthProjectionMismatchError(ManifestAuthError):
    code = "manifest_auth_projection_mismatch_v1"


class ManifestAuthBadSignatureError(ManifestAuthError):
    code = "manifest_auth_bad_signature_v1"


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestAuthMalformedError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json(raw: str, *, subject: str) -> object:
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (TypeError, UnicodeError, json.JSONDecodeError, ManifestAuthMalformedError) as exc:
        if isinstance(exc, ManifestAuthMalformedError):
            raise
        raise ManifestAuthMalformedError(f"malformed {subject} JSON") from exc


def canonical_json(value: Mapping[str, object]) -> bytes:
    """Return v1 canonical JSON: sorted, compact UTF-8, and LF terminated."""
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ManifestAuthMalformedError("value cannot be canonically encoded") from exc
    return (encoded + "\n").encode("utf-8")


def _ascii_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise ManifestAuthMalformedError(f"{field} must be non-empty ASCII text")
    return value


def _validate_projection(projection: object) -> dict[str, str]:
    if not isinstance(projection, dict) or set(projection) != _PROJECTION_FIELDS:
        raise ManifestAuthMalformedError("projection must have exactly the v1 fields")
    result = {field: _ascii_text(projection[field], field) for field in sorted(_PROJECTION_FIELDS)}
    if not _SHA1.fullmatch(result["commit_sha"]):
        raise ManifestAuthMalformedError("projection commit_sha is malformed")
    if result["host"] not in _HOSTS:
        raise ManifestAuthMalformedError("projection host is unsupported")
    if result["source"] not in _SOURCES:
        raise ManifestAuthMalformedError("projection source is unsupported")
    if result["materialized_tree_hash_algorithm"] != "dirhash-h1-sha256-v1":
        raise ManifestAuthMalformedError("projection tree-hash algorithm is unsupported")
    if result["materialized_tree_hash_scope"] not in {"full", "sampled"}:
        raise ManifestAuthMalformedError("projection tree-hash scope is unsupported")
    digest = result["materialized_tree_hash"]
    if not digest.startswith("h1:"):
        raise ManifestAuthMalformedError("projection materialized_tree_hash is malformed")
    _b64decode(digest[3:], "materialized_tree_hash", expected_length=32)
    return result


def derive_projection(manifest: Mapping[str, object]) -> dict[str, str]:
    """Derive the only signable v1 projection from a verified loaded manifest."""
    if not isinstance(manifest, Mapping):
        raise ManifestAuthMalformedError("manifest must be an object")
    return _validate_projection({field: manifest.get(field) for field in _PROJECTION_FIELDS})


def _b64decode(value: object, field: str, *, expected_length: int | None = None) -> bytes:
    text = _ascii_text(value, field)
    try:
        decoded = base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ManifestAuthMalformedError(f"{field} is not canonical base64") from exc
    if base64.standard_b64encode(decoded).decode("ascii") != text:
        raise ManifestAuthMalformedError(f"{field} is not canonical base64")
    if expected_length is not None and len(decoded) != expected_length:
        raise ManifestAuthMalformedError(f"{field} has an invalid length")
    return decoded


def _provider() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives import serialization  # type: ignore[import-not-found]
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore[import-not-found]
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise ManifestAuthExtraMissingError("manifest authentication requires the separately installed auth extra") from exc
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature, serialization


def key_id_for_public_key(public_key: bytes) -> str:
    """Return the stable key identifier used by the signing ceremony helper."""
    if len(public_key) != 32:
        raise ManifestAuthMalformedError("Ed25519 public key must be 32 bytes")
    return hashlib.sha256(public_key).hexdigest()


def load_trusted_keys(
    path: str | Path | None = None, *, shelf_context: str | Path | None = None
) -> dict[str, bytes]:
    """Load the closed out-of-band ``trusted-keys.json`` configuration schema."""
    config_path = Path(path).expanduser() if path is not None else TRUSTED_KEYS_DEFAULT.expanduser()
    if not config_path.is_absolute():
        raise ManifestAuthMalformedError("trusted-keys path must be absolute")
    if shelf_context is not None:
        try:
            resolved_keys = config_path.resolve(strict=False)
            resolved_shelf = Path(shelf_context).resolve(strict=False)
            resolved_keys.relative_to(resolved_shelf)
        except ValueError:
            pass
        except OSError as exc:
            raise ManifestAuthMalformedError(f"cannot resolve trusted keys at {config_path}") from exc
        else:
            raise ManifestAuthKeysInShelfError(
                f"trusted-keys path must be outside the authenticated shelf: {config_path}"
            )
    try:
        raw = read_regular_file(config_path, maximum_bytes=_MAX_AUTH_INPUT_BYTES).decode("utf-8", "strict")
    except FileNotFoundError as exc:
        raise ManifestAuthNoKeysError(f"no trusted keys configured at {config_path}") from exc
    except (OSError, UnicodeError, ValueError) as exc:
        raise ManifestAuthMalformedError(f"cannot read trusted keys at {config_path}") from exc
    payload = _parse_json(raw, subject="trusted-key configuration")
    if not isinstance(payload, dict) or set(payload) != {"keys"} or not isinstance(payload["keys"], list):
        raise ManifestAuthMalformedError("trusted-key configuration must be {'keys': [...]}")
    keys: dict[str, bytes] = {}
    for item in payload["keys"]:
        if not isinstance(item, dict) or set(item) != _KEY_FIELDS:
            raise ManifestAuthMalformedError("trusted key must have exactly key_id, public_key_b64, and note")
        key_id = _ascii_text(item["key_id"], "key_id")
        if not isinstance(item["note"], str):
            raise ManifestAuthMalformedError("trusted key note must be text")
        if key_id in keys:
            raise ManifestAuthMalformedError(f"duplicate configured key_id: {key_id}")
        keys[key_id] = _b64decode(item["public_key_b64"], "public_key_b64", expected_length=32)
    if not keys:
        raise ManifestAuthNoKeysError("no trusted keys configured")
    return keys


def sign_projection(projection: Mapping[str, object], private_key: object) -> dict[str, object]:
    """Sign a v1 projection for an offline key ceremony.

    The helper's key ID is SHA-256 of raw public-key bytes. Verification still
    selects only the exact configured key ID.
    """
    Ed25519PrivateKey, _Ed25519PublicKey, _InvalidSignature, serialization = _provider()
    validated = _validate_projection(dict(projection))
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ManifestAuthMalformedError("private_key is not an Ed25519 private key")
    canonical = canonical_json(validated)
    public_bytes = private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return {
        "schema_version": AUTH_SCHEMA_VERSION,
        "key_id": key_id_for_public_key(public_bytes),
        "projection": validated,
        "projection_digest": hashlib.sha256(canonical).hexdigest(),
        "algorithm": "ed25519",
        "signature": base64.standard_b64encode(private_key.sign(canonical)).decode("ascii"),
    }


def _read_record(shelf_context: str | Path) -> dict[str, object]:
    shelf = Path(shelf_context)
    # Tree hashing intentionally includes every ordinary shelf file except the
    # manifest. Keep this attacker-controlled detached payload shelf-adjacent,
    # rather than in the shelf, so it cannot make the signed tree hash recursive.
    record_path = shelf.parent / f"{shelf.name}.{AUTH_RECORD_NAME}"
    try:
        data = read_regular_file(record_path, maximum_bytes=_MAX_AUTH_INPUT_BYTES)
        raw = data.decode("utf-8", "strict")
    except (OSError, UnicodeError, ValueError) as exc:
        raise ManifestAuthMalformedError(f"cannot read manifest authorization record: {record_path}") from exc
    payload = _parse_json(raw, subject="manifest authorization record")
    if not isinstance(payload, dict) or set(payload) != _RECORD_FIELDS:
        raise ManifestAuthMalformedError("authorization record must have exactly the v1 fields")
    if data != canonical_json(payload):
        raise ManifestAuthMalformedError("authorization record is not canonically encoded")
    return payload


def require_manifest_auth(manifest: Mapping[str, object], shelf_context: str | Path, *, trusted_keys: Mapping[str, bytes]) -> None:
    """Require a verified shelf's detached record to authorize its derived projection."""
    _Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature, _serialization = _provider()
    if not trusted_keys:
        raise ManifestAuthNoKeysError("no trusted keys configured")
    derived = derive_projection(manifest)
    record = _read_record(shelf_context)
    if record["schema_version"] != AUTH_SCHEMA_VERSION:
        raise ManifestAuthMalformedError("unsupported authorization record schema_version")
    if record["algorithm"] != "ed25519":
        raise ManifestAuthWrongAlgorithmError("authorization record algorithm must be ed25519")
    key_id = _ascii_text(record["key_id"], "key_id")
    public_key = trusted_keys.get(key_id)
    if public_key is None:
        raise ManifestAuthUnknownKeyError(f"unconfigured authorization key_id: {key_id}")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ManifestAuthMalformedError("configured public key is malformed")
    supplied = _validate_projection(record["projection"])
    if supplied != derived:
        raise ManifestAuthProjectionMismatchError("authorization record projection does not match verified manifest")
    canonical = canonical_json(derived)
    digest = _ascii_text(record["projection_digest"], "projection_digest")
    if not _SHA256.fullmatch(digest) or digest != hashlib.sha256(canonical).hexdigest():
        raise ManifestAuthProjectionMismatchError("authorization record projection_digest does not match projection")
    signature = _b64decode(record["signature"], "signature", expected_length=64)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical)
    except InvalidSignature as exc:
        raise ManifestAuthBadSignatureError("authorization record signature is invalid") from exc
    except ValueError as exc:
        raise ManifestAuthMalformedError("configured public key is malformed") from exc


def require_detached_projection_auth(
    projection: Mapping[str, object], record_path: str | Path, *, trusted_keys: Mapping[str, bytes]
) -> None:
    """Verify a canonical detached record for a caller-defined closed projection.

    The caller owns the projection schema; this shared primitive supplies the
    same key-ID selection, canonical bytes, and Ed25519 verification as shelf
    manifest authentication.  It deliberately has no default trust root.
    """

    _Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature, _serialization = _provider()
    if not trusted_keys:
        raise ManifestAuthNoKeysError("no trusted keys configured")
    if not isinstance(projection, Mapping):
        raise ManifestAuthMalformedError("projection must be an object")
    try:
        canonical = canonical_json(dict(projection))
        data = read_regular_file(Path(record_path), maximum_bytes=_MAX_AUTH_INPUT_BYTES)
        record = _parse_json(data.decode("utf-8", "strict"), subject="detached authorization record")
    except (OSError, UnicodeError, ValueError) as exc:
        raise ManifestAuthMalformedError(f"cannot read detached authorization record: {record_path}") from exc
    if not isinstance(record, dict) or set(record) != _RECORD_FIELDS or data != canonical_json(record):
        raise ManifestAuthMalformedError("detached authorization record has an invalid canonical schema")
    if record["schema_version"] != AUTH_SCHEMA_VERSION or record["algorithm"] != "ed25519":
        raise ManifestAuthWrongAlgorithmError("detached authorization record must use the v1 Ed25519 schema")
    key_id = _ascii_text(record["key_id"], "key_id")
    public_key = trusted_keys.get(key_id)
    if public_key is None:
        raise ManifestAuthUnknownKeyError(f"unconfigured authorization key_id: {key_id}")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ManifestAuthMalformedError("configured public key is malformed")
    if record["projection"] != dict(projection):
        raise ManifestAuthProjectionMismatchError("detached authorization projection does not match")
    digest = _ascii_text(record["projection_digest"], "projection_digest")
    if _SHA256.fullmatch(digest) is None or digest != hashlib.sha256(canonical).hexdigest():
        raise ManifestAuthProjectionMismatchError("detached authorization projection digest does not match")
    signature = _b64decode(record["signature"], "signature", expected_length=64)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical)
    except InvalidSignature as exc:
        raise ManifestAuthBadSignatureError("detached authorization signature is invalid") from exc
    except ValueError as exc:
        raise ManifestAuthMalformedError("configured public key is malformed") from exc
