"""Optional detached Ed25519 authorization for materialized manifests.

This module deliberately has no cryptography-provider import at module load time.
The default Leitir installation therefore remains stdlib-only; callers that opt
into verification must install the separately hash-locked ``auth`` extra.

Trusted-key files carry a lifecycle from schema version 2 onward: per-key
``expires_at`` / ``revoked_at`` (with a required ``revocation_reason``) are
enforced fail-closed at load against an injectable clock, and expired or
revoked keys are refused with distinct typed errors. Version 1 files load
unchanged; see ADR-0022 for the schema and the rotation ceremonies.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from leitir.safeio import NoFollowUnavailableError, read_regular_file

AUTH_SCHEMA_VERSION = "leitir-manifest-auth-v1"
AUTH_RECORD_NAME = "leitir-manifest-auth.json"
TRUSTED_KEYS_DEFAULT = Path("~/.leitir/trusted-keys.json")
TRUSTED_KEYS_SCHEMA_VERSION = 2
_PROJECTION_FIELDS = frozenset({"host", "owner", "repo", "commit_sha", "source", "materialized_tree_hash_algorithm", "materialized_tree_hash", "materialized_tree_hash_scope"})
_RECORD_FIELDS = frozenset({"schema_version", "key_id", "projection", "projection_digest", "algorithm", "signature"})
_KEY_FIELDS = frozenset({"key_id", "public_key_b64", "note"})
_LIFECYCLE_FIELDS = frozenset({"expires_at", "revoked_at", "revocation_reason"})
_UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
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


class ManifestAuthKeyExpiredError(ManifestAuthError):
    code = "manifest_auth_key_expired_v1"


class ManifestAuthKeyRevokedError(ManifestAuthError):
    code = "manifest_auth_key_revoked_v1"


class ManifestAuthWrongAlgorithmError(ManifestAuthError):
    code = "manifest_auth_wrong_algorithm_v1"


class ManifestAuthProjectionMismatchError(ManifestAuthError):
    code = "manifest_auth_projection_mismatch_v1"


class ManifestAuthBadSignatureError(ManifestAuthError):
    code = "manifest_auth_bad_signature_v1"


class ManifestAuthPlatformCapabilityError(ManifestAuthError):
    """The host platform cannot enforce a required reading guarantee.

    Distinct from :class:`ManifestAuthMalformedError` on purpose: a platform
    that lacks ``O_NOFOLLOW`` (or another reading capability) is an
    environment limitation, not evidence of tampering. Raising the malformed
    class here would be a false integrity accusation.
    """

    code = "manifest_auth_platform_capability_v1"


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


def _format_utc(moment: datetime | None) -> str:
    if moment is None:
        return "unknown"
    return f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}T{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}Z"


def _parse_utc_timestamp(value: object, field: str) -> datetime:
    """Parse the strict canonical lifecycle timestamp: ``YYYY-MM-DDTHH:MM:SSZ`` (UTC only)."""
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        raise ManifestAuthMalformedError(f"{field} must be an RFC-3339 UTC timestamp of the form YYYY-MM-DDTHH:MM:SSZ")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ManifestAuthMalformedError(f"{field} is not a real UTC calendar instant: {value}") from exc
    if _format_utc(parsed) != value:
        raise ManifestAuthMalformedError(f"{field} is not a canonical UTC timestamp: {value}")
    return parsed


@dataclass(frozen=True)
class TrustedKeyLifecycle:
    """One v2 key's lifecycle, evaluated once at load against the injected clock.

    ``state`` records that evaluation: a key is *expired* when
    ``now >= expires_at`` and *revoked* when ``now >= revoked_at`` (the
    boundary instant itself is already invalid — validity is strictly
    ``now < expires_at`` / ``now < revoked_at``). When both apply, revocation
    wins: compromise is the stronger claim and the distinct refusal surfaces
    the revocation reason.
    """

    expires_at: datetime | None
    revoked_at: datetime | None
    revocation_reason: str | None
    state: str  # "active" | "expired" | "revoked" — frozen at load time


class TrustedKeys(dict[str, bytes]):
    """Active trusted keys plus the lifecycle table needed for distinct refusals.

    It is a ``dict[str, bytes]`` of the keys that may still authenticate (so
    every existing ``Mapping[str, bytes]`` consumer and equality check is
    unchanged); keys that were expired or revoked at load are deliberately
    absent from the mapping yet retained in the lifecycle table so that
    verification can refuse them with distinct typed errors instead of the
    generic unknown-key refusal. Iteration order is sorted by ``key_id``.
    """

    __slots__ = ("_lifecycle",)

    def __init__(self, active: Mapping[str, bytes], lifecycle: Mapping[str, TrustedKeyLifecycle] | None = None) -> None:
        super().__init__({key_id: active[key_id] for key_id in sorted(active)})
        self._lifecycle: dict[str, TrustedKeyLifecycle] = dict(lifecycle) if lifecycle is not None else {}

    def lifecycle_for(self, key_id: str) -> TrustedKeyLifecycle | None:
        """Return the recorded lifecycle for a configured key, or ``None`` when absent."""
        return self._lifecycle.get(key_id)


def _parse_lifecycle(item: Mapping[str, object]) -> tuple[datetime | None, datetime | None, str | None]:
    if ("revoked_at" in item) != ("revocation_reason" in item):
        raise ManifestAuthMalformedError("revoked_at and revocation_reason must be provided together")
    expires_at = _parse_utc_timestamp(item["expires_at"], "expires_at") if "expires_at" in item else None
    revoked_at = _parse_utc_timestamp(item["revoked_at"], "revoked_at") if "revoked_at" in item else None
    revocation_reason = _ascii_text(item["revocation_reason"], "revocation_reason") if "revocation_reason" in item else None
    return expires_at, revoked_at, revocation_reason


def _evaluate_lifecycle(
    expires_at: datetime | None, revoked_at: datetime | None, revocation_reason: str | None, now: datetime
) -> TrustedKeyLifecycle:
    if revoked_at is not None and now >= revoked_at:
        state = "revoked"
    elif expires_at is not None and now >= expires_at:
        state = "expired"
    else:
        state = "active"
    return TrustedKeyLifecycle(expires_at=expires_at, revoked_at=revoked_at, revocation_reason=revocation_reason, state=state)


def _lifecycle_now(clock: Callable[[], datetime] | None) -> datetime:
    """Read the evaluation instant once, from the injectable clock when given."""
    now = clock() if clock is not None else datetime.now(UTC)
    if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
        raise ManifestAuthMalformedError("trusted-key lifecycle clock must return timezone-aware datetimes")
    return now.astimezone(UTC)


def _resolve_public_key(trusted_keys: Mapping[str, bytes], key_id: str) -> bytes:
    """Select a key, refusing expired and revoked keys with distinct typed errors."""
    public_key = trusted_keys.get(key_id)
    if public_key is None:
        if isinstance(trusted_keys, TrustedKeys):
            lifecycle = trusted_keys.lifecycle_for(key_id)
            if lifecycle is not None:
                if lifecycle.state == "revoked":
                    raise ManifestAuthKeyRevokedError(
                        f"authorization key_id is revoked: {key_id} (revocation reason: {lifecycle.revocation_reason or 'unrecorded'})"
                    )
                if lifecycle.state == "expired":
                    raise ManifestAuthKeyExpiredError(
                        f"authorization key_id is expired: {key_id} (expired at {_format_utc(lifecycle.expires_at)})"
                    )
        raise ManifestAuthUnknownKeyError(f"unconfigured authorization key_id: {key_id}")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ManifestAuthMalformedError("configured public key is malformed")
    return public_key


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
    path: str | Path | None = None,
    *,
    shelf_context: str | Path | None = None,
    clock: Callable[[], datetime] | None = None,
) -> TrustedKeys:
    """Load the closed out-of-band ``trusted-keys.json`` configuration schema.

    Version 1 files (``{"keys": [...]}`` with rows of exactly ``key_id``,
    ``public_key_b64``, and ``note``) load unchanged and unconditionally
    active. Version 2 files add a per-file ``schema_version: 2`` marker and
    optional per-key lifecycle fields (``expires_at``, ``revoked_at`` with a
    required ``revocation_reason``); lifecycle timestamps are compared once
    against ``clock`` (UTC now when not injected). Keys expired or revoked at
    the evaluation instant are excluded from the returned mapping but retained
    in its lifecycle table, and a file left with no active keys fails closed
    with :class:`ManifestAuthNoKeysError`.
    """
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
    except NoFollowUnavailableError as exc:
        raise ManifestAuthPlatformCapabilityError(
            f"platform cannot enforce O_NOFOLLOW for trusted keys at {config_path}"
        ) from exc
    except (OSError, UnicodeError, ValueError) as exc:
        raise ManifestAuthMalformedError(f"cannot read trusted keys at {config_path}") from exc
    payload = _parse_json(raw, subject="trusted-key configuration")
    if not isinstance(payload, dict) or "keys" not in payload or not isinstance(payload["keys"], list):
        raise ManifestAuthMalformedError("trusted-key configuration must be {'keys': [...]}")
    if "schema_version" not in payload:
        if set(payload) != {"keys"}:
            raise ManifestAuthMalformedError("trusted-key configuration must be {'keys': [...]}")
        version = 1
    else:
        if set(payload) != {"schema_version", "keys"}:
            raise ManifestAuthMalformedError("trusted-key configuration must be {'keys': [...]}")
        declared_version = payload["schema_version"]
        if isinstance(declared_version, bool) or not isinstance(declared_version, int) or declared_version != TRUSTED_KEYS_SCHEMA_VERSION:
            raise ManifestAuthMalformedError(
                f"unsupported trusted-keys schema_version: {declared_version!r} (expected integer {TRUSTED_KEYS_SCHEMA_VERSION})"
            )
        version = TRUSTED_KEYS_SCHEMA_VERSION
    parsed: dict[str, tuple[bytes, tuple[datetime | None, datetime | None, str | None]]] = {}
    for item in payload["keys"]:
        if not isinstance(item, dict):
            raise ManifestAuthMalformedError(
                "trusted key must have exactly key_id, public_key_b64, and note"
                if version == 1
                else "v2 trusted key must have key_id, public_key_b64, and note, adding only expires_at, revoked_at, and revocation_reason"
            )
        fields = set(item)
        if version == 1 and fields != _KEY_FIELDS:
            raise ManifestAuthMalformedError("trusted key must have exactly key_id, public_key_b64, and note")
        if version == TRUSTED_KEYS_SCHEMA_VERSION and not _KEY_FIELDS <= fields <= _KEY_FIELDS | _LIFECYCLE_FIELDS:
            raise ManifestAuthMalformedError(
                "v2 trusted key must have key_id, public_key_b64, and note, adding only expires_at, revoked_at, and revocation_reason"
            )
        key_id = _ascii_text(item["key_id"], "key_id")
        if not isinstance(item["note"], str):
            raise ManifestAuthMalformedError("trusted key note must be text")
        if key_id in parsed:
            raise ManifestAuthMalformedError(f"duplicate configured key_id: {key_id}")
        public_bytes = _b64decode(item["public_key_b64"], "public_key_b64", expected_length=32)
        parsed[key_id] = (public_bytes, _parse_lifecycle(item) if version == TRUSTED_KEYS_SCHEMA_VERSION else (None, None, None))
    if not parsed:
        raise ManifestAuthNoKeysError("no trusted keys configured")
    now: datetime | None = None
    active: dict[str, bytes] = {}
    lifecycle: dict[str, TrustedKeyLifecycle] = {}
    for key_id in sorted(parsed):
        public_bytes, raw_lifecycle = parsed[key_id]
        expires_at, revoked_at, revocation_reason = raw_lifecycle
        if expires_at is not None or revoked_at is not None:
            if now is None:
                now = _lifecycle_now(clock)
            evaluated = _evaluate_lifecycle(expires_at, revoked_at, revocation_reason, now)
        else:
            evaluated = None
        if evaluated is not None:
            lifecycle[key_id] = evaluated
            if evaluated.state != "active":
                continue
        active[key_id] = public_bytes
    if not active:
        detail = "all configured keys are expired or revoked" if lifecycle else "no trusted keys configured"
        raise ManifestAuthNoKeysError(f"no active trusted keys configured: {detail}")
    return TrustedKeys(active, lifecycle)


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
    except NoFollowUnavailableError as exc:
        raise ManifestAuthPlatformCapabilityError(
            f"platform cannot enforce O_NOFOLLOW for the manifest authorization record: {record_path}"
        ) from exc
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
    public_key = _resolve_public_key(trusted_keys, key_id)
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
    except NoFollowUnavailableError as exc:
        raise ManifestAuthPlatformCapabilityError(
            f"platform cannot enforce O_NOFOLLOW for the detached authorization record: {record_path}"
        ) from exc
    except (OSError, UnicodeError, ValueError) as exc:
        raise ManifestAuthMalformedError(f"cannot read detached authorization record: {record_path}") from exc
    if not isinstance(record, dict) or set(record) != _RECORD_FIELDS or data != canonical_json(record):
        raise ManifestAuthMalformedError("detached authorization record has an invalid canonical schema")
    if record["schema_version"] != AUTH_SCHEMA_VERSION or record["algorithm"] != "ed25519":
        raise ManifestAuthWrongAlgorithmError("detached authorization record must use the v1 Ed25519 schema")
    key_id = _ascii_text(record["key_id"], "key_id")
    public_key = _resolve_public_key(trusted_keys, key_id)
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
