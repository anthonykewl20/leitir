"""Canonical-bytes and digest helpers shared within the usage evidence package.

Defined once per the shared engineering brief for issues #255-#259: every
module inside ``src/leitir/usage/`` imports these instead of redefining the
convention. This module is package-private plumbing; it is not imported by
any module outside ``leitir.usage``.
"""

from __future__ import annotations

import hashlib
import json

_SHA256_HEX_LENGTH = 64


def canonical_bytes(value: object) -> bytes:
    """Return the canonical JSON encoding used for all usage-package digests."""

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest_value(value: object) -> str:
    """Return the ``sha256:<hex>`` digest of ``value``'s canonical JSON encoding."""

    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_bytes(data: bytes) -> str:
    """Return the ``sha256:<hex>`` digest of raw bytes (no JSON canonicalization)."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def is_sha256_digest(value: object) -> bool:
    """Return whether ``value`` is a well-formed ``sha256:<64 lowercase hex>`` digest."""

    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    hex_part = value[len("sha256:") :]
    if len(hex_part) != _SHA256_HEX_LENGTH:
        return False
    return all(char in "0123456789abcdef" for char in hex_part)
