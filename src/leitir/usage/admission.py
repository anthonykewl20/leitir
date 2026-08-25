"""Admission gate for the usage evidence pipeline (issue #256).

Before any usage report is assembled, a consumer must be *admitted*:

- its source ref must be a full, pinned SHA -- never a floating branch,
  tag, or ``HEAD`` -- and must match the ref recorded out-of-band for it;
- its ``requirements.txt`` must contain only exact direct pins
  (``name==version``); ranges, wildcards, bare unpinned names, and
  VCS/URL requirements without an exact pin are rejected;
- the actual on-disk ``requirements.txt`` bytes must match the digest
  recorded for it out-of-band.

Every check here is fail-closed: on any doubt the candidate is rejected
and no dependency claim is retained. A successfully admitted consumer
carries forward the *exact* :class:`~leitir.usage.DependencyEvidence`
(the verified bytes, digest, and parser identity) -- never a re-derived
or lossy copy -- for use by later stages (#257-#259).

Nothing in this module performs network I/O or imports/executes consumer
code; it only compares bytes and strings that are handed to it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NoReturn

from ._canonical import digest_bytes, digest_value, is_sha256_digest
from .contract import DEPENDENCY_EVIDENCE_SCHEMA_VERSION, IDENTITY_SCHEMA_VERSION, DependencyEvidence, Identity
from .errors import UsageErrorEvidence, UsageTamperError, UsageUnsupportedError

# --------------------------------------------------------------------------
# Schema version and parser identity literals.
# --------------------------------------------------------------------------

ADMITTED_CONSUMER_SCHEMA_VERSION = "leitir-usage-admitted-consumer-v1"
PINNED_REQUIREMENT_SCHEMA_VERSION = "leitir-usage-pinned-requirement-v1"

#: Identity of the exact-pin requirements parser used by :func:`admit_consumer`.
REQUIREMENTS_PARSER_NAME = "leitir-usage-exact-pin-parser"
REQUIREMENTS_PARSER_VERSION = "v1"

# --------------------------------------------------------------------------
# Bounds (module-level, near their consumer -- see BRIEF.md convention).
# --------------------------------------------------------------------------

#: A git-style full commit SHA: 40 lowercase hex characters. Anything shorter,
#: uppercase, or symbolic (branch/tag/"HEAD"/"latest") is a floating ref.
_GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")

#: PEP 508 distribution name: letters/digits, optionally separated by
#: ``-``/``_``/``.``, starting and ending with an alphanumeric character.
_DISTRIBUTION_NAME_PATTERN = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")

#: A conservative PEP 440-ish exact version token: no wildcards, no
#: whitespace, no comparison operators other than the leading ``==``.
_VERSION_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")

#: The only requirement-line shape admission accepts: an exact direct pin.
_EXACT_PIN_LINE_PATTERN = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==(?P<version>[A-Za-z0-9][A-Za-z0-9.+!_-]*)$"
)

MAX_REQUIREMENTS_LINES = 2_000


@dataclass(frozen=True, slots=True)
class PinnedRequirement:
    """One exact direct pin (``name==version``) parsed from ``requirements.txt``."""

    schema_version: str
    distribution: str
    version: str
    raw_line: str

    def __post_init__(self) -> None:
        if self.schema_version != PINNED_REQUIREMENT_SCHEMA_VERSION:
            raise ValueError("pinned_requirement.schema_version is unsupported")
        if not self.distribution or not self.version or not self.raw_line:
            raise ValueError("pinned_requirement fields must be non-empty")


@dataclass(frozen=True, slots=True)
class AdmittedConsumer:
    """An admitted consumer: its verified identity and its exact dependency evidence."""

    schema_version: str
    consumer_identity: Identity
    dependency_evidence: DependencyEvidence
    direct_pins: tuple[PinnedRequirement, ...]

    def __post_init__(self) -> None:
        if self.schema_version != ADMITTED_CONSUMER_SCHEMA_VERSION:
            raise ValueError("admitted_consumer.schema_version is unsupported")
        if self.consumer_identity.role != "consumer":
            raise ValueError("admitted_consumer.consumer_identity.role must be 'consumer'")
        if not self.direct_pins:
            raise ValueError("admitted_consumer.direct_pins must be non-empty")


def _reject_unsupported(context: str, message: str, *, expected: str | None = None, actual: str | None = None) -> NoReturn:
    raise UsageUnsupportedError(
        UsageErrorEvidence(message=message, stage="validate", field=context, expected=expected, actual=actual)
    )


def _reject_tamper(context: str, message: str, *, expected: str, actual: str) -> NoReturn:
    raise UsageTamperError(
        UsageErrorEvidence(message=message, stage="validate", field=context, expected=expected, actual=actual)
    )


def _is_pinned_ref(ref: str) -> bool:
    return bool(_GIT_SHA_PATTERN.fullmatch(ref))


def parse_exact_pins(requirements_text: str) -> tuple[PinnedRequirement, ...]:
    """Parse ``requirements_text`` into exact direct pins, fail-closed.

    Blank lines and ``#``-prefixed comment lines are skipped. Every other
    line must match ``name==version`` exactly; a range (``>=``, ``~=``,
    ``!=``, ``<``, ``>``), a wildcard (``*``), a bare unpinned name, an
    environment marker (``;``), an extras spec (``[...]``), or a VCS/URL
    requirement (``git+``, ``://``, ``-e``, ``@``) is rejected -- this
    function never guesses at intent, it only accepts the one unambiguous
    shape.
    """

    lines = requirements_text.splitlines()
    if len(lines) > MAX_REQUIREMENTS_LINES:
        _reject_unsupported(
            "requirements_text",
            "requirements.txt exceeds the supported line count",
            expected=f"<= {MAX_REQUIREMENTS_LINES} lines",
            actual=f"{len(lines)} lines",
        )
    pins: list[PinnedRequirement] = []
    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _EXACT_PIN_LINE_PATTERN.fullmatch(stripped)
        if match is None:
            _reject_unsupported(
                f"requirements_text:line {line_number}",
                "requirement line is not an exact direct pin (name==version)",
                expected="name==version",
                actual=stripped,
            )
        name = match.group("name")
        version = match.group("version")
        if not _DISTRIBUTION_NAME_PATTERN.fullmatch(name) or not _VERSION_TOKEN_PATTERN.fullmatch(version):
            _reject_unsupported(
                f"requirements_text:line {line_number}",
                "requirement name or version contains unsupported characters",
                expected="name==version",
                actual=stripped,
            )
        pins.append(
            PinnedRequirement(
                schema_version=PINNED_REQUIREMENT_SCHEMA_VERSION,
                distribution=name,
                version=version,
                raw_line=stripped,
            )
        )
    if not pins:
        _reject_unsupported(
            "requirements_text",
            "requirements.txt contains no exact direct pins",
            expected=">=1 exact pin",
            actual="0 pins",
        )
    return tuple(pins)


def admit_consumer(
    *,
    consumer_name: str,
    consumer_version: str,
    consumer_ref: str,
    expected_consumer_ref: str,
    requirements_bytes: bytes,
    recorded_requirements_digest: str,
) -> AdmittedConsumer:
    """Admit a consumer, or reject it fail-closed.

    ``consumer_ref`` is the ref the candidate claims to be pinned at;
    ``expected_consumer_ref`` is the ref recorded for it out-of-band (e.g.
    from a trusted index). ``requirements_bytes`` are the actual on-disk
    ``requirements.txt`` bytes; ``recorded_requirements_digest`` is the
    digest recorded for them out-of-band. Every comparison is exact and
    every rejection is typed:

    - a non-SHA-pinned (floating) ``consumer_ref`` -> :class:`UsageUnsupportedError`
    - ``consumer_ref != expected_consumer_ref`` -> :class:`UsageTamperError`
    - any non-exact-pin requirements line -> :class:`UsageUnsupportedError`
      (raised by :func:`parse_exact_pins`)
    - a requirements digest mismatch -> :class:`UsageTamperError`, and no
      :class:`~leitir.usage.DependencyEvidence` is ever constructed for it

    On success the returned :class:`AdmittedConsumer` retains the exact
    verified ``requirements_bytes`` (decoded once, byte-for-byte) inside
    its :class:`~leitir.usage.DependencyEvidence` -- never a re-derived
    copy -- alongside the recorded parser identity.
    """

    if not isinstance(consumer_ref, str) or not isinstance(expected_consumer_ref, str):
        raise TypeError("consumer_ref and expected_consumer_ref must be str")
    if not _is_pinned_ref(consumer_ref):
        _reject_unsupported(
            "consumer_ref",
            "consumer ref is not a full pinned SHA (floating/unpinned refs are rejected)",
            expected="40 lowercase hex characters",
            actual=consumer_ref,
        )
    if not _is_pinned_ref(expected_consumer_ref):
        _reject_unsupported(
            "expected_consumer_ref",
            "recorded consumer ref is not a full pinned SHA",
            expected="40 lowercase hex characters",
            actual=expected_consumer_ref,
        )
    if consumer_ref != expected_consumer_ref:
        _reject_tamper(
            "consumer_ref",
            "consumer SHA does not match the recorded/expected ref",
            expected=expected_consumer_ref,
            actual=consumer_ref,
        )

    if not is_sha256_digest(recorded_requirements_digest):
        _reject_unsupported(
            "recorded_requirements_digest",
            "recorded requirements digest is not a well-formed sha256 digest",
            expected="sha256:<64 lowercase hex>",
            actual=recorded_requirements_digest,
        )
    actual_digest = digest_bytes(requirements_bytes)
    if actual_digest != recorded_requirements_digest:
        # Reject before any dependency claim is constructed -- no partial
        # or unverifiable DependencyEvidence is ever built past this point.
        _reject_tamper(
            "requirements_bytes",
            "requirements.txt bytes do not match the recorded digest",
            expected=recorded_requirements_digest,
            actual=actual_digest,
        )

    requirements_text = requirements_bytes.decode("utf-8")
    direct_pins = parse_exact_pins(requirements_text)

    dependency_evidence = DependencyEvidence(
        schema_version=DEPENDENCY_EVIDENCE_SCHEMA_VERSION,
        requirements_text=requirements_text,
        requirements_digest=actual_digest,
        parser_name=REQUIREMENTS_PARSER_NAME,
        parser_version=REQUIREMENTS_PARSER_VERSION,
    )

    consumer_identity = Identity(
        schema_version=IDENTITY_SCHEMA_VERSION,
        role="consumer",
        name=consumer_name,
        version=consumer_version,
        digest=digest_value(
            {
                "ref": consumer_ref,
                "name": consumer_name,
                "version": consumer_version,
                "requirements_digest": actual_digest,
            }
        ),
    )

    return AdmittedConsumer(
        schema_version=ADMITTED_CONSUMER_SCHEMA_VERSION,
        consumer_identity=consumer_identity,
        dependency_evidence=dependency_evidence,
        direct_pins=direct_pins,
    )


__all__ = [
    "ADMITTED_CONSUMER_SCHEMA_VERSION",
    "MAX_REQUIREMENTS_LINES",
    "PINNED_REQUIREMENT_SCHEMA_VERSION",
    "REQUIREMENTS_PARSER_NAME",
    "REQUIREMENTS_PARSER_VERSION",
    "AdmittedConsumer",
    "PinnedRequirement",
    "admit_consumer",
    "parse_exact_pins",
]
