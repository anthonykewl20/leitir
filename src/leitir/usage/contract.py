"""The closed, versioned usage evidence and offline replay contract.

This module freezes the data shape that issues #256 (admission + import
catalog), #257 (static resolver), #258 (evidence assembler), and #259 (CLI +
replay + E2E) all build on. It defines:

- frozen, ``slots``-equipped dataclasses for every evidence structure
  (identities, dependency evidence, import mappings, source references,
  coverage, and advisory license evidence) plus the top-level
  :class:`UsageReport`;
- a closed-schema parser (:func:`report_from_dict` /
  :func:`report_from_json_bytes`) that rejects unknown or missing fields,
  malformed types, and unsupported versions *before* any digest work;
- a fully offline :func:`replay_report` that recomputes every digest from
  the bytes actually present in a fixture corpus and rejects (fail-closed)
  on the first mismatch, never substituting or executing anything.

Nothing in this module performs network I/O, imports or executes consumer
code, or writes to the filesystem. All reads go through
``leitir.safeio.read_regular_file`` with an explicit byte bound.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TypeVar

from leitir.safeio import confined_path, read_regular_file

from ._canonical import canonical_bytes, digest_bytes, digest_value, is_sha256_digest
from .errors import UsageErrorEvidence, UsageMalformedError, UsageTamperError, UsageUnsupportedError

# --------------------------------------------------------------------------
# Schema version literals -- "leitir-usage-<name>-v1", per the shared brief.
# --------------------------------------------------------------------------

REPORT_SCHEMA_VERSION = "leitir-usage-report-v1"
IDENTITY_SCHEMA_VERSION = "leitir-usage-identity-v1"
DEPENDENCY_EVIDENCE_SCHEMA_VERSION = "leitir-usage-dependency-v1"
IMPORT_MAPPING_SCHEMA_VERSION = "leitir-usage-import-mapping-v1"
CODE_REFERENCE_SCHEMA_VERSION = "leitir-usage-reference-v1"
COVERAGE_RECORD_SCHEMA_VERSION = "leitir-usage-coverage-record-v1"
COVERAGE_SUMMARY_SCHEMA_VERSION = "leitir-usage-coverage-v1"
LICENSE_EVIDENCE_SCHEMA_VERSION = "leitir-usage-license-v1"
FIXTURE_MANIFEST_SCHEMA_VERSION = "leitir-usage-fixture-manifest-v1"

CONTRACT_VERSION = "leitir-usage-contract-v1"
TOOL_VERSION = "leitir-usage-tool-v1"

# --------------------------------------------------------------------------
# Bounds -- module-level, named near their consumer, per the shared brief.
# --------------------------------------------------------------------------

MAX_REQUIREMENTS_BYTES = 65_536
MAX_SNIPPET_BYTES = 4_096
MAX_COVERAGE_CAP = 10_000
MAX_REFERENCES = 2_000
MAX_IMPORT_MAPPINGS = 500
MAX_IMPORT_ROOTS_PER_MAPPING = 64
MAX_LICENSE_EVIDENCE = 500
MAX_COVERAGE_RECORDS = MAX_COVERAGE_CAP
MAX_EXCLUSIONS = MAX_COVERAGE_CAP

_ROLES = frozenset({"provider", "consumer"})
_CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})


class UnresolvedState(str, Enum):  # noqa: UP042 - JSON-serializable str values are required
    """The closed set of coverage states a source file/span can carry.

    ``RESOLVED`` marks full, unambiguous resolution; every other member is a
    distinct typed reason resolution could not complete. This set is closed:
    no other value is ever produced or accepted, so downstream issues
    (#257's resolver, #258's assembler) can switch on it exhaustively.
    """

    RESOLVED = "resolved"
    DYNAMIC_IMPORT = "dynamic-import"
    STAR_IMPORT = "star-import"
    AMBIGUOUS_BINDING = "ambiguous-binding"
    RE_EXPORT = "re-export"
    UNSUPPORTED_SYNTAX = "unsupported-syntax"
    CAP_EXCEEDED = "cap-exceeded"


# --------------------------------------------------------------------------
# Closed-dict parsing helpers.
# --------------------------------------------------------------------------

_T = TypeVar("_T")


def _malformed(stage: str, context: str, message: str, *, expected: str | None = None, actual: str | None = None) -> UsageMalformedError:
    return UsageMalformedError(
        UsageErrorEvidence(message=f"{context}: {message}", stage=stage, field=context, expected=expected, actual=actual)
    )


def _unsupported(stage: str, context: str, message: str, *, expected: str | None = None, actual: str | None = None) -> UsageUnsupportedError:
    return UsageUnsupportedError(
        UsageErrorEvidence(message=f"{context}: {message}", stage=stage, field=context, expected=expected, actual=actual)
    )


def _tamper(stage: str, context: str, message: str, *, expected: str | None = None, actual: str | None = None) -> UsageTamperError:
    return UsageTamperError(
        UsageErrorEvidence(message=f"{context}: {message}", stage=stage, field=context, expected=expected, actual=actual)
    )


def _closed_dict(payload: object, allowed: frozenset[str], *, stage: str, context: str) -> dict[str, object]:
    if not isinstance(payload, dict) or not all(isinstance(key, str) for key in payload):
        raise _malformed(stage, context, "must be a JSON object with string keys")
    keys = frozenset(payload.keys())
    unknown = sorted(keys - allowed)
    if unknown:
        raise _malformed(stage, context, "has unknown fields", actual=repr(unknown))
    missing = sorted(allowed - keys)
    if missing:
        raise _malformed(stage, context, "is missing required fields", actual=repr(missing))
    return dict(payload)


def _require_str(payload: dict[str, object], field_name: str, *, stage: str, context: str, allow_empty: bool = False) -> str:
    value = payload[field_name]
    if not isinstance(value, str) or (not allow_empty and not value):
        raise _malformed(stage, f"{context}.{field_name}", "must be a non-empty string")
    return value


def _require_bool(payload: dict[str, object], field_name: str, *, stage: str, context: str) -> bool:
    value = payload[field_name]
    if type(value) is not bool:
        raise _malformed(stage, f"{context}.{field_name}", "must be a boolean")
    return value


def _require_int(payload: dict[str, object], field_name: str, *, stage: str, context: str, minimum: int) -> int:
    value = payload[field_name]
    if type(value) is not int or value < minimum:
        raise _malformed(stage, f"{context}.{field_name}", f"must be an int >= {minimum}")
    return value


def _require_digest(payload: dict[str, object], field_name: str, *, stage: str, context: str) -> str:
    value = _require_str(payload, field_name, stage=stage, context=context)
    if not is_sha256_digest(value):
        raise _malformed(stage, f"{context}.{field_name}", "must be a sha256:<64 lowercase hex> digest")
    return value


def _require_schema_version(payload: dict[str, object], expected: str, *, stage: str, context: str) -> str:
    value = payload["schema_version"]
    if not isinstance(value, str) or not value:
        raise _malformed(stage, f"{context}.schema_version", "must be a non-empty string")
    if value != expected:
        raise _unsupported(stage, f"{context}.schema_version", "is not a supported schema version", expected=expected, actual=value)
    return value


def _require_list(payload: dict[str, object], field_name: str, *, stage: str, context: str, maximum: int) -> list[object]:
    value = payload[field_name]
    if not isinstance(value, list):
        raise _malformed(stage, f"{context}.{field_name}", "must be a JSON array")
    if len(value) > maximum:
        raise _unsupported(stage, f"{context}.{field_name}", f"exceeds the maximum of {maximum} entries")
    return list(value)


def _parse_tuple(
    items: Sequence[object], parser: Callable[[object, int], _T], *, stage: str, context: str
) -> tuple[_T, ...]:
    return tuple(parser(item, index) for index, item in enumerate(items))


# --------------------------------------------------------------------------
# Value objects.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """A file-relative, 1-indexed line / 0-indexed column source range."""

    file: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def __post_init__(self) -> None:
        if not isinstance(self.file, str) or not self.file:
            raise ValueError("span.file must be a non-empty string")
        for name in ("start_line", "end_line"):
            if getattr(self, name) < 1:
                raise ValueError(f"span.{name} must be >= 1")
        for name in ("start_col", "end_col"):
            if getattr(self, name) < 0:
                raise ValueError(f"span.{name} must be >= 0")
        if (self.end_line, self.end_col) < (self.start_line, self.start_col):
            raise ValueError("span end must not precede span start")

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "start_line": self.start_line,
            "start_col": self.start_col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }


_SPAN_FIELDS = frozenset({"file", "start_line", "start_col", "end_line", "end_col"})


def _span_from_dict(payload: object, *, stage: str, context: str) -> SourceSpan:
    body = _closed_dict(payload, _SPAN_FIELDS, stage=stage, context=context)
    try:
        return SourceSpan(
            file=_require_str(body, "file", stage=stage, context=context),
            start_line=_require_int(body, "start_line", stage=stage, context=context, minimum=1),
            start_col=_require_int(body, "start_col", stage=stage, context=context, minimum=0),
            end_line=_require_int(body, "end_line", stage=stage, context=context, minimum=1),
            end_col=_require_int(body, "end_col", stage=stage, context=context, minimum=0),
        )
    except ValueError as exc:
        raise _malformed(stage, context, str(exc)) from exc


# --------------------------------------------------------------------------
# Identity.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Identity:
    """A SHA-pinned identity for one side of a usage relationship."""

    schema_version: str
    role: str
    name: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        if self.schema_version != IDENTITY_SCHEMA_VERSION:
            raise ValueError("identity.schema_version is unsupported")
        if self.role not in _ROLES:
            raise ValueError("identity.role must be 'provider' or 'consumer'")
        if not self.name:
            raise ValueError("identity.name must be non-empty")
        if not self.version:
            raise ValueError("identity.version must be non-empty")
        if not is_sha256_digest(self.digest):
            raise ValueError("identity.digest must be a sha256:<64 lowercase hex> digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "role": self.role,
            "name": self.name,
            "version": self.version,
            "digest": self.digest,
        }


_IDENTITY_FIELDS = frozenset({"schema_version", "role", "name", "version", "digest"})


def _identity_from_dict(payload: object, *, stage: str, context: str, expected_role: str) -> Identity:
    body = _closed_dict(payload, _IDENTITY_FIELDS, stage=stage, context=context)
    _require_schema_version(body, IDENTITY_SCHEMA_VERSION, stage=stage, context=context)
    role = _require_str(body, "role", stage=stage, context=context)
    if role != expected_role:
        raise _malformed(stage, f"{context}.role", f"must equal {expected_role!r}", expected=expected_role, actual=role)
    try:
        return Identity(
            schema_version=IDENTITY_SCHEMA_VERSION,
            role=role,
            name=_require_str(body, "name", stage=stage, context=context),
            version=_require_str(body, "version", stage=stage, context=context),
            digest=_require_digest(body, "digest", stage=stage, context=context),
        )
    except ValueError as exc:
        raise _malformed(stage, context, str(exc)) from exc


# --------------------------------------------------------------------------
# Dependency evidence.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DependencyEvidence:
    """The exact ``requirements.txt`` bytes, their digest, and the parser identity."""

    schema_version: str
    requirements_text: str
    requirements_digest: str
    parser_name: str
    parser_version: str

    def __post_init__(self) -> None:
        if self.schema_version != DEPENDENCY_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("dependency_evidence.schema_version is unsupported")
        if len(self.requirements_text.encode("utf-8")) > MAX_REQUIREMENTS_BYTES:
            raise ValueError("dependency_evidence.requirements_text exceeds the byte cap")
        if not is_sha256_digest(self.requirements_digest):
            raise ValueError("dependency_evidence.requirements_digest must be a sha256:<64 lowercase hex> digest")
        if digest_bytes(self.requirements_text.encode("utf-8")) != self.requirements_digest:
            raise ValueError("dependency_evidence.requirements_digest does not match requirements_text")
        if not self.parser_name or not self.parser_version:
            raise ValueError("dependency_evidence.parser_name and parser_version must be non-empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "requirements_text": self.requirements_text,
            "requirements_digest": self.requirements_digest,
            "parser_name": self.parser_name,
            "parser_version": self.parser_version,
        }


_DEPENDENCY_FIELDS = frozenset(
    {"schema_version", "requirements_text", "requirements_digest", "parser_name", "parser_version"}
)


def _dependency_from_dict(payload: object, *, stage: str, context: str) -> DependencyEvidence:
    body = _closed_dict(payload, _DEPENDENCY_FIELDS, stage=stage, context=context)
    _require_schema_version(body, DEPENDENCY_EVIDENCE_SCHEMA_VERSION, stage=stage, context=context)
    requirements_text = _require_str(body, "requirements_text", stage=stage, context=context, allow_empty=True)
    requirements_digest = _require_digest(body, "requirements_digest", stage=stage, context=context)
    if digest_bytes(requirements_text.encode("utf-8")) != requirements_digest:
        raise _tamper(
            stage,
            f"{context}.requirements_digest",
            "does not match the digest of requirements_text",
            expected=digest_bytes(requirements_text.encode("utf-8")),
            actual=requirements_digest,
        )
    try:
        return DependencyEvidence(
            schema_version=DEPENDENCY_EVIDENCE_SCHEMA_VERSION,
            requirements_text=requirements_text,
            requirements_digest=requirements_digest,
            parser_name=_require_str(body, "parser_name", stage=stage, context=context),
            parser_version=_require_str(body, "parser_version", stage=stage, context=context),
        )
    except ValueError as exc:
        raise _malformed(stage, context, str(exc)) from exc


# --------------------------------------------------------------------------
# Import mapping.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ImportMapping:
    """One distribution name mapped to its top-level import roots."""

    schema_version: str
    distribution: str
    import_roots: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != IMPORT_MAPPING_SCHEMA_VERSION:
            raise ValueError("import_mapping.schema_version is unsupported")
        if not self.distribution:
            raise ValueError("import_mapping.distribution must be non-empty")
        if not self.import_roots:
            raise ValueError("import_mapping.import_roots must be non-empty")
        if len(self.import_roots) > MAX_IMPORT_ROOTS_PER_MAPPING:
            raise ValueError("import_mapping.import_roots exceeds the cap")
        if len(set(self.import_roots)) != len(self.import_roots):
            raise ValueError("import_mapping.import_roots must not contain duplicates")
        if any(not root for root in self.import_roots):
            raise ValueError("import_mapping.import_roots entries must be non-empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "distribution": self.distribution,
            "import_roots": list(self.import_roots),
        }


_IMPORT_MAPPING_FIELDS = frozenset({"schema_version", "distribution", "import_roots"})


def _import_mapping_from_dict(payload: object, *, stage: str, context: str) -> ImportMapping:
    body = _closed_dict(payload, _IMPORT_MAPPING_FIELDS, stage=stage, context=context)
    _require_schema_version(body, IMPORT_MAPPING_SCHEMA_VERSION, stage=stage, context=context)
    roots_field = _require_list(body, "import_roots", stage=stage, context=context, maximum=MAX_IMPORT_ROOTS_PER_MAPPING)
    roots: list[str] = []
    for index, item in enumerate(roots_field):
        if not isinstance(item, str) or not item:
            raise _malformed(stage, f"{context}.import_roots[{index}]", "must be a non-empty string")
        roots.append(item)
    try:
        return ImportMapping(
            schema_version=IMPORT_MAPPING_SCHEMA_VERSION,
            distribution=_require_str(body, "distribution", stage=stage, context=context),
            import_roots=tuple(roots),
        )
    except ValueError as exc:
        raise _malformed(stage, context, str(exc)) from exc


# --------------------------------------------------------------------------
# Code reference.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CodeReference:
    """A source span attributed to one distribution, with its own code digest."""

    schema_version: str
    distribution: str
    span: SourceSpan
    code_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != CODE_REFERENCE_SCHEMA_VERSION:
            raise ValueError("reference.schema_version is unsupported")
        if not self.distribution:
            raise ValueError("reference.distribution must be non-empty")
        if not isinstance(self.span, SourceSpan):
            raise ValueError("reference.span must be a SourceSpan")
        if not is_sha256_digest(self.code_digest):
            raise ValueError("reference.code_digest must be a sha256:<64 lowercase hex> digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "distribution": self.distribution,
            "span": self.span.to_dict(),
            "code_digest": self.code_digest,
        }


_REFERENCE_FIELDS = frozenset({"schema_version", "distribution", "span", "code_digest"})


def _reference_from_dict(payload: object, *, stage: str, context: str) -> CodeReference:
    body = _closed_dict(payload, _REFERENCE_FIELDS, stage=stage, context=context)
    _require_schema_version(body, CODE_REFERENCE_SCHEMA_VERSION, stage=stage, context=context)
    try:
        return CodeReference(
            schema_version=CODE_REFERENCE_SCHEMA_VERSION,
            distribution=_require_str(body, "distribution", stage=stage, context=context),
            span=_span_from_dict(body["span"], stage=stage, context=f"{context}.span"),
            code_digest=_require_digest(body, "code_digest", stage=stage, context=context),
        )
    except ValueError as exc:
        raise _malformed(stage, context, str(exc)) from exc


# --------------------------------------------------------------------------
# Coverage.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CoverageRecord:
    """One file's coverage outcome: fully resolved, or one typed unresolved state."""

    schema_version: str
    file: str
    state: UnresolvedState

    def __post_init__(self) -> None:
        if self.schema_version != COVERAGE_RECORD_SCHEMA_VERSION:
            raise ValueError("coverage_record.schema_version is unsupported")
        if not self.file:
            raise ValueError("coverage_record.file must be non-empty")
        if not isinstance(self.state, UnresolvedState):
            raise ValueError("coverage_record.state must be an UnresolvedState")

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": self.schema_version, "file": self.file, "state": self.state.value}


_COVERAGE_RECORD_FIELDS = frozenset({"schema_version", "file", "state"})


def _coverage_record_from_dict(payload: object, *, stage: str, context: str) -> CoverageRecord:
    body = _closed_dict(payload, _COVERAGE_RECORD_FIELDS, stage=stage, context=context)
    _require_schema_version(body, COVERAGE_RECORD_SCHEMA_VERSION, stage=stage, context=context)
    state_raw = _require_str(body, "state", stage=stage, context=context)
    try:
        state = UnresolvedState(state_raw)
    except ValueError as exc:
        raise _malformed(
            stage, f"{context}.state", "is not a member of the closed UnresolvedState set", actual=state_raw
        ) from exc
    try:
        return CoverageRecord(
            schema_version=COVERAGE_RECORD_SCHEMA_VERSION,
            file=_require_str(body, "file", stage=stage, context=context),
            state=state,
        )
    except ValueError as exc:
        raise _malformed(stage, context, str(exc)) from exc


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    """Coverage records, explicit exclusions, and the bounded cap applied."""

    schema_version: str
    records: tuple[CoverageRecord, ...]
    exclusions: tuple[str, ...]
    cap: int
    capped: bool

    def __post_init__(self) -> None:
        if self.schema_version != COVERAGE_SUMMARY_SCHEMA_VERSION:
            raise ValueError("coverage.schema_version is unsupported")
        if not (1 <= self.cap <= MAX_COVERAGE_CAP):
            raise ValueError(f"coverage.cap must be between 1 and {MAX_COVERAGE_CAP}")
        if len(self.records) > self.cap:
            raise ValueError("coverage.records exceeds the declared cap")
        files = [record.file for record in self.records]
        if len(set(files)) != len(files):
            raise ValueError("coverage.records must not repeat a file")
        if len(set(self.exclusions)) != len(self.exclusions):
            raise ValueError("coverage.exclusions must not contain duplicates")
        if any(not excluded for excluded in self.exclusions):
            raise ValueError("coverage.exclusions entries must be non-empty")
        if set(files) & set(self.exclusions):
            raise ValueError("coverage.records and coverage.exclusions must be disjoint")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "records": [record.to_dict() for record in self.records],
            "exclusions": list(self.exclusions),
            "cap": self.cap,
            "capped": self.capped,
        }


_COVERAGE_SUMMARY_FIELDS = frozenset({"schema_version", "records", "exclusions", "cap", "capped"})


def _coverage_summary_from_dict(payload: object, *, stage: str, context: str) -> CoverageSummary:
    body = _closed_dict(payload, _COVERAGE_SUMMARY_FIELDS, stage=stage, context=context)
    _require_schema_version(body, COVERAGE_SUMMARY_SCHEMA_VERSION, stage=stage, context=context)
    records_field = _require_list(body, "records", stage=stage, context=context, maximum=MAX_COVERAGE_RECORDS)
    records = _parse_tuple(
        records_field,
        lambda item, index: _coverage_record_from_dict(item, stage=stage, context=f"{context}.records[{index}]"),
        stage=stage,
        context=context,
    )
    exclusions_field = _require_list(body, "exclusions", stage=stage, context=context, maximum=MAX_EXCLUSIONS)
    exclusions: list[str] = []
    for index, item in enumerate(exclusions_field):
        if not isinstance(item, str) or not item:
            raise _malformed(stage, f"{context}.exclusions[{index}]", "must be a non-empty string")
        exclusions.append(item)
    try:
        return CoverageSummary(
            schema_version=COVERAGE_SUMMARY_SCHEMA_VERSION,
            records=records,
            exclusions=tuple(exclusions),
            cap=_require_int(body, "cap", stage=stage, context=context, minimum=1),
            capped=_require_bool(body, "capped", stage=stage, context=context),
        )
    except ValueError as exc:
        raise _malformed(stage, context, str(exc)) from exc


# --------------------------------------------------------------------------
# License evidence (advisory only).
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LicenseSnippetEvidence:
    """Advisory, non-authoritative license evidence for one code span.

    ``advisory`` is always ``True``: this contract never claims a snippet's
    license with certainty, and a payload that sets ``advisory: false`` is
    rejected as malformed rather than silently accepted as authoritative.
    """

    schema_version: str
    span: SourceSpan
    license_guess: str
    confidence: str
    advisory: bool

    def __post_init__(self) -> None:
        if self.schema_version != LICENSE_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("license_evidence.schema_version is unsupported")
        if not isinstance(self.span, SourceSpan):
            raise ValueError("license_evidence.span must be a SourceSpan")
        if not self.license_guess:
            raise ValueError("license_evidence.license_guess must be non-empty")
        if self.confidence not in _CONFIDENCE_LEVELS:
            raise ValueError("license_evidence.confidence must be low, medium, or high")
        if self.advisory is not True:
            raise ValueError("license_evidence.advisory must be true (non-authoritative)")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "span": self.span.to_dict(),
            "license_guess": self.license_guess,
            "confidence": self.confidence,
            "advisory": self.advisory,
        }


_LICENSE_FIELDS = frozenset({"schema_version", "span", "license_guess", "confidence", "advisory"})


def _license_from_dict(payload: object, *, stage: str, context: str) -> LicenseSnippetEvidence:
    body = _closed_dict(payload, _LICENSE_FIELDS, stage=stage, context=context)
    _require_schema_version(body, LICENSE_EVIDENCE_SCHEMA_VERSION, stage=stage, context=context)
    advisory = _require_bool(body, "advisory", stage=stage, context=context)
    if advisory is not True:
        raise _malformed(stage, f"{context}.advisory", "must be true (this evidence is never authoritative)")
    confidence = _require_str(body, "confidence", stage=stage, context=context)
    if confidence not in _CONFIDENCE_LEVELS:
        raise _malformed(stage, f"{context}.confidence", "must be one of low, medium, high", actual=confidence)
    try:
        return LicenseSnippetEvidence(
            schema_version=LICENSE_EVIDENCE_SCHEMA_VERSION,
            span=_span_from_dict(body["span"], stage=stage, context=f"{context}.span"),
            license_guess=_require_str(body, "license_guess", stage=stage, context=context),
            confidence=confidence,
            advisory=advisory,
        )
    except ValueError as exc:
        raise _malformed(stage, context, str(exc)) from exc


# --------------------------------------------------------------------------
# The top-level report.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UsageReport:
    """The closed, versioned usage evidence report.

    ``report_digest`` is a digest over the canonical JSON of every other
    field (see :meth:`recompute_digest`); a mismatch is a tamper signal, not
    a validation nicety, and is checked before any replay work runs.
    """

    schema_version: str
    tool_version: str
    contract_version: str
    provider_identity: Identity
    consumer_identity: Identity
    dependency_evidence: DependencyEvidence
    import_mappings: tuple[ImportMapping, ...]
    references: tuple[CodeReference, ...]
    coverage: CoverageSummary
    license_evidence: tuple[LicenseSnippetEvidence, ...]
    report_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != REPORT_SCHEMA_VERSION:
            raise ValueError("report.schema_version is unsupported")
        if not self.tool_version or not self.contract_version:
            raise ValueError("report.tool_version and contract_version must be non-empty")
        if self.provider_identity.role != "provider":
            raise ValueError("report.provider_identity.role must be 'provider'")
        if self.consumer_identity.role != "consumer":
            raise ValueError("report.consumer_identity.role must be 'consumer'")
        if len(self.import_mappings) > MAX_IMPORT_MAPPINGS:
            raise ValueError("report.import_mappings exceeds the cap")
        distributions = [mapping.distribution for mapping in self.import_mappings]
        if len(set(distributions)) != len(distributions):
            raise ValueError("report.import_mappings must not repeat a distribution")
        if len(self.references) > MAX_REFERENCES:
            raise ValueError("report.references exceeds the cap")
        if len(self.license_evidence) > MAX_LICENSE_EVIDENCE:
            raise ValueError("report.license_evidence exceeds the cap")
        if not is_sha256_digest(self.report_digest):
            raise ValueError("report.report_digest must be a sha256:<64 lowercase hex> digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "contract_version": self.contract_version,
            "provider_identity": self.provider_identity.to_dict(),
            "consumer_identity": self.consumer_identity.to_dict(),
            "dependency_evidence": self.dependency_evidence.to_dict(),
            "import_mappings": [mapping.to_dict() for mapping in self.import_mappings],
            "references": [reference.to_dict() for reference in self.references],
            "coverage": self.coverage.to_dict(),
            "license_evidence": [evidence.to_dict() for evidence in self.license_evidence],
            "report_digest": self.report_digest,
        }

    def recompute_digest(self) -> str:
        """Return the digest ``report_digest`` must equal for a self-consistent report."""

        payload = self.to_dict()
        del payload["report_digest"]
        return digest_value(payload)

    def to_json_bytes(self) -> bytes:
        """Return the canonical (stable, sorted-key) JSON encoding of this report."""

        return canonical_bytes(self.to_dict())


_REPORT_FIELDS = frozenset(
    {
        "schema_version",
        "tool_version",
        "contract_version",
        "provider_identity",
        "consumer_identity",
        "dependency_evidence",
        "import_mappings",
        "references",
        "coverage",
        "license_evidence",
        "report_digest",
    }
)


def build_report(
    *,
    provider_identity: Identity,
    consumer_identity: Identity,
    dependency_evidence: DependencyEvidence,
    import_mappings: Sequence[ImportMapping],
    references: Sequence[CodeReference],
    coverage: CoverageSummary,
    license_evidence: Sequence[LicenseSnippetEvidence],
    tool_version: str = TOOL_VERSION,
    contract_version: str = CONTRACT_VERSION,
) -> UsageReport:
    """Construct a self-consistent :class:`UsageReport`, computing its digest."""

    draft = UsageReport(
        schema_version=REPORT_SCHEMA_VERSION,
        tool_version=tool_version,
        contract_version=contract_version,
        provider_identity=provider_identity,
        consumer_identity=consumer_identity,
        dependency_evidence=dependency_evidence,
        import_mappings=tuple(import_mappings),
        references=tuple(references),
        coverage=coverage,
        license_evidence=tuple(license_evidence),
        report_digest="sha256:" + "0" * 64,
    )
    digest = draft.recompute_digest()
    return UsageReport(
        schema_version=draft.schema_version,
        tool_version=draft.tool_version,
        contract_version=draft.contract_version,
        provider_identity=draft.provider_identity,
        consumer_identity=draft.consumer_identity,
        dependency_evidence=draft.dependency_evidence,
        import_mappings=draft.import_mappings,
        references=draft.references,
        coverage=draft.coverage,
        license_evidence=draft.license_evidence,
        report_digest=digest,
    )


def report_from_dict(payload: object, *, stage: str = "validate") -> UsageReport:
    """Parse and validate a closed usage report; reject before any replay work.

    Raises :class:`UsageMalformedError` for structural defects,
    :class:`UsageUnsupportedError` for an unsupported version, and
    :class:`UsageTamperError` when the report's own ``report_digest`` does
    not match the digest recomputed from its declared content.
    """

    context = "report"
    body = _closed_dict(payload, _REPORT_FIELDS, stage=stage, context=context)
    _require_schema_version(body, REPORT_SCHEMA_VERSION, stage=stage, context=context)
    provider = _identity_from_dict(
        body["provider_identity"], stage=stage, context=f"{context}.provider_identity", expected_role="provider"
    )
    consumer = _identity_from_dict(
        body["consumer_identity"], stage=stage, context=f"{context}.consumer_identity", expected_role="consumer"
    )
    dependency_evidence = _dependency_from_dict(body["dependency_evidence"], stage=stage, context=f"{context}.dependency_evidence")
    mappings_field = _require_list(body, "import_mappings", stage=stage, context=context, maximum=MAX_IMPORT_MAPPINGS)
    import_mappings = _parse_tuple(
        mappings_field,
        lambda item, index: _import_mapping_from_dict(item, stage=stage, context=f"{context}.import_mappings[{index}]"),
        stage=stage,
        context=context,
    )
    references_field = _require_list(body, "references", stage=stage, context=context, maximum=MAX_REFERENCES)
    references = _parse_tuple(
        references_field,
        lambda item, index: _reference_from_dict(item, stage=stage, context=f"{context}.references[{index}]"),
        stage=stage,
        context=context,
    )
    coverage = _coverage_summary_from_dict(body["coverage"], stage=stage, context=f"{context}.coverage")
    license_field = _require_list(body, "license_evidence", stage=stage, context=context, maximum=MAX_LICENSE_EVIDENCE)
    license_evidence = _parse_tuple(
        license_field,
        lambda item, index: _license_from_dict(item, stage=stage, context=f"{context}.license_evidence[{index}]"),
        stage=stage,
        context=context,
    )
    report_digest = _require_digest(body, "report_digest", stage=stage, context=context)
    try:
        report = UsageReport(
            schema_version=REPORT_SCHEMA_VERSION,
            tool_version=_require_str(body, "tool_version", stage=stage, context=context),
            contract_version=_require_str(body, "contract_version", stage=stage, context=context),
            provider_identity=provider,
            consumer_identity=consumer,
            dependency_evidence=dependency_evidence,
            import_mappings=import_mappings,
            references=references,
            coverage=coverage,
            license_evidence=license_evidence,
            report_digest=report_digest,
        )
    except ValueError as exc:
        raise _malformed(stage, context, str(exc)) from exc
    expected_digest = report.recompute_digest()
    if expected_digest != report.report_digest:
        raise _tamper(
            stage,
            f"{context}.report_digest",
            "does not match the digest recomputed from the report's own content",
            expected=expected_digest,
            actual=report.report_digest,
        )
    return report


def report_from_json_bytes(data: bytes, *, stage: str = "validate") -> UsageReport:
    """Parse a closed usage report from raw JSON bytes."""

    if not isinstance(data, bytes):
        raise _malformed(stage, "report", "input must be bytes")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _malformed(stage, "report", f"is not valid UTF-8 JSON: {exc}") from exc
    return report_from_dict(payload, stage=stage)


# --------------------------------------------------------------------------
# Offline replay.
# --------------------------------------------------------------------------


def _extract_snippet(source_text: str, span: SourceSpan) -> str:
    lines = source_text.splitlines(keepends=True)
    if span.end_line > len(lines):
        raise ValueError("span end_line is beyond the end of the file")
    selected = lines[span.start_line - 1 : span.end_line]
    if len(selected) == 1:
        return selected[0][span.start_col : span.end_col]
    selected[0] = selected[0][span.start_col :]
    selected[-1] = selected[-1][: span.end_col]
    return "".join(selected)


def replay_report(report: UsageReport, *, corpus_root: Path, dependency_path: Path) -> UsageReport:
    """Deterministically, offline replay ``report`` against real corpus bytes.

    Recomputes every digest from the bytes actually present on disk --
    ``dependency_path`` for the pinned ``requirements.txt``, and each code
    reference's span read from ``corpus_root`` -- and compares them against
    what the report declares. This is the only place tamper of the
    *fixture/corpus bytes themselves* (as opposed to the report's own
    internal self-consistency, checked by :func:`report_from_dict`) can be
    caught, so it deliberately never trusts the report's own recorded text
    as a stand-in for the real file.

    Performs no network access, imports or executes no consumer code, and
    writes nothing. On success, returns ``report`` unchanged (the replay is
    a verification, never a substitution); on any mismatch it raises
    :class:`UsageTamperError` before doing anything else with the input, and
    on any structurally invalid on-disk input it raises
    :class:`UsageMalformedError`.
    """

    stage = "replay"
    dependency = report.dependency_evidence
    try:
        on_disk_requirements = read_regular_file(dependency_path, maximum_bytes=MAX_REQUIREMENTS_BYTES, no_follow=True)
    except OSError as exc:
        raise _malformed(stage, "dependency_evidence.requirements_text", f"could not be read: {exc}") from exc
    try:
        on_disk_text = on_disk_requirements.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _malformed(stage, "dependency_evidence.requirements_text", "is not valid UTF-8") from exc
    if on_disk_text != dependency.requirements_text:
        raise _tamper(
            stage,
            "dependency_evidence.requirements_text",
            "does not match the requirements.txt bytes actually on disk",
        )
    recomputed_dependency_digest = digest_bytes(on_disk_requirements)
    if recomputed_dependency_digest != dependency.requirements_digest:
        raise _tamper(
            stage,
            "dependency_evidence.requirements_digest",
            "does not match the digest of the requirements.txt bytes actually on disk",
            expected=recomputed_dependency_digest,
            actual=dependency.requirements_digest,
        )

    source_cache: dict[str, str] = {}
    for index, reference in enumerate(report.references):
        relative = reference.span.file
        if relative not in source_cache:
            try:
                path = confined_path(corpus_root, relative)
            except ValueError as exc:
                raise _malformed(stage, f"references[{index}].span.file", str(exc)) from exc
            try:
                raw = read_regular_file(path, maximum_bytes=MAX_SNIPPET_BYTES, no_follow=True)
            except OSError as exc:
                raise _malformed(stage, f"references[{index}].span.file", f"could not be read: {exc}") from exc
            try:
                source_cache[relative] = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _malformed(stage, f"references[{index}].span.file", "is not valid UTF-8") from exc
        try:
            snippet = _extract_snippet(source_cache[relative], reference.span)
        except ValueError as exc:
            raise _malformed(stage, f"references[{index}].span", str(exc)) from exc
        recomputed = digest_bytes(snippet.encode("utf-8"))
        if recomputed != reference.code_digest:
            raise _tamper(
                stage,
                f"references[{index}].code_digest",
                "does not match the digest recomputed from the source span",
                expected=recomputed,
                actual=reference.code_digest,
            )

    recomputed_report_digest = report.recompute_digest()
    if recomputed_report_digest != report.report_digest:
        raise _tamper(
            stage,
            "report_digest",
            "does not match the digest recomputed from the report's own content",
            expected=recomputed_report_digest,
            actual=report.report_digest,
        )
    return report
