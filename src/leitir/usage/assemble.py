"""Deterministic usage evidence assembly (issue #258).

This is the final assembly stage of the usage evidence pipeline: it takes
typed resolver output (:mod:`leitir.usage.resolver`), admission evidence
(:mod:`leitir.usage.admission`), and import-catalog evidence
(:mod:`leitir.usage.import_catalog`), and produces a bounded, explainable,
deterministic :class:`AssembledEvidenceReport`.

Four properties this module guarantees:

- **Explainable ranking** -- every :class:`UsageResult` carries a
  :class:`ScoreExplanation` naming each scoring component, its raw value,
  its weight, and its contribution; ties break on an explicit, stable
  ``tie_break_key`` derived only from the result's own identity fields
  (never insertion or hash order).
- **Provenance-preserving deduplication** -- two :class:`~leitir.usage.CodeReference`
  entries naming the same distribution and the same source span are the
  same logical usage and collapse into one :class:`UsageResult`, but every
  originating :class:`ProvenanceRecord` (one per origin/``code_digest``
  occurrence) is retained. Conflicting provenance (same identity,
  disagreeing ``code_digest``) is never silently merged or picked-one: it
  is retained and surfaced (``conflicting=True`` plus an
  ``AMBIGUOUS_BINDING`` coverage record).
- **Bounded snippets/results** -- ``MAX_RESULTS``, ``MAX_PROVENANCE_PER_RESULT``,
  ``MAX_LICENSE_SNIPPETS_PER_RESULT``, and ``MAX_TOTAL_OUTPUT_BYTES`` are
  never silently exceeded: a result whose provenance exceeds its cap, or
  that falls outside the ranked top ``MAX_RESULTS``, is moved (with its
  *full*, untruncated provenance) into ``capped_results`` and recorded as a
  ``CAP_EXCEEDED`` coverage entry; an oversized total assembled payload is
  rejected outright (:class:`~leitir.usage.errors.UsageUnsupportedError`)
  rather than silently truncated.
- **Advisory per-snippet licensing** -- every :class:`~leitir.usage.LicenseSnippetEvidence`
  this module produces has ``advisory=True`` and never asserts a definite
  SPDX id for content that carries no explicit ``SPDX-License-Identifier``
  marker (``license_guess="unknown"`` in that case).

Nothing here imports or executes consumer code. File reads (for the
advisory license scan) go through ``leitir.usage._io.read_portable_file``
(itself backed by ``leitir.safeio.read_regular_file``) with an explicit byte bound, and are entirely best-effort: any I/O failure
degrades to an "unknown" advisory license record rather than raising.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from leitir.safeio import confined_path

from ._canonical import canonical_bytes, digest_value, is_sha256_digest
from ._io import read_portable_file
from .contract import (
    CODE_REFERENCE_SCHEMA_VERSION,
    CONTRACT_VERSION,
    COVERAGE_RECORD_SCHEMA_VERSION,
    COVERAGE_SUMMARY_SCHEMA_VERSION,
    LICENSE_EVIDENCE_SCHEMA_VERSION,
    MAX_COVERAGE_CAP,
    MAX_IMPORT_MAPPINGS,
    MAX_LICENSE_EVIDENCE,
    MAX_REFERENCES,
    MAX_SNIPPET_BYTES,
    TOOL_VERSION,
    CodeReference,
    CoverageRecord,
    CoverageSummary,
    DependencyEvidence,
    Identity,
    ImportMapping,
    LicenseSnippetEvidence,
    SourceSpan,
    UnresolvedState,
    UsageReport,
    build_report,
)
from .errors import UsageErrorEvidence, UsageMalformedError, UsageUnsupportedError
from .import_catalog import UnresolvedDistribution

# --------------------------------------------------------------------------
# Schema version literals.
# --------------------------------------------------------------------------

ASSEMBLED_REPORT_SCHEMA_VERSION = "leitir-usage-assembled-report-v1"
USAGE_RESULT_SCHEMA_VERSION = "leitir-usage-result-v1"
CAPPED_RESULT_SCHEMA_VERSION = "leitir-usage-capped-result-v1"
PROVENANCE_RECORD_SCHEMA_VERSION = "leitir-usage-provenance-record-v1"
SCORE_EXPLANATION_SCHEMA_VERSION = "leitir-usage-score-explanation-v1"
SCORE_COMPONENT_SCHEMA_VERSION = "leitir-usage-score-component-v1"
REFERENCE_BATCH_SCHEMA_VERSION = "leitir-usage-reference-batch-v1"

# --------------------------------------------------------------------------
# Bounds (module-level, near their consumer -- see BRIEF.md convention).
# --------------------------------------------------------------------------

#: Maximum number of ranked results kept in ``AssembledEvidenceReport.results``.
MAX_RESULTS = 200

#: Maximum number of provenance records retained for one result before the
#: whole identity is moved (with its full provenance) to ``capped_results``.
MAX_PROVENANCE_PER_RESULT = 50

#: Maximum number of advisory license snippets attached to one result.
MAX_LICENSE_SNIPPETS_PER_RESULT = 5

#: Maximum number of leading lines of a file inspected for a license marker.
MAX_LICENSE_SCAN_LINES = 20

#: Maximum canonical-JSON byte size of one assembled report; exceeding this
#: is rejected outright (never silently truncated).
MAX_TOTAL_OUTPUT_BYTES = 1_048_576

# --------------------------------------------------------------------------
# Explicit, documented scoring function.
# --------------------------------------------------------------------------
#
# total_score = sum(weight * raw_value) over these components, evaluated in
# a fixed alphabetical component-name order so the explanation is always
# built (and thus serialized) in the same order regardless of dict/hash
# iteration behavior:
#
#   conflicting_penalty  -- 1.0 if the result's provenance disagrees on
#                            code_digest, else 0.0; weight -2.0 (conflicting
#                            evidence is surfaced, never hidden, but ranks
#                            lower because it is less trustworthy).
#   license_confidence    -- 2.0/1.0/0.0 for high/medium/low advisory
#                            license-scan confidence; weight 1.0.
#   provenance_count      -- number of retained provenance records; weight
#                            3.0 (usage reported from more places ranks
#                            higher).
#   span_width             -- (end_line - start_line + 1); weight 0.1 (a very
#                            small tie-nudge favoring wider usage sites).
#
# Ties on total_score break on ``tie_break_key``, a tuple of the result's
# own identity fields (distribution, file, zero-padded line/col numbers) so
# lexicographic string comparison matches numeric comparison -- a key
# derived only from the result's own data, never insertion or hash order.

_SCORE_WEIGHTS: dict[str, float] = {
    "conflicting_penalty": -2.0,
    "license_confidence": 1.0,
    "provenance_count": 3.0,
    "span_width": 0.1,
}

_LICENSE_CONFIDENCE_VALUE: dict[str, float] = {"high": 2.0, "medium": 1.0, "low": 0.0}

_SPDX_PATTERN = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+-]+)")
_WEAK_LICENSE_KEYWORD_PATTERN = re.compile(r"license", re.IGNORECASE)


# --------------------------------------------------------------------------
# Value objects.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScoreComponent:
    """One named, weighted signal contributing to a result's total score."""

    schema_version: str
    name: str
    weight: float
    raw_value: float
    contribution: float

    def __post_init__(self) -> None:
        if self.schema_version != SCORE_COMPONENT_SCHEMA_VERSION:
            raise ValueError("score_component.schema_version is unsupported")
        if not self.name:
            raise ValueError("score_component.name must be non-empty")
        for value in (self.weight, self.raw_value, self.contribution):
            if not isinstance(value, float) or value != value:  # NaN check (self != self)
                raise ValueError("score_component numeric fields must be finite floats")
        if self.contribution != self.weight * self.raw_value:
            raise ValueError("score_component.contribution must equal weight * raw_value")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "weight": self.weight,
            "raw_value": self.raw_value,
            "contribution": self.contribution,
        }


@dataclass(frozen=True, slots=True)
class ScoreExplanation:
    """The machine-readable explanation for one result's ranking score."""

    schema_version: str
    total_score: float
    components: tuple[ScoreComponent, ...]
    tie_break_key: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != SCORE_EXPLANATION_SCHEMA_VERSION:
            raise ValueError("score_explanation.schema_version is unsupported")
        if not self.components:
            raise ValueError("score_explanation.components must be non-empty")
        names = [component.name for component in self.components]
        if len(set(names)) != len(names):
            raise ValueError("score_explanation.components must not repeat a component name")
        expected_total = sum(component.contribution for component in self.components)
        if self.total_score != expected_total:
            raise ValueError("score_explanation.total_score must equal the sum of component contributions")
        if not self.tie_break_key or any(not part for part in self.tie_break_key):
            raise ValueError("score_explanation.tie_break_key must be a non-empty tuple of non-empty strings")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "total_score": self.total_score,
            "components": [component.to_dict() for component in self.components],
            "tie_break_key": list(self.tie_break_key),
        }


@dataclass(frozen=True, slots=True)
class ProvenanceRecord:
    """One originating occurrence (origin + exact code digest) for a result's identity."""

    schema_version: str
    code_digest: str
    consumer: str

    def __post_init__(self) -> None:
        if self.schema_version != PROVENANCE_RECORD_SCHEMA_VERSION:
            raise ValueError("provenance_record.schema_version is unsupported")
        if not is_sha256_digest(self.code_digest):
            raise ValueError("provenance_record.code_digest must be a sha256:<64 lowercase hex> digest")
        if not self.consumer:
            raise ValueError("provenance_record.consumer must be non-empty")

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": self.schema_version, "code_digest": self.code_digest, "consumer": self.consumer}


@dataclass(frozen=True, slots=True)
class UsageResult:
    """One deduplicated, ranked usage-evidence result.

    ``conflicting`` is derived and checked, never asserted independently of
    ``provenance``: it is ``True`` exactly when ``provenance`` carries more
    than one distinct ``code_digest`` for this identity.
    """

    schema_version: str
    distribution: str
    span: SourceSpan
    identity_digest: str
    provenance: tuple[ProvenanceRecord, ...]
    conflicting: bool
    license_snippets: tuple[LicenseSnippetEvidence, ...]
    score_explanation: ScoreExplanation

    def __post_init__(self) -> None:
        if self.schema_version != USAGE_RESULT_SCHEMA_VERSION:
            raise ValueError("usage_result.schema_version is unsupported")
        if not self.distribution:
            raise ValueError("usage_result.distribution must be non-empty")
        if not isinstance(self.span, SourceSpan):
            raise ValueError("usage_result.span must be a SourceSpan")
        if not is_sha256_digest(self.identity_digest):
            raise ValueError("usage_result.identity_digest must be a sha256:<64 lowercase hex> digest")
        if not self.provenance:
            raise ValueError("usage_result.provenance must be non-empty")
        if len(self.provenance) > MAX_PROVENANCE_PER_RESULT:
            raise ValueError("usage_result.provenance exceeds the per-result cap")
        digests = {record.code_digest for record in self.provenance}
        if self.conflicting != (len(digests) > 1):
            raise ValueError("usage_result.conflicting must reflect whether provenance code_digests disagree")
        if len(self.license_snippets) > MAX_LICENSE_SNIPPETS_PER_RESULT:
            raise ValueError("usage_result.license_snippets exceeds the per-result cap")
        for snippet in self.license_snippets:
            if snippet.advisory is not True:
                raise ValueError("usage_result.license_snippets must all be advisory")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "distribution": self.distribution,
            "span": self.span.to_dict(),
            "identity_digest": self.identity_digest,
            "provenance": [record.to_dict() for record in self.provenance],
            "conflicting": self.conflicting,
            "license_snippets": [snippet.to_dict() for snippet in self.license_snippets],
            "score_explanation": self.score_explanation.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class CappedResult:
    """A result excluded from ``results`` by a bound, with its full provenance retained.

    This is how a per-result or per-run cap is honored *without* ever
    dropping a duplicate provenance record: the identity is excluded from
    the ranked, bounded ``results`` list, but every provenance record it
    carried is preserved here, untruncated.
    """

    schema_version: str
    distribution: str
    span: SourceSpan
    identity_digest: str
    provenance: tuple[ProvenanceRecord, ...]
    reason: str

    def __post_init__(self) -> None:
        if self.schema_version != CAPPED_RESULT_SCHEMA_VERSION:
            raise ValueError("capped_result.schema_version is unsupported")
        if not self.distribution:
            raise ValueError("capped_result.distribution must be non-empty")
        if not isinstance(self.span, SourceSpan):
            raise ValueError("capped_result.span must be a SourceSpan")
        if not is_sha256_digest(self.identity_digest):
            raise ValueError("capped_result.identity_digest must be a sha256:<64 lowercase hex> digest")
        if not self.provenance:
            raise ValueError("capped_result.provenance must be non-empty")
        if not self.reason:
            raise ValueError("capped_result.reason must be non-empty")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "distribution": self.distribution,
            "span": self.span.to_dict(),
            "identity_digest": self.identity_digest,
            "provenance": [record.to_dict() for record in self.provenance],
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ReferenceBatch:
    """One batch of typed resolver output, tagged with a human-readable origin.

    ``origin`` becomes :attr:`ProvenanceRecord.consumer` for every reference
    in this batch -- it names where the evidence came from (a resolver run,
    a file glob, a consumer identity) so provenance stays attributable after
    batches from multiple sources are merged.
    """

    schema_version: str
    origin: str
    references: tuple[CodeReference, ...]
    coverage: CoverageSummary

    def __post_init__(self) -> None:
        if self.schema_version != REFERENCE_BATCH_SCHEMA_VERSION:
            raise ValueError("reference_batch.schema_version is unsupported")
        if not self.origin:
            raise ValueError("reference_batch.origin must be non-empty")
        if not isinstance(self.coverage, CoverageSummary):
            raise ValueError("reference_batch.coverage must be a CoverageSummary")


@dataclass(frozen=True, slots=True)
class AssembledEvidenceReport:
    """The final, bounded, explainable, deterministic usage evidence report."""

    schema_version: str
    report: UsageReport
    results: tuple[UsageResult, ...]
    capped_results: tuple[CappedResult, ...]
    unresolved_distributions: tuple[UnresolvedDistribution, ...]
    capped: bool

    def __post_init__(self) -> None:
        if self.schema_version != ASSEMBLED_REPORT_SCHEMA_VERSION:
            raise ValueError("assembled_report.schema_version is unsupported")
        if not isinstance(self.report, UsageReport):
            raise ValueError("assembled_report.report must be a UsageReport")
        if len(self.results) > MAX_RESULTS:
            raise ValueError("assembled_report.results exceeds the cap")
        ordering = [(-result.score_explanation.total_score, result.score_explanation.tie_break_key) for result in self.results]
        if ordering != sorted(ordering):
            raise ValueError("assembled_report.results must be sorted by descending score with deterministic tie-break")
        identity_digests = [result.identity_digest for result in self.results]
        if len(set(identity_digests)) != len(identity_digests):
            raise ValueError("assembled_report.results must not repeat an identity_digest")
        if type(self.capped) is not bool:
            raise ValueError("assembled_report.capped must be a bool")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "report": self.report.to_dict(),
            "results": [result.to_dict() for result in self.results],
            "capped_results": [entry.to_dict() for entry in self.capped_results],
            "unresolved_distributions": [
                {
                    "schema_version": entry.schema_version,
                    "distribution": entry.distribution,
                    "state": entry.state.value,
                    "reason": entry.reason,
                }
                for entry in self.unresolved_distributions
            ],
            "capped": self.capped,
        }

    def to_json_bytes(self) -> bytes:
        """Return the canonical (stable, sorted-key) JSON encoding of this report."""

        return canonical_bytes(self.to_dict())


# --------------------------------------------------------------------------
# Internal helpers.
# --------------------------------------------------------------------------


def _identity_key(reference: CodeReference) -> tuple[str, str, int, int, int, int]:
    span = reference.span
    return (reference.distribution, span.file, span.start_line, span.start_col, span.end_line, span.end_col)


def _identity_digest(key: tuple[str, str, int, int, int, int]) -> str:
    distribution, file, start_line, start_col, end_line, end_col = key
    return digest_value(
        {
            "distribution": distribution,
            "file": file,
            "start_line": start_line,
            "start_col": start_col,
            "end_line": end_line,
            "end_col": end_col,
        }
    )


def _tie_break_key(distribution: str, span: SourceSpan) -> tuple[str, ...]:
    return (
        distribution,
        span.file,
        f"{span.start_line:010d}",
        f"{span.start_col:010d}",
        f"{span.end_line:010d}",
        f"{span.end_col:010d}",
    )


def _score_components(*, provenance_count: int, conflicting: bool, license_confidence: str, span_width: int) -> tuple[ScoreComponent, ...]:
    raw_values: dict[str, float] = {
        "conflicting_penalty": 1.0 if conflicting else 0.0,
        "license_confidence": _LICENSE_CONFIDENCE_VALUE.get(license_confidence, 0.0),
        "provenance_count": float(provenance_count),
        "span_width": float(span_width),
    }
    components: list[ScoreComponent] = []
    for name in sorted(_SCORE_WEIGHTS):
        weight = _SCORE_WEIGHTS[name]
        raw_value = raw_values[name]
        components.append(
            ScoreComponent(
                schema_version=SCORE_COMPONENT_SCHEMA_VERSION,
                name=name,
                weight=weight,
                raw_value=raw_value,
                contribution=weight * raw_value,
            )
        )
    return tuple(components)


def _scan_license_evidence(
    *,
    span: SourceSpan,
    consumer_root: Path | None,
    path_prefix: str,
    max_scan_bytes: int,
    max_scan_lines: int,
) -> LicenseSnippetEvidence:
    """Best-effort, advisory license scan of the leading lines of ``span.file``.

    Never raises: any I/O failure (missing root, unreadable/oversized file,
    bad UTF-8, escaping path) degrades to an "unknown" advisory record
    rather than propagating -- license evidence is advisory by contract and
    must never block assembly.
    """

    guess = "unknown"
    confidence = "low"
    if consumer_root is not None:
        relative = span.file
        if path_prefix and relative.startswith(path_prefix):
            relative = relative[len(path_prefix) :]
        try:
            target = confined_path(consumer_root, relative)
            data = read_portable_file(target, maximum_bytes=max_scan_bytes)
            text = data.decode("utf-8")
        except (OSError, ValueError, UnicodeDecodeError):
            text = ""
        header = "\n".join(text.splitlines()[:max_scan_lines])
        spdx_match = _SPDX_PATTERN.search(header)
        if spdx_match:
            guess = spdx_match.group(1)
            confidence = "high"
        elif _WEAK_LICENSE_KEYWORD_PATTERN.search(header):
            guess = "unknown"
            confidence = "medium"
    return LicenseSnippetEvidence(
        schema_version=LICENSE_EVIDENCE_SCHEMA_VERSION,
        span=span,
        license_guess=guess,
        confidence=confidence,
        advisory=True,
    )


def _reject_unsupported(field: str, message: str, *, expected: str, actual: str) -> UsageUnsupportedError:
    return UsageUnsupportedError(
        UsageErrorEvidence(message=message, stage="validate", field=field, expected=expected, actual=actual)
    )


# --------------------------------------------------------------------------
# Public entry point.
# --------------------------------------------------------------------------


def assemble_usage_evidence(
    *,
    provider_identity: Identity,
    consumer_identity: Identity,
    dependency_evidence: DependencyEvidence,
    import_mappings: Sequence[ImportMapping],
    reference_batches: Sequence[ReferenceBatch],
    unresolved_distributions: Sequence[UnresolvedDistribution] = (),
    consumer_root: Path | None = None,
    path_prefix: str = "",
    max_results: int = MAX_RESULTS,
    max_provenance_per_result: int = MAX_PROVENANCE_PER_RESULT,
    max_license_snippets_per_result: int = MAX_LICENSE_SNIPPETS_PER_RESULT,
    max_license_scan_bytes: int = MAX_SNIPPET_BYTES,
    max_license_scan_lines: int = MAX_LICENSE_SCAN_LINES,
    max_total_output_bytes: int = MAX_TOTAL_OUTPUT_BYTES,
    tool_version: str = TOOL_VERSION,
    contract_version: str = CONTRACT_VERSION,
) -> AssembledEvidenceReport:
    """Assemble bounded, explainable, deterministic usage evidence.

    ``reference_batches`` supplies one or more batches of typed resolver
    output (see :class:`ReferenceBatch`); references naming the same
    distribution and source span across batches are the same logical usage
    and collapse into one :class:`UsageResult`, retaining every provenance
    record. ``unresolved_distributions`` (typically
    :attr:`~leitir.usage.import_catalog.ImportCatalog.unresolved`) is
    carried forward verbatim and also folded into the underlying report's
coverage as exclusion entries (``"unresolved-distribution:<name>:<state>"``).

    ``CoverageSummary.exclusions`` grammar (undocumented in the frozen #255
    contract, since ``exclusions`` is declared there only as an opaque
    ``tuple[str, ...]`` free-text bag -- this docstring is the closest
    thing to a spec). This module contributes exactly three colon-delimited
    string shapes into that shared bag, alongside whatever opaque strings
    upstream resolver batches already put there:

    - ``"unresolved-distribution:<name>:<state>"`` -- one entry per
      ``unresolved_distributions`` member, added here.
    - ``"assemble:conflicting-provenance:<identity_digest>"`` -- a result
      whose provenance records disagree on ``code_digest`` for the same
      logical usage (see the ``conflicting`` branch above).
    - ``"assemble:capped-result:<identity_digest>"`` -- a result excluded
      from ``results``/``capped_results`` bookkeeping by
      ``max_provenance_per_result`` or ranking (see the ``CAP_EXCEEDED``
      branch above).

    **Collision caveat**: all three shapes, plus any upstream batch's own
    exclusion strings, share one flat ``set[str]`` with no namespacing
    enforced beyond the literal prefixes above -- nothing prevents an
    upstream batch from independently emitting a string that happens to
    collide with one of these three shapes (they would simply deduplicate,
    silently). ``<name>`` in the first shape is PEP 503-normalized (never
    contains ``:``); ``<state>`` is an ``UnresolvedState.value`` (also
    never contains ``:``); ``<identity_digest>`` is a ``sha256:``-prefixed
    digest string, which DOES contain a ``:`` -- round-tripping any of
    these three shapes back into parts must use ``rsplit(":", 1)`` (state
    values never contain ``:``, so this recovers ``state`` correctly even
    though ``identity_digest`` itself has an internal colon) rather than a
    naive ``split(":")``. There is no reverse-parsing helper in this
    package; a caller that needs to distinguish these programmatically
    should match on the literal prefix (``"unresolved-distribution:"``,
    ``"assemble:conflicting-provenance:"``, ``"assemble:capped-result:"``)
    rather than guessing at colon positions.

    Every bound is enforced without ever dropping a duplicate provenance
    record: a result whose provenance exceeds ``max_provenance_per_result``,
    or that ranks outside the top ``max_results``, is excluded from
    ``results`` but preserved (with full, untruncated provenance) in
    ``capped_results``, and recorded as a ``CAP_EXCEEDED`` coverage entry.
    Only the whole-payload ``max_total_output_bytes`` bound is enforced by
    outright rejection (:class:`~leitir.usage.errors.UsageUnsupportedError`)
    rather than partial output, since there is no meaningful way to retain
    "some" of an oversized payload without silently truncating it.
    """

    groups: dict[tuple[str, str, int, int, int, int], list[tuple[str, CodeReference]]] = {}
    for batch in reference_batches:
        for reference in batch.references:
            groups.setdefault(_identity_key(reference), []).append((batch.origin, reference))

    accepted_results: list[UsageResult] = []
    capped_entries: list[CappedResult] = []
    extra_coverage_records: list[CoverageRecord] = []
    license_cache: dict[str, LicenseSnippetEvidence] = {}

    for key in sorted(groups):
        distribution, file, start_line, start_col, end_line, end_col = key
        span = SourceSpan(file=file, start_line=start_line, start_col=start_col, end_line=end_line, end_col=end_col)
        identity_digest = _identity_digest(key)
        occurrences = sorted(groups[key], key=lambda item: (item[0], item[1].code_digest))
        provenance = tuple(
            ProvenanceRecord(schema_version=PROVENANCE_RECORD_SCHEMA_VERSION, code_digest=reference.code_digest, consumer=origin)
            for origin, reference in occurrences
        )
        conflicting = len({record.code_digest for record in provenance}) > 1

        if len(provenance) > max_provenance_per_result:
            capped_entries.append(
                CappedResult(
                    schema_version=CAPPED_RESULT_SCHEMA_VERSION,
                    distribution=distribution,
                    span=span,
                    identity_digest=identity_digest,
                    provenance=provenance,
                    reason="provenance-cap-exceeded",
                )
            )
            extra_coverage_records.append(
                CoverageRecord(
                    schema_version=COVERAGE_RECORD_SCHEMA_VERSION,
                    file=f"assemble:capped-result:{identity_digest}",
                    state=UnresolvedState.CAP_EXCEEDED,
                )
            )
            continue

        if conflicting:
            extra_coverage_records.append(
                CoverageRecord(
                    schema_version=COVERAGE_RECORD_SCHEMA_VERSION,
                    file=f"assemble:conflicting-provenance:{identity_digest}",
                    state=UnresolvedState.AMBIGUOUS_BINDING,
                )
            )

        if file not in license_cache:
            license_cache[file] = _scan_license_evidence(
                span=span,
                consumer_root=consumer_root,
                path_prefix=path_prefix,
                max_scan_bytes=max_license_scan_bytes,
                max_scan_lines=max_license_scan_lines,
            )
        license_snippets: tuple[LicenseSnippetEvidence, ...] = (license_cache[file],)
        if len(license_snippets) > max_license_snippets_per_result:
            license_snippets = ()
            extra_coverage_records.append(
                CoverageRecord(
                    schema_version=COVERAGE_RECORD_SCHEMA_VERSION,
                    file=f"assemble:capped-license:{identity_digest}",
                    state=UnresolvedState.CAP_EXCEEDED,
                )
            )

        license_confidence = license_snippets[0].confidence if license_snippets else "low"
        span_width = end_line - start_line + 1
        components = _score_components(
            provenance_count=len(provenance), conflicting=conflicting, license_confidence=license_confidence, span_width=span_width
        )
        explanation = ScoreExplanation(
            schema_version=SCORE_EXPLANATION_SCHEMA_VERSION,
            total_score=sum(component.contribution for component in components),
            components=components,
            tie_break_key=_tie_break_key(distribution, span),
        )
        accepted_results.append(
            UsageResult(
                schema_version=USAGE_RESULT_SCHEMA_VERSION,
                distribution=distribution,
                span=span,
                identity_digest=identity_digest,
                provenance=provenance,
                conflicting=conflicting,
                license_snippets=license_snippets,
                score_explanation=explanation,
            )
        )

    accepted_results.sort(key=lambda result: (-result.score_explanation.total_score, result.score_explanation.tie_break_key))
    if len(accepted_results) > max_results:
        overflow = accepted_results[max_results:]
        accepted_results = accepted_results[:max_results]
        for result in overflow:
            capped_entries.append(
                CappedResult(
                    schema_version=CAPPED_RESULT_SCHEMA_VERSION,
                    distribution=result.distribution,
                    span=result.span,
                    identity_digest=result.identity_digest,
                    provenance=result.provenance,
                    reason="results-cap-exceeded",
                )
            )
            extra_coverage_records.append(
                CoverageRecord(
                    schema_version=COVERAGE_RECORD_SCHEMA_VERSION,
                    file=f"assemble:capped-result:{result.identity_digest}",
                    state=UnresolvedState.CAP_EXCEEDED,
                )
            )

    capped_entries.sort(
        key=lambda entry: (entry.distribution, entry.span.file, entry.span.start_line, entry.span.start_col, entry.span.end_line, entry.span.end_col)
    )

    # ---- Merge coverage across batches, capped entries, and unresolved distributions. ----
    merged_records: dict[str, CoverageRecord] = {}
    merged_exclusions: set[str] = set()
    any_input_capped = False
    for batch in reference_batches:
        any_input_capped = any_input_capped or batch.coverage.capped
        for record in batch.coverage.records:
            existing = merged_records.get(record.file)
            if existing is not None and existing.state != record.state:
                raise UsageMalformedError(
                    UsageErrorEvidence(
                        message=f"coverage records disagree for file {record.file!r}",
                        stage="validate",
                        field="coverage.records",
                        expected=existing.state.value,
                        actual=record.state.value,
                    )
                )
            merged_records[record.file] = record
        merged_exclusions.update(batch.coverage.exclusions)

    for record in extra_coverage_records:
        merged_records[record.file] = record

    sorted_unresolved = tuple(sorted(unresolved_distributions, key=lambda entry: entry.distribution))
    for unresolved in sorted_unresolved:
        merged_exclusions.add(f"unresolved-distribution:{unresolved.distribution}:{unresolved.state.value}")

    merged_exclusions -= set(merged_records)

    coverage_cap = MAX_COVERAGE_CAP
    total_entries = len(merged_records) + len(merged_exclusions)
    if total_entries > coverage_cap:
        raise _reject_unsupported(
            "coverage",
            "assembled coverage exceeds the maximum coverage cap",
            expected=f"<= {coverage_cap}",
            actual=str(total_entries),
        )
    capped_flag = any_input_capped or bool(capped_entries)

    coverage = CoverageSummary(
        schema_version=COVERAGE_SUMMARY_SCHEMA_VERSION,
        records=tuple(merged_records[key] for key in sorted(merged_records)),
        exclusions=tuple(sorted(merged_exclusions)),
        cap=coverage_cap,
        capped=capped_flag,
    )

    # ---- Build the underlying frozen UsageReport. ----
    report_references: list[CodeReference] = [
        CodeReference(
            schema_version=CODE_REFERENCE_SCHEMA_VERSION,
            distribution=result.distribution,
            span=result.span,
            code_digest=result.provenance[0].code_digest,
        )
        for result in accepted_results
        if not result.conflicting
    ]
    if len(report_references) > MAX_REFERENCES:
        raise _reject_unsupported(
            "references", "assembled references exceed the maximum cap", expected=f"<= {MAX_REFERENCES}", actual=str(len(report_references))
        )
    if len(import_mappings) > MAX_IMPORT_MAPPINGS:
        raise _reject_unsupported(
            "import_mappings",
            "assembled import mappings exceed the maximum cap",
            expected=f"<= {MAX_IMPORT_MAPPINGS}",
            actual=str(len(import_mappings)),
        )

    license_by_key: dict[tuple[str, int, int, int, int, str, str], LicenseSnippetEvidence] = {}
    for result in accepted_results:
        for snippet in result.license_snippets:
            license_by_key[
                (
                    snippet.span.file,
                    snippet.span.start_line,
                    snippet.span.start_col,
                    snippet.span.end_line,
                    snippet.span.end_col,
                    snippet.license_guess,
                    snippet.confidence,
                )
            ] = snippet
    if len(license_by_key) > MAX_LICENSE_EVIDENCE:
        raise _reject_unsupported(
            "license_evidence",
            "assembled license evidence exceeds the maximum cap",
            expected=f"<= {MAX_LICENSE_EVIDENCE}",
            actual=str(len(license_by_key)),
        )
    license_evidence = tuple(license_by_key[key] for key in sorted(license_by_key))

    report = build_report(
        provider_identity=provider_identity,
        consumer_identity=consumer_identity,
        dependency_evidence=dependency_evidence,
        import_mappings=import_mappings,
        references=report_references,
        coverage=coverage,
        license_evidence=license_evidence,
        tool_version=tool_version,
        contract_version=contract_version,
    )

    assembled = AssembledEvidenceReport(
        schema_version=ASSEMBLED_REPORT_SCHEMA_VERSION,
        report=report,
        results=tuple(accepted_results),
        capped_results=tuple(capped_entries),
        unresolved_distributions=sorted_unresolved,
        capped=capped_flag,
    )

    output_size = len(assembled.to_json_bytes())
    if output_size > max_total_output_bytes:
        raise _reject_unsupported(
            "assembled_report",
            "assembled evidence report exceeds the maximum total output size",
            expected=f"<= {max_total_output_bytes} bytes",
            actual=f"{output_size} bytes",
        )
    return assembled


__all__ = [
    "ASSEMBLED_REPORT_SCHEMA_VERSION",
    "CAPPED_RESULT_SCHEMA_VERSION",
    "MAX_LICENSE_SCAN_LINES",
    "MAX_LICENSE_SNIPPETS_PER_RESULT",
    "MAX_PROVENANCE_PER_RESULT",
    "MAX_RESULTS",
    "MAX_TOTAL_OUTPUT_BYTES",
    "PROVENANCE_RECORD_SCHEMA_VERSION",
    "REFERENCE_BATCH_SCHEMA_VERSION",
    "SCORE_COMPONENT_SCHEMA_VERSION",
    "SCORE_EXPLANATION_SCHEMA_VERSION",
    "USAGE_RESULT_SCHEMA_VERSION",
    "AssembledEvidenceReport",
    "CappedResult",
    "ProvenanceRecord",
    "ReferenceBatch",
    "ScoreComponent",
    "ScoreExplanation",
    "UsageResult",
    "assemble_usage_evidence",
]
