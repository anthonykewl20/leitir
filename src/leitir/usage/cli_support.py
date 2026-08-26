"""CLI-facing support for the leitir ``usage`` subcommand (issue #259, #266 B2).

Wires the frozen usage contract (#255), admission/import catalog (#256),
static resolver (#257), and evidence assembler (#258) into three offline
operations the CLI exposes:

- ``assemble`` -- parse a closed ``assemble-plan.json`` (typed resolver
  output, import-catalog evidence, and dependency/identity evidence, all
  supplied by the caller), call ``leitir.usage.assemble.assemble_usage_evidence``,
  and atomically write the resulting ``report.json``. The freshly assembled
  report is round-tripped through the exact parser ``verify`` uses
  (``leitir.usage.report_from_json_bytes``) *before* anything touches disk:
  a report that would fail its own ``verify`` is rejected here, at assembly
  time, rather than written out as an artifact that only fails later.
- ``verify`` -- parse and structurally validate a usage evidence report
  (``leitir.usage.report_from_json_bytes``), rejecting a malformed,
  unsupported, or self-inconsistent (tampered) report before returning
  anything.
- ``replay`` -- fully offline, deterministic replay of an already-verified
  report against the real corpus/requirements bytes on disk
  (``leitir.usage.replay_report``), run ``times`` times (default 2) and
  compared byte-for-byte.

Nothing here performs network I/O or imports/executes consumer code: every
file read goes through ``leitir.usage._io.read_portable_file`` (itself backed by
``leitir.safeio.read_regular_file``) with an explicit byte bound, and replay only ever reads source text to recompute digests,
never executes it. The assembled report is written with
``leitir.safeio.atomic_write_bytes`` -- the same tempfile + ``os.replace`` +
fsync primitive ``leitir.materialize._write_manifest`` uses -- so a crash or
concurrent read never observes a partially written ``report.json``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..safeio import atomic_write_bytes
from . import (
    MAX_IMPORT_MAPPINGS,
    MAX_IMPORT_ROOTS_PER_MAPPING,
    MAX_REFERENCES,
    DependencyEvidence,
    Identity,
    ImportMapping,
    UnresolvedState,
    UsageErrorEvidence,
    UsageMalformedError,
    UsageReport,
    UsageTamperError,
    UsageUnsupportedError,
    replay_report,
    report_from_json_bytes,
)
from ._io import read_portable_file
from .assemble import REFERENCE_BATCH_SCHEMA_VERSION, ReferenceBatch, assemble_usage_evidence
from .contract import (
    _closed_dict,
    _coverage_summary_from_dict,
    _dependency_from_dict,
    _identity_from_dict,
    _import_mapping_from_dict,
    _malformed,
    _parse_tuple,
    _reference_from_dict,
    _require_list,
    _require_schema_version,
    _require_str,
)
from .import_catalog import (
    DISTRIBUTION_RECORD_SCHEMA_VERSION,
    UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
    DistributionRecord,
    UnresolvedDistribution,
)

# A generous but bounded cap on the report document itself -- reports are
# closed, capped structures (MAX_REFERENCES etc. in contract.py), so a
# report this large already implies a cap was hit; this is purely a
# CLI-boundary read guard, not a contract bound, so it is declared here
# rather than in the frozen contract module.
MAX_REPORT_BYTES = 4 * 1024 * 1024

#: CLI-boundary read guard on the assemble-plan document. Larger than
#: ``MAX_REPORT_BYTES`` because a plan is pre-deduplication -- the same
#: logical usage can legitimately appear in several ``reference_batches``
#: before ``assemble_usage_evidence`` collapses it into one result.
MAX_PLAN_BYTES = 8 * 1024 * 1024

CLI_VERIFY_SCHEMA_VERSION = "leitir-usage-cli-verify-v1"
CLI_REPLAY_SCHEMA_VERSION = "leitir-usage-cli-replay-v1"
CLI_ASSEMBLE_SCHEMA_VERSION = "leitir-usage-cli-assemble-v1"

#: Schema version for the CLI-only "assemble plan" input document -- the
#: typed evidence ``assemble_usage_evidence`` needs, expressed as closed
#: JSON so it can be produced by an offline tool and read back
#: deterministically. This is a CLI-boundary convenience format, not part
#: of the frozen #255 report contract.
ASSEMBLE_PLAN_SCHEMA_VERSION = "leitir-usage-cli-assemble-plan-v1"

_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "provider_identity",
        "consumer_identity",
        "dependency_evidence",
        "import_mappings",
        "reference_batches",
        "unresolved_distributions",
        "path_prefix",
    }
)
_REFERENCE_BATCH_FIELDS = frozenset({"origin", "references", "coverage"})
_DISTRIBUTION_RECORD_FIELDS = frozenset({"distribution", "declared_roots", "source"})
_UNRESOLVED_DISTRIBUTION_FIELDS = frozenset({"distribution", "state", "reason", "evidence"})


def _identity_payload(identity: Identity) -> dict[str, object]:
    return {"name": identity.name, "version": identity.version, "digest": identity.digest}


def load_report(report_path: Path) -> UsageReport:
    """Read and structurally validate a usage report from ``report_path``.

    Raises :class:`leitir.usage.UsageMalformedError` (missing file,
    permission denied, not a regular file, or any other operating-system
    read failure), :class:`leitir.usage.UsageUnsupportedError` (the file
    on disk exceeds ``MAX_REPORT_BYTES``, or the parsed report declares an
    unsupported schema/parser version), or :class:`leitir.usage.UsageTamperError`
    (self-inconsistent ``report_digest``) -- never partially returns a
    report that failed validation, and never lets a bare ``OSError`` or
    ``ValueError`` escape to the caller, so the CLI's ``--json`` diagnostic
    contract always gets a structured ``usage_*`` envelope instead of raw
    Python exception text.
    """

    try:
        raw = read_portable_file(report_path, maximum_bytes=MAX_REPORT_BYTES)
    except ValueError as exc:
        raise UsageUnsupportedError(
            UsageErrorEvidence(
                message=f"report file exceeds the {MAX_REPORT_BYTES}-byte CLI read bound: {exc}",
                stage="load",
                field="report",
            )
        ) from exc
    except OSError as exc:
        raise UsageMalformedError(
            UsageErrorEvidence(
                message=f"report file could not be read: {exc}",
                stage="load",
                field="report",
            )
        ) from exc
    return report_from_json_bytes(raw)


def verify_payload(report: UsageReport) -> dict[str, object]:
    """Build the canonical CLI payload for a successfully verified report."""

    return {
        "schema_version": CLI_VERIFY_SCHEMA_VERSION,
        "action": "verify",
        "report_digest": report.report_digest,
        "tool_version": report.tool_version,
        "contract_version": report.contract_version,
        "provider": _identity_payload(report.provider_identity),
        "consumer": _identity_payload(report.consumer_identity),
        "reference_count": len(report.references),
        "import_mapping_count": len(report.import_mappings),
        "license_evidence_count": len(report.license_evidence),
        "coverage_cap": report.coverage.cap,
        "coverage_capped": report.coverage.capped,
        "coverage_record_count": len(report.coverage.records),
    }


def replay_payload(report: UsageReport, *, corpus_root: Path, dependency_path: Path, times: int = 2) -> dict[str, object]:
    """Replay ``report`` offline ``times`` times and confirm byte-identical output.

    Raises :class:`leitir.usage.UsageMalformedError`,
    :class:`leitir.usage.UsageUnsupportedError` (an on-disk file exceeds
    this build's whole-file read bound), or :class:`leitir.usage.UsageTamperError`
    (fail-closed) if any replay pass rejects the on-disk bytes. If every
    individual pass succeeds but their canonical bytes somehow disagree --
    which should be unreachable given :func:`leitir.usage.replay_report`'s
    own determinism -- this raises :class:`leitir.usage.UsageTamperError`
    rather than reporting a false "byte_identical" claim.

    Note: a successful, ``byte_identical`` replay proves *span-level*
    integrity -- every reference's recorded ``code_digest`` matches the
    bytes at its recorded span, read fresh from disk on each pass -- not
    whole-file integrity. Bytes outside every referenced span (e.g.
    unrelated content appended to a source file) are not covered by any
    digest this function checks.
    """

    if times < 1:
        raise ValueError("times must be >= 1")
    passes = [replay_report(report, corpus_root=corpus_root, dependency_path=dependency_path).to_json_bytes() for _ in range(times)]
    byte_identical = all(passed == passes[0] for passed in passes)
    if not byte_identical:
        raise UsageTamperError(
            UsageErrorEvidence(
                message="replay passes produced non-identical canonical bytes",
                stage="replay",
                field="report",
            )
        )
    return {
        "schema_version": CLI_REPLAY_SCHEMA_VERSION,
        "action": "replay",
        "report_digest": report.report_digest,
        "replay_count": times,
        "byte_identical": byte_identical,
    }


# --------------------------------------------------------------------------
# assemble: parse a closed "assemble plan" document into typed evidence.
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AssemblePlan:
    """Typed, validated inputs for :func:`leitir.usage.assemble.assemble_usage_evidence`.

    Everything :func:`assemble_usage_evidence` needs *except* ``consumer_root``
    (a local filesystem path supplied separately by the CLI, via
    ``--corpus-root``, never embedded in a portable plan document).
    """

    provider_identity: Identity
    consumer_identity: Identity
    dependency_evidence: DependencyEvidence
    import_mappings: tuple[ImportMapping, ...]
    reference_batches: tuple[ReferenceBatch, ...]
    unresolved_distributions: tuple[UnresolvedDistribution, ...]
    path_prefix: str


def _distribution_record_from_dict(payload: object, *, context: str) -> DistributionRecord:
    body = _closed_dict(payload, _DISTRIBUTION_RECORD_FIELDS, stage="validate", context=context)
    roots_field = _require_list(body, "declared_roots", stage="validate", context=context, maximum=MAX_IMPORT_ROOTS_PER_MAPPING)
    roots: list[str] = []
    for index, item in enumerate(roots_field):
        if not isinstance(item, str) or not item:
            raise _malformed("validate", f"{context}.declared_roots[{index}]", "must be a non-empty string")
        roots.append(item)
    try:
        return DistributionRecord(
            schema_version=DISTRIBUTION_RECORD_SCHEMA_VERSION,
            distribution=_require_str(body, "distribution", stage="validate", context=context),
            declared_roots=tuple(roots),
            source=_require_str(body, "source", stage="validate", context=context),
        )
    except ValueError as exc:
        raise _malformed("validate", context, str(exc)) from exc


def _unresolved_distribution_from_dict(payload: object, *, context: str) -> UnresolvedDistribution:
    body = _closed_dict(payload, _UNRESOLVED_DISTRIBUTION_FIELDS, stage="validate", context=context)
    state_raw = _require_str(body, "state", stage="validate", context=context)
    try:
        state = UnresolvedState(state_raw)
    except ValueError as exc:
        raise _malformed(
            "validate", f"{context}.state", "is not a member of the closed UnresolvedState set", actual=state_raw
        ) from exc
    evidence_field = _require_list(body, "evidence", stage="validate", context=context, maximum=MAX_IMPORT_MAPPINGS)
    evidence = _parse_tuple(
        evidence_field,
        lambda item, index: _distribution_record_from_dict(item, context=f"{context}.evidence[{index}]"),
        stage="validate",
        context=context,
    )
    try:
        return UnresolvedDistribution(
            schema_version=UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
            distribution=_require_str(body, "distribution", stage="validate", context=context),
            state=state,
            reason=_require_str(body, "reason", stage="validate", context=context),
            evidence=evidence,
        )
    except ValueError as exc:
        raise _malformed("validate", context, str(exc)) from exc


def _reference_batch_from_dict(payload: object, *, index: int) -> ReferenceBatch:
    context = f"plan.reference_batches[{index}]"
    body = _closed_dict(payload, _REFERENCE_BATCH_FIELDS, stage="validate", context=context)
    origin = _require_str(body, "origin", stage="validate", context=context)
    refs_field = _require_list(body, "references", stage="validate", context=context, maximum=MAX_REFERENCES)
    references = _parse_tuple(
        refs_field,
        lambda item, i: _reference_from_dict(item, stage="validate", context=f"{context}.references[{i}]"),
        stage="validate",
        context=context,
    )
    coverage = _coverage_summary_from_dict(body["coverage"], stage="validate", context=f"{context}.coverage")
    try:
        return ReferenceBatch(
            schema_version=REFERENCE_BATCH_SCHEMA_VERSION,
            origin=origin,
            references=references,
            coverage=coverage,
        )
    except ValueError as exc:
        raise _malformed("validate", context, str(exc)) from exc


def load_assemble_plan(plan_path: Path) -> AssemblePlan:
    """Read and structurally validate an assemble-plan document from ``plan_path``.

    Raises :class:`leitir.usage.UsageMalformedError` (missing file,
    permission denied, any other read failure, invalid JSON, or a
    structurally invalid plan field), or :class:`leitir.usage.UsageUnsupportedError`
    (the file on disk exceeds ``MAX_PLAN_BYTES``, or the parsed plan
    declares an unsupported ``schema_version`` or exceeds one of the
    contract's declared bounds) -- fail-closed, matching :func:`load_report`.
    """

    try:
        raw = read_portable_file(plan_path, maximum_bytes=MAX_PLAN_BYTES)
    except ValueError as exc:
        raise UsageUnsupportedError(
            UsageErrorEvidence(
                message=f"assemble plan file exceeds the {MAX_PLAN_BYTES}-byte CLI read bound: {exc}",
                stage="load",
                field="plan",
            )
        ) from exc
    except OSError as exc:
        raise UsageMalformedError(
            UsageErrorEvidence(
                message=f"assemble plan file could not be read: {exc}",
                stage="load",
                field="plan",
            )
        ) from exc

    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UsageMalformedError(
            UsageErrorEvidence(message=f"assemble plan is not valid UTF-8 JSON: {exc}", stage="load", field="plan")
        ) from exc

    body = _closed_dict(payload, _PLAN_FIELDS, stage="validate", context="plan")
    _require_schema_version(body, ASSEMBLE_PLAN_SCHEMA_VERSION, stage="validate", context="plan")

    provider_identity = _identity_from_dict(
        body["provider_identity"], stage="validate", context="plan.provider_identity", expected_role="provider"
    )
    consumer_identity = _identity_from_dict(
        body["consumer_identity"], stage="validate", context="plan.consumer_identity", expected_role="consumer"
    )
    dependency_evidence = _dependency_from_dict(body["dependency_evidence"], stage="validate", context="plan.dependency_evidence")

    mappings_field = _require_list(body, "import_mappings", stage="validate", context="plan", maximum=MAX_IMPORT_MAPPINGS)
    import_mappings = _parse_tuple(
        mappings_field,
        lambda item, i: _import_mapping_from_dict(item, stage="validate", context=f"plan.import_mappings[{i}]"),
        stage="validate",
        context="plan",
    )

    batches_field = _require_list(body, "reference_batches", stage="validate", context="plan", maximum=MAX_REFERENCES)
    reference_batches = tuple(_reference_batch_from_dict(item, index=i) for i, item in enumerate(batches_field))

    unresolved_field = _require_list(body, "unresolved_distributions", stage="validate", context="plan", maximum=MAX_IMPORT_MAPPINGS)
    unresolved_distributions = _parse_tuple(
        unresolved_field,
        lambda item, i: _unresolved_distribution_from_dict(item, context=f"plan.unresolved_distributions[{i}]"),
        stage="validate",
        context="plan",
    )

    path_prefix = _require_str(body, "path_prefix", stage="validate", context="plan", allow_empty=True)

    return AssemblePlan(
        provider_identity=provider_identity,
        consumer_identity=consumer_identity,
        dependency_evidence=dependency_evidence,
        import_mappings=import_mappings,
        reference_batches=reference_batches,
        unresolved_distributions=unresolved_distributions,
        path_prefix=path_prefix,
    )


def assemble_payload(plan: AssemblePlan, *, consumer_root: Path | None, out_path: Path) -> dict[str, object]:
    """Assemble a usage evidence report from ``plan`` and atomically write it to ``out_path``.

    The report is built entirely in memory
    (:func:`leitir.usage.assemble.assemble_usage_evidence`), then -- before
    a single byte reaches disk -- round-tripped through the exact parser
    ``leitir usage verify`` uses (:func:`leitir.usage.report_from_json_bytes`):
    a report this call would produce but that could not itself pass
    ``verify`` is rejected right here, at assembly time, as
    :class:`leitir.usage.UsageTamperError`, rather than written out as an
    artifact that only fails later at ``verify`` or ``replay``. Only after
    that self-verification succeeds is ``out_path`` written, atomically
    (:func:`leitir.safeio.atomic_write_bytes`: tempfile + ``os.replace`` +
    fsync) -- so a rejected assembly, or a crash mid-write, never leaves a
    partial or invalid ``report.json`` on disk.
    """

    assembled = assemble_usage_evidence(
        provider_identity=plan.provider_identity,
        consumer_identity=plan.consumer_identity,
        dependency_evidence=plan.dependency_evidence,
        import_mappings=plan.import_mappings,
        reference_batches=plan.reference_batches,
        unresolved_distributions=plan.unresolved_distributions,
        consumer_root=consumer_root,
        path_prefix=plan.path_prefix,
    )
    report_bytes = assembled.report.to_json_bytes()

    # CRITICAL: prove the report this call is about to write would itself
    # pass `leitir usage verify` -- round-trip it through the exact parser
    # `verify` uses before writing anything to disk.
    try:
        reparsed = report_from_json_bytes(report_bytes)
    except (UsageMalformedError, UsageUnsupportedError, UsageTamperError) as exc:
        raise UsageTamperError(
            UsageErrorEvidence(
                message=f"assembled report failed its own verify round-trip: {exc}",
                stage="assemble",
                field="report",
            )
        ) from exc
    if reparsed.report_digest != assembled.report.report_digest:
        raise UsageTamperError(
            UsageErrorEvidence(
                message="assembled report digest changed across the verify round-trip",
                stage="assemble",
                field="report.report_digest",
                expected=assembled.report.report_digest,
                actual=reparsed.report_digest,
            )
        )

    atomic_write_bytes(out_path, report_bytes)

    return {
        "schema_version": CLI_ASSEMBLE_SCHEMA_VERSION,
        "action": "assemble",
        "report_digest": assembled.report.report_digest,
        "output_path": str(out_path),
        "result_count": len(assembled.results),
        "capped_result_count": len(assembled.capped_results),
        "unresolved_distribution_count": len(assembled.unresolved_distributions),
        "capped": assembled.capped,
        "reference_count": len(assembled.report.references),
        "import_mapping_count": len(assembled.report.import_mappings),
        "license_evidence_count": len(assembled.report.license_evidence),
        "coverage_cap": assembled.report.coverage.cap,
        "coverage_capped": assembled.report.coverage.capped,
        "coverage_record_count": len(assembled.report.coverage.records),
    }
