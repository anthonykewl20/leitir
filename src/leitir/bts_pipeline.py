"""Reusable end-to-end orchestration for one Behavioral Transplant Set donor.

The pipeline composes the authoritative BTS, relocation, rerun, and probe
boundaries.  It does not provide an alternate execution path: untrusted donor
execution continues to require the S2 nsjail policy and exact opt-in enforced by
``rerun_transplant`` and the supplied probe execution policy.  Leitir's own
reviewed fixture can replace those execution ports in tests; that exception is
not an authorization to execute external donor bytes without S2.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import Enum

from leitir.bts import (
    BTSBudget,
    BTSResult,
    BTSStatus,
    DonorSnapshot,
    GraphProvider,
    ResolutionPolicy,
    compute_bts,
)
from leitir.bts_errors import BTSRejectReason, TransplantError
from leitir.graph.model import NodeId
from leitir.probes import ProbeExecutionPolicy, ProbeReport, ProbeSet, ProbeStatus, run_probes
from leitir.relocate import (
    EMPTY_RECIPIENT_BINDINGS,
    ContractTest,
    ModuleMap,
    RecipientBindingManifest,
    Relocation,
    SourceFile,
    relocate_tests,
)
from leitir.rerun import (
    ContractBaselineEvidence,
    RerunExecutionPolicy,
    RerunReport,
    RerunResult,
    ValidationStatus,
    rerun_transplant,
)

PIPELINE_SCHEMA_VERSION = "leitir-bts-pipeline-v1"


@dataclass(frozen=True, slots=True)
class BTSPipelineRequest:
    """All donor-specific inputs needed by the reusable one-donor engine."""

    snapshot: DonorSnapshot
    seed: NodeId
    graph: GraphProvider
    budget: BTSBudget
    resolution_policy: ResolutionPolicy
    module_map: ModuleMap
    source_files: tuple[SourceFile, ...]
    contract_tests: tuple[ContractTest, ...]
    baseline: ContractBaselineEvidence
    rerun_execution_policy: RerunExecutionPolicy
    probe_set: ProbeSet
    probe_execution_policy: ProbeExecutionPolicy
    declared_external_modules: tuple[str, ...] = ()
    recipient_bindings: RecipientBindingManifest = EMPTY_RECIPIENT_BINDINGS
    test_import_aliases: tuple[tuple[str, str], ...] = ()
    # The CLI performs relocation before it can construct the S2 policy: the
    # policy must bind every E1-authorized file, not a directory approximation.
    # Keep the value typed and verify its BTS binding below; this is not an
    # alternate relocation path.
    precomputed_relocation: Relocation | None = None


@dataclass(frozen=True, slots=True)
class PipelineValidationVerdict:
    schema_version: str
    status: ValidationStatus
    reason: BTSRejectReason | None
    detail_categories: tuple[str, ...]
    bts_digest: str
    relocation_digest: str
    rerun_report_digest: str | None
    probe_report_digest: str | None
    validation_digest: str

    def to_bytes(self) -> bytes:
        return _canonical(self, omit_digest=False)


@dataclass(frozen=True, slots=True)
class BTSPipelineResult:
    """Typed component artifacts plus the non-compensating final verdict."""

    bts: BTSResult
    relocation: Relocation
    rerun: RerunResult
    probes: ProbeReport
    verdict: PipelineValidationVerdict

    def to_bytes(self) -> bytes:
        """Render stable result identity without host paths or execution output."""

        payload = {
            "analysis_digest": self.bts.report.analysis_digest,
            "bts_digest": self.verdict.bts_digest,
            "probe_report_digest": self.verdict.probe_report_digest,
            "relocation_digest": self.verdict.relocation_digest,
            "rerun_report_digest": self.verdict.rerun_report_digest,
            "schema_version": PIPELINE_SCHEMA_VERSION,
            "validation_digest": self.verdict.validation_digest,
            "validation_status": self.verdict.status.value,
        }
        return _json_bytes(payload)


def _json_value(value: object, *, omit_digest: bool) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, PipelineValidationVerdict):
        return {
            "bts_digest": value.bts_digest,
            "detail_categories": list(value.detail_categories),
            "probe_report_digest": value.probe_report_digest,
            "reason": None if value.reason is None else value.reason.value,
            "relocation_digest": value.relocation_digest,
            "rerun_report_digest": value.rerun_report_digest,
            "schema_version": value.schema_version,
            "status": value.status.value,
            **({} if omit_digest else {"validation_digest": value.validation_digest}),
        }
    raise TypeError(f"unsupported pipeline canonical value: {type(value).__name__}")


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def _canonical(value: PipelineValidationVerdict, *, omit_digest: bool) -> bytes:
    return _json_bytes(_json_value(value, omit_digest=omit_digest))


def _digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _verdict(
    bts: BTSResult,
    relocation: Relocation,
    rerun: RerunResult,
    probes: ProbeReport,
) -> PipelineValidationVerdict:
    if bts.bts is None:
        raise TransplantError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "pipeline verdict requires a COMPLETE BTS",
            detail_code="pipeline_non_complete_bts_v1",
        )
    details: list[str] = []
    reasons: list[BTSRejectReason] = []
    rerun_digest: str | None = None
    if isinstance(rerun, RerunReport):
        rerun_digest = rerun.report_digest
        details.extend(rerun.detail_categories)
        if rerun.reason is not None:
            reasons.append(rerun.reason)
    else:
        details.append(rerun.detail_category)
        reasons.append(rerun.reason)
    if probes.status is not ProbeStatus.COMPLETE:
        if probes.abort is not None:
            details.append(probes.abort.detail_category)
            reasons.append(probes.abort.reason)
        else:
            details.extend(item.detail_code for item in probes.blockers)
            reasons.extend(item.reason for item in probes.blockers)
    complete = isinstance(rerun, RerunReport) and rerun.status is ValidationStatus.COMPLETE and probes.status is ProbeStatus.COMPLETE
    reason = None if complete else _precedent(reasons)
    draft = PipelineValidationVerdict(
        PIPELINE_SCHEMA_VERSION,
        ValidationStatus.COMPLETE if complete else ValidationStatus.REJECT,
        reason,
        tuple(sorted(set(details))),
        bts.bts.bts_digest,
        relocation.relocation_digest,
        rerun_digest,
        probes.report_digest,
        "sha256:" + "0" * 64,
    )
    return replace(draft, validation_digest=_digest(_canonical(draft, omit_digest=True)))


def _precedent(reasons: list[BTSRejectReason]) -> BTSRejectReason:
    order = (
        BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED,
        BTSRejectReason.REJECT_EXECUTION_THREAT,
        BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
        BTSRejectReason.REJECT_MOVING_REFERENCE,
        BTSRejectReason.REJECT_DUPLICATE_RESULT,
        BTSRejectReason.REJECT_COVERAGE_MISCOUNT,
        BTSRejectReason.REJECT_SEMANTIC_DEGRADATION,
        BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT,
        BTSRejectReason.REJECT_UNRESOLVED_EDGE,
        BTSRejectReason.REJECT_UNDER_COLLECTION,
        BTSRejectReason.REJECT_BUDGET_EXCEEDED,
        BTSRejectReason.REJECT_HARD_GATE_FAILED,
    )
    ranks = {reason: rank for rank, reason in enumerate(order)}
    return min(
        reasons or [BTSRejectReason.REJECT_HARD_GATE_FAILED],
        key=lambda reason: (ranks.get(reason, len(ranks)), reason.value),
    )


def run_bts_pipeline(request: BTSPipelineRequest) -> BTSPipelineResult:
    """Run the full static-to-behavioral chain for exactly one donor seed."""

    if not isinstance(request, BTSPipelineRequest):
        raise TypeError("request must be a BTSPipelineRequest")
    bts = compute_bts(
        request.snapshot,
        request.seed,
        request.graph,
        request.budget,
        request.resolution_policy,
    )
    if bts.status is not BTSStatus.COMPLETE or bts.bts is None:
        raise TransplantError(
            BTSRejectReason.REJECT_HARD_GATE_FAILED,
            "only a COMPLETE BTS may enter the pipeline relocation boundary",
            detail_code="pipeline_non_complete_bts_v1",
        )
    derived_relocation = relocate_tests(
        bts,
        module_map=request.module_map,
        source_files=request.source_files,
        tests=request.contract_tests,
        declared_external_modules=request.declared_external_modules,
        recipient_bindings=request.recipient_bindings,
        test_import_aliases=request.test_import_aliases,
    )
    if request.precomputed_relocation is not None:
        relocation = request.precomputed_relocation
        if (
            relocation.bts_digest != bts.bts.bts_digest
            or relocation.relocation_digest != derived_relocation.relocation_digest
        ):
            raise TransplantError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "precomputed relocation does not reproduce the authoritative E1 output",
                detail_code="pipeline_precomputed_relocation_mismatch_v1",
            )
    else:
        relocation = derived_relocation
    rerun = rerun_transplant(
        relocation,
        bts,
        request.baseline,
        execution_policy=request.rerun_execution_policy,
    )
    probes = run_probes(request.probe_set, relocation, execution_policy=request.probe_execution_policy)
    return BTSPipelineResult(bts, relocation, rerun, probes, _verdict(bts, relocation, rerun, probes))


__all__ = [
    "PIPELINE_SCHEMA_VERSION",
    "BTSPipelineRequest",
    "BTSPipelineResult",
    "PipelineValidationVerdict",
    "run_bts_pipeline",
]
