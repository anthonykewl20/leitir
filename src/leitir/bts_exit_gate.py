"""Ratified, non-compensating N-donor BTS milestone exit gate.

The corpus manifest digest is recomputed from its content, while
``ratified_manifest_digest`` is the independently reviewed value pinned by the
release policy.  Keeping those identities separate is what makes replacement
or cherry-picking detectable; a manifest self-hash alone is not authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum

from leitir.bts import BTSStatus
from leitir.bts_errors import BTSRejectReason
from leitir.bts_pipeline import BTSPipelineRequest, BTSPipelineResult
from leitir.graph.runtime import DonorAbsenceAuthority
from leitir.probes import ProbeStatus
from leitir.rerun import ContractBaselineEvidence, RerunReport, ValidationStatus

EXIT_CORPUS_SCHEMA_VERSION = "leitir-bts-exit-corpus-v1"
EXIT_GATE_SCHEMA_VERSION = "leitir-bts-exit-gate-v1"
MINIMUM_EXIT_DONORS = 5
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _check_text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value or "\x00" in value or len(value.encode("utf-8")) > 512:
        raise ValueError(f"{name} must be nonempty bounded UTF-8 text")


def _check_digest(value: object, name: str) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase sha256 digest")


def _json_value(value: object, *, omit: frozenset[str] = frozenset()) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _json_value(getattr(value, item.name), omit=omit) for item in fields(value) if item.name not in omit}
    if isinstance(value, (tuple, list)):
        return [_json_value(item, omit=omit) for item in value]
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical exit-gate mappings require string keys")
        return {key: _json_value(item, omit=omit) for key, item in value.items()}
    if value is None or isinstance(value, (str, bool)) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise TypeError(f"unsupported canonical exit-gate value: {type(value).__name__}")


def _canonical_bytes(value: object, *, omit: frozenset[str] = frozenset()) -> bytes:
    payload = json.dumps(_json_value(value, omit=omit), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return (payload + "\n").encode("utf-8")


def _digest(value: object, *, omit: frozenset[str] = frozenset()) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value, omit=omit)).hexdigest()


def _case_manifest(case: ExitCorpusCase) -> dict[str, object]:
    snapshot = case.request.snapshot
    seed = case.request.seed
    return {
        "baseline_digest": case.baseline_digest,
        "case_id": case.case_id,
        "donor": {
            "commit_sha": snapshot.commit_sha,
            "materialized_tree_hash": snapshot.materialized_tree_hash,
            "materialized_tree_hash_algorithm": snapshot.materialized_tree_hash_algorithm,
            "materialized_tree_hash_scope": snapshot.materialized_tree_hash_scope,
            "slug": snapshot.slug,
        },
        "probe_execution_policy_digest": case.probe_execution_policy_digest,
        "rerun_execution_policy_digest": case.rerun_execution_policy_digest,
        "resolution_policy_digest": case.resolution_policy_digest,
        "review_receipt_digest": case.review_receipt_digest,
        "seed": {
            "kind": seed.kind.value,
            "location_key": seed.location_key,
            "module": seed.module,
            "origin": seed.origin.value,
            "qualified_name": seed.qualified_name,
        },
        "source_provenance": case.source_provenance,
    }


@dataclass(frozen=True, slots=True)
class ExitCorpusCase:
    """One reviewed donor entry and all policy identities pinned for its run."""

    case_id: str
    source_provenance: str
    review_receipt_digest: str
    request: BTSPipelineRequest
    baseline_digest: str
    resolution_policy_digest: str
    rerun_execution_policy_digest: str
    probe_execution_policy_digest: str
    case_digest: str

    def __post_init__(self) -> None:
        _check_text(self.case_id, "case_id")
        _check_text(self.source_provenance, "source_provenance")
        if not isinstance(self.request, BTSPipelineRequest):
            raise TypeError("request must be a BTSPipelineRequest")
        for name in (
            "review_receipt_digest",
            "baseline_digest",
            "resolution_policy_digest",
            "rerun_execution_policy_digest",
            "probe_execution_policy_digest",
            "case_digest",
        ):
            _check_digest(getattr(self, name), name)
        expected = (
            self.request.baseline.baseline_digest,
            self.request.resolution_policy.policy_digest,
            self.request.rerun_execution_policy.policy_digest,
            getattr(self.request.probe_execution_policy, "execution_policy_digest", None),
        )
        actual = (
            self.baseline_digest,
            self.resolution_policy_digest,
            self.rerun_execution_policy_digest,
            self.probe_execution_policy_digest,
        )
        if actual != expected:
            raise ValueError("case policy digests do not match the pinned pipeline request")
        if self.case_digest != _digest(_case_manifest(self)):
            raise ValueError("case digest does not match its manifest entry")

    @classmethod
    def pin(
        cls,
        case_id: str,
        source_provenance: str,
        review_receipt_digest: str,
        request: BTSPipelineRequest,
    ) -> ExitCorpusCase:
        probe_digest = getattr(request.probe_execution_policy, "execution_policy_digest", None)
        _check_digest(probe_digest, "probe_execution_policy_digest")
        assert isinstance(probe_digest, str)
        draft = cls.__new__(cls)
        values = (
            case_id,
            source_provenance,
            review_receipt_digest,
            request,
            request.baseline.baseline_digest,
            request.resolution_policy.policy_digest,
            request.rerun_execution_policy.policy_digest,
            probe_digest,
            "sha256:" + "0" * 64,
        )
        for item, value in zip(fields(cls), values, strict=True):
            object.__setattr__(draft, item.name, value)
        return cls(
            case_id,
            source_provenance,
            review_receipt_digest,
            request,
            request.baseline.baseline_digest,
            request.resolution_policy.policy_digest,
            request.rerun_execution_policy.policy_digest,
            probe_digest,
            _digest(_case_manifest(draft)),
        )


@dataclass(frozen=True, slots=True)
class ExitCorpus:
    """Externally ratified, versioned and content-addressed exit corpus."""

    schema_version: str
    authority: str
    release_id: str
    cases: tuple[ExitCorpusCase, ...]
    ratified_manifest_digest: str
    corpus_manifest_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != EXIT_CORPUS_SCHEMA_VERSION:
            raise ValueError("unsupported exit corpus schema")
        _check_text(self.authority, "authority")
        _check_text(self.release_id, "release_id")
        _check_digest(self.ratified_manifest_digest, "ratified_manifest_digest")
        _check_digest(self.corpus_manifest_digest, "corpus_manifest_digest")
        if not isinstance(self.cases, tuple) or not all(isinstance(case, ExitCorpusCase) for case in self.cases):
            raise TypeError("cases must be a tuple of ExitCorpusCase values")
        if len(self.cases) < MINIMUM_EXIT_DONORS:
            raise ValueError(f"the exit corpus requires at least {MINIMUM_EXIT_DONORS} donors")
        keys = tuple((case.case_id, case.source_provenance) for case in self.cases)
        if keys != tuple(sorted(keys)) or len(set(keys)) != len(keys):
            raise ValueError("corpus cases must have sorted unique identities")
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("corpus case IDs must be unique")
        if len({case.source_provenance for case in self.cases}) != len(self.cases):
            raise ValueError("exit donors must have materially distinct source provenance")
        if self.corpus_manifest_digest != self.compute_manifest_digest(self.authority, self.release_id, self.cases):
            raise ValueError("corpus manifest digest does not match its content")

    @staticmethod
    def compute_manifest_digest(authority: str, release_id: str, cases: tuple[ExitCorpusCase, ...]) -> str:
        manifest = {
            "authority": authority,
            "cases": [
                {
                    **_case_manifest(case),
                    "case_digest": case.case_digest,
                }
                for case in cases
            ],
            "release_id": release_id,
            "schema_version": EXIT_CORPUS_SCHEMA_VERSION,
        }
        return _digest(manifest)

    @classmethod
    def pin(
        cls,
        authority: str,
        release_id: str,
        cases: tuple[ExitCorpusCase, ...],
        *,
        ratified_manifest_digest: str,
    ) -> ExitCorpus:
        return cls(
            EXIT_CORPUS_SCHEMA_VERSION,
            authority,
            release_id,
            cases,
            ratified_manifest_digest,
            cls.compute_manifest_digest(authority, release_id, cases),
        )


@dataclass(frozen=True, slots=True)
class ExitDonorReport:
    case_id: str
    status: ValidationStatus
    complete_bts: bool
    exact_rerun_parity: bool
    donor_ban_proved: bool
    no_observed_donor_import: bool
    probes_complete: bool
    zero_failure_baseline: bool
    pipeline_validation_digest: str | None
    detail_categories: tuple[str, ...]
    recorded_outcome_vector: tuple[tuple[str, str], ...] | None = None
    recorded_counts: tuple[tuple[str, int], ...] | None = None
    expected_outcome_vector: tuple[tuple[str, str], ...] | None = None
    expected_counts: tuple[tuple[str, int], ...] | None = None


@dataclass(frozen=True, slots=True)
class ExitGateReport:
    schema_version: str
    status: ValidationStatus
    authority_digest_matches: bool
    corpus_manifest_digest: str
    ratified_manifest_digest: str
    donors: tuple[ExitDonorReport, ...]
    report_digest: str

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)


Pipeline = Callable[[BTSPipelineRequest], BTSPipelineResult]


def _run_case(case: ExitCorpusCase, pipeline: Pipeline) -> ExitDonorReport:
    zero = case.request.baseline.counts.failed == 0
    try:
        result = pipeline(case.request)
    except Exception:  # A case failure must not prevent the remaining donors from running.
        return ExitDonorReport(case.case_id, ValidationStatus.REJECT, False, False, False, False, False, zero, None, ("exit_pipeline_error_v1",))
    rerun = result.rerun if isinstance(result.rerun, RerunReport) else None
    complete_bts = result.bts.status is BTSStatus.COMPLETE and result.bts.bts is not None
    parity = (
        rerun is not None
        and rerun.status is ValidationStatus.COMPLETE
        and rerun.baseline_digest == case.baseline_digest
        and rerun.counts == case.request.baseline.counts
        and rerun.selected_test_ids == case.request.baseline.selected_test_ids
        # ADR-0009 §5 (lines 365-366) requires exact canonical-ID tuples,
        # counts, and per-ID semantic outcomes. Detail categories and digests
        # bind distinct baseline/rerun executors, so they may differ.
        and tuple((item.canonical_test_id, item.outcome) for item in rerun.outcomes)
        == tuple((item.canonical_test_id, item.outcome) for item in case.request.baseline.outcomes)
    )
    donor_ban = rerun is not None and rerun.donor_absence_authority is DonorAbsenceAuthority.FILESYSTEM_MOUNT_BOUNDARY
    # E2 makes an observed donor import terminal, so a COMPLETE bound report is
    # the positive evidence that no such observation occurred.
    no_import = rerun is not None and rerun.status is ValidationStatus.COMPLETE
    probes = result.probes.status is ProbeStatus.COMPLETE
    pipeline_complete = result.verdict.status is ValidationStatus.COMPLETE
    passed = complete_bts and parity and donor_ban and no_import and probes and pipeline_complete and zero
    details = list(result.verdict.detail_categories)
    if not zero:
        details.append("exit_nonzero_baseline_failures_v1")
    recorded_vector = None if rerun is None else tuple(
        (item.canonical_test_id, item.outcome.value) for item in rerun.outcomes
    )
    recorded_counts = None if rerun is None else (
        ("failed", rerun.counts.failed),
        ("passed", rerun.counts.passed),
        ("skipped", rerun.counts.skipped),
    )
    expected_vector, expected_counts = _baseline_observation(case.request.baseline)
    return ExitDonorReport(
        case.case_id,
        ValidationStatus.COMPLETE if passed else ValidationStatus.REJECT,
        complete_bts,
        parity,
        donor_ban,
        no_import,
        probes,
        zero,
        result.verdict.validation_digest,
        tuple(sorted(set(details))),
        recorded_vector,
        recorded_counts,
        expected_vector,
        expected_counts,
    )


def run_exit_gate(corpus: ExitCorpus, pipeline: Pipeline) -> ExitGateReport:
    """Run every donor; authority and every donor are non-compensating gates."""

    if not isinstance(corpus, ExitCorpus):
        raise TypeError("corpus must be an ExitCorpus")
    if not callable(pipeline):
        raise TypeError("pipeline must be callable")
    donors = tuple(_run_case(case, pipeline) for case in corpus.cases)
    authority_matches = corpus.corpus_manifest_digest == corpus.ratified_manifest_digest
    passed = authority_matches and all(item.status is ValidationStatus.COMPLETE for item in donors)
    draft = ExitGateReport(
        EXIT_GATE_SCHEMA_VERSION,
        ValidationStatus.COMPLETE if passed else ValidationStatus.REJECT,
        authority_matches,
        corpus.corpus_manifest_digest,
        corpus.ratified_manifest_digest,
        donors,
        "sha256:" + "0" * 64,
    )
    return replace(draft, report_digest=_digest(draft, omit=frozenset({"report_digest"})))


def _baseline_observation(baseline: ContractBaselineEvidence | None) -> tuple[tuple[tuple[str, str], ...] | None, tuple[tuple[str, int], ...] | None]:
    """Project baseline evidence into deterministic, inspectable reject fields."""

    if baseline is None:
        return None, None
    return (
        tuple((item.canonical_test_id, item.outcome.value) for item in baseline.outcomes),
        (("failed", baseline.counts.failed), ("passed", baseline.counts.passed), ("skipped", baseline.counts.skipped)),
    )


def rejected_preparation_report(
    case_id: str,
    reason: BTSRejectReason,
    detail_code: str | None,
    *,
    cause: BaseException | None = None,
    recorded_baseline: ContractBaselineEvidence | None = None,
    expected_baseline: ContractBaselineEvidence | None = None,
) -> ExitDonorReport:
    """Record a typed pre-pipeline failure without hiding its donor identity."""

    detail = detail_code or "unspecified"
    details = [f"exit_preparation_error_v1:{reason.value}:{detail}"]
    if cause is not None:
        details.append(f"exit_preparation_cause_v1:{type(cause).__name__}:{cause}")
    recorded_vector, recorded_counts = _baseline_observation(recorded_baseline)
    expected_vector, expected_counts = _baseline_observation(expected_baseline)
    return ExitDonorReport(
        case_id, ValidationStatus.REJECT, False, False, False, False, False,
        False, None, tuple(details), recorded_vector, recorded_counts, expected_vector, expected_counts,
    )


def report_prepared_cases(
    *,
    corpus_manifest_digest: str,
    ratified_manifest_digest: str,
    reports: tuple[ExitDonorReport, ...],
) -> ExitGateReport:
    """Build a rejecting report when a corpus case failed before pipeline assembly."""

    draft = ExitGateReport(
        EXIT_GATE_SCHEMA_VERSION, ValidationStatus.REJECT, False,
        corpus_manifest_digest, ratified_manifest_digest,
        tuple(sorted(reports, key=lambda report: report.case_id)),
        "sha256:" + "0" * 64,
    )
    return replace(draft, report_digest=_digest(draft, omit=frozenset({"report_digest"})))


__all__ = [
    "EXIT_CORPUS_SCHEMA_VERSION",
    "EXIT_GATE_SCHEMA_VERSION",
    "MINIMUM_EXIT_DONORS",
    "ExitCorpus",
    "ExitCorpusCase",
    "ExitDonorReport",
    "ExitGateReport",
    "Pipeline",
    "rejected_preparation_report",
    "report_prepared_cases",
    "run_exit_gate",
]
