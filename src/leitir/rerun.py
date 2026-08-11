"""Donor-absent, exact-outcome reruns for relocated contract tests.

The import recorder consumed by the child is diagnostic only.  This module's
donor-absence claim comes exclusively from validating the E1 rerun
authorization and the S2 mount plan before the child is released.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
from pathlib import PurePosixPath

from leitir.bts import BTS, BTSResult, BTSStatus
from leitir.bts import _digest as _bts_digest
from leitir.bts_errors import BTSRejectReason, TransplantError
from leitir.exec_sandbox import (
    ContainmentPolicy,
    ExecutionResult,
    ValidationAbortEnvelope,
    prepare_execution,
    run_contained,
)
from leitir.graph.runtime import DonorAbsenceAuthority, RuntimeEvidenceRole
from leitir.relocate import RELOCATION_SCHEMA_VERSION, Relocation

RERUN_SCHEMA_VERSION = "leitir-bts-rerun-v1"
BASELINE_SCHEMA_VERSION = "leitir-contract-baseline-v1"
RERUN_POLICY_SCHEMA_VERSION = "leitir-rerun-execution-policy-v1"
RUNNER_FRAME_SCHEMA_VERSION = "leitir-rerun-runner-frame-v1"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_TESTS = 1_000_000
_MAX_TEXT_BYTES = 512


class ValidationStatus(str, Enum):  # noqa: UP042 - canonical ADR contract
    COMPLETE = "complete"
    REJECT = "reject"


class TestOutcome(str, Enum):  # noqa: UP042 - canonical ADR contract
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True, slots=True, order=True)
class OutcomeCounts:
    passed: int
    failed: int
    skipped: int

    def __post_init__(self) -> None:
        for value in (self.passed, self.failed, self.skipped):
            if type(value) is not int or not 0 <= value <= _MAX_TESTS:
                raise ValueError("outcome counts must be bounded nonnegative integers")
        if self.passed + self.failed + self.skipped > _MAX_TESTS:
            raise ValueError("total outcome count exceeds the rerun bound")


@dataclass(frozen=True, slots=True, order=True)
class TestOutcomeEvidence:
    """One runner-independent test identity and its canonical outcome."""

    canonical_test_id: str
    outcome: TestOutcome
    detail_category: str
    detail_digest: str

    def __post_init__(self) -> None:
        _bounded_text(self.canonical_test_id, "canonical_test_id")
        _bounded_text(self.detail_category, "detail_category", maximum=96)
        _digest(self.detail_digest, "detail_digest")
        if not isinstance(self.outcome, TestOutcome):
            raise ValueError("outcome must be a TestOutcome")
        if "\n" in self.canonical_test_id or "\r" in self.canonical_test_id:
            raise ValueError("canonical_test_id must be a single-line pinned identity")


def _bounded_text(value: object, name: str, *, maximum: int = _MAX_TEXT_BYTES) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be nonempty bounded text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be strict UTF-8") from exc
    if len(encoded) > maximum:
        raise ValueError(f"{name} exceeds its byte bound")


def _digest(value: object, name: str) -> None:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase sha256 digest")


def _json_value(value: object, *, omit: frozenset[str] = frozenset()) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _json_value(getattr(value, item.name), omit=omit)
            for item in fields(value)
            if item.name not in omit
        }
    if isinstance(value, tuple):
        return [_json_value(item, omit=omit) for item in value]
    if isinstance(value, list):
        return [_json_value(item, omit=omit) for item in value]
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical rerun mappings require string keys")
        return {key: _json_value(item, omit=omit) for key, item in value.items()}
    if value is None or isinstance(value, (str, bool)) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise TypeError(f"unsupported canonical rerun value: {type(value).__name__}")


def _canonical_bytes(value: object, *, omit: frozenset[str] = frozenset()) -> bytes:
    return (
        json.dumps(
            _json_value(value, omit=omit),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8", errors="strict")


def _canonical_digest(value: object, *, omit: frozenset[str] = frozenset()) -> str:
    return f"sha256:{hashlib.sha256(_canonical_bytes(value, omit=omit)).hexdigest()}"


def _counts(outcomes: Sequence[TestOutcomeEvidence]) -> OutcomeCounts:
    return OutcomeCounts(
        sum(item.outcome is TestOutcome.PASS for item in outcomes),
        sum(item.outcome is TestOutcome.FAIL for item in outcomes),
        sum(item.outcome is TestOutcome.SKIP for item in outcomes),
    )


def _validate_outcomes(outcomes: object) -> tuple[TestOutcomeEvidence, ...]:
    if not isinstance(outcomes, tuple) or not all(isinstance(item, TestOutcomeEvidence) for item in outcomes):
        raise ValueError("outcomes must be a tuple of TestOutcomeEvidence values")
    ordered = tuple(sorted(outcomes))
    if outcomes != ordered:
        raise ValueError("outcomes must use canonical test-ID ordering")
    ids = tuple(item.canonical_test_id for item in outcomes)
    if len(ids) > _MAX_TESTS or len(set(ids)) != len(ids):
        raise ValueError("canonical test IDs must be bounded and unique")
    return outcomes


@dataclass(frozen=True, slots=True)
class ContractBaselineEvidence:
    """Pinned baseline; its digest is always re-derived at the E2 boundary."""

    schema_version: str
    outcomes: tuple[TestOutcomeEvidence, ...]
    counts: OutcomeCounts
    selected_test_ids: tuple[str, ...]
    baseline_mount_plan_digest: str
    baseline_execution_policy_digest: str
    baseline_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != BASELINE_SCHEMA_VERSION:
            raise ValueError("unsupported baseline schema")
        _validate_outcomes(self.outcomes)
        if self.counts != _counts(self.outcomes):
            raise ValueError("baseline counts do not match its outcome vector")
        ids = tuple(item.canonical_test_id for item in self.outcomes)
        if self.selected_test_ids != ids:
            raise ValueError("baseline selected IDs do not exactly match its outcome vector")
        for name in ("baseline_mount_plan_digest", "baseline_execution_policy_digest", "baseline_digest"):
            _digest(getattr(self, name), name)
        if self.baseline_digest != _canonical_digest(self, omit=frozenset({"baseline_digest"})):
            raise ValueError("baseline digest does not match the pinned evidence")

    @classmethod
    def create(
        cls,
        outcomes: tuple[TestOutcomeEvidence, ...],
        *,
        baseline_mount_plan_digest: str,
        baseline_execution_policy_digest: str,
    ) -> ContractBaselineEvidence:
        """Construct a baseline artifact while deriving all redundant evidence."""

        checked = _validate_outcomes(outcomes)
        draft = cls.__new__(cls)
        object.__setattr__(draft, "schema_version", BASELINE_SCHEMA_VERSION)
        object.__setattr__(draft, "outcomes", checked)
        object.__setattr__(draft, "counts", _counts(checked))
        object.__setattr__(draft, "selected_test_ids", tuple(item.canonical_test_id for item in checked))
        object.__setattr__(draft, "baseline_mount_plan_digest", baseline_mount_plan_digest)
        object.__setattr__(draft, "baseline_execution_policy_digest", baseline_execution_policy_digest)
        object.__setattr__(draft, "baseline_digest", "sha256:" + "0" * 64)
        digest = _canonical_digest(draft, omit=frozenset({"baseline_digest"}))
        return cls(
            BASELINE_SCHEMA_VERSION,
            checked,
            _counts(checked),
            tuple(item.canonical_test_id for item in checked),
            baseline_mount_plan_digest,
            baseline_execution_policy_digest,
            digest,
        )

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)


@dataclass(frozen=True, slots=True)
class RerunExecutionPolicy:
    """Role-distinct runner closure layered over the S2 containment policy."""

    schema_version: str
    containment: ContainmentPolicy
    runner_argv: tuple[str, ...]
    runner_closure_digest: str
    baseline_execution_policy_digest: str
    donor_roots: tuple[str, ...]
    python_hash_seed: str = "0"

    def __post_init__(self) -> None:
        if self.schema_version != RERUN_POLICY_SCHEMA_VERSION or not isinstance(self.containment, ContainmentPolicy):
            raise ValueError("unsupported rerun execution policy")
        for name in ("runner_closure_digest", "baseline_execution_policy_digest"):
            _digest(getattr(self, name), name)
        if not isinstance(self.runner_argv, tuple) or not self.runner_argv:
            raise ValueError("runner_argv must be a nonempty tuple")
        if any(not isinstance(item, str) or not item or "\x00" in item for item in self.runner_argv):
            raise ValueError("runner argv contains an invalid value")
        if "-I" in self.runner_argv:
            raise ValueError("isolated mode is forbidden because it ignores PYTHONHASHSEED")
        if self.python_hash_seed != "0":
            raise ValueError("v1 fixes PYTHONHASHSEED to numeric zero")
        roots = tuple(sorted(self.donor_roots))
        if roots != self.donor_roots or len(set(roots)) != len(roots) or not roots:
            raise ValueError("donor roots must be a sorted, unique, nonempty tuple")
        if any(not _absolute_path(root) for root in roots):
            raise ValueError("donor roots must be normalized absolute paths")
        environment = _environment(self.containment.environment)
        if environment.get("PYTHONHASHSEED") != self.python_hash_seed:
            raise ValueError("containment environment must fix PYTHONHASHSEED=0")
        if environment.get("TZ") != "UTC" or not any(environment.get(name) in {"C.UTF-8", "C.utf8"} for name in ("LANG", "LC_ALL")):
            raise ValueError("containment environment must fix UTC and a UTF-8 C locale")

    @property
    def policy_digest(self) -> str:
        return _canonical_digest(self)


def _environment(entries: tuple[str, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in entries:
        name, separator, value = entry.partition("=")
        if separator != "=" or name in result:
            raise ValueError("containment environment is malformed")
        result[name] = value
    return result


def _absolute_path(value: str) -> bool:
    path = PurePosixPath(value)
    return value.startswith("/") and value == str(path) and ".." not in path.parts


def _paths_overlap(left: str, right: str) -> bool:
    a = PurePosixPath(left)
    b = PurePosixPath(right)
    return a == b or a in b.parents or b in a.parents


def _path_is_within(path: str, root: str) -> bool:
    candidate = PurePosixPath(path)
    boundary = PurePosixPath(root)
    return candidate == boundary or boundary in candidate.parents


@dataclass(frozen=True, slots=True)
class RerunReport:
    schema_version: str
    status: ValidationStatus
    reason: BTSRejectReason | None
    detail_categories: tuple[str, ...]
    bts_digest: str
    relocation_digest: str
    baseline_digest: str
    execution_policy_digest: str
    baseline_mount_plan_digest: str
    rerun_mount_plan_digest: str
    environment_digest: str
    python_hash_seed: str
    donor_absence_authority: DonorAbsenceAuthority
    runtime_evidence_role: RuntimeEvidenceRole
    runtime_observation_digest: str | None
    counts: OutcomeCounts
    selected_test_ids: tuple[str, ...]
    outcomes: tuple[TestOutcomeEvidence, ...]
    report_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != RERUN_SCHEMA_VERSION or not isinstance(self.status, ValidationStatus):
            raise ValueError("unsupported rerun report")
        if self.status is ValidationStatus.COMPLETE and self.reason is not None:
            raise ValueError("a complete rerun cannot have a reject reason")
        if self.status is ValidationStatus.REJECT and not isinstance(self.reason, BTSRejectReason):
            raise ValueError("a rejected rerun requires a reject reason")
        _validate_outcomes(self.outcomes)
        if self.counts != _counts(self.outcomes):
            raise ValueError("rerun counts do not match outcomes")
        if self.selected_test_ids != tuple(item.canonical_test_id for item in self.outcomes):
            raise ValueError("rerun selected IDs do not match outcomes")
        if tuple(sorted(set(self.detail_categories))) != self.detail_categories:
            raise ValueError("rerun detail categories must be sorted and unique")
        for name in (
            "bts_digest",
            "relocation_digest",
            "baseline_digest",
            "execution_policy_digest",
            "baseline_mount_plan_digest",
            "rerun_mount_plan_digest",
            "environment_digest",
            "report_digest",
        ):
            _digest(getattr(self, name), name)
        if self.runtime_observation_digest is not None:
            _digest(self.runtime_observation_digest, "runtime_observation_digest")
        if self.donor_absence_authority is not DonorAbsenceAuthority.FILESYSTEM_MOUNT_BOUNDARY:
            raise ValueError("donor absence must be proved by the filesystem mount boundary")
        if self.runtime_evidence_role is not RuntimeEvidenceRole.DIAGNOSTIC_ONLY:
            raise ValueError("runtime evidence must remain diagnostic-only")
        if self.python_hash_seed != "0":
            raise ValueError("canonical reruns require PYTHONHASHSEED=0")
        if self.report_digest != _canonical_digest(self, omit=frozenset({"report_digest"})):
            raise ValueError("rerun report digest mismatch")

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)

    def to_json(self) -> str:
        return self.to_bytes().decode("utf-8", errors="strict")


RerunResult = RerunReport | ValidationAbortEnvelope


def _abort(subject_digest: str, reason: BTSRejectReason, detail: str, result: ExecutionResult | None = None) -> ValidationAbortEnvelope:
    return ValidationAbortEnvelope(
        schema_version="leitir-validation-abort-v1",
        stage="rerun",
        role="rerun",
        reason=reason,
        detail_category=detail,
        subject_digest=subject_digest,
        stdout_bytes=0 if result is None else min(len(result.stdout), 2**63 - 1),
        stderr_bytes=0 if result is None else min(len(result.stderr), 2**63 - 1),
    )


def _reject(reason: BTSRejectReason, message: str, detail: str) -> TransplantError:
    return TransplantError(reason, message, detail_code=detail)


def _validated_bts(value: BTS | BTSResult) -> BTS:
    bare = isinstance(value, BTS)
    if isinstance(value, BTSResult):
        if value.status is not BTSStatus.COMPLETE or value.report.status is not BTSStatus.COMPLETE or value.bts is None:
            raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "only a COMPLETE BTS may be rerun", "rerun_non_complete_bts_v1")
        value = value.bts
    if not isinstance(value, BTS):
        raise TypeError("bts must be a BTS or BTSResult")
    _digest(value.bts_digest, "bts_digest")
    _digest(value.member_equivalence_digest, "member_equivalence_digest")
    equivalence = _bts_digest(value, omit=frozenset({"bts_digest", "member_equivalence_digest"}))
    if bare and value.member_equivalence_digest != equivalence:
        raise _reject(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "bare BTS identity does not match its canonical records",
            "rerun_bts_identity_v1",
        )
    return value


def _mount_plan_has_donor(policy: RerunExecutionPolicy) -> bool:
    return any(
        _paths_overlap(mount.source, root) or _path_is_within(mount.destination, root)
        for mount in policy.containment.readonly_mounts
        for root in policy.donor_roots
    )


def _mount_plan_covers_relocation(relocation: Relocation, policy: RerunExecutionPolicy) -> bool:
    mounts = {mount.destination: mount for mount in policy.containment.readonly_mounts}
    if len(mounts) != len(policy.containment.readonly_mounts):
        return False
    files = {item.path: item for item in relocation.files}
    for authorization in relocation.rerun_mounts:
        relocated = files.get(authorization.logical_path)
        mount = mounts.get(f"/{authorization.logical_path}")
        if relocated is None or mount is None or mount.source_digest != relocated.sha256:
            return False
    return True


def _duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate runner-frame key")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class _RunnerFrame:
    outcomes: tuple[TestOutcomeEvidence, ...]
    runtime_observation_digest: str | None
    donor_import_observed: bool
    recorder_complete: bool
    teardown_complete: bool


def _parse_runner_frame(data: bytes) -> _RunnerFrame:
    try:
        text = data.decode("utf-8", errors="strict")
        raw = json.loads(text, object_pairs_hook=_duplicate_pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("runner frame is malformed") from exc
    expected = {
        "schema_version",
        "outcomes",
        "runtime_observation_digest",
        "donor_import_observed",
        "recorder_complete",
        "teardown_complete",
    }
    if not isinstance(raw, dict) or set(raw) != expected or raw.get("schema_version") != RUNNER_FRAME_SCHEMA_VERSION:
        raise ValueError("runner frame has an unsupported shape")
    donor_observed = raw["donor_import_observed"]
    recorder_complete = raw["recorder_complete"]
    teardown_complete = raw["teardown_complete"]
    if type(donor_observed) is not bool or type(recorder_complete) is not bool or type(teardown_complete) is not bool:
        raise ValueError("runner frame gate fields are malformed")
    raw_outcomes = raw["outcomes"]
    # The recorder is diagnostic-only, but an observed donor import is terminal
    # even when the remaining untrusted runner vector is malformed.
    if donor_observed:
        raw_runtime_digest = raw["runtime_observation_digest"]
        runtime_digest = raw_runtime_digest if isinstance(raw_runtime_digest, str) and _DIGEST_RE.fullmatch(raw_runtime_digest) else None
        return _RunnerFrame((), runtime_digest, True, recorder_complete, teardown_complete)
    runtime_digest = raw["runtime_observation_digest"]
    _digest(runtime_digest, "runtime_observation_digest")
    assert isinstance(runtime_digest, str)
    if not isinstance(raw_outcomes, list) or len(raw_outcomes) > _MAX_TESTS:
        raise CoverageFrameError("runner outcome vector has an invalid shape")
    outcomes: list[TestOutcomeEvidence] = []
    try:
        for item in raw_outcomes:
            if not isinstance(item, Mapping) or set(item) != {"canonical_test_id", "outcome", "detail_category", "detail_digest"}:
                raise CoverageFrameError("runner outcome entry has an invalid shape")
            outcomes.append(
                TestOutcomeEvidence(
                    item["canonical_test_id"],
                    TestOutcome(item["outcome"]),
                    item["detail_category"],
                    item["detail_digest"],
                )
            )
        checked = _validate_outcomes(tuple(outcomes))
    except (TypeError, ValueError) as exc:
        raise CoverageFrameError("runner outcome vector is noncanonical") from exc
    frame = _RunnerFrame(checked, runtime_digest, donor_observed, recorder_complete, teardown_complete)
    canonical = {
        "donor_import_observed": donor_observed,
        "outcomes": [_json_value(item) for item in checked],
        "recorder_complete": recorder_complete,
        "runtime_observation_digest": runtime_digest,
        "schema_version": RUNNER_FRAME_SCHEMA_VERSION,
        "teardown_complete": teardown_complete,
    }
    if data != _canonical_bytes(canonical):
        raise ValueError("runner frame is not canonical JSON")
    return frame


class CoverageFrameError(ValueError):
    """A syntactically valid runner frame has an invalid outcome vector."""


def _report(
    *,
    status: ValidationStatus,
    reason: BTSRejectReason | None,
    details: tuple[str, ...],
    artifact: BTS,
    relocation: Relocation,
    baseline: ContractBaselineEvidence,
    policy: RerunExecutionPolicy,
    outcomes: tuple[TestOutcomeEvidence, ...],
    runtime_digest: str | None,
) -> RerunReport:
    environment_digest = _canonical_digest(policy.containment.environment)
    draft = RerunReport.__new__(RerunReport)
    values: tuple[tuple[str, object], ...] = (
        ("schema_version", RERUN_SCHEMA_VERSION),
        ("status", status),
        ("reason", reason),
        ("detail_categories", tuple(sorted(set(details)))),
        ("bts_digest", artifact.bts_digest),
        ("relocation_digest", relocation.relocation_digest),
        ("baseline_digest", baseline.baseline_digest),
        ("execution_policy_digest", policy.policy_digest),
        ("baseline_mount_plan_digest", baseline.baseline_mount_plan_digest),
        ("rerun_mount_plan_digest", policy.containment.mount_plan_digest),
        ("environment_digest", environment_digest),
        ("python_hash_seed", policy.python_hash_seed),
        ("donor_absence_authority", DonorAbsenceAuthority.FILESYSTEM_MOUNT_BOUNDARY),
        ("runtime_evidence_role", RuntimeEvidenceRole.DIAGNOSTIC_ONLY),
        ("runtime_observation_digest", runtime_digest),
        ("counts", _counts(outcomes)),
        ("selected_test_ids", tuple(item.canonical_test_id for item in outcomes)),
        ("outcomes", outcomes),
        ("report_digest", "sha256:" + "0" * 64),
    )
    for name, value in values:
        object.__setattr__(draft, name, value)
    digest = _canonical_digest(draft, omit=frozenset({"report_digest"}))
    return replace(draft, report_digest=digest)


def rerun_transplant(
    relocation: Relocation,
    bts: BTS | BTSResult,
    baseline: ContractBaselineEvidence,
    *,
    execution_policy: RerunExecutionPolicy,
) -> RerunResult:
    """Run relocated tests once under S2 and require exact baseline parity.

    Operational failures return a noncanonical :class:`ValidationAbortEnvelope`;
    completed semantic/coverage failures return a content-addressed report.
    """

    artifact = _validated_bts(bts)
    if not isinstance(relocation, Relocation) or not isinstance(baseline, ContractBaselineEvidence):
        raise TypeError("rerun_transplant requires Relocation and ContractBaselineEvidence values")
    if not isinstance(execution_policy, RerunExecutionPolicy):
        raise TypeError("execution_policy must be a RerunExecutionPolicy")
    # Re-run dataclass validation at this trust boundary, including baseline digest.
    ContractBaselineEvidence(*[getattr(baseline, item.name) for item in fields(ContractBaselineEvidence)])
    RerunExecutionPolicy(*[getattr(execution_policy, item.name) for item in fields(RerunExecutionPolicy)])
    if relocation.schema_version != RELOCATION_SCHEMA_VERSION or relocation.bts_digest != artifact.bts_digest:
        raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "relocation does not bind the supplied BTS", "rerun_relocation_binding_v1")
    if not relocation.rerun_mounts or any(item.donor_present or not item.read_only for item in relocation.rerun_mounts):
        raise _reject(BTSRejectReason.REJECT_EXECUTION_THREAT, "E1 rerun authorization does not exclude donor bytes", "rerun_e1_mount_authorization_v1")
    if not any(item.donor_present and item.read_only for item in relocation.baseline_mounts):
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "E1 baseline authorization does not contain a read-only donor", "rerun_baseline_mount_authorization_v1")
    if baseline.baseline_mount_plan_digest == execution_policy.containment.mount_plan_digest:
        raise _reject(BTSRejectReason.REJECT_EXECUTION_THREAT, "baseline and rerun mount plans must be distinct", "rerun_mount_plans_not_distinct_v1")
    if baseline.baseline_execution_policy_digest != execution_policy.baseline_execution_policy_digest:
        raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "baseline execution policy binding does not match", "rerun_baseline_policy_binding_v1")
    if baseline.baseline_execution_policy_digest == execution_policy.policy_digest:
        raise _reject(BTSRejectReason.REJECT_EXECUTION_THREAT, "baseline and rerun execution policies must be role-distinct", "rerun_execution_policies_not_distinct_v1")
    if not _mount_plan_covers_relocation(relocation, execution_policy):
        raise _reject(BTSRejectReason.REJECT_EXECUTION_THREAT, "S2 mount plan does not expose every E1 rerun input", "rerun_relocation_mount_missing_v1")
    if _mount_plan_has_donor(execution_policy):
        return _report(
            status=ValidationStatus.REJECT,
            reason=BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED,
            details=("rerun_donor_mount_present_v1",),
            artifact=artifact,
            relocation=relocation,
            baseline=baseline,
            policy=execution_policy,
            outcomes=(),
            runtime_digest=None,
        )

    try:
        plan = prepare_execution(execution_policy.containment)
        result = run_contained(plan, execution_policy.runner_argv)
    except TransplantError as exc:
        return _abort(execution_policy.policy_digest, exc.reason, exc.evidence.detail_code or "rerun_containment_failure_v1")
    if not result.completed:
        if result.abort is None:
            return _abort(execution_policy.policy_digest, BTSRejectReason.REJECT_HARD_GATE_FAILED, "rerun_missing_abort_v1")
        return ValidationAbortEnvelope(
            result.abort.schema_version,
            "rerun",
            "rerun",
            result.abort.reason,
            result.abort.detail_category,
            execution_policy.policy_digest,
            result.abort.stdout_bytes,
            result.abort.stderr_bytes,
            result.abort.blockers,
        )
    try:
        frame = _parse_runner_frame(result.stdout)
    except CoverageFrameError:
        return _report(
            status=ValidationStatus.REJECT,
            reason=BTSRejectReason.REJECT_COVERAGE_MISCOUNT,
            details=("rerun_outcome_vector_shape_v1",),
            artifact=artifact,
            relocation=relocation,
            baseline=baseline,
            policy=execution_policy,
            outcomes=(),
            runtime_digest=None,
        )
    except ValueError:
        return _abort(execution_policy.policy_digest, BTSRejectReason.REJECT_HARD_GATE_FAILED, "rerun_malformed_runner_frame_v1", result)

    if frame.donor_import_observed:
        return _report(
            status=ValidationStatus.REJECT,
            reason=BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED,
            details=("rerun_donor_import_observed_v1",),
            artifact=artifact,
            relocation=relocation,
            baseline=baseline,
            policy=execution_policy,
            outcomes=frame.outcomes,
            runtime_digest=frame.runtime_observation_digest,
        )
    if not frame.recorder_complete:
        return _abort(execution_policy.policy_digest, BTSRejectReason.REJECT_HARD_GATE_FAILED, "rerun_recorder_failure_v1", result)
    if not frame.teardown_complete:
        return _abort(execution_policy.policy_digest, BTSRejectReason.REJECT_HARD_GATE_FAILED, "rerun_teardown_failure_v1", result)

    rerun_counts = _counts(frame.outcomes)
    rerun_ids = tuple(item.canonical_test_id for item in frame.outcomes)
    if rerun_counts != baseline.counts or rerun_ids != baseline.selected_test_ids:
        return _report(
            status=ValidationStatus.REJECT,
            reason=BTSRejectReason.REJECT_COVERAGE_MISCOUNT,
            details=("rerun_exact_count_or_id_mismatch_v1",),
            artifact=artifact,
            relocation=relocation,
            baseline=baseline,
            policy=execution_policy,
            outcomes=frame.outcomes,
            runtime_digest=frame.runtime_observation_digest,
        )
    if tuple(item.outcome for item in frame.outcomes) != tuple(item.outcome for item in baseline.outcomes):
        return _report(
            status=ValidationStatus.REJECT,
            reason=BTSRejectReason.REJECT_SEMANTIC_DEGRADATION,
            details=("rerun_same_id_outcome_transition_v1",),
            artifact=artifact,
            relocation=relocation,
            baseline=baseline,
            policy=execution_policy,
            outcomes=frame.outcomes,
            runtime_digest=frame.runtime_observation_digest,
        )
    return _report(
        status=ValidationStatus.COMPLETE,
        reason=None,
        details=(),
        artifact=artifact,
        relocation=relocation,
        baseline=baseline,
        policy=execution_policy,
        outcomes=frame.outcomes,
        runtime_digest=frame.runtime_observation_digest,
    )


__all__ = [
    "BASELINE_SCHEMA_VERSION",
    "RERUN_POLICY_SCHEMA_VERSION",
    "RERUN_SCHEMA_VERSION",
    "RUNNER_FRAME_SCHEMA_VERSION",
    "ContractBaselineEvidence",
    "OutcomeCounts",
    "RerunExecutionPolicy",
    "RerunReport",
    "RerunResult",
    "TestOutcome",
    "TestOutcomeEvidence",
    "ValidationStatus",
    "rerun_transplant",
]
