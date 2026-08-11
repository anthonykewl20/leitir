"""Maintainer-authored, content-pinned behavioral probes for ``TESTED_BY`` edges.

This module is the E3 boundary from ADR-0009.  It deliberately contains no
probe generator: v1 accepts only reviewed source bytes from a ratified catalog.
Execution is supplied through a small containment port so offline tests can use
an inert stub while production adapters retain the S2 donor-absent boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
from itertools import pairwise
from pathlib import PurePosixPath, PureWindowsPath
from typing import Protocol

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import Edge, EdgeKind, NodeId, NodeOrigin
from leitir.relocate import RELOCATION_SCHEMA_VERSION, Relocation

PROBE_SCHEMA_VERSION = "leitir-pinned-probes-v1"
PROBE_REPORT_SCHEMA_VERSION = "leitir-probe-report-v1"
PROBE_ABORT_SCHEMA_VERSION = "leitir-probe-abort-v1"
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DETAIL_RE = re.compile(r"[a-z][a-z0-9_]{0,95}\Z")
_MAX_PROBES = 10_000
_MAX_PROBE_BYTES = 1_048_576
_MAX_TEXT_BYTES = 512


class ProbeOutcome(str, Enum):  # noqa: UP042 - canonical ADR contract
    PASS = "pass"
    FAIL = "fail"


class ProbeStatus(str, Enum):  # noqa: UP042 - canonical ADR contract
    COMPLETE = "complete"
    REJECT = "reject"
    ABORT = "abort"


def _canonical_value(value: object, *, omit: frozenset[str] = frozenset()) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return value.hex()
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _canonical_value(getattr(value, item.name), omit=omit)
            for item in fields(value)
            if item.name not in omit
        }
    if isinstance(value, tuple):
        return [_canonical_value(item, omit=omit) for item in value]
    if isinstance(value, Mapping) and all(isinstance(key, str) for key in value):
        return {key: _canonical_value(item, omit=omit) for key, item in value.items()}
    if value is None or isinstance(value, (str, bool)) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise TypeError(f"unsupported canonical probe value: {type(value).__name__}")


def _canonical_bytes(value: object, *, omit: frozenset[str] = frozenset()) -> bytes:
    return (
        json.dumps(
            _canonical_value(value, omit=omit),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8", errors="strict")


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _digest(value: object, *, omit: frozenset[str] = frozenset()) -> str:
    return _digest_bytes(_canonical_bytes(value, omit=omit))


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST_RE.fullmatch(value) is not None


def _text(value: object, name: str, *, maximum: int = _MAX_TEXT_BYTES) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be non-empty bounded text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be strict UTF-8") from exc
    if len(encoded) > maximum:
        raise ValueError(f"{name} must be non-empty bounded text")


def _path(value: object) -> None:
    _text(value, "source_path")
    assert isinstance(value, str)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or PureWindowsPath(value).drive
        or "\\" in value
        or ".." in path.parts
        or path.as_posix() != value
        or value == "."
        or not value.endswith(".py")
    ):
        raise ValueError("source_path must be a normalized relative POSIX Python path")


def _edge_digest(edge: Edge) -> str:
    return _digest(edge)


def _edge_key(edge: Edge) -> tuple[str, str]:
    return (_edge_digest(edge), edge.source.location_key)


@dataclass(frozen=True, slots=True)
class PinnedProbe:
    """One reviewed assertion file bound to exactly one ``TESTED_BY`` edge."""

    probe_id: str
    edge: Edge
    source_path: str
    source_bytes: bytes
    source_sha256: str
    expected_outcome: ProbeOutcome
    review_digest: str

    def __post_init__(self) -> None:
        _text(self.probe_id, "probe_id")
        if not isinstance(self.edge, Edge) or self.edge.kind is not EdgeKind.TESTED_BY:
            raise ValueError("probe edge must be a TESTED_BY Edge")
        if self.edge.source.origin is not NodeOrigin.DONOR or self.edge.target.origin is not NodeOrigin.TEST:
            raise ValueError("TESTED_BY must point from donor production to a test target")
        _path(self.source_path)
        if not isinstance(self.source_bytes, bytes) or not self.source_bytes or len(self.source_bytes) > _MAX_PROBE_BYTES:
            raise ValueError("probe source bytes must be non-empty and bounded")
        if not _valid_digest(self.source_sha256) or not _valid_digest(self.review_digest):
            raise ValueError("probe source and review digests must be lowercase sha256 digests")
        if not isinstance(self.expected_outcome, ProbeOutcome):
            raise ValueError("expected_outcome must be a ProbeOutcome")

    @classmethod
    def pin(
        cls,
        probe_id: str,
        edge: Edge,
        source_path: str,
        source_bytes: bytes,
        expected_outcome: ProbeOutcome,
        review_digest: str,
    ) -> PinnedProbe:
        """Pin maintainer-supplied bytes; this does not synthesize probe source."""

        return cls(probe_id, edge, source_path, source_bytes, _digest_bytes(source_bytes), expected_outcome, review_digest)


@dataclass(frozen=True, slots=True)
class ProbeSet:
    """Explicit probe catalog, deterministic applicability proof, and pins."""

    schema_version: str
    bts_digest: str
    seed: NodeId
    bts_members: tuple[NodeId, ...]
    catalog_edges: tuple[Edge, ...]
    catalog_digest: str
    probes: tuple[PinnedProbe, ...]
    applicability_digest: str
    probe_set_digest: str

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)

    @classmethod
    def pin(
        cls,
        *,
        bts_digest: str,
        seed: NodeId,
        bts_members: Sequence[NodeId],
        catalog_edges: Sequence[Edge],
        probes: Sequence[PinnedProbe],
    ) -> ProbeSet:
        """Build an explicit set from reviewed bytes and a finite ratified catalog."""

        members = tuple(sorted(bts_members, key=_node_key))
        edges = tuple(sorted(catalog_edges, key=_edge_key))
        pinned = tuple(sorted(probes, key=_probe_key))
        catalog_digest = _digest({"edges": edges, "schema_version": PROBE_SCHEMA_VERSION})
        applicable = _applicable_edges(seed, members, edges)
        applicability_digest = _digest(
            {
                "applicable_edge_digests": tuple(_edge_digest(edge) for edge in applicable),
                "bts_digest": bts_digest,
                "catalog_digest": catalog_digest,
                "members": members,
                "seed": seed,
            }
        )
        draft = cls(
            PROBE_SCHEMA_VERSION,
            bts_digest,
            seed,
            members,
            edges,
            catalog_digest,
            pinned,
            applicability_digest,
            "sha256:" + "0" * 64,
        )
        return replace(draft, probe_set_digest=_digest(draft, omit=frozenset({"probe_set_digest"})))


def _node_key(node: NodeId) -> tuple[str, str, str, str, str]:
    return (node.origin.value, node.kind.value, node.module, node.qualified_name, node.location_key)


def _probe_key(probe: PinnedProbe) -> tuple[str, str, str]:
    return (probe.probe_id, _edge_digest(probe.edge), probe.source_path)


def _applicable_edges(seed: NodeId, members: Sequence[NodeId], edges: Sequence[Edge]) -> tuple[Edge, ...]:
    identities = {seed, *members}
    return tuple(edge for edge in edges if edge.source in identities)


def _validate_probe_set(probe_set: ProbeSet, relocation: Relocation) -> tuple[Edge, ...]:
    if probe_set.schema_version != PROBE_SCHEMA_VERSION:
        raise ValueError("unsupported probe set schema")
    if not _valid_digest(probe_set.bts_digest) or probe_set.bts_digest != relocation.bts_digest:
        raise ValueError("probe set BTS identity does not match relocation")
    if not isinstance(probe_set.seed, NodeId):
        raise ValueError("probe seed must be a NodeId")
    if probe_set.bts_members != tuple(sorted(probe_set.bts_members, key=_node_key)):
        raise ValueError("BTS members must be canonically ordered")
    if len(set(probe_set.bts_members)) != len(probe_set.bts_members):
        raise ValueError("duplicate BTS member identity")
    if len(probe_set.catalog_edges) > _MAX_PROBES or len(probe_set.probes) > _MAX_PROBES:
        raise ValueError("probe catalog exceeds its finite bound")
    if not all(
        isinstance(edge, Edge)
        and edge.kind is EdgeKind.TESTED_BY
        and edge.source.origin is NodeOrigin.DONOR
        and edge.target.origin is NodeOrigin.TEST
        for edge in probe_set.catalog_edges
    ):
        raise ValueError("catalog contains a non-TESTED_BY edge")
    ordered_edges = tuple(sorted(probe_set.catalog_edges, key=_edge_key))
    if ordered_edges != probe_set.catalog_edges or any(_edge_key(left) == _edge_key(right) for left, right in pairwise(ordered_edges)):
        raise ValueError("catalog edges must have unique canonical ordering")
    expected_catalog = _digest({"edges": ordered_edges, "schema_version": PROBE_SCHEMA_VERSION})
    if probe_set.catalog_digest != expected_catalog:
        raise ValueError("probe catalog digest mismatch")
    if not all(isinstance(probe, PinnedProbe) for probe in probe_set.probes):
        raise ValueError("probes must contain only PinnedProbe values")
    ordered_probes = tuple(sorted(probe_set.probes, key=_probe_key))
    if ordered_probes != probe_set.probes or any(_probe_key(left) == _probe_key(right) for left, right in pairwise(ordered_probes)):
        raise ValueError("probes must have unique canonical ordering")
    probe_ids = tuple(probe.probe_id for probe in ordered_probes)
    source_paths = tuple(probe.source_path for probe in ordered_probes)
    if len(set(probe_ids)) != len(probe_ids) or len(set(source_paths)) != len(source_paths):
        raise ValueError("probe IDs and source paths must be unique")
    for probe in ordered_probes:
        if _digest_bytes(probe.source_bytes) != probe.source_sha256:
            raise ValueError("probe source bytes do not match their content pin")
    applicable = _applicable_edges(probe_set.seed, probe_set.bts_members, ordered_edges)
    expected_applicability = _digest(
        {
            "applicable_edge_digests": tuple(_edge_digest(edge) for edge in applicable),
            "bts_digest": probe_set.bts_digest,
            "catalog_digest": probe_set.catalog_digest,
            "members": probe_set.bts_members,
            "seed": probe_set.seed,
        }
    )
    if probe_set.applicability_digest != expected_applicability:
        raise ValueError("probe applicability derivation mismatch")
    applicable_digests = tuple(_edge_digest(edge) for edge in applicable)
    probe_edge_digests = tuple(_edge_digest(probe.edge) for probe in ordered_probes)
    if tuple(sorted(probe_edge_digests)) != tuple(sorted(applicable_digests)):
        raise ValueError("each applicable TESTED_BY edge requires exactly one pinned probe")
    expected_set = _digest(probe_set, omit=frozenset({"probe_set_digest"}))
    if probe_set.probe_set_digest != expected_set:
        raise ValueError("probe set digest mismatch")
    return applicable


@dataclass(frozen=True, slots=True)
class ProbeExecutionRequest:
    """Exact immutable input supplied to one fresh contained child."""

    sequence: int
    probe_id: str
    source_path: str
    source_bytes: bytes
    source_sha256: str
    expected_outcome: ProbeOutcome
    edge_digest: str
    bts_digest: str
    relocation_digest: str
    probe_set_digest: str


@dataclass(frozen=True, slots=True)
class ProbeRuntimeEvidence:
    """Bounded B6 adapter result; non-observation is not an absence proof."""

    observation_digest: str
    recorder_complete: bool
    donor_import_observed: bool

    def __post_init__(self) -> None:
        if not _valid_digest(self.observation_digest):
            raise ValueError("observation_digest must be a lowercase sha256 digest")
        if type(self.recorder_complete) is not bool or type(self.donor_import_observed) is not bool:
            raise ValueError("runtime evidence flags must be bool values")


@dataclass(frozen=True, slots=True)
class ProbeExecutionResult:
    """Trusted containment-adapter receipt for one child invocation."""

    completed: bool
    observed_outcome: ProbeOutcome | None
    fresh_child_attested: bool
    donor_absent_attested: bool
    execution_receipt_digest: str | None
    runtime: ProbeRuntimeEvidence | None
    abort_reason: BTSRejectReason | None = None
    abort_detail_category: str | None = None


class ProbeExecutionPolicy(Protocol):
    """Containment port implemented by S2/E2 adapters and inert test stubs."""

    execution_policy_digest: str

    def execute_probe(self, request: ProbeExecutionRequest, relocation: Relocation) -> ProbeExecutionResult:
        """Execute exactly one request in a newly created contained child."""


@dataclass(frozen=True, slots=True, order=True)
class ProbeOutcomeEvidence:
    probe_id: str
    edge_digest: str
    source_sha256: str
    expected_outcome: ProbeOutcome
    observed_outcome: ProbeOutcome
    execution_receipt_digest: str
    runtime_observation_digest: str


@dataclass(frozen=True, slots=True, order=True)
class ProbeBlocker:
    reason: BTSRejectReason
    detail_code: str
    probe_id: str
    edge_digest: str


@dataclass(frozen=True, slots=True)
class ProbeAbortEnvelope:
    schema_version: str
    stage: str
    role: str
    reason: BTSRejectReason
    detail_category: str
    subject_digest: str
    completed_probes: int

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)


@dataclass(frozen=True, slots=True)
class ProbeReport:
    schema_version: str
    status: ProbeStatus
    bts_digest: str
    relocation_digest: str
    probe_set_digest: str
    execution_policy_digest: str
    outcomes: tuple[ProbeOutcomeEvidence, ...]
    blockers: tuple[ProbeBlocker, ...]
    report_digest: str | None
    abort: ProbeAbortEnvelope | None = None

    def to_bytes(self) -> bytes:
        return self.abort.to_bytes() if self.abort is not None else _canonical_bytes(self)

    def to_json(self) -> str:
        return self.to_bytes().decode("utf-8", errors="strict")


def _safe_subject(relocation: object) -> tuple[str, str]:
    if isinstance(relocation, Relocation) and _valid_digest(relocation.bts_digest) and _valid_digest(relocation.relocation_digest):
        return relocation.bts_digest, relocation.relocation_digest
    return _digest("invalid-bts-subject-v1"), _digest("invalid-relocation-subject-v1")


def _final_report(
    status: ProbeStatus,
    *,
    bts_digest: str,
    relocation_digest: str,
    probe_set_digest: str,
    execution_policy_digest: str,
    outcomes: Sequence[ProbeOutcomeEvidence],
    blockers: Sequence[ProbeBlocker],
) -> ProbeReport:
    draft = ProbeReport(
        PROBE_REPORT_SCHEMA_VERSION,
        status,
        bts_digest,
        relocation_digest,
        probe_set_digest,
        execution_policy_digest,
        tuple(sorted(outcomes)),
        tuple(sorted(blockers)),
        None,
    )
    return replace(draft, report_digest=_digest(draft, omit=frozenset({"report_digest"})))


def _input_reject(relocation: object, policy_digest: object, detail: str) -> ProbeReport:
    bts_digest, relocation_digest = _safe_subject(relocation)
    execution_digest = (
        policy_digest
        if isinstance(policy_digest, str) and _valid_digest(policy_digest)
        else _digest("invalid-execution-policy-v1")
    )
    blocker = ProbeBlocker(BTSRejectReason.REJECT_HARD_GATE_FAILED, detail, "<probe-set>", _digest(detail))
    return _final_report(
        ProbeStatus.REJECT,
        bts_digest=bts_digest,
        relocation_digest=relocation_digest,
        probe_set_digest=_digest({"invalid_probe_set": detail, "bts_digest": bts_digest}),
        execution_policy_digest=execution_digest,
        outcomes=(),
        blockers=(blocker,),
    )


def _validate_relocation(relocation: Relocation) -> None:
    if relocation.schema_version != RELOCATION_SCHEMA_VERSION:
        raise ValueError("unsupported relocation schema")
    if not _valid_digest(relocation.bts_digest) or not _valid_digest(relocation.relocation_digest):
        raise ValueError("relocation identity is malformed")
    required = {"staging-v1/src", "staging-v1/probes"}
    realized = {item.logical_path for item in relocation.rerun_mounts if item.read_only and not item.donor_present}
    if not required <= realized or any(item.donor_present for item in relocation.rerun_mounts):
        raise ValueError("probe rerun mount plan does not attest donor absence")
    if relocation.rerun_mounts != tuple(sorted(relocation.rerun_mounts)):
        raise ValueError("rerun mount plan is not canonical")


def _validate_execution_result(result: ProbeExecutionResult) -> None:
    if not isinstance(result, ProbeExecutionResult):
        raise ValueError("execution policy returned a malformed result")
    if type(result.completed) is not bool:
        raise ValueError("execution completed flag is malformed")
    if result.completed:
        if (
            not isinstance(result.observed_outcome, ProbeOutcome)
            or type(result.fresh_child_attested) is not bool
            or type(result.donor_absent_attested) is not bool
            or not _valid_digest(result.execution_receipt_digest)
            or not isinstance(result.runtime, ProbeRuntimeEvidence)
            or result.abort_reason is not None
            or result.abort_detail_category is not None
        ):
            raise ValueError("completed probe receipt is malformed")
    elif (
        result.observed_outcome is not None
        or result.execution_receipt_digest is not None
        or result.runtime is not None
        or not isinstance(result.abort_reason, BTSRejectReason)
        or not isinstance(result.abort_detail_category, str)
        or _DETAIL_RE.fullmatch(result.abort_detail_category) is None
    ):
        raise ValueError("aborted probe receipt is malformed")


def _abort_report(
    *,
    bts_digest: str,
    relocation_digest: str,
    probe_set_digest: str,
    execution_policy_digest: str,
    reason: BTSRejectReason,
    detail: str,
    completed: int,
) -> ProbeReport:
    envelope = ProbeAbortEnvelope(
        PROBE_ABORT_SCHEMA_VERSION,
        "validation",
        "probe",
        reason,
        detail[:96] if detail else "probe_execution_abort",
        probe_set_digest,
        completed,
    )
    return ProbeReport(
        PROBE_REPORT_SCHEMA_VERSION,
        ProbeStatus.ABORT,
        bts_digest,
        relocation_digest,
        probe_set_digest,
        execution_policy_digest,
        (),
        (),
        None,
        envelope,
    )


def run_probes(
    probe_set: ProbeSet | None,
    relocation: Relocation,
    *,
    execution_policy: ProbeExecutionPolicy,
) -> ProbeReport:
    """Run each required pinned probe in a fresh donor-absent child.

    Probe failures are independent blockers.  Operational failures return a
    bounded noncanonical abort and therefore carry no report digest.
    """

    policy_digest = getattr(execution_policy, "execution_policy_digest", None)
    if probe_set is None:
        return _input_reject(relocation, policy_digest, "probe_set_required_v1")
    try:
        if not isinstance(relocation, Relocation):
            raise ValueError("relocation is required")
        _validate_relocation(relocation)
        _validate_probe_set(probe_set, relocation)
        if not _valid_digest(policy_digest) or not callable(getattr(execution_policy, "execute_probe", None)):
            raise ValueError("execution policy is malformed")
    except (TypeError, ValueError):
        return _input_reject(relocation, policy_digest, "probe_input_integrity_v1")
    assert isinstance(policy_digest, str)

    outcomes: list[ProbeOutcomeEvidence] = []
    blockers: list[ProbeBlocker] = []
    for sequence, probe in enumerate(probe_set.probes):
        edge_digest = _edge_digest(probe.edge)
        request = ProbeExecutionRequest(
            sequence,
            probe.probe_id,
            probe.source_path,
            probe.source_bytes,
            probe.source_sha256,
            probe.expected_outcome,
            edge_digest,
            probe_set.bts_digest,
            relocation.relocation_digest,
            probe_set.probe_set_digest,
        )
        try:
            result = execution_policy.execute_probe(request, relocation)
            _validate_execution_result(result)
        except BTSError as exc:
            return _abort_report(
                bts_digest=probe_set.bts_digest,
                relocation_digest=relocation.relocation_digest,
                probe_set_digest=probe_set.probe_set_digest,
                execution_policy_digest=policy_digest,
                reason=exc.reason,
                detail=(
                    "probe_donor_import_observed"
                    if exc.reason is BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED
                    else "probe_execution_rejected"
                ),
                completed=len(outcomes),
            )
        except Exception:
            return _abort_report(
                bts_digest=probe_set.bts_digest,
                relocation_digest=relocation.relocation_digest,
                probe_set_digest=probe_set.probe_set_digest,
                execution_policy_digest=policy_digest,
                reason=BTSRejectReason.REJECT_HARD_GATE_FAILED,
                detail="probe_runner_failure",
                completed=len(outcomes),
            )
        if not result.completed:
            assert result.abort_reason is not None and result.abort_detail_category is not None
            return _abort_report(
                bts_digest=probe_set.bts_digest,
                relocation_digest=relocation.relocation_digest,
                probe_set_digest=probe_set.probe_set_digest,
                execution_policy_digest=policy_digest,
                reason=result.abort_reason,
                detail=result.abort_detail_category,
                completed=len(outcomes),
            )
        assert result.observed_outcome is not None
        assert result.execution_receipt_digest is not None
        assert result.runtime is not None
        outcome = ProbeOutcomeEvidence(
            probe.probe_id,
            edge_digest,
            probe.source_sha256,
            probe.expected_outcome,
            result.observed_outcome,
            result.execution_receipt_digest,
            result.runtime.observation_digest,
        )
        outcomes.append(outcome)
        if not result.fresh_child_attested:
            blockers.append(ProbeBlocker(BTSRejectReason.REJECT_HARD_GATE_FAILED, "probe_fresh_child_v1", probe.probe_id, edge_digest))
        if not result.donor_absent_attested:
            blockers.append(ProbeBlocker(BTSRejectReason.REJECT_EXECUTION_THREAT, "probe_donor_absence_v1", probe.probe_id, edge_digest))
        if not result.runtime.recorder_complete:
            blockers.append(ProbeBlocker(BTSRejectReason.REJECT_HARD_GATE_FAILED, "probe_runtime_recorder_v1", probe.probe_id, edge_digest))
        if result.runtime.donor_import_observed:
            blockers.append(
                ProbeBlocker(BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED, "probe_donor_import_observed_v1", probe.probe_id, edge_digest)
            )
        if result.observed_outcome is not probe.expected_outcome:
            blockers.append(
                ProbeBlocker(BTSRejectReason.REJECT_SEMANTIC_DEGRADATION, "probe_outcome_mismatch_v1", probe.probe_id, edge_digest)
            )

    status = ProbeStatus.COMPLETE if not blockers else ProbeStatus.REJECT
    return _final_report(
        status,
        bts_digest=probe_set.bts_digest,
        relocation_digest=relocation.relocation_digest,
        probe_set_digest=probe_set.probe_set_digest,
        execution_policy_digest=policy_digest,
        outcomes=outcomes,
        blockers=blockers,
    )


__all__ = [
    "PROBE_ABORT_SCHEMA_VERSION",
    "PROBE_REPORT_SCHEMA_VERSION",
    "PROBE_SCHEMA_VERSION",
    "PinnedProbe",
    "ProbeAbortEnvelope",
    "ProbeBlocker",
    "ProbeExecutionPolicy",
    "ProbeExecutionRequest",
    "ProbeExecutionResult",
    "ProbeOutcome",
    "ProbeOutcomeEvidence",
    "ProbeReport",
    "ProbeRuntimeEvidence",
    "ProbeSet",
    "ProbeStatus",
    "run_probes",
]
