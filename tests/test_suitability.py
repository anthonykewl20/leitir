from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace

import pytest

from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.candidates import CandidateProposal, EvidencePointer, RetrievalProvenance
from leitir.capability import PINNED_BEHAVIOR_CONTRACT_REGISTRY
from leitir.lockfiles import DependencyManifestPolicy
from leitir.project_profile import RecipientInputManifest, profile_project
from leitir.suitability import (
    PINNED_SUITABILITY_POLICY,
    GateStatus,
    GateVerdictStatus,
    SuitabilityPolicy,
    build_survivor_set,
    evaluate_gates,
)
from tests.test_capability import _spec

_SHA = "1" * 40
_BLOB = "2" * 40
_DIGEST = "sha256:" + "3" * 64


def _pointer(kind: str, collector: str = "leitir.fixture", version: str = "v1") -> EvidencePointer:
    return EvidencePointer(kind, collector, version, _DIGEST)


def _profile():
    manifest = RecipientInputManifest.create("recipient:suitability", ())
    return profile_project(manifest, DependencyManifestPolicy(()))


def _required_proof() -> EvidencePointer:
    contract = PINNED_BEHAVIOR_CONTRACT_REGISTRY.resolve("python.callable.sync", "v1")
    kind = f"behavior-proof:python.callable.sync@v1:{contract.content_digest}"
    return _pointer(kind, contract.collector_id, contract.collector_version)


def _passing_context() -> tuple[EvidencePointer, ...]:
    return (
        _pointer("dependency-closure:complete"),
        _pointer("interface-proof:parse"),
        _pointer("language:python"),
        _pointer("license:MIT"),
        _pointer("platform:any"),
        _pointer("runtime:python>=3.11"),
        _required_proof(),
    )


def _candidate(*, context: tuple[EvidencePointer, ...] | None = None, column: int = 0) -> CandidateProposal:
    return CandidateProposal(
        slug="owner/repo",
        commit_sha=_SHA,
        path="src/api.py",
        blob_sha=_BLOB,
        start_line=1,
        start_col=column,
        end_line=2,
        end_col=column + 4,
        symbol_kind="function",
        qualified_name=f"api.parse_{column}",
        extraction_method="python_ast",
        extraction_version="v1",
        proposal_rule_id="python.symbol.exact",
        proposal_rule_version="v1",
        extraction_evidence=(_pointer("ast"),),
        context_evidence=_passing_context() if context is None else context,
        retrieval_provenance=(RetrievalProvenance("a" * 64, _DIGEST, ("identifier",), "0x1.0000000000000p+0"),),
    )


def _replace_kind(items: tuple[EvidencePointer, ...], old: str, replacement: EvidencePointer) -> tuple[EvidencePointer, ...]:
    return tuple(replacement if item.evidence_kind == old else item for item in items)


def _fixture_bytes() -> bytes:
    candidates = (_candidate(column=8), _candidate(column=0))
    return build_survivor_set(candidates, _spec(), _profile()).to_bytes()


def test_all_required_gates_pass_and_candidate_survives() -> None:
    outcome = evaluate_gates(_candidate(), _spec(), _profile())
    assert outcome.verdict is GateVerdictStatus.PASS
    assert outcome.survives is True
    assert all(
        result.status in {GateStatus.PASS, GateStatus.NOT_APPLICABLE}
        for result in outcome.results
        if result.mode.value == "required"
    )
    survivors = build_survivor_set((_candidate(),), _spec(), _profile())
    assert len(survivors.candidates) == 1


def test_one_required_failure_rejects_despite_all_other_strong_evidence() -> None:
    context = _replace_kind(
        _passing_context(),
        "runtime:python>=3.11",
        _pointer("gate-status/runtime.python>=3.11/fail", "leitir.suitability_assessment"),
    )
    outcome = evaluate_gates(_candidate(context=context), _spec(), _profile())
    assert outcome.verdict is GateVerdictStatus.REJECT
    assert outcome.survives is False
    assert [result.status for result in outcome.results].count(GateStatus.FAIL) == 1
    assert build_survivor_set((_candidate(context=context),), _spec(), _profile()).candidates == ()


@pytest.mark.parametrize("status", [GateStatus.UNKNOWN, GateStatus.ERROR, GateStatus.SKIPPED])
def test_required_unresolved_status_remains_distinct_and_never_survives(status: GateStatus) -> None:
    context = _replace_kind(
        _passing_context(),
        "runtime:python>=3.11",
        _pointer(f"gate-status/runtime.python>=3.11/{status.value}", "leitir.suitability_assessment"),
    )
    outcome = evaluate_gates(_candidate(context=context), _spec(), _profile())
    runtime = next(result for result in outcome.results if result.gate_id == "runtime.python>=3.11")
    assert runtime.status is status
    assert runtime.status_evidence.original_status == status.value
    assert outcome.verdict is GateVerdictStatus.INDETERMINATE
    assert outcome.complete is False
    assert outcome.survives is False


def test_failure_dominates_unresolved_and_retains_both_blockers() -> None:
    context = tuple(
        item for item in _passing_context() if item.evidence_kind not in {"runtime:python>=3.11", "license:MIT"}
    ) + (
        _pointer("gate-status/runtime.python>=3.11/error", "leitir.suitability_assessment"),
        _pointer("license:GPL-3.0-only"),
    )
    outcome = evaluate_gates(_candidate(context=context), _spec(), _profile())
    assert outcome.verdict is GateVerdictStatus.REJECT
    assert outcome.complete is False
    assert {GateStatus.FAIL, GateStatus.ERROR} <= {result.status for result in outcome.results}


def test_not_applicable_is_derived_only_from_empty_spec_field() -> None:
    outcome = evaluate_gates(_candidate(), _spec(), _profile())
    prohibited = next(result for result in outcome.results if result.gate_id == "prohibited_behavior.none")
    assert prohibited.status is GateStatus.NOT_APPLICABLE
    assert prohibited.evidence == ()
    with pytest.raises(BTSError) as caught:
        evaluate_gates(
            _candidate(context=_passing_context() + (_pointer("gate-status/license/not_applicable", "leitir.suitability_assessment"),)),
            _spec(),
            _profile(),
        )
    assert caught.value.evidence.detail_code == "suitability_status_conversion_v1"


def test_advisory_failure_cannot_change_required_verdict_or_rescue_failure() -> None:
    advisory_fail = _pointer("gate-status/performance.duration/fail", "leitir.suitability_assessment")
    passing = evaluate_gates(_candidate(context=_passing_context() + (advisory_fail,)), _spec(), _profile())
    assert passing.verdict is GateVerdictStatus.PASS

    required_fail = _pointer("gate-status/runtime.python>=3.11/fail", "leitir.suitability_assessment")
    context = tuple(item for item in _passing_context() if item.evidence_kind != "runtime:python>=3.11") + (advisory_fail, required_fail)
    rejected = evaluate_gates(_candidate(context=context), _spec(), _profile())
    assert rejected.verdict is GateVerdictStatus.REJECT


def test_behavior_term_hint_without_registry_backed_proof_is_unknown() -> None:
    context = tuple(item for item in _passing_context() if not item.evidence_kind.startswith("behavior-proof:")) + (
        _pointer("term-hint:parse"),
    )
    outcome = evaluate_gates(_candidate(context=context), _spec(), _profile())
    behavior = next(result for result in outcome.results if result.gate_id.startswith("required_behavior."))
    assert behavior.status is GateStatus.UNKNOWN
    assert outcome.verdict is GateVerdictStatus.INDETERMINATE


def test_behavior_proof_with_wrong_registry_collector_is_not_proof() -> None:
    proof = _required_proof()
    context = tuple(item for item in _passing_context() if item is not proof and not item.evidence_kind.startswith("behavior-proof:")) + (
        _pointer(proof.evidence_kind, "untrusted.collector"),
    )
    outcome = evaluate_gates(_candidate(context=context), _spec(), _profile())
    behavior = next(result for result in outcome.results if result.gate_kind.value == "required_behavior")
    assert behavior.status is GateStatus.UNKNOWN


def test_unpinned_policy_edit_rejects_even_with_recomputed_digest() -> None:
    changed_gate = replace(PINNED_SUITABILITY_POLICY.gates[0], rule_version="v2")
    changed = SuitabilityPolicy.create(
        policy_id=PINNED_SUITABILITY_POLICY.policy_id,
        policy_version=PINNED_SUITABILITY_POLICY.policy_version,
        gates=(changed_gate,) + PINNED_SUITABILITY_POLICY.gates[1:],
    )
    with pytest.raises(BTSError) as caught:
        evaluate_gates(_candidate(), _spec(), _profile(), changed)
    assert caught.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_survivor_set_is_byte_identical_across_hash_seeds(seed: str) -> None:
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = seed
    environment["PYTHONPATH"] = "src"
    completed = subprocess.run(
        [sys.executable, "-c", "from tests.test_suitability import _fixture_bytes; import sys; sys.stdout.buffer.write(_fixture_bytes())"],
        cwd=os.fspath(os.path.dirname(os.path.dirname(__file__))),
        env=environment,
        check=True,
        capture_output=True,
    )
    assert completed.stdout == _fixture_bytes()
