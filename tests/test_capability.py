from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import FrozenInstanceError, replace

import pytest

import leitir.capability as capability
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.capability import (
    PINNED_BEHAVIOR_CONTRACT_REGISTRY,
    BehaviorContract,
    BehaviorContractRegistry,
    BehaviorRequirement,
    CapabilitySpec,
    ConstraintMode,
    InterfaceKind,
    InterfaceRequirement,
    LicensePolicy,
    PerformanceConstraint,
)


def _spec(registry: BehaviorContractRegistry = PINNED_BEHAVIOR_CONTRACT_REGISTRY) -> CapabilitySpec:
    return CapabilitySpec(
        required_behaviors=(BehaviorRequirement("python.callable.sync", "v1", ("parse", "parser")),),
        prohibited_behaviors=(),
        target_language="python",
        target_runtime="python>=3.11",
        interfaces=(
            InterfaceRequirement(
                "parse",
                InterfaceKind.FUNCTION,
                ("positional_or_keyword",),
                "value",
                ("pure",),
                ConstraintMode.REQUIRED,
            ),
        ),
        performance_constraints=(
            PerformanceConstraint(
                "duration", "leitir.perf_counter_ns", "v1", "le", 1_000_000, "ns", ConstraintMode.PREFERRED
            ),
        ),
        license_policy=LicensePolicy.create(policy_id="permissive", policy_version="v1", allowed_spdx_expressions=("MIT",)),
        prohibited_dependencies=("pickle",),
        required_platforms=("any",),
        behavior_registry=registry,
    )


def test_valid_spec_digest_is_stable_frozen_and_round_trips() -> None:
    first = _spec()
    second = _spec()
    assert first.spec_digest == second.spec_digest
    assert first.to_bytes() == second.to_bytes()
    assert CapabilitySpec.from_json(first.to_json()).to_bytes() == first.to_bytes()
    with pytest.raises(FrozenInstanceError):
        first.target_language = "other"  # type: ignore[misc]


def test_unregistered_behavior_rejects_at_construction() -> None:
    with pytest.raises(BTSError) as caught:
        replace(
            _spec(),
            required_behaviors=(BehaviorRequirement("python.unknown", "v1"),),
        )
    assert caught.value.reason is BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT
    assert caught.value.evidence.detail_code == "behavior_contract_unsupported_v1"


@pytest.mark.parametrize("field", ["required_behaviors", "required_platforms"])
def test_missing_required_value_rejects(field: str) -> None:
    with pytest.raises(BTSError) as caught:
        replace(_spec(), **{field: ()})
    assert caught.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED


def test_missing_serialized_field_rejects() -> None:
    malformed = _spec().to_json().replace('"target_language":"python",', "")
    with pytest.raises(BTSError) as caught:
        CapabilitySpec.from_json(malformed)
    assert caught.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED


def test_registry_binding_changes_digest_and_substitution_rejects() -> None:
    original_contract = PINNED_BEHAVIOR_CONTRACT_REGISTRY.contracts[0]
    changed_contract = BehaviorContract.create(
        behavior_id=original_contract.behavior_id,
        contract_version=original_contract.contract_version,
        proof_rule_id=original_contract.proof_rule_id,
        proof_rule_version="v2",
        collector_id=original_contract.collector_id,
        collector_version=original_contract.collector_version,
        evidence_schema_id=original_contract.evidence_schema_id,
        evidence_schema_version=original_contract.evidence_schema_version,
        structural_requirements=original_contract.structural_requirements,
    )
    contracts = tuple(
        changed_contract if item.behavior_id == changed_contract.behavior_id else item
        for item in PINNED_BEHAVIOR_CONTRACT_REGISTRY.contracts
    )
    registry_v2 = BehaviorContractRegistry.create("v2", contracts)
    first = _spec()
    second = _spec(registry_v2)
    assert first.behavior_registry_digest != second.behavior_registry_digest
    assert first.spec_digest != second.spec_digest
    with pytest.raises(BTSError) as caught:
        first.validate_registry(registry_v2)
    assert caught.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    with pytest.raises(BTSError):
        CapabilitySpec.from_json(first.to_json(), registry_v2)


def test_evidence_terms_are_hints_not_contract_proof() -> None:
    with_terms = _spec()
    without_terms = replace(
        with_terms,
        required_behaviors=(BehaviorRequirement("python.callable.sync", "v1"),),
    )
    assert with_terms.spec_digest != without_terms.spec_digest
    assert with_terms.referenced_contract_digests == without_terms.referenced_contract_digests
    assert not hasattr(with_terms.required_behaviors[0], "proof")


def test_natural_language_compilation_is_excluded() -> None:
    assert not hasattr(capability, "compile_natural_language")
    assert not hasattr(CapabilitySpec, "from_prompt")


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_hash_seed_determinism(seed: str) -> None:
    script = "from tests.test_capability import _spec; import sys; sys.stdout.buffer.write(_spec().to_bytes())"
    environment = os.environ.copy()
    environment["PYTHONHASHSEED"] = seed
    environment["PYTHONPATH"] = "src"
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=os.fspath(os.path.dirname(os.path.dirname(__file__))),
        env=environment,
        check=True,
        capture_output=True,
    )
    assert result.stdout == _spec().to_bytes()
