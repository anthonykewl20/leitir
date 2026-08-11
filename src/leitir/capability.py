"""Typed, model-free capability intent and pinned behavior contracts.

This module is deliberately non-authorizing beyond intent validation.  It does
not retrieve donors, prove behavior, mint graph node identities, or compute a
Behavioral Transplant Set.  Retrieval terms are hints; only C2's application of
the contracts below to verified bytes can produce behavior evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from itertools import pairwise
from typing import Any, ClassVar, NoReturn

from leitir.bts_errors import BTSError, BTSRejectReason

CAPABILITY_SCHEMA_VERSION = "leitir-capability-v1"
BEHAVIOR_REGISTRY_ID = "leitir-behavior-contracts"
BEHAVIOR_REGISTRY_AUTHORITY = "leitir-maintainers"
_MAX_TEXT = 256
_MAX_ITEMS = 128
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ID = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")


class ConstraintMode(str, Enum):  # noqa: UP042 - serialized contract is str based
    REQUIRED = "required"
    PREFERRED = "preferred"


class InterfaceKind(str, Enum):  # noqa: UP042 - serialized contract is str based
    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    ITERATOR = "iterator"
    ASYNC_ITERATOR = "async_iterator"
    CONTEXT_MANAGER = "context_manager"
    ASYNC_CONTEXT_MANAGER = "async_context_manager"


class StructuralRuleKind(str, Enum):  # noqa: UP042 - serialized contract is str based
    AST = "ast"
    SYMBOL = "symbol"
    INTERFACE = "interface"
    EFFECT = "effect"
    TYPED_EVIDENCE = "typed_evidence"


_STRUCTURAL_PREDICATES = frozenset(
    {
        (StructuralRuleKind.AST, "node_kind_is"),
        (StructuralRuleKind.SYMBOL, "symbol_kind_is"),
        (StructuralRuleKind.INTERFACE, "interface_kind_is"),
        (StructuralRuleKind.EFFECT, "effect_absent"),
        (StructuralRuleKind.TYPED_EVIDENCE, "evidence_field_equals"),
    }
)
_STRUCTURAL_VALUES = {
    (StructuralRuleKind.AST, "node_kind_is"): frozenset({"function_def", "async_function_def"}),
    (StructuralRuleKind.SYMBOL, "symbol_kind_is"): frozenset({"function", "async_function", "method", "async_method"}),
    (StructuralRuleKind.INTERFACE, "interface_kind_is"): frozenset(kind.value for kind in InterfaceKind),
    (StructuralRuleKind.EFFECT, "effect_absent"): frozenset(
        {"filesystem", "network", "process", "environment", "clock", "random"}
    ),
    (StructuralRuleKind.TYPED_EVIDENCE, "evidence_field_equals"): frozenset({"true", "false"}),
}
_LANGUAGES = frozenset({"python"})
_RUNTIMES = frozenset({"python>=3.11", "cpython>=3.11"})
_PLATFORMS = frozenset({"any", "linux", "macos", "windows"})
_PARAMETER_KINDS = frozenset(
    {"positional_only", "positional_or_keyword", "var_positional", "keyword_only", "var_keyword"}
)
_RETURN_KINDS = frozenset(
    {"any", "value", "none", "iterator", "async_iterator", "context_manager", "async_context_manager"}
)
_EFFECT_KINDS = frozenset({"pure", "filesystem", "network", "process", "environment", "clock", "random"})
_PERFORMANCE_CONTRACTS = frozenset(
    {
        ("duration", "leitir.perf_counter_ns", "v1", "ns"),
        ("peak_memory", "leitir.tracemalloc_peak", "v1", "bytes"),
    }
)
_OPERATORS = frozenset({"lt", "le", "eq", "ge", "gt"})
_SPDX_EXPRESSIONS = frozenset({"MIT", "Apache-2.0", "BSD-3-Clause", "Python-2.0"})


def _reject(reason: BTSRejectReason, message: str, detail_code: str) -> NoReturn:
    raise BTSError(reason, message, detail_code=detail_code)


def _schema_reject(message: str) -> NoReturn:
    _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, message, "capability_schema_invalid_v1")


def _unsupported(message: str, detail: str = "behavior_contract_unsupported_v1") -> NoReturn:
    _reject(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, message, detail)


def _text(value: object, name: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT:
        _schema_reject(f"{name} must be a bounded non-empty string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _schema_reject(f"{name} must be strict UTF-8")
    if identifier and _ID.fullmatch(value) is None:
        _schema_reject(f"{name} must be a canonical identifier")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        _reject(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            f"{name} must be a lowercase sha256 digest",
            "capability_registry_digest_v1",
        )
    return value


def _canonical_bytes(payload: object) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def _content_digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _enum(value: object, enum_type: type[Enum], name: str) -> None:
    if not isinstance(value, enum_type):
        _schema_reject(f"{name} must be a {enum_type.__name__}")


def _strings(values: object, name: str, *, identifier: bool = False) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > _MAX_ITEMS:
        _schema_reject(f"{name} must be a bounded tuple")
    checked = tuple(_text(value, f"{name} item", identifier=identifier) for value in values)
    ordered = tuple(sorted(checked))
    if any(left == right for left, right in pairwise(ordered)):
        _schema_reject(f"{name} contains duplicates")
    return ordered


@dataclass(frozen=True, slots=True, order=True)
class StructuralProofRule:
    """One closed, declarative structural predicate (never executable code)."""

    kind: StructuralRuleKind
    predicate: str
    subject: str
    expected_values: tuple[str, ...]

    def __post_init__(self) -> None:
        _enum(self.kind, StructuralRuleKind, "kind")
        _text(self.predicate, "predicate", identifier=True)
        _text(self.subject, "subject", identifier=True)
        object.__setattr__(self, "expected_values", _strings(self.expected_values, "expected_values"))
        if (self.kind, self.predicate) not in _STRUCTURAL_PREDICATES:
            _unsupported("unsupported structural proof rule", "behavior_proof_rule_unsupported_v1")
        if not self.expected_values or not set(self.expected_values) <= _STRUCTURAL_VALUES[(self.kind, self.predicate)]:
            _unsupported("unsupported structural proof value", "behavior_proof_rule_unsupported_v1")

    def _payload(self) -> dict[str, object]:
        return {
            "expected_values": list(self.expected_values),
            "kind": self.kind.value,
            "predicate": self.predicate,
            "subject": self.subject,
        }


@dataclass(frozen=True, slots=True, order=True)
class BehaviorContract:
    behavior_id: str
    contract_version: str
    proof_rule_id: str
    proof_rule_version: str
    collector_id: str
    collector_version: str
    evidence_schema_id: str
    evidence_schema_version: str
    structural_requirements: tuple[StructuralProofRule, ...]
    content_digest: str

    def __post_init__(self) -> None:
        for name in (
            "behavior_id",
            "contract_version",
            "proof_rule_id",
            "proof_rule_version",
            "collector_id",
            "collector_version",
            "evidence_schema_id",
            "evidence_schema_version",
        ):
            _text(getattr(self, name), name, identifier=True)
        if not isinstance(self.structural_requirements, tuple) or not self.structural_requirements:
            _schema_reject("structural_requirements must be a non-empty tuple")
        if len(self.structural_requirements) > _MAX_ITEMS or not all(
            isinstance(rule, StructuralProofRule) for rule in self.structural_requirements
        ):
            _schema_reject("structural_requirements contains an invalid rule")
        ordered = tuple(sorted(self.structural_requirements))
        rule_keys = tuple((rule.kind.value, rule.predicate, rule.subject) for rule in ordered)
        if len(rule_keys) != len(set(rule_keys)):
            _schema_reject("structural_requirements contains duplicate or conflicting rule keys")
        object.__setattr__(self, "structural_requirements", ordered)
        _digest(self.content_digest, "contract content_digest")
        if self.content_digest != _content_digest(self._payload(include_digest=False)):
            _reject(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "behavior contract content digest mismatch",
                "capability_registry_digest_v1",
            )

    @classmethod
    def create(
        cls,
        *,
        behavior_id: str,
        contract_version: str,
        proof_rule_id: str,
        proof_rule_version: str,
        collector_id: str,
        collector_version: str,
        evidence_schema_id: str,
        evidence_schema_version: str,
        structural_requirements: tuple[StructuralProofRule, ...],
    ) -> BehaviorContract:
        payload = {
            "behavior_id": behavior_id,
            "collector_id": collector_id,
            "collector_version": collector_version,
            "contract_version": contract_version,
            "evidence_schema_id": evidence_schema_id,
            "evidence_schema_version": evidence_schema_version,
            "proof_rule_id": proof_rule_id,
            "proof_rule_version": proof_rule_version,
            "structural_requirements": [rule._payload() for rule in sorted(structural_requirements)],
        }
        return cls(content_digest=_content_digest(payload), **{**payload, "structural_requirements": structural_requirements})  # type: ignore[arg-type]

    def _payload(self, *, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "behavior_id": self.behavior_id,
            "collector_id": self.collector_id,
            "collector_version": self.collector_version,
            "contract_version": self.contract_version,
            "evidence_schema_id": self.evidence_schema_id,
            "evidence_schema_version": self.evidence_schema_version,
            "proof_rule_id": self.proof_rule_id,
            "proof_rule_version": self.proof_rule_version,
            "structural_requirements": [rule._payload() for rule in self.structural_requirements],
        }
        if include_digest:
            payload["content_digest"] = self.content_digest
        return payload


@dataclass(frozen=True, slots=True)
class BehaviorContractRegistry:
    """Content-addressed registry envelope maintained by the Leitir authority."""

    registry_id: str
    registry_version: str
    authority: str
    contracts: tuple[BehaviorContract, ...]
    content_digest: str

    def __post_init__(self) -> None:
        if self.registry_id != BEHAVIOR_REGISTRY_ID or self.authority != BEHAVIOR_REGISTRY_AUTHORITY:
            _unsupported("unsupported behavior registry authority")
        _text(self.registry_version, "registry_version", identifier=True)
        if not isinstance(self.contracts, tuple) or not self.contracts or len(self.contracts) > _MAX_ITEMS:
            _schema_reject("contracts must be a bounded non-empty tuple")
        if not all(isinstance(contract, BehaviorContract) for contract in self.contracts):
            _schema_reject("contracts contains an invalid behavior contract")
        ordered = tuple(sorted(self.contracts, key=lambda item: (item.behavior_id, item.contract_version)))
        keys = tuple((item.behavior_id, item.contract_version) for item in ordered)
        if any(left == right for left, right in pairwise(keys)):
            _schema_reject("duplicate behavior contract key")
        object.__setattr__(self, "contracts", ordered)
        _digest(self.content_digest, "registry content_digest")
        if self.content_digest != _content_digest(self._payload(include_digest=False)):
            _reject(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "behavior registry content digest mismatch",
                "capability_registry_digest_v1",
            )

    @classmethod
    def create(cls, registry_version: str, contracts: tuple[BehaviorContract, ...]) -> BehaviorContractRegistry:
        ordered = tuple(sorted(contracts, key=lambda item: (item.behavior_id, item.contract_version)))
        payload = {
            "authority": BEHAVIOR_REGISTRY_AUTHORITY,
            "contracts": [contract._payload() for contract in ordered],
            "registry_id": BEHAVIOR_REGISTRY_ID,
            "registry_version": registry_version,
        }
        return cls(
            registry_id=BEHAVIOR_REGISTRY_ID,
            registry_version=registry_version,
            authority=BEHAVIOR_REGISTRY_AUTHORITY,
            contracts=ordered,
            content_digest=_content_digest(payload),
        )

    @property
    def registry_digest(self) -> str:
        return self.content_digest

    def resolve(self, behavior_id: str, contract_version: str) -> BehaviorContract:
        for contract in self.contracts:
            if (contract.behavior_id, contract.contract_version) == (behavior_id, contract_version):
                return contract
        _unsupported(f"unregistered behavior contract: {behavior_id}@{contract_version}")

    def _payload(self, *, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "authority": self.authority,
            "contracts": [contract._payload() for contract in self.contracts],
            "registry_id": self.registry_id,
            "registry_version": self.registry_version,
        }
        if include_digest:
            payload["content_digest"] = self.content_digest
        return payload


@dataclass(frozen=True, slots=True, order=True)
class BehaviorRequirement:
    behavior_id: str
    contract_version: str
    evidence_terms: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.behavior_id, "behavior_id", identifier=True)
        _text(self.contract_version, "contract_version", identifier=True)
        object.__setattr__(self, "evidence_terms", _strings(self.evidence_terms, "evidence_terms"))

    def _payload(self, contract_digest: str) -> dict[str, object]:
        return {
            "behavior_id": self.behavior_id,
            "contract_digest": contract_digest,
            "contract_version": self.contract_version,
            "evidence_terms": list(self.evidence_terms),
        }


@dataclass(frozen=True, slots=True, order=True)
class InterfaceRequirement:
    interface_id: str
    kind: InterfaceKind
    parameter_kinds: tuple[str, ...]
    return_kind: str
    effect_kinds: tuple[str, ...]
    mode: ConstraintMode

    def __post_init__(self) -> None:
        _text(self.interface_id, "interface_id", identifier=True)
        _enum(self.kind, InterfaceKind, "kind")
        _enum(self.mode, ConstraintMode, "mode")
        parameters = _strings(self.parameter_kinds, "parameter_kinds")
        effects = _strings(self.effect_kinds, "effect_kinds")
        if not set(parameters) <= _PARAMETER_KINDS or not effects or not set(effects) <= _EFFECT_KINDS:
            _unsupported("unsupported interface parameter or effect semantics")
        if "pure" in effects and len(effects) != 1:
            _reject(
                BTSRejectReason.REJECT_HARD_GATE_FAILED,
                "pure cannot be combined with effectful interface requirements",
                "capability_constraint_conflict_v1",
            )
        if self.return_kind not in _RETURN_KINDS:
            _unsupported("unsupported interface return semantics")
        object.__setattr__(self, "parameter_kinds", parameters)
        object.__setattr__(self, "effect_kinds", effects)

    def _payload(self) -> dict[str, object]:
        return {
            "effect_kinds": list(self.effect_kinds),
            "interface_id": self.interface_id,
            "kind": self.kind.value,
            "mode": self.mode.value,
            "parameter_kinds": list(self.parameter_kinds),
            "return_kind": self.return_kind,
        }


@dataclass(frozen=True, slots=True, order=True)
class PerformanceConstraint:
    metric_id: str
    collector_id: str
    collector_version: str
    operator: str
    integer_value: int
    unit: str
    mode: ConstraintMode

    def __post_init__(self) -> None:
        for name in ("metric_id", "collector_id", "collector_version", "operator", "unit"):
            _text(getattr(self, name), name, identifier=name != "operator")
        _enum(self.mode, ConstraintMode, "mode")
        if isinstance(self.integer_value, bool) or not isinstance(self.integer_value, int) or not 0 <= self.integer_value <= 10**15:
            _schema_reject("integer_value must be a bounded non-negative integer")
        if (self.metric_id, self.collector_id, self.collector_version, self.unit) not in _PERFORMANCE_CONTRACTS:
            _unsupported("unsupported metric collector", "capability_collector_unsupported_v1")
        if self.operator not in _OPERATORS:
            _unsupported("unsupported performance operator", "capability_collector_unsupported_v1")

    def _payload(self) -> dict[str, object]:
        return {
            "collector_id": self.collector_id,
            "collector_version": self.collector_version,
            "integer_value": self.integer_value,
            "metric_id": self.metric_id,
            "mode": self.mode.value,
            "operator": self.operator,
            "unit": self.unit,
        }


@dataclass(frozen=True, slots=True)
class LicensePolicy:
    policy_id: str
    policy_version: str
    allowed_spdx_expressions: tuple[str, ...]
    prohibited_spdx_expressions: tuple[str, ...]
    allow_unknown: bool
    policy_digest: str

    def __post_init__(self) -> None:
        _text(self.policy_id, "policy_id", identifier=True)
        _text(self.policy_version, "policy_version", identifier=True)
        allowed = _strings(self.allowed_spdx_expressions, "allowed_spdx_expressions")
        prohibited = _strings(self.prohibited_spdx_expressions, "prohibited_spdx_expressions")
        if not allowed or not set(allowed) <= _SPDX_EXPRESSIONS or not set(prohibited) <= _SPDX_EXPRESSIONS:
            _unsupported("unsupported SPDX expression")
        if set(allowed) & set(prohibited):
            _reject(
                BTSRejectReason.REJECT_HARD_GATE_FAILED,
                "license policy is contradictory",
                "capability_constraint_conflict_v1",
            )
        if self.allow_unknown is not False:
            _unsupported("v1 does not allow unknown licenses")
        object.__setattr__(self, "allowed_spdx_expressions", allowed)
        object.__setattr__(self, "prohibited_spdx_expressions", prohibited)
        _digest(self.policy_digest, "policy_digest")
        if self.policy_digest != _content_digest(self._payload(include_digest=False)):
            _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "license policy digest mismatch", "capability_registry_digest_v1")

    @classmethod
    def create(
        cls,
        *,
        policy_id: str,
        policy_version: str,
        allowed_spdx_expressions: tuple[str, ...],
        prohibited_spdx_expressions: tuple[str, ...] = (),
    ) -> LicensePolicy:
        allowed = tuple(sorted(allowed_spdx_expressions))
        prohibited = tuple(sorted(prohibited_spdx_expressions))
        payload = {
            "allow_unknown": False,
            "allowed_spdx_expressions": list(allowed),
            "policy_id": policy_id,
            "policy_version": policy_version,
            "prohibited_spdx_expressions": list(prohibited),
        }
        return cls(policy_id, policy_version, allowed, prohibited, False, _content_digest(payload))

    def _payload(self, *, include_digest: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "allow_unknown": self.allow_unknown,
            "allowed_spdx_expressions": list(self.allowed_spdx_expressions),
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "prohibited_spdx_expressions": list(self.prohibited_spdx_expressions),
        }
        if include_digest:
            payload["policy_digest"] = self.policy_digest
        return payload


def _seed_registry() -> BehaviorContractRegistry:
    sync = BehaviorContract.create(
        behavior_id="python.callable.sync",
        contract_version="v1",
        proof_rule_id="python.callable.sync.ast",
        proof_rule_version="v1",
        collector_id="leitir.python_ast",
        collector_version="v1",
        evidence_schema_id="leitir.python_callable_evidence",
        evidence_schema_version="v1",
        structural_requirements=(
            StructuralProofRule(StructuralRuleKind.AST, "node_kind_is", "candidate", ("function_def",)),
            StructuralProofRule(StructuralRuleKind.INTERFACE, "interface_kind_is", "candidate", ("function",)),
        ),
    )
    async_contract = BehaviorContract.create(
        behavior_id="python.callable.async",
        contract_version="v1",
        proof_rule_id="python.callable.async.ast",
        proof_rule_version="v1",
        collector_id="leitir.python_ast",
        collector_version="v1",
        evidence_schema_id="leitir.python_callable_evidence",
        evidence_schema_version="v1",
        structural_requirements=(
            StructuralProofRule(StructuralRuleKind.AST, "node_kind_is", "candidate", ("async_function_def",)),
            StructuralProofRule(StructuralRuleKind.INTERFACE, "interface_kind_is", "candidate", ("async_function",)),
        ),
    )
    return BehaviorContractRegistry.create("v1", (sync, async_contract))


PINNED_BEHAVIOR_CONTRACT_REGISTRY = _seed_registry()
DEFAULT_BEHAVIOR_CONTRACT_REGISTRY = PINNED_BEHAVIOR_CONTRACT_REGISTRY


@dataclass(frozen=True, slots=True)
class CapabilitySpec:
    """Validated authorizing intent; behavior evidence is produced elsewhere."""

    required_behaviors: tuple[BehaviorRequirement, ...]
    prohibited_behaviors: tuple[BehaviorRequirement, ...]
    target_language: str
    target_runtime: str
    interfaces: tuple[InterfaceRequirement, ...]
    performance_constraints: tuple[PerformanceConstraint, ...]
    license_policy: LicensePolicy
    prohibited_dependencies: tuple[str, ...]
    required_platforms: tuple[str, ...]
    behavior_registry: BehaviorContractRegistry = field(repr=False, compare=False)
    schema_version: str = CAPABILITY_SCHEMA_VERSION
    behavior_registry_digest: str = field(init=False)
    referenced_contract_digests: tuple[str, ...] = field(init=False)
    spec_digest: str = field(init=False)

    _FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "behavior_registry_digest",
            "interfaces",
            "license_policy",
            "performance_constraints",
            "prohibited_behaviors",
            "prohibited_dependencies",
            "referenced_contract_digests",
            "required_behaviors",
            "required_platforms",
            "schema_version",
            "spec_digest",
            "target_language",
            "target_runtime",
        }
    )

    def __post_init__(self) -> None:
        if self.schema_version != CAPABILITY_SCHEMA_VERSION:
            _unsupported("unsupported capability schema")
        if not isinstance(self.behavior_registry, BehaviorContractRegistry):
            _schema_reject("behavior_registry is required")
        if self.target_language not in _LANGUAGES or self.target_runtime not in _RUNTIMES:
            _unsupported("unsupported target language or runtime")
        required = self._requirements(self.required_behaviors, "required_behaviors")
        prohibited = self._requirements(self.prohibited_behaviors, "prohibited_behaviors")
        if not required:
            _schema_reject("at least one required behavior is mandatory")
        required_keys = {(item.behavior_id, item.contract_version) for item in required}
        prohibited_keys = {(item.behavior_id, item.contract_version) for item in prohibited}
        if required_keys & prohibited_keys:
            _reject(
                BTSRejectReason.REJECT_HARD_GATE_FAILED,
                "a behavior cannot be both required and prohibited",
                "capability_constraint_conflict_v1",
            )
        if not isinstance(self.interfaces, tuple) or len(self.interfaces) > _MAX_ITEMS or not all(
            isinstance(item, InterfaceRequirement) for item in self.interfaces
        ):
            _schema_reject("interfaces must be a bounded tuple of InterfaceRequirement values")
        if not isinstance(self.performance_constraints, tuple) or len(self.performance_constraints) > _MAX_ITEMS or not all(
            isinstance(item, PerformanceConstraint) for item in self.performance_constraints
        ):
            _schema_reject("performance_constraints must be a bounded tuple of PerformanceConstraint values")
        interfaces = tuple(sorted(self.interfaces))
        performance = tuple(sorted(self.performance_constraints))
        if any(left.interface_id == right.interface_id for left, right in pairwise(interfaces)):
            _schema_reject("duplicate interface_id")
        performance_keys = tuple((item.metric_id, item.collector_id, item.collector_version) for item in performance)
        if len(performance_keys) != len(set(performance_keys)):
            _schema_reject("duplicate performance constraint")
        dependencies = _strings(self.prohibited_dependencies, "prohibited_dependencies", identifier=True)
        platforms = _strings(self.required_platforms, "required_platforms")
        if not platforms:
            _schema_reject("at least one required platform is mandatory")
        if not set(platforms) <= _PLATFORMS or ("any" in platforms and len(platforms) != 1):
            _unsupported("unsupported or contradictory target platform")
        if not isinstance(self.license_policy, LicensePolicy):
            _schema_reject("license_policy is required")

        contracts = tuple(self.behavior_registry.resolve(*key) for key in sorted(required_keys | prohibited_keys))
        object.__setattr__(self, "required_behaviors", required)
        object.__setattr__(self, "prohibited_behaviors", prohibited)
        object.__setattr__(self, "interfaces", interfaces)
        object.__setattr__(self, "performance_constraints", performance)
        object.__setattr__(self, "prohibited_dependencies", dependencies)
        object.__setattr__(self, "required_platforms", platforms)
        object.__setattr__(self, "behavior_registry_digest", self.behavior_registry.registry_digest)
        object.__setattr__(self, "referenced_contract_digests", tuple(contract.content_digest for contract in contracts))
        object.__setattr__(self, "spec_digest", _content_digest(self._payload(include_digest=False)))

    def _requirements(self, value: object, name: str) -> tuple[BehaviorRequirement, ...]:
        if not isinstance(value, tuple) or len(value) > _MAX_ITEMS or not all(
            isinstance(item, BehaviorRequirement) for item in value
        ):
            _schema_reject(f"{name} must be a bounded tuple of BehaviorRequirement values")
        ordered = tuple(sorted(value))
        keys = tuple((item.behavior_id, item.contract_version) for item in ordered)
        if any(left == right for left, right in pairwise(keys)):
            _schema_reject(f"{name} contains duplicate contract keys")
        return ordered

    def validate_registry(self, registry: BehaviorContractRegistry) -> None:
        """Reject registry substitution; never silently rebind a specification."""

        if not isinstance(registry, BehaviorContractRegistry) or registry.registry_digest != self.behavior_registry_digest:
            _reject(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "capability specification behavior registry mismatch",
                "capability_registry_digest_v1",
            )

    def _payload(self, *, include_digest: bool = True) -> dict[str, object]:
        contract_digests = {
            (contract.behavior_id, contract.contract_version): contract.content_digest
            for contract in self.behavior_registry.contracts
        }
        payload: dict[str, object] = {
            "behavior_registry_digest": self.behavior_registry_digest,
            "interfaces": [item._payload() for item in self.interfaces],
            "license_policy": self.license_policy._payload(),
            "performance_constraints": [item._payload() for item in self.performance_constraints],
            "prohibited_behaviors": [
                item._payload(contract_digests[(item.behavior_id, item.contract_version)])
                for item in self.prohibited_behaviors
            ],
            "prohibited_dependencies": list(self.prohibited_dependencies),
            "referenced_contract_digests": list(self.referenced_contract_digests),
            "required_behaviors": [
                item._payload(contract_digests[(item.behavior_id, item.contract_version)])
                for item in self.required_behaviors
            ],
            "required_platforms": list(self.required_platforms),
            "schema_version": self.schema_version,
            "target_language": self.target_language,
            "target_runtime": self.target_runtime,
        }
        if include_digest:
            payload["spec_digest"] = self.spec_digest
        return payload

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self._payload())

    def to_json(self) -> str:
        return self.to_bytes().decode("utf-8")

    @classmethod
    def from_json(
        cls,
        data: str | bytes,
        registry: BehaviorContractRegistry = PINNED_BEHAVIOR_CONTRACT_REGISTRY,
    ) -> CapabilitySpec:
        try:
            decoded = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
            _schema_reject(f"invalid capability JSON: {exc}")
        if not isinstance(decoded, dict) or set(decoded) != cls._FIELDS:
            _schema_reject("capability JSON has missing or unknown fields")
        try:
            required = tuple(_requirement_from_payload(item) for item in _list(decoded, "required_behaviors"))
            prohibited = tuple(_requirement_from_payload(item) for item in _list(decoded, "prohibited_behaviors"))
            interfaces = tuple(_interface_from_payload(item) for item in _list(decoded, "interfaces"))
            performance = tuple(_performance_from_payload(item) for item in _list(decoded, "performance_constraints"))
            license_policy = _license_from_payload(decoded["license_policy"])
            spec = cls(
                required_behaviors=required,
                prohibited_behaviors=prohibited,
                target_language=decoded["target_language"],
                target_runtime=decoded["target_runtime"],
                interfaces=interfaces,
                performance_constraints=performance,
                license_policy=license_policy,
                prohibited_dependencies=tuple(
                    _text(item, "prohibited_dependencies item") for item in _list(decoded, "prohibited_dependencies")
                ),
                required_platforms=tuple(
                    _text(item, "required_platforms item") for item in _list(decoded, "required_platforms")
                ),
                behavior_registry=registry,
                schema_version=decoded["schema_version"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            _schema_reject(f"invalid capability value: {exc}")
        if decoded != spec._payload():
            _reject(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "capability payload or digest mismatch",
                "capability_registry_digest_v1",
            )
        return spec


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _schema_reject(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _mapping(value: object, fields: frozenset[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        _schema_reject(f"{name} has missing or unknown fields")
    return value


def _list(payload: dict[str, object], name: str) -> list[object]:
    value = payload[name]
    if not isinstance(value, list):
        _schema_reject(f"{name} must be a list")
    return value


def _requirement_from_payload(value: object) -> BehaviorRequirement:
    payload = _mapping(value, frozenset({"behavior_id", "contract_digest", "contract_version", "evidence_terms"}), "behavior")
    terms = payload["evidence_terms"]
    if not isinstance(terms, list):
        _schema_reject("evidence_terms must be a list")
    # contract_digest is checked against the registry by CapabilitySpec's complete payload digest.
    _digest(payload["contract_digest"], "contract_digest")
    return BehaviorRequirement(payload["behavior_id"], payload["contract_version"], tuple(terms))  # type: ignore[arg-type]


def _interface_from_payload(value: object) -> InterfaceRequirement:
    payload = _mapping(
        value,
        frozenset({"effect_kinds", "interface_id", "kind", "mode", "parameter_kinds", "return_kind"}),
        "interface",
    )
    return InterfaceRequirement(
        interface_id=payload["interface_id"],  # type: ignore[arg-type]
        kind=InterfaceKind(payload["kind"]),
        parameter_kinds=tuple(payload["parameter_kinds"]),  # type: ignore[arg-type]
        return_kind=payload["return_kind"],  # type: ignore[arg-type]
        effect_kinds=tuple(payload["effect_kinds"]),  # type: ignore[arg-type]
        mode=ConstraintMode(payload["mode"]),
    )


def _performance_from_payload(value: object) -> PerformanceConstraint:
    payload = _mapping(
        value,
        frozenset({"collector_id", "collector_version", "integer_value", "metric_id", "mode", "operator", "unit"}),
        "performance constraint",
    )
    return PerformanceConstraint(
        metric_id=payload["metric_id"],  # type: ignore[arg-type]
        collector_id=payload["collector_id"],  # type: ignore[arg-type]
        collector_version=payload["collector_version"],  # type: ignore[arg-type]
        operator=payload["operator"],  # type: ignore[arg-type]
        integer_value=payload["integer_value"],  # type: ignore[arg-type]
        unit=payload["unit"],  # type: ignore[arg-type]
        mode=ConstraintMode(payload["mode"]),
    )


def _license_from_payload(value: object) -> LicensePolicy:
    payload = _mapping(
        value,
        frozenset(
            {
                "allow_unknown",
                "allowed_spdx_expressions",
                "policy_digest",
                "policy_id",
                "policy_version",
                "prohibited_spdx_expressions",
            }
        ),
        "license policy",
    )
    return LicensePolicy(
        policy_id=payload["policy_id"],  # type: ignore[arg-type]
        policy_version=payload["policy_version"],  # type: ignore[arg-type]
        allowed_spdx_expressions=tuple(payload["allowed_spdx_expressions"]),  # type: ignore[arg-type]
        prohibited_spdx_expressions=tuple(payload["prohibited_spdx_expressions"]),  # type: ignore[arg-type]
        allow_unknown=payload["allow_unknown"],  # type: ignore[arg-type]
        policy_digest=payload["policy_digest"],  # type: ignore[arg-type]
    )


__all__ = [
    "BEHAVIOR_REGISTRY_AUTHORITY",
    "BEHAVIOR_REGISTRY_ID",
    "CAPABILITY_SCHEMA_VERSION",
    "DEFAULT_BEHAVIOR_CONTRACT_REGISTRY",
    "PINNED_BEHAVIOR_CONTRACT_REGISTRY",
    "BehaviorContract",
    "BehaviorContractRegistry",
    "BehaviorRequirement",
    "CapabilitySpec",
    "ConstraintMode",
    "InterfaceKind",
    "InterfaceRequirement",
    "LicensePolicy",
    "PerformanceConstraint",
    "StructuralProofRule",
    "StructuralRuleKind",
]
