"""Fail-closed validation for attaching a BTS to an occupied recipient.

This module is deliberately an evidence gate, not an execution fallback.  Its
execution callback exists for reviewed in-tree fixtures; production callers
must obtain outcomes through the S2 executor and pass its already canonical
vector here.  The binding-collision check is defense-in-depth: a binding can
overlap only when its module overlaps, so the later module-namespace check
provably rejects every binding overlap too.  Binding is checked first to retain
the more specific, deterministic diagnostic.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
from pathlib import PurePosixPath

from leitir.bts import BTS, BTSResult, BTSStatus
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.composition import (
    COMPOSITION_MATRIX_SCHEMA,
    CompositionCandidateRef,
    CompositionEligibilityStatus,
    ConflictMatrix,
    evaluate_eligibility,
)
from leitir.graph.model import NodeKind
from leitir.project_profile import RECIPIENT_MANIFEST_SCHEMA, RecipientInputManifest
from leitir.project_profile import _validate_manifest as _validate_recipient_manifest
from leitir.relocate import ModuleMap
from leitir.rerun import OutcomeCounts, TestOutcome, TestOutcomeEvidence

OCCUPIED_POLICY_SCHEMA_VERSION = "leitir-occupied-attachment-policy-v1"
OCCUPIED_INVENTORY_SCHEMA_VERSION = "leitir-recipient-binding-inventory-v1"
RECIPIENT_BASELINE_SCHEMA_VERSION = "leitir-recipient-baseline-v1"
OCCUPIED_CORPUS_SCHEMA_VERSION = "leitir-occupied-corpus-v1"
OCCUPIED_GATE_SCHEMA_VERSION = "leitir-occupied-gate-v1"
MINIMUM_OCCUPIED_CASES = 5
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*\Z")
_MAX_BINDINGS = 1_000_000


class OccupiedRole(str, Enum):  # noqa: UP042 - ADR-0017 pins str, Enum
    RECIPIENT_BASELINE = "recipient_baseline"
    OCCUPIED_RERUN = "occupied_rerun"


@dataclass(frozen=True, slots=True, order=True)
class RecipientBindingIdentity:
    language: str
    module: str
    qualified_name: str
    scope: str
    kind: str
    source_path: str
    source_digest: str

    def __post_init__(self) -> None:
        try:
            for name in ("language", "module", "qualified_name", "scope", "kind", "source_path"):
                _text(getattr(self, name), name)
            _digest_value(self.source_digest, "source_digest")
        except (TypeError, ValueError) as exc:
            raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "binding identity is malformed", "occupied_binding_identity_malformed_v1", exc) from exc
        if self.language != "python" or self.kind not in {"function", "async_function", "class", "import", "binding"} or self.scope not in {"module", "class", "function"}:
            raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "binding identity uses an unsupported taxonomy", "occupied_binding_identity_taxonomy_v1")
        if any(_IDENTIFIER.fullmatch(part) is None for part in self.module.split(".")):
            raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "binding module is malformed", "occupied_binding_identity_module_v1")

    @property
    def collision_key(self) -> tuple[str, str, str, str, str]:
        return (self.language, self.module, self.qualified_name, self.scope, self.kind)


@dataclass(frozen=True, slots=True)
class RecipientBaselineEvidence:
    schema_version: str
    status: str
    recipient_manifest_digest: str
    test_set_digest: str
    runner_closure_digest: str
    config_closure_digest: str
    mount_plan_digest: str
    execution_policy_digest: str
    canonical_test_ids: tuple[str, ...]
    outcomes: tuple[TestOutcomeEvidence, ...]
    counts: OutcomeCounts
    qualification_runs: int
    evidence_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != RECIPIENT_BASELINE_SCHEMA_VERSION or self.status != "qualified":
            raise ValueError("recipient baseline is not qualified")
        for name in (
            "recipient_manifest_digest",
            "test_set_digest",
            "runner_closure_digest",
            "config_closure_digest",
            "mount_plan_digest",
            "execution_policy_digest",
            "evidence_digest",
        ):
            _digest_value(getattr(self, name), name)
        checked = _outcomes(self.outcomes)
        if self.canonical_test_ids != tuple(item.canonical_test_id for item in checked):
            raise ValueError("baseline canonical IDs do not match outcomes")
        if self.counts != _outcome_counts(checked) or self.counts.failed != 0:
            raise ValueError("recipient baseline must have matching zero-failure counts")
        if type(self.qualification_runs) is not int or self.qualification_runs != 2:
            raise ValueError("recipient baseline requires exactly two qualification runs")
        if self.evidence_digest != _canonical_digest(self, omit=frozenset({"evidence_digest"})):
            raise ValueError("recipient baseline evidence digest mismatch")

    @classmethod
    def qualify_fixture(
        cls,
        *,
        recipient_manifest_digest: str,
        test_set_digest: str,
        runner_closure_digest: str,
        config_closure_digest: str,
        mount_plan_digest: str,
        execution_policy_digest: str,
        execute: Callable[[], tuple[TestOutcomeEvidence, ...]],
    ) -> RecipientBaselineEvidence:
        """Qualify a fixture only by executing it twice with identical evidence.

        Production baselines must be built from S2-produced outcome vectors per
        ADR-0009/ADR-0017, never via an arbitrary in-process callback.
        """

        if not callable(execute):
            raise TypeError("execute must be callable")
        try:
            first = _outcomes(execute())
            second = _outcomes(execute())
        except (TypeError, ValueError, BTSError) as exc:
            raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "recipient baseline execution failed", "occupied_baseline_execution_v1", exc) from exc
        if first != second or _outcome_counts(first) != _outcome_counts(second):
            raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "recipient baseline is not reproducible", "occupied_baseline_nondeterministic_v1")
        if _outcome_counts(first).failed != 0:
            raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "recipient baseline has failures", "occupied_baseline_nonzero_failures_v1")
        draft = cls.__new__(cls)
        values: tuple[object, ...] = (
            RECIPIENT_BASELINE_SCHEMA_VERSION,
            "qualified",
            recipient_manifest_digest,
            test_set_digest,
            runner_closure_digest,
            config_closure_digest,
            mount_plan_digest,
            execution_policy_digest,
            tuple(item.canonical_test_id for item in first),
            first,
            _outcome_counts(first),
            2,
            "sha256:" + "0" * 64,
        )
        for field, value in zip(fields(cls), values, strict=True):
            object.__setattr__(draft, field.name, value)
        return replace(draft, evidence_digest=_canonical_digest(draft, omit=frozenset({"evidence_digest"})))

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)


@dataclass(frozen=True, slots=True)
class OccupiedAttachmentPolicy:
    schema_version: str
    authority: str
    policy_id: str
    policy_version: str
    supported_languages: tuple[str, ...]
    recipient_manifest_schema: str
    inventory_rule_id: str
    inventory_rule_version: str
    collision_detail_registry_digest: str
    conflict_policy_digest: str
    recipient_baseline_mount_plan_digest: str
    occupied_rerun_mount_plan_digest: str
    recipient_baseline_execution_policy_digest: str
    occupied_rerun_execution_policy_digest: str
    corpus_manifest_digest: str
    content_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != OCCUPIED_POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported occupied attachment policy schema")
        for name in ("authority", "policy_id", "policy_version", "inventory_rule_id", "inventory_rule_version"):
            _text(getattr(self, name), name)
        if self.recipient_manifest_schema != RECIPIENT_MANIFEST_SCHEMA:
            raise ValueError("unsupported recipient manifest schema")
        if self.supported_languages != tuple(sorted(self.supported_languages)) or len(set(self.supported_languages)) != len(self.supported_languages):
            raise ValueError("supported languages must be sorted and unique")
        if self.supported_languages != ("python",):
            raise ValueError("v1 supports exactly Python source")
        for name in (
            "collision_detail_registry_digest",
            "conflict_policy_digest",
            "recipient_baseline_mount_plan_digest",
            "occupied_rerun_mount_plan_digest",
            "recipient_baseline_execution_policy_digest",
            "occupied_rerun_execution_policy_digest",
            "corpus_manifest_digest",
            "content_digest",
        ):
            _digest_value(getattr(self, name), name)
        if self.recipient_baseline_mount_plan_digest == self.occupied_rerun_mount_plan_digest:
            raise ValueError("occupied roles require distinct mount plans")
        if self.recipient_baseline_execution_policy_digest == self.occupied_rerun_execution_policy_digest:
            raise ValueError("occupied roles require distinct execution policies")


@dataclass(frozen=True, slots=True)
class RecipientBindingInventory:
    schema_version: str
    recipient_manifest_digest: str
    bindings: tuple[RecipientBindingIdentity, ...]
    module_paths: tuple[str, ...]
    inventory_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != OCCUPIED_INVENTORY_SCHEMA_VERSION:
            raise ValueError("unsupported recipient inventory schema")
        _digest_value(self.recipient_manifest_digest, "recipient_manifest_digest")
        _digest_value(self.inventory_digest, "inventory_digest")
        if self.bindings != tuple(sorted(self.bindings)) or len(self.bindings) > _MAX_BINDINGS:
            raise ValueError("recipient bindings are noncanonical or exceed the bound")
        keys = tuple(item.collision_key for item in self.bindings)
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate recipient binding identity")
        if self.module_paths != tuple(sorted(self.module_paths)) or len(self.module_paths) != len(set(self.module_paths)):
            raise ValueError("recipient module paths must be sorted and unique")
        if self.inventory_digest != _canonical_digest(self, omit=frozenset({"inventory_digest"})):
            raise ValueError("recipient inventory digest mismatch")

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)


class OccupiedRecipientProfile(str, Enum):  # noqa: UP042 - closed corpus contract
    ASYNC_WEB_API = "async_web_api"
    SYNC_CLI = "sync_cli"


@dataclass(frozen=True, slots=True, order=True)
class OccupiedCorpusCase:
    case_id: str
    donor_provenance: str
    recipient_provenance: str
    recipient_profile: OccupiedRecipientProfile
    case_digest: str

    def __post_init__(self) -> None:
        for name in ("case_id", "donor_provenance", "recipient_provenance"):
            _text(getattr(self, name), name)
        if not isinstance(self.recipient_profile, OccupiedRecipientProfile):
            raise ValueError("recipient profile is unsupported")
        _digest_value(self.case_digest, "case_digest")
        if self.case_digest != _canonical_digest(self, omit=frozenset({"case_digest"})):
            raise ValueError("occupied corpus case digest mismatch")

    @classmethod
    def pin(cls, case_id: str, donor_provenance: str, recipient_provenance: str, recipient_profile: OccupiedRecipientProfile) -> OccupiedCorpusCase:
        draft = cls.__new__(cls)
        for name, value in zip(
            (field.name for field in fields(cls)),
            (case_id, donor_provenance, recipient_provenance, recipient_profile, "sha256:" + "0" * 64),
            strict=True,
        ):
            object.__setattr__(draft, name, value)
        return replace(draft, case_digest=_canonical_digest(draft, omit=frozenset({"case_digest"})))


@dataclass(frozen=True, slots=True)
class OccupiedCorpus:
    schema_version: str
    authority: str
    release_id: str
    cases: tuple[OccupiedCorpusCase, ...]
    predecessor_case_ids: tuple[str, ...]
    ratified_manifest_digest: str
    corpus_manifest_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != OCCUPIED_CORPUS_SCHEMA_VERSION:
            raise ValueError("unsupported occupied corpus schema")
        _text(self.authority, "authority")
        _text(self.release_id, "release_id")
        for name in ("ratified_manifest_digest", "corpus_manifest_digest"):
            _digest_value(getattr(self, name), name)
        if len(self.cases) < MINIMUM_OCCUPIED_CASES or self.cases != tuple(sorted(self.cases)):
            raise ValueError("occupied corpus requires at least five canonically ordered cases")
        ids = tuple(item.case_id for item in self.cases)
        pairs = tuple((item.donor_provenance, item.recipient_provenance) for item in self.cases)
        if len(ids) != len(set(ids)) or len(pairs) != len(set(pairs)):
            raise ValueError("occupied corpus identities must be unique")
        required = {OccupiedRecipientProfile.ASYNC_WEB_API, OccupiedRecipientProfile.SYNC_CLI}
        if not required.issubset({item.recipient_profile for item in self.cases}):
            raise ValueError("occupied corpus is missing a required recipient profile")
        if self.predecessor_case_ids != tuple(sorted(self.predecessor_case_ids)) or not set(self.predecessor_case_ids).issubset(ids):
            raise ValueError("occupied corpus membership is not monotonic")
        if self.corpus_manifest_digest != _canonical_digest(self, omit=frozenset({"ratified_manifest_digest", "corpus_manifest_digest"})):
            raise ValueError("occupied corpus manifest digest mismatch")

    @classmethod
    def pin(
        cls,
        authority: str,
        release_id: str,
        cases: tuple[OccupiedCorpusCase, ...],
        *,
        predecessor_case_ids: tuple[str, ...] = (),
        ratified_manifest_digest: str,
    ) -> OccupiedCorpus:
        ordered = tuple(sorted(cases))
        draft = cls.__new__(cls)
        values: tuple[object, ...] = (
            OCCUPIED_CORPUS_SCHEMA_VERSION,
            authority,
            release_id,
            ordered,
            tuple(sorted(predecessor_case_ids)),
            "sha256:" + "0" * 64,
            "sha256:" + "0" * 64,
        )
        for field, value in zip(fields(cls), values, strict=True):
            object.__setattr__(draft, field.name, value)
        digest = _canonical_digest(draft, omit=frozenset({"ratified_manifest_digest", "corpus_manifest_digest"}))
        return cls(
            OCCUPIED_CORPUS_SCHEMA_VERSION,
            authority,
            release_id,
            ordered,
            tuple(sorted(predecessor_case_ids)),
            ratified_manifest_digest,
            digest,
        )


@dataclass(frozen=True, slots=True, order=True)
class OccupiedCaseReport:
    case_id: str
    passed: bool
    detail_code: str | None


@dataclass(frozen=True, slots=True)
class OccupiedGateReport:
    schema_version: str
    accepted: bool
    authority_digest_matches: bool
    cases: tuple[OccupiedCaseReport, ...]
    report_digest: str

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)


def _text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value or "\x00" in value or len(value.encode("utf-8", errors="strict")) > 512:
        raise ValueError(f"{name} must be nonempty bounded UTF-8 text")


def _digest_value(value: object, name: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase sha256 digest")


def _json_value(value: object, *, omit: frozenset[str] = frozenset()) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_value(getattr(value, field.name), omit=omit) for field in fields(value) if field.name not in omit}
    if isinstance(value, (tuple, list)):
        return [_json_value(item, omit=omit) for item in value]
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical occupied mappings require string keys")
        return {key: _json_value(value[key], omit=omit) for key in sorted(value)}
    if value is None or isinstance(value, (str, bool)) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise TypeError(f"unsupported canonical occupied value: {type(value).__name__}")


def _canonical_bytes(value: object, *, omit: frozenset[str] = frozenset()) -> bytes:
    return (json.dumps(_json_value(value, omit=omit), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8", errors="strict")


def _canonical_digest(value: object, *, omit: frozenset[str] = frozenset()) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value, omit=omit)).hexdigest()


def _reject(reason: BTSRejectReason, message: str, detail: str, cause: BaseException | None = None) -> BTSError:
    return BTSError(reason, message, detail_code=detail, cause=cause)


def _outcomes(value: object) -> tuple[TestOutcomeEvidence, ...]:
    if not isinstance(value, tuple) or not all(isinstance(item, TestOutcomeEvidence) for item in value):
        raise ValueError("outcomes must be a tuple of TestOutcomeEvidence")
    if value != tuple(sorted(value)):
        raise ValueError("outcomes must use canonical ordering")
    ids = tuple(item.canonical_test_id for item in value)
    if len(ids) != len(set(ids)):
        raise ValueError("outcome IDs must be unique")
    return value


def _outcome_counts(outcomes: Sequence[TestOutcomeEvidence]) -> OutcomeCounts:
    return OutcomeCounts(
        sum(item.outcome is TestOutcome.PASS for item in outcomes),
        sum(item.outcome is TestOutcome.FAIL for item in outcomes),
        sum(item.outcome is TestOutcome.SKIP for item in outcomes),
    )


def _module_and_path(path: str) -> tuple[str, str]:
    candidate = PurePosixPath(path)
    if candidate.suffix != ".py":
        raise _reject(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "recipient source language is unsupported", "occupied_inventory_unsupported_language_v1")
    parts = list(candidate.parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if not parts:
        raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "source path has no module", "occupied_inventory_module_missing_v1")
    normalized_path = "/".join(parts)
    leaf = parts[-1][:-3]
    module_parts = parts[:-1] if leaf == "__init__" else [*parts[:-1], leaf]
    if not module_parts or any(_IDENTIFIER.fullmatch(part) is None for part in module_parts):
        raise _reject(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "recipient module path is unsupported", "occupied_inventory_unsupported_language_v1")
    return ".".join(module_parts), normalized_path


def _binding_kind(node: ast.AST, scope: str) -> NodeKind:
    if isinstance(node, ast.AsyncFunctionDef):
        return NodeKind.ASYNC_METHOD if scope == "class" else NodeKind.ASYNC_FUNCTION
    if isinstance(node, ast.FunctionDef):
        return NodeKind.METHOD if scope == "class" else NodeKind.FUNCTION
    if isinstance(node, ast.ClassDef):
        return NodeKind.CLASS
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return NodeKind.RESOURCE
    return NodeKind.CONSTANT


def _binding_label(kind: NodeKind, scope: str) -> tuple[str, str]:
    """Map graph and AST identities through one closed occupied taxonomy."""

    kinds = {
        NodeKind.FUNCTION: "function",
        NodeKind.METHOD: "function",
        NodeKind.TEST: "function",
        NodeKind.ASYNC_FUNCTION: "async_function",
        NodeKind.ASYNC_METHOD: "async_function",
        NodeKind.CLASS: "class",
        NodeKind.CONSTANT: "binding",
        NodeKind.MODULE: "binding",
        NodeKind.RESOURCE: "import",
    }
    if scope not in {"module", "class", "function"}:
        raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "binding scope is unsupported", "occupied_binding_identity_taxonomy_v1")
    return kinds[kind], scope


def _extract_python_bindings(module: str, path: str, digest: str, content: bytes) -> list[RecipientBindingIdentity]:
    try:
        tree = ast.parse(content.decode("utf-8", errors="strict"), type_comments=True, feature_version=(3, 11))
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "recipient source could not be parsed", "occupied_inventory_parse_failed_v1", exc) from exc
    result: list[RecipientBindingIdentity] = []

    def add(name: str, parents: tuple[str, ...], scope: str, kind: NodeKind) -> None:
        qualified = ".".join((module, *parents, name))
        label, labeled_scope = _binding_label(kind, scope)
        result.append(RecipientBindingIdentity("python", module, qualified, labeled_scope, label, path, digest))

    def visit(statements: list[ast.stmt], parents: tuple[str, ...], scope: str) -> None:
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                add(node.name, parents, scope, _binding_kind(node, scope))
                inner_scope = "class" if isinstance(node, ast.ClassDef) else "function"
                visit(node.body, (*parents, node.name), inner_scope)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    for name in sorted(item.id for item in ast.walk(target) if isinstance(item, ast.Name)):
                        add(name, parents, scope, NodeKind.CONSTANT)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in sorted(node.names, key=lambda item: (item.name, item.asname or "")):
                    name = alias.asname or (alias.name if isinstance(node, ast.ImportFrom) else alias.name.split(".", 1)[0])
                    add(name, parents, scope, NodeKind.RESOURCE)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith, ast.If, ast.While, ast.Try, ast.Match)):
                child_lists = [value for value in ast.iter_fields(node) if isinstance(value[1], list)]
                for _, children in child_lists:
                    visit([item for item in children if isinstance(item, ast.stmt)], parents, scope)

    visit(tree.body, (), "module")
    return result


def derive_recipient_binding_inventory(manifest: RecipientInputManifest, policy: OccupiedAttachmentPolicy) -> RecipientBindingInventory:
    """Parse every manifest-declared source byte and produce collision authority."""

    if not isinstance(manifest, RecipientInputManifest) or not isinstance(policy, OccupiedAttachmentPolicy):
        raise TypeError("manifest and policy have invalid types")
    try:
        _validate_recipient_manifest(manifest)
        OccupiedAttachmentPolicy(*[getattr(policy, field.name) for field in fields(OccupiedAttachmentPolicy)])
    except (TypeError, ValueError, BTSError) as exc:
        raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "recipient inventory inputs are malformed", "occupied_inventory_manifest_mismatch_v1", exc) from exc
    source_entries = tuple(entry for entry in manifest.entries if entry.role == "source")
    if not source_entries:
        raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "recipient manifest declares no source", "occupied_inventory_source_omitted_v1")
    bindings: list[RecipientBindingIdentity] = []
    module_paths: list[str] = []
    for entry in source_entries:
        module, module_path = _module_and_path(entry.path)
        module_paths.append(module_path)
        bindings.extend(_extract_python_bindings(module, entry.path, entry.sha256, entry.content))
    ordered = tuple(sorted(bindings))
    keys = tuple(item.collision_key for item in ordered)
    if len(keys) != len(set(keys)):
        raise _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "recipient contains duplicate binding identities", "occupied_inventory_duplicate_binding_v1")
    if len(module_paths) != len(set(module_paths)):
        raise _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "recipient contains duplicate module paths", "occupied_inventory_duplicate_module_v1")
    draft = RecipientBindingInventory.__new__(RecipientBindingInventory)
    values: tuple[object, ...] = (
        OCCUPIED_INVENTORY_SCHEMA_VERSION,
        manifest.manifest_digest,
        ordered,
        tuple(sorted(module_paths)),
        "sha256:" + "0" * 64,
    )
    for field, value in zip(fields(RecipientBindingInventory), values, strict=True):
        object.__setattr__(draft, field.name, value)
    return RecipientBindingInventory(
        draft.schema_version,
        draft.recipient_manifest_digest,
        draft.bindings,
        draft.module_paths,
        _canonical_digest(draft, omit=frozenset({"inventory_digest"})),
    )


def _artifact(value: BTS | BTSResult) -> BTS:
    if isinstance(value, BTSResult):
        if value.status is not BTSStatus.COMPLETE or value.bts is None:
            raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied attachment requires a complete BTS", "occupied_bts_incomplete_v1")
        return value.bts
    if isinstance(value, BTS):
        return value
    raise TypeError("bts must be BTS or BTSResult")


def derive_emitted_bts_identities(bts: BTS | BTSResult, module_map: ModuleMap) -> tuple[RecipientBindingIdentity, ...]:
    """Apply the relocation ModuleMap to every BTS member identity."""

    artifact = _artifact(bts)
    if not isinstance(module_map, ModuleMap):
        raise TypeError("module_map must be ModuleMap")
    result: list[RecipientBindingIdentity] = []
    member_kinds = {member.node.qualified_name: member.node.kind for member in artifact.members}
    for member in artifact.members:
        target = module_map.exact(member.node.module)
        if target is None:
            raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "ModuleMap is not total for BTS members", "occupied_module_map_not_total_v1")
        prefix = member.node.module
        qualified = member.node.qualified_name
        if qualified != prefix and not qualified.startswith(prefix + "."):
            raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "BTS member identity is malformed", "occupied_member_identity_v1")
        emitted_qualified = target + qualified[len(prefix) :]
        suffix = qualified[len(prefix) :].lstrip(".")
        depth = suffix.count(".")
        parent = qualified.rsplit(".", 1)[0] if "." in qualified else ""
        parent_kind = member_kinds.get(parent)
        scope = "module" if depth == 0 else "class" if member.node.kind in {NodeKind.METHOD, NodeKind.ASYNC_METHOD} or parent_kind is NodeKind.CLASS else "function"
        kind, scope = _binding_label(member.node.kind, scope)
        result.append(
            RecipientBindingIdentity(
                "python",
                target,
                emitted_qualified,
                scope,
                kind,
                member.source.path,
                member.source_bytes_sha256,
            )
        )
    ordered = tuple(sorted(result))
    keys = tuple(item.collision_key for item in ordered)
    if len(keys) != len(set(keys)):
        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "emitted BTS identities collide", "occupied_binding_collision_v1")
    return ordered


def validate_collisions(inventory: RecipientBindingInventory, bts: BTS | BTSResult, module_map: ModuleMap) -> tuple[RecipientBindingIdentity, ...]:
    """Reject any binding overlap and any independently colliding output path."""

    if not isinstance(inventory, RecipientBindingInventory):
        raise TypeError("inventory must be RecipientBindingInventory")
    try:
        RecipientBindingInventory(*[getattr(inventory, field.name) for field in fields(RecipientBindingInventory)])
    except (TypeError, ValueError) as exc:
        raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "recipient inventory is malformed", "occupied_inventory_digest_mismatch_v1", exc) from exc
    emitted = derive_emitted_bts_identities(bts, module_map)
    recipient_keys = {item.collision_key for item in inventory.bindings}
    if any(item.collision_key in recipient_keys for item in emitted):
        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "BTS binding collides with occupied recipient", "occupied_binding_collision_v1")
    emitted_paths: set[str] = set()
    for module in sorted({item.module for item in emitted}):
        parts = module.split(".")
        emitted_paths.add("/".join(parts) + ".py")
        for length in range(1, len(parts)):
            emitted_paths.add("/".join(parts[:length]) + "/__init__.py")
    if emitted_paths.intersection(inventory.module_paths):
        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "BTS module path collides with occupied recipient", "occupied_module_collision_v1")
    recipient_modules = tuple(sorted(_module_and_path(path)[0] for path in inventory.module_paths))
    emitted_modules = tuple(sorted({item.module for item in emitted}))
    if any(
        recipient == target
        or recipient.startswith(target + ".")
        or target.startswith(recipient + ".")
        for recipient in recipient_modules
        for target in emitted_modules
    ):
        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "BTS module namespace collides with occupied recipient", "occupied_module_collision_v1")
    return emitted


def validate_conflict_matrix(
    matrix: ConflictMatrix | None,
    *,
    policy: OccupiedAttachmentPolicy,
    recipient_subject: str,
    candidate: CompositionCandidateRef,
) -> None:
    """Consume the canonical ADR-0013 matrix; never regenerate weaker evidence."""

    if matrix is None:
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "conflict matrix is absent", "occupied_conflict_matrix_absent_v1")
    if not isinstance(candidate, CompositionCandidateRef):
        raise TypeError("candidate must be CompositionCandidateRef")
    if matrix.schema_version != COMPOSITION_MATRIX_SCHEMA or matrix.recipient_subject != recipient_subject or matrix.policy_digest != policy.conflict_policy_digest:
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "conflict matrix identity mismatches attachment", "occupied_conflict_matrix_identity_v1")
    matches = tuple(item for item in matrix.candidates if item.candidate_key == candidate.candidate_key)
    if len(matches) != 1 or matches[0] != candidate:
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "conflict matrix candidate identity mismatches attachment", "occupied_conflict_matrix_identity_v1")
    try:
        eligibility = evaluate_eligibility(matrix)
    except (TypeError, ValueError, BTSError) as exc:
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "conflict matrix is malformed", "occupied_conflict_matrix_malformed_v1", exc) from exc
    if eligibility.status is not CompositionEligibilityStatus.ACCEPT:
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "conflict matrix has hard or unresolved rows", "occupied_conflict_matrix_blocked_v1")


def validate_recipient_parity(
    baseline: RecipientBaselineEvidence,
    occupied_outcomes: tuple[TestOutcomeEvidence, ...],
    *,
    policy: OccupiedAttachmentPolicy,
    recipient_manifest_digest: str,
    test_set_digest: str,
    runner_closure_digest: str,
    config_closure_digest: str,
) -> None:
    """Validate baseline freshness then require exact occupied-rerun parity."""

    if not isinstance(baseline, RecipientBaselineEvidence):
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "recipient baseline is missing", "occupied_baseline_missing_v1")
    try:
        RecipientBaselineEvidence(*[getattr(baseline, field.name) for field in fields(RecipientBaselineEvidence)])
    except (TypeError, ValueError) as exc:
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "recipient baseline is malformed", "occupied_baseline_malformed_v1", exc) from exc
    expected = (
        recipient_manifest_digest,
        test_set_digest,
        runner_closure_digest,
        config_closure_digest,
        policy.recipient_baseline_mount_plan_digest,
        policy.recipient_baseline_execution_policy_digest,
    )
    actual = (
        baseline.recipient_manifest_digest,
        baseline.test_set_digest,
        baseline.runner_closure_digest,
        baseline.config_closure_digest,
        baseline.mount_plan_digest,
        baseline.execution_policy_digest,
    )
    if actual != expected:
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "recipient baseline is stale or mismatched", "occupied_baseline_stale_v1")
    try:
        outcomes = _outcomes(occupied_outcomes)
    except (TypeError, ValueError) as exc:
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied rerun outcomes are malformed", "occupied_rerun_malformed_v1", exc) from exc
    if (
        tuple(item.canonical_test_id for item in outcomes) != baseline.canonical_test_ids
        or _outcome_counts(outcomes) != baseline.counts
        or outcomes != baseline.outcomes
    ):
        raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "occupied rerun differs from recipient baseline", "occupied_exact_parity_failed_v1")


def run_occupied_corpus_gate(
    corpus: OccupiedCorpus,
    run_case: Callable[[OccupiedCorpusCase], bool],
) -> OccupiedGateReport:
    """Run every case and apply authority/profile/case gates as one AND."""

    if not isinstance(corpus, OccupiedCorpus) or not callable(run_case):
        raise TypeError("invalid occupied corpus gate input")
    reports: list[OccupiedCaseReport] = []
    for case in corpus.cases:
        try:
            passed = run_case(case) is True
            detail = None if passed else "occupied_case_failed_v1"
        except Exception:  # Every corpus case still runs after an earlier failure.
            passed = False
            detail = "occupied_case_error_v1"
        reports.append(OccupiedCaseReport(case.case_id, passed, detail))
    authority = corpus.corpus_manifest_digest == corpus.ratified_manifest_digest
    ordered = tuple(reports)
    draft = OccupiedGateReport(
        OCCUPIED_GATE_SCHEMA_VERSION,
        authority and all(item.passed for item in ordered),
        authority,
        ordered,
        "sha256:" + "0" * 64,
    )
    return replace(draft, report_digest=_canonical_digest(draft, omit=frozenset({"report_digest"})))


__all__ = [
    "MINIMUM_OCCUPIED_CASES",
    "OCCUPIED_CORPUS_SCHEMA_VERSION",
    "OCCUPIED_GATE_SCHEMA_VERSION",
    "OCCUPIED_INVENTORY_SCHEMA_VERSION",
    "OCCUPIED_POLICY_SCHEMA_VERSION",
    "RECIPIENT_BASELINE_SCHEMA_VERSION",
    "OccupiedAttachmentPolicy",
    "OccupiedCaseReport",
    "OccupiedCorpus",
    "OccupiedCorpusCase",
    "OccupiedGateReport",
    "OccupiedRecipientProfile",
    "OccupiedRole",
    "RecipientBaselineEvidence",
    "RecipientBindingIdentity",
    "RecipientBindingInventory",
    "derive_emitted_bts_identities",
    "derive_recipient_binding_inventory",
    "run_occupied_corpus_gate",
    "validate_collisions",
    "validate_conflict_matrix",
    "validate_recipient_parity",
]
