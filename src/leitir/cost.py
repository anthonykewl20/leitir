"""Closed, advisory integration-cost evidence (ADR-0019).

This module deliberately contains no ranking or aggregation operation.  Its
collectors turn only digest-bound, exact evidence into counts; absence of an
authority is represented by an observation state, never by zero.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from itertools import pairwise
from leitir.bts import (
    AdaptRule,
    AdapterCatalog,
    BTSDisposition,
    BTSReport,
    BTSStatus,
    _disposition_key,
    _digest as _bts_digest,
)
from leitir.candidates import CandidateKey
from leitir.comparison import DependencyCostValue, ExtractionDifficultyValue

COST_EVIDENCE_SCHEMA = "leitir-integration-cost-evidence-v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_COUNT = 10**9


class CostObservationState(str, Enum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


class CostConfidence(str, Enum):
    EXACT = "exact"


def _digest_text(value: object, name: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _text(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be strict UTF-8") from exc


def _count(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_COUNT:
        raise ValueError(f"{name} must be a bounded non-negative integer")


def _json_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("canonical cost evidence keys must be strings")
        return {key: _json_value(item) for key, item in value.items()}
    if value is None or isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise TypeError(f"unsupported cost evidence value: {type(value).__name__}")


def _canonical_bytes(value: object, *, omit_record_digest: bool = False) -> bytes:
    payload = _json_value(value)
    if omit_record_digest:
        assert isinstance(payload, dict)
        payload.pop("record_digest", None)
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode(
        "utf-8", errors="strict"
    )


def _digest(value: object, *, omit_record_digest: bool = False) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value, omit_record_digest=omit_record_digest)).hexdigest()


@dataclass(frozen=True, slots=True)
class CostMethod:
    method_id: str
    method_version: str
    input_digests: tuple[str, ...]
    method_digest: str

    def __post_init__(self) -> None:
        _text(self.method_id, "method_id")
        _text(self.method_version, "method_version")
        if self.method_version != "1":
            raise ValueError("unsupported cost method version")
        if not isinstance(self.input_digests, tuple):
            raise ValueError("input_digests must be a tuple")
        for value in self.input_digests:
            _digest_text(value, "input digest")
        if tuple(sorted(self.input_digests)) != self.input_digests or len(set(self.input_digests)) != len(self.input_digests):
            raise ValueError("method input digests must be canonical and unique")
        _digest_text(self.method_digest, "method_digest")
        expected = _digest({"input_digests": list(self.input_digests), "method_id": self.method_id, "method_version": self.method_version})
        if self.method_digest != expected:
            raise ValueError("method_digest mismatch")

    @classmethod
    def create(cls, method_id: str, method_version: str, input_digests: tuple[str, ...]) -> CostMethod:
        ordered = tuple(sorted(input_digests))
        payload = {"input_digests": list(ordered), "method_id": method_id, "method_version": method_version}
        return cls(method_id, method_version, ordered, _digest(payload))


@dataclass(frozen=True, slots=True)
class CostObservation:
    state: CostObservationState
    value: int | None
    confidence: CostConfidence | None
    method: CostMethod
    detail_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.state, CostObservationState) or not isinstance(self.method, CostMethod):
            raise ValueError("invalid cost observation type")
        _text(self.detail_code, "detail_code")
        if self.state is CostObservationState.KNOWN:
            _count(self.value, "observation value")
            if self.confidence is not CostConfidence.EXACT:
                raise ValueError("known observations require exact confidence")
        elif self.value is not None or self.confidence is not None:
            raise ValueError("non-known observations cannot carry a value or confidence")


@dataclass(frozen=True, slots=True)
class DependencyDelta:
    state: CostObservationState
    confidence: CostConfidence | None
    new_direct: int | None
    new_transitive: int | None
    removed_direct: int | None
    removed_transitive: int | None
    unresolved: int
    before_manifest_digest: str | None
    after_manifest_digest: str | None
    method: CostMethod

    def __post_init__(self) -> None:
        if not isinstance(self.state, CostObservationState) or not isinstance(self.method, CostMethod):
            raise ValueError("invalid dependency delta type")
        _count(self.unresolved, "unresolved")
        values = (self.new_direct, self.new_transitive, self.removed_direct, self.removed_transitive)
        if self.state is CostObservationState.KNOWN:
            for index, value in enumerate(values):
                _count(value, f"dependency delta value {index}")
            if self.confidence is not CostConfidence.EXACT or self.unresolved != 0:
                raise ValueError("known dependency delta requires exact, complete values")
            if self.before_manifest_digest is None or self.after_manifest_digest is None:
                raise ValueError("known dependency delta requires exact before/after manifests")
        elif any(value is not None for value in values) or self.confidence is not None:
            raise ValueError("non-known dependency delta cannot carry substitute values or confidence")
        for name, value in (("before_manifest_digest", self.before_manifest_digest), ("after_manifest_digest", self.after_manifest_digest)):
            if value is not None:
                _digest_text(value, name)


@dataclass(frozen=True, slots=True, order=True)
class TestSurfaceChange:
    path: str
    before_sha256: str | None
    after_sha256: str | None
    change_kind: str

    def __post_init__(self) -> None:
        _text(self.path, "test path")
        _text(self.change_kind, "change_kind")
        if self.before_sha256 is None and self.after_sha256 is None:
            raise ValueError("a test change must have a before or after identity")
        for name, value in (("before_sha256", self.before_sha256), ("after_sha256", self.after_sha256)):
            if value is not None:
                _digest_text(value, name)


@dataclass(frozen=True, slots=True)
class IntegrationCostEvidence:
    schema_version: str
    candidate_key: CandidateKey
    bts_digest: str
    recipient_profile_digest: str | None
    bts_members: CostObservation
    source_lines: CostObservation
    adapt_instances: CostObservation
    replace_instances: CostObservation
    external_instances: CostObservation
    external_interfaces: CostObservation
    adapter_template_physical_lines: CostObservation
    dependency_delta: DependencyDelta
    test_surface_state: CostObservationState
    test_surface_confidence: CostConfidence | None
    test_surface_changes: tuple[TestSurfaceChange, ...]
    record_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != COST_EVIDENCE_SCHEMA:
            raise ValueError("unsupported cost evidence schema")
        if (
            not isinstance(self.candidate_key, tuple)
            or len(self.candidate_key) != 16
            or not all(isinstance(item, str) for item in self.candidate_key[:4] + self.candidate_key[8:])
            or not all(isinstance(item, int) and not isinstance(item, bool) for item in self.candidate_key[4:8])
        ):
            raise ValueError("invalid complete CandidateKey")
        _digest_text(self.bts_digest, "bts_digest")
        if self.recipient_profile_digest is not None:
            _digest_text(self.recipient_profile_digest, "recipient_profile_digest")
        observations = (
            self.bts_members, self.source_lines, self.adapt_instances, self.replace_instances,
            self.external_instances, self.external_interfaces, self.adapter_template_physical_lines,
        )
        if not all(isinstance(item, CostObservation) for item in observations) or not isinstance(self.dependency_delta, DependencyDelta):
            raise ValueError("invalid typed cost component")
        if not isinstance(self.test_surface_state, CostObservationState) or not isinstance(self.test_surface_changes, tuple) or not all(isinstance(item, TestSurfaceChange) for item in self.test_surface_changes):
            raise ValueError("invalid test-surface component")
        ordered = tuple(sorted(self.test_surface_changes, key=_test_change_key))
        if ordered != self.test_surface_changes or any(_test_change_key(left) == _test_change_key(right) for left, right in pairwise(ordered)):
            raise ValueError("test changes must be canonical and unique")
        if self.test_surface_state is CostObservationState.KNOWN:
            if self.test_surface_confidence is not CostConfidence.EXACT:
                raise ValueError("known test surface requires exact confidence")
        elif self.test_surface_confidence is not None or self.test_surface_changes:
            raise ValueError("non-known test surface cannot carry changes or confidence")
        _digest_text(self.record_digest, "record_digest")
        if self.record_digest != _digest(self, omit_record_digest=True):
            raise ValueError("record_digest mismatch")

    def to_bytes(self) -> bytes:
        return _canonical_bytes(self)

    @classmethod
    def from_json(cls, value: str | bytes) -> IntegrationCostEvidence:
        """Decode only the closed canonical schema and recheck its digest."""
        try:
            text = value.decode("utf-8", errors="strict") if isinstance(value, bytes) else value
            raw = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
            if not isinstance(raw, dict) or set(raw) != {field.name for field in fields(cls)}:
                raise ValueError("cost evidence has missing or unknown fields")
            observation_names = {
                "bts_members", "source_lines", "adapt_instances", "replace_instances",
                "external_instances", "external_interfaces", "adapter_template_physical_lines",
            }
            arguments: dict[str, object] = dict(raw)
            arguments["candidate_key"] = _tuple(raw["candidate_key"], "candidate_key")
            for name in observation_names:
                arguments[name] = _decode_observation(raw[name])
            arguments["dependency_delta"] = _decode_dependency_delta(raw["dependency_delta"])
            arguments["test_surface_state"] = CostObservationState(raw["test_surface_state"])
            confidence = raw["test_surface_confidence"]
            arguments["test_surface_confidence"] = None if confidence is None else CostConfidence(confidence)
            arguments["test_surface_changes"] = tuple(
                _decode_dataclass(item, TestSurfaceChange) for item in _tuple(raw["test_surface_changes"], "test_surface_changes")
            )
            record = cls(**arguments)  # type: ignore[arg-type]
            if record.to_bytes().decode("utf-8") != text:
                raise ValueError("cost evidence is not canonical JSON")
            return record
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid or noncanonical integration cost evidence") from exc


def _test_change_key(item: TestSurfaceChange) -> tuple[str, str, str, str]:
    return item.path, item.before_sha256 or "", item.after_sha256 or "", item.change_kind


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _tuple(value: object, name: str) -> tuple[object, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array")
    return tuple(value)


def _decode_dataclass(value: object, record_type: type[object]) -> object:
    if not isinstance(value, dict) or set(value) != {field.name for field in fields(record_type)}:
        raise ValueError(f"invalid closed {record_type.__name__} record")
    return record_type(**value)


def _decode_method(value: object) -> CostMethod:
    if not isinstance(value, dict) or set(value) != {field.name for field in fields(CostMethod)}:
        raise ValueError("invalid closed CostMethod record")
    arguments = dict(value)
    arguments["input_digests"] = _tuple(value["input_digests"], "input_digests")
    return CostMethod(**arguments)  # type: ignore[arg-type]


def _decode_observation(value: object) -> CostObservation:
    if not isinstance(value, dict) or set(value) != {field.name for field in fields(CostObservation)}:
        raise ValueError("invalid closed CostObservation record")
    confidence = value["confidence"]
    return CostObservation(
        CostObservationState(value["state"]), value["value"],
        None if confidence is None else CostConfidence(confidence), _decode_method(value["method"]), value["detail_code"],
    )  # type: ignore[arg-type]


def _decode_dependency_delta(value: object) -> DependencyDelta:
    if not isinstance(value, dict) or set(value) != {field.name for field in fields(DependencyDelta)}:
        raise ValueError("invalid closed DependencyDelta record")
    arguments = dict(value)
    arguments["state"] = CostObservationState(value["state"])
    confidence = value["confidence"]
    arguments["confidence"] = None if confidence is None else CostConfidence(confidence)
    arguments["method"] = _decode_method(value["method"])
    return DependencyDelta(**arguments)  # type: ignore[arg-type]


def _known(value: int, method: CostMethod, detail: str) -> CostObservation:
    return CostObservation(CostObservationState.KNOWN, value, CostConfidence.EXACT, method, detail)


def _unknown(method: CostMethod, detail: str) -> CostObservation:
    return CostObservation(CostObservationState.UNKNOWN, None, None, method, detail)


def collect_integration_cost_evidence(
    report: BTSReport,
    candidate_key: CandidateKey,
    adapter_catalog: AdapterCatalog,
    *,
    recipient_profile_digest: str | None = None,
    test_surface_changes: tuple[TestSurfaceChange, ...] | None = None,
    test_plan_digest: str | None = None,
) -> IntegrationCostEvidence:
    """Collect the currently provable ADR-0019 components from a COMPLETE report.

    Dependency additions stay unknown here because ``DependencyEdge`` does not
    prove directness.  A recipient-specific dependency-plan collector can create
    a fully proved :class:`DependencyDelta` separately.
    """
    if not isinstance(report, BTSReport) or report.status is not BTSStatus.COMPLETE:
        raise ValueError("integration cost requires a COMPLETE BTS report")
    # Construction alone does not validate an artifact's analysis digest.
    if report.analysis_digest != _bts_digest(report, omit=frozenset({"analysis_digest"})):
        raise ValueError("BTS report analysis_digest mismatch")
    _digest_text(report.analysis_digest, "BTS analysis_digest")
    dispositions = tuple(sorted(report.dispositions, key=_disposition_key))
    if any(_disposition_key(left) == _disposition_key(right) for left, right in pairwise(dispositions)):
        raise ValueError("BTS dispositions must be unique")
    instances = tuple(item for item in dispositions if item.edge is not None and item.disposition in {BTSDisposition.ADAPT, BTSDisposition.REPLACE, BTSDisposition.EXTERNAL})
    method = CostMethod.create("leitir.bts-cost-counts", "1", (report.analysis_digest,))
    catalog_method = CostMethod.create("leitir.adapter-template-physical-lines", "1", (adapter_catalog.content_digest, report.analysis_digest))
    entries = {entry.adapter_id: entry for entry in adapter_catalog.entries}
    line_count = 0
    adapter_keys: list[tuple[object, ...]] = []
    for item in instances:
        if item.disposition is not BTSDisposition.ADAPT:
            continue
        if not isinstance(item.rule_payload, AdaptRule):
            raise ValueError("ADAPT instance lacks its pinned AdaptRule")
        entry = entries.get(item.rule_payload.adapter_id)
        if entry is None:
            raise ValueError("ADAPT instance refers to an absent catalog entry")
        template_bytes = entry.template.encode("utf-8", errors="strict")
        actual = "sha256:" + hashlib.sha256(template_bytes).hexdigest()
        if actual != entry.template_bytes_sha256:
            raise ValueError("adapter template bytes do not match template_bytes_sha256")
        key = (*_disposition_key(item), entry.adapter_id, entry.template_bytes_sha256, item.rule_payload.parameters)
        if key in adapter_keys:
            raise ValueError("duplicate complete adapter instance key")
        adapter_keys.append(key)
        line_count += len(template_bytes.splitlines())
    if adapter_keys != sorted(adapter_keys):
        raise ValueError("adapter instances are not canonically ordered")
    dependency_method = CostMethod.create("leitir.dependency-delta", "1", tuple(sorted(filter(None, (recipient_profile_digest, report.analysis_digest)))))
    dependency = DependencyDelta(CostObservationState.UNKNOWN, None, None, None, None, None, 0, None, None, dependency_method)
    if test_surface_changes is None:
        test_state, test_confidence, changes = CostObservationState.UNKNOWN, None, ()
    else:
        if test_plan_digest is None:
            raise ValueError("exact test changes require a pinned plan digest")
        _digest_text(test_plan_digest, "test_plan_digest")
        changes = tuple(sorted(test_surface_changes, key=_test_change_key))
        test_state, test_confidence = CostObservationState.KNOWN, CostConfidence.EXACT
    values: tuple[object, ...] = (
        COST_EVIDENCE_SCHEMA, candidate_key, report.analysis_digest, recipient_profile_digest,
        _known(len(report.members), method, "bts_members_exact_v1"),
        _known(report.counters.source_lines, method, "bts_source_lines_exact_v1"),
        _known(sum(item.disposition is BTSDisposition.ADAPT for item in instances), method, "bts_adapt_instances_exact_v1"),
        _known(sum(item.disposition is BTSDisposition.REPLACE for item in instances), method, "bts_replace_instances_exact_v1"),
        _known(sum(item.disposition is BTSDisposition.EXTERNAL for item in instances), method, "bts_external_instances_exact_v1"),
        _known(report.counters.external_interfaces, method, "bts_external_interfaces_exact_v1"),
        _known(line_count, catalog_method, "adapter_template_physical_lines_exact_v1"),
        dependency, test_state, test_confidence, changes,
    )
    names = tuple(field.name for field in fields(IntegrationCostEvidence) if field.name != "record_digest")
    payload = dict(zip(names, values, strict=True))
    return IntegrationCostEvidence(*values, _digest(payload))


def extraction_difficulty_value(evidence: IntegrationCostEvidence) -> ExtractionDifficultyValue | None:
    """Map exact ADR-0019 counts to ADR-0010 extraction difficulty."""
    observations = (evidence.bts_members, evidence.source_lines, evidence.adapt_instances, evidence.external_interfaces)
    if any(item.state is not CostObservationState.KNOWN for item in observations):
        return None
    values = tuple(item.value for item in observations)
    if any(value is None for value in values):
        return None
    return ExtractionDifficultyValue(*values)  # type: ignore[arg-type]


def dependency_cost_value(delta: DependencyDelta) -> DependencyCostValue | None:
    """Map only a complete proved addition delta to ADR-0010 dependency cost."""
    if delta.state is not CostObservationState.KNOWN or delta.new_direct is None or delta.new_transitive is None or delta.unresolved != 0:
        return None
    return DependencyCostValue(delta.new_direct, delta.new_transitive, 0)


__all__ = [
    "COST_EVIDENCE_SCHEMA", "CostConfidence", "CostMethod", "CostObservation", "CostObservationState",
    "DependencyDelta", "IntegrationCostEvidence", "TestSurfaceChange", "collect_integration_cost_evidence",
    "dependency_cost_value", "extraction_difficulty_value",
]
