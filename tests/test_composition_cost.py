from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import fields, replace

import pytest

from leitir.bts import (
    AdaptRule,
    AdapterCatalog,
    AdapterCatalogEntry,
    AnalysisInputs,
    BTSBudget,
    BTSDisposition,
    BTSReport,
    BTSStatus,
    BudgetCounters,
    DispositionEvidence,
    MemberEvidence,
    _digest as _bts_digest,
)
from leitir.cost import (
    COST_EVIDENCE_SCHEMA,
    CostConfidence,
    CostMethod,
    CostObservation,
    CostObservationState,
    DependencyDelta,
    IntegrationCostEvidence,
    TestSurfaceChange as SurfaceChange,
    collect_integration_cost_evidence,
    dependency_cost_value,
    extraction_difficulty_value,
)
from leitir.comparison import DependencyCostValue
from leitir.graph.model import Edge, EdgeKind, EdgeProvenance, NodeId, NodeKind, NodeOrigin, SourceRef


def _digest(value: str | bytes) -> str:
    data = value if isinstance(value, bytes) else value.encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _node(name: str, origin: NodeOrigin = NodeOrigin.DONOR) -> NodeId:
    return NodeId(origin, NodeKind.FUNCTION, "pkg.mod", name, f"pkg/mod.py:{name}")


def _edge(number: int, target: NodeId) -> Edge:
    source = SourceRef("owner/repo", "a" * 40, "pkg/mod.py", "b" * 40, number, 0, number, 1)
    return Edge(EdgeKind.CALLS, _node("seed"), target, EdgeProvenance(source, None, "Call", "exact_v1"))


def _candidate_key() -> tuple[str, str, str, str, int, int, int, int, str, str, str, str, str, str, str, str]:
    return ("owner/repo", "a" * 40, "pkg/mod.py", "b" * 40, 1, 0, 2, 0, "function", "pkg.mod", "seed", "python", "python", "source", "collector", "v1")


def _catalog(template: str = "first\nsecond\n", *, template_digest: str | None = None) -> AdapterCatalog:
    entry = AdapterCatalogEntry("adapter", template, template_digest or _digest(template), ("name",))
    return AdapterCatalog("catalog", "v1", _digest("catalog"), (entry,))


def _report(dispositions: tuple[DispositionEvidence, ...]) -> BTSReport:
    seed = _node("seed")
    budget = BTSBudget(100, 100, 100, 10, 10, 10, 10, 2, 100, 10, 100, 10, 10)
    inputs = AnalysisInputs(
        seed, "owner/repo", "a" * 40, _digest("tree"), "git-tree-sha1-v1", "leitir-bts-graph-v1",
        _digest("graph"), "leitir-bts-walk-v1", budget, "policy", _digest("policy"),
        _digest("envelope"), _digest("stdlib"), _digest("catalog"),
    )
    source_one = SourceRef("owner/repo", "a" * 40, "pkg/mod.py", "b" * 40, 1, 0, 1, 1)
    source_two = SourceRef("owner/repo", "a" * 40, "pkg/mod.py", "b" * 40, 2, 0, 2, 1)
    draft = BTSReport(
        "leitir-bts-v1", BTSStatus.COMPLETE, inputs,
        (MemberEvidence(_node("one"), source_one, _digest("one")), MemberEvidence(_node("two"), source_two, _digest("two"))),
        tuple(sorted(dispositions, key=lambda item: (item.edge.provenance.site.start_line if item.edge else 0))), (), (), (), (),
        BudgetCounters(source_lines=17, external_interfaces=1), "",
    )
    return replace(draft, analysis_digest=_bts_digest(draft, omit=frozenset({"analysis_digest"})))


def _dispositions() -> tuple[DispositionEvidence, ...]:
    shared = _node("shared", NodeOrigin.DECLARED_EXTERNAL)
    adapt = DispositionEvidence(
        _edge(1, _node("adapted")), _node("adapted"), BTSDisposition.ADAPT, "adapt-rule",
        evidence_digest=_digest("adapt"), rule_payload=AdaptRule("adapter", (("name", "value"),)),
    )
    replace_item = DispositionEvidence(_edge(2, _node("replaced")), _node("replaced"), BTSDisposition.REPLACE, "replace-rule")
    external_one = DispositionEvidence(_edge(3, shared), shared, BTSDisposition.EXTERNAL, "external-rule")
    external_two = DispositionEvidence(_edge(4, shared), shared, BTSDisposition.EXTERNAL, "external-rule")
    declaration_only = DispositionEvidence(None, _node("not-an-instance"), BTSDisposition.ADAPT, "declaration")
    return adapt, replace_item, external_one, external_two, declaration_only


def _evidence(dispositions: tuple[DispositionEvidence, ...] | None = None) -> IntegrationCostEvidence:
    return collect_integration_cost_evidence(_report(dispositions or _dispositions()), _candidate_key(), _catalog())


def test_complete_report_counts_instances_and_unique_external_identities_separately() -> None:
    evidence = _evidence()
    assert evidence.bts_members.value == 2
    assert evidence.source_lines.value == 17
    assert evidence.adapt_instances.value == 1
    assert evidence.replace_instances.value == 1
    assert evidence.external_instances.value == 2
    assert evidence.external_interfaces.value == 1
    assert extraction_difficulty_value(evidence).external_interfaces == 1  # type: ignore[union-attr]


def test_adapter_template_bytes_are_verified_before_physical_lines_are_measured() -> None:
    assert _evidence().adapter_template_physical_lines.value == 2
    with pytest.raises(ValueError, match="template bytes"):
        collect_integration_cost_evidence(_report(_dispositions()), _candidate_key(), _catalog(template_digest=_digest("other")))


@pytest.mark.parametrize("state", [
    CostObservationState.UNKNOWN, CostObservationState.ERROR, CostObservationState.SKIPPED,
    CostObservationState.NOT_APPLICABLE,
])
def test_non_known_observation_rejects_substitute_zero_and_confidence(state: CostObservationState) -> None:
    method = CostMethod.create("test", "1", ())
    with pytest.raises(ValueError, match="non-known"):
        CostObservation(state, 0, None, method, "test_v1")
    with pytest.raises(ValueError, match="non-known"):
        CostObservation(state, None, CostConfidence.EXACT, method, "test_v1")


def test_known_requires_exact_confidence() -> None:
    method = CostMethod.create("test", "1", ())
    with pytest.raises(ValueError, match="exact"):
        CostObservation(CostObservationState.KNOWN, 1, None, method, "test_v1")


def test_dependency_delta_is_unknown_without_direct_requirement_evidence() -> None:
    evidence = _evidence()
    assert evidence.dependency_delta.state is CostObservationState.UNKNOWN
    assert evidence.dependency_delta.new_direct is None
    assert evidence.dependency_delta.new_transitive is None
    assert dependency_cost_value(evidence.dependency_delta) is None


def test_dependency_unknown_rejects_values_even_with_empty_unresolved_count() -> None:
    method = CostMethod.create("dependency", "1", ())
    with pytest.raises(ValueError, match="non-known"):
        DependencyDelta(CostObservationState.UNKNOWN, None, 0, 0, None, None, 0, None, None, method)


def test_complete_known_dependency_delta_maps_to_dependency_cost_value() -> None:
    method = CostMethod.create("dependency", "1", (_digest("after"), _digest("before")))
    delta = DependencyDelta(
        CostObservationState.KNOWN,
        CostConfidence.EXACT,
        2,
        5,
        1,
        3,
        0,
        _digest("before"),
        _digest("after"),
        method,
    )

    assert dependency_cost_value(delta) == DependencyCostValue(new_direct=2, new_transitive=5, unresolved=0)


def test_record_has_no_aggregation_or_comparison_surface() -> None:
    public = {name for name in dir(IntegrationCostEvidence) if not name.startswith("_")}
    assert not ({"total", "score", "aggregate", "compare"} & public)
    assert not any(name.startswith("__lt__") or name.startswith("__gt__") for name in IntegrationCostEvidence.__dict__)
    assert tuple(field.name for field in fields(IntegrationCostEvidence))[-1] == "record_digest"


def test_ordering_and_digest_are_deterministic_across_input_permutations() -> None:
    dispositions = _dispositions()
    forward = _evidence(dispositions)
    reverse = _evidence(tuple(reversed(dispositions)))
    assert forward == reverse
    assert forward.to_bytes() == reverse.to_bytes()


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_hash_seed_determinism(seed: str) -> None:
    script = (
        "from tests.test_composition_cost import _evidence; import sys; "
        "evidence = _evidence(); sys.stdout.buffer.write(evidence.to_bytes() + evidence.record_digest.encode())"
    )
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
    evidence = _evidence()
    assert result.stdout == evidence.to_bytes() + evidence.record_digest.encode()


@pytest.mark.parametrize("status", [BTSStatus.PARTIAL, BTSStatus.REJECT])
def test_non_complete_report_is_rejected(status: BTSStatus) -> None:
    report = replace(_report(_dispositions()), status=status)

    with pytest.raises(ValueError, match="COMPLETE BTS report"):
        collect_integration_cost_evidence(report, _candidate_key(), _catalog())


def test_exact_test_surface_requires_pinned_plan_digest() -> None:
    change = SurfaceChange("tests/test_example.py", _digest("before"), _digest("after"), "modified")

    with pytest.raises(ValueError, match="pinned plan digest"):
        collect_integration_cost_evidence(
            _report(_dispositions()),
            _candidate_key(),
            _catalog(),
            test_surface_changes=(change,),
        )


def test_forged_record_digest_is_rejected() -> None:
    evidence = _evidence()
    assert evidence.schema_version == COST_EVIDENCE_SCHEMA
    assert IntegrationCostEvidence.from_json(evidence.to_bytes()) == evidence
    with pytest.raises(ValueError, match="record_digest mismatch"):
        replace(evidence, record_digest=_digest("forged"))


def test_noncanonical_json_key_order_is_rejected() -> None:
    evidence = _evidence()
    canonical = json.loads(evidence.to_bytes())
    reordered = dict(reversed(tuple(canonical.items())))
    noncanonical = json.dumps(reordered, separators=(",", ":"), ensure_ascii=False) + "\n"

    with pytest.raises(ValueError, match="invalid or noncanonical integration cost evidence"):
        IntegrationCostEvidence.from_json(noncanonical)
