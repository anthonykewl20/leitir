from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace

import pytest

from leitir.bts import (
    BTS_SCHEMA_VERSION,
    AdapterCatalog,
    AdaptRule,
    BTSBudget,
    BTSDisposition,
    BTSStatus,
    DispositionRule,
    ExternalRule,
    RejectRule,
    ResolutionPolicy,
    StdlibIdentity,
    StdlibInterface,
    compute_bts,
)
from leitir.bts_errors import BTSRejectReason
from leitir.graph.model import (
    GRAPH_SCHEMA_VERSION,
    Edge,
    EdgeKind,
    EdgeProvenance,
    Graph,
    GraphCoverage,
    Node,
    NodeId,
    NodeKind,
    NodeOrigin,
    SourceRef,
    UnresolvedEdge,
)
from leitir.graph.python import extract_static_edges


def _budget(**changes: int) -> BTSBudget:
    values = {
        "max_input_bytes": 100_000,
        "max_file_bytes": 100_000,
        "max_ast_nodes_per_file": 10_000,
        "max_files": 10,
        "max_edges": 100,
        "max_nodes": 100,
        "max_queue_entries": 100,
        "max_depth": 20,
        "max_work_units": 10_000,
        "max_symbols": 100,
        "max_source_lines": 1_000,
        "max_external_interfaces": 100,
        "max_config_entries": 100,
        "max_donor_source_bps": 10_000,
    }
    values.update(changes)
    return BTSBudget(**values)


def _policy(*rules: DispositionRule, stdlib: tuple[StdlibInterface, ...] = ()) -> ResolutionPolicy:
    return ResolutionPolicy(
        BTS_SCHEMA_VERSION,
        "leitir-maintainers",
        "test-policy",
        "sha256:" + "1" * 64,
        StdlibIdentity("cpython", ">=3.11,<3.12", "v1", "sha256:" + "2" * 64, stdlib),
        AdapterCatalog("empty", "v1", "sha256:" + "3" * 64),
        rules,
    )


def _fixture() -> tuple[NodeId, Graph]:
    source = b"def helper(x):\n    return x + 1\n\ndef seed(x):\n    return helper(x)\n"
    extraction = extract_static_edges(
        source,
        slug="owner/repo",
        commit_sha="a" * 40,
        path="src/pkg/mod.py",
        blob_sha="b" * 40,
        package_root="src",
    )
    graph = extraction.to_graph()
    seed = next(node.id for node in graph.nodes if node.id.qualified_name == "pkg.mod.seed")
    return seed, graph


def test_complete_walk_has_exact_members_dispositions_and_digests() -> None:
    seed, graph = _fixture()
    result = compute_bts(seed, graph, _budget(), _policy())
    assert result.status is BTSStatus.COMPLETE
    assert result.bts is not None
    assert [member.node.qualified_name for member in result.bts.members] == ["pkg.mod.helper", "pkg.mod.seed"]
    assert [item.disposition for item in result.report.traversed_edges] == [BTSDisposition.INCLUDE]
    assert result.report.analysis_digest.startswith("sha256:") and len(result.report.analysis_digest) == 71
    assert result.bts.bts_digest.startswith("sha256:") and len(result.bts.bts_digest) == 71


@pytest.mark.parametrize("change", [{"max_nodes": 1}, {"max_donor_source_bps": 4_000}])
def test_budget_exhaustion_is_partial_without_bts(change: dict[str, int]) -> None:
    seed, graph = _fixture()
    result = compute_bts(seed, graph, _budget(**change), _policy())
    assert result.status is BTSStatus.PARTIAL
    assert result.bts is None
    assert any(
        getattr(blocker, "reason", None) is BTSRejectReason.REJECT_BUDGET_EXCEEDED
        for blocker in result.report.blockers
    )
    assert result.report.frontier


def test_reachable_unresolved_reject_dominates_budget() -> None:
    seed, graph = _fixture()
    node = next(item for item in graph.nodes if item.id == seed)
    assert node.source is not None
    unresolved = UnresolvedEdge(
        EdgeKind.READS,
        seed,
        "unknown",
        EdgeProvenance(node.source, None, "Name", "runtime_reference_v1"),
        BTSRejectReason.REJECT_UNRESOLVED_EDGE,
        "unresolved_nonlocal_load_v1",
    )
    graph = Graph(graph.schema_version, graph.nodes, graph.edges, (unresolved,), graph.coverage)
    result = compute_bts(seed, graph, _budget(max_nodes=1), _policy())
    assert result.status is BTSStatus.REJECT
    assert result.bts is None
    assert result.report.unresolved == (unresolved,)


def _one_edge(target: NodeId) -> tuple[NodeId, Graph]:
    source_ref = SourceRef("owner/repo", "a" * 40, "src/pkg/mod.py", "b" * 40, 1, 0, 1, 12)
    seed = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "pkg.mod", "pkg.mod.seed", "seed")
    edge = Edge(EdgeKind.READS, seed, target, EdgeProvenance(source_ref, None, "Name", "runtime_reference_v1"))
    return seed, Graph(
        GRAPH_SCHEMA_VERSION,
        (Node(seed, source_ref, "ast"), Node(target, None, "ast")),
        (edge,),
        (),
        GraphCoverage((source_ref,), (source_ref,)),
    )


def test_disposition_precedence_exact_then_defaults_then_reject() -> None:
    external = NodeId(NodeOrigin.DECLARED_EXTERNAL, NodeKind.FUNCTION, "vendor", "vendor.f", "external:vendor.f")
    seed, graph = _one_edge(external)
    explicit = DispositionRule(
        "external-v1", external, BTSDisposition.EXTERNAL,
        ExternalRule(external, "vendor>=1"), "sha256:" + "4" * 64,
    )
    assert compute_bts(seed, graph, _budget(), _policy(explicit)).status is BTSStatus.COMPLETE
    assert compute_bts(seed, graph, _budget(), _policy()).status is BTSStatus.REJECT

    reject = DispositionRule(
        "reject-v1", external, BTSDisposition.REJECT,
        RejectRule(BTSRejectReason.REJECT_HARD_GATE_FAILED, "policy_reject_v1"), "sha256:" + "5" * 64,
    )
    assert compute_bts(seed, graph, _budget(), _policy(reject)).status is BTSStatus.REJECT

    stdlib = NodeId(NodeOrigin.STDLIB, NodeKind.FUNCTION, "math", "math.sqrt", "stdlib:math:sqrt")
    seed, graph = _one_edge(stdlib)
    pure = StdlibInterface("math", "math.sqrt")
    assert compute_bts(seed, graph, _budget(), _policy(stdlib=(pure,))).status is BTSStatus.COMPLETE


def test_policy_rejects_contradictory_exact_rules_and_unpinned_adapter() -> None:
    target = NodeId(NodeOrigin.DECLARED_EXTERNAL, NodeKind.FUNCTION, "vendor", "vendor.f", "external:vendor.f")
    rule = DispositionRule("a", target, BTSDisposition.EXTERNAL, ExternalRule(target, "vendor"), "sha256:" + "a" * 64)
    with pytest.raises(ValueError, match="duplicate"):
        _policy(rule, replace(rule, rule_id="b"))
    adapt = DispositionRule("adapt", target, BTSDisposition.ADAPT, AdaptRule("missing"), "sha256:" + "b" * 64)
    with pytest.raises(ValueError, match="unknown adapter"):
        _policy(adapt)


def test_r2_missing_runtime_reference_coverage_cannot_complete() -> None:
    seed, graph = _fixture()
    graph = Graph(graph.schema_version, graph.nodes, graph.edges, graph.unresolved, GraphCoverage())
    result = compute_bts(seed, graph, _budget(), _policy())
    assert result.status is BTSStatus.PARTIAL
    assert any(getattr(item, "detail_code", None) == "b4_runtime_references_incomplete_v1" for item in result.report.blockers)


def test_digest_reproduction_and_invalidation() -> None:
    seed, graph = _fixture()
    first = compute_bts(seed, graph, _budget(), _policy())
    assert first.bts is not None
    assert compute_bts(seed, graph, _budget(), _policy()).bts == first.bts
    changed_budget = compute_bts(seed, graph, _budget(max_edges=101), _policy())
    changed_policy = compute_bts(seed, graph, _budget(), replace(_policy(), policy_id="other"))
    assert changed_budget.bts is not None and changed_budget.bts.bts_digest != first.bts.bts_digest
    assert changed_policy.bts is not None and changed_policy.bts.bts_digest != first.bts.bts_digest

    unreachable = next(node for node in graph.nodes if node.id.kind is NodeKind.MODULE)
    assert unreachable.source is not None
    changed_node = replace(unreachable, source=replace(unreachable.source, blob_sha="c" * 40))
    changed_nodes = tuple(changed_node if node.id == unreachable.id else node for node in graph.nodes)
    changed_graph = Graph(graph.schema_version, changed_nodes, graph.edges, graph.unresolved, graph.coverage)
    changed = compute_bts(seed, changed_graph, _budget(), _policy())
    assert changed.bts is not None and changed.bts.bts_digest != first.bts.bts_digest


@pytest.mark.parametrize("hash_seed", ["0", "1", "42"])
def test_hash_seed_byte_identity(hash_seed: str) -> None:
    script = """
from tests.test_bts_walk import _budget, _fixture, _policy
from leitir.bts import compute_bts
seed, graph = _fixture()
result = compute_bts(seed, graph, _budget(), _policy())
assert result.bts is not None
print(result.report.analysis_digest + ':' + result.bts.bts_digest)
"""
    environment = {**os.environ, "PYTHONHASHSEED": hash_seed, "PYTHONPATH": "src:."}
    completed = subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, text=True, env=environment)
    baseline_environment = {**environment, "PYTHONHASHSEED": "0"}
    baseline = subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, text=True, env=baseline_environment)
    assert completed.stdout == baseline.stdout


def test_budget_validation_rejects_bool_and_out_of_range_ratio() -> None:
    with pytest.raises(ValueError):
        _budget(max_nodes=True)
    with pytest.raises(ValueError):
        _budget(max_donor_source_bps=10_001)
