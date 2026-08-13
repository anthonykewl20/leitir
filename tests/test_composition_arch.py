from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace

import pytest

from leitir.architecture import (
    CATALOG_AUTHORITY,
    CATALOG_SCHEMA_VERSION,
    BlockingCallCatalog,
    BlockingCallCatalogEntry,
    CompatibilityStatus,
    CompositionCandidateRef,
    ConflictKind,
    EvidenceRef,
    assess_architecture,
    classify_concurrency,
)
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import (
    GRAPH_SCHEMA_VERSION,
    Edge,
    EdgeKind,
    EdgeProvenance,
    Graph,
    Node,
    NodeId,
    NodeKind,
    NodeOrigin,
    SourceRef,
)


def _id(name: str, kind: NodeKind = NodeKind.FUNCTION, origin: NodeOrigin = NodeOrigin.DONOR) -> NodeId:
    return NodeId(origin, kind, "pkg.mod" if origin is NodeOrigin.DONOR else "vendor.api", name, f"id:{name}")


def _node(node_id: NodeId) -> Node:
    return Node(node_id, None, "synthetic")


def _edge(source: NodeId, target: NodeId, column: int) -> Edge:
    ref = SourceRef("o/r", "a" * 40, "pkg/mod.py", "b" * 40, 1, column, 1, column + 1)
    return Edge(EdgeKind.CALLS, source, target, EdgeProvenance(ref, None, "Call", "test_v1"))


def _subject() -> CompositionCandidateRef:
    return CompositionCandidateRef(("candidate", 1), "sha256:" + "1" * 64, "sha256:" + "2" * 64, "sha256:" + "3" * 64)


def _catalog(target: NodeId) -> BlockingCallCatalog:
    return BlockingCallCatalog.create("python-blocking", "1", (BlockingCallCatalogEntry.create(target, "blocking-io"),))


def _graph(nodes: tuple[NodeId, ...], edges: tuple[Edge, ...]) -> Graph:
    return Graph(GRAPH_SCHEMA_VERSION, tuple(_node(item) for item in nodes), edges, ())


def test_catalogued_blocking_call_reachable_through_sync_helper_is_incompatible_with_exact_path():
    root, helper = _id("root", NodeKind.ASYNC_FUNCTION), _id("helper")
    blocking = _id("vendor.api.block", origin=NodeOrigin.DECLARED_EXTERNAL)
    calls = (_edge(root, helper, 1), _edge(helper, blocking, 2))
    result = assess_architecture(_subject(), _graph((blocking, helper, root), tuple(reversed(calls))), _catalog(blocking))
    assert result.status is CompatibilityStatus.INCOMPATIBLE
    assert result.concurrency_model == "mixed"
    assert len(result.async_paths) == 1
    evidence = result.async_paths[0]
    assert evidence.source == root and evidence.target == blocking and evidence.calls == calls
    assert evidence.conflict_kind is ConflictKind.BLOCKING_CALL_IN_ASYNC_PATH
    assert evidence.catalog_entry == _catalog(blocking).entries[0]


def test_catalogued_call_only_in_sync_context_is_compatible():
    root = _id("root")
    blocking = _id("vendor.api.block", origin=NodeOrigin.DECLARED_EXTERNAL)
    result = assess_architecture(_subject(), _graph((root, blocking), (_edge(root, blocking, 1),)), _catalog(blocking))
    assert result.status is CompatibilityStatus.COMPATIBLE
    assert result.async_paths == ()


def test_async_clean_complete_graph_is_compatible_without_paths():
    root, helper, safe = _id("root", NodeKind.ASYNC_FUNCTION), _id("helper"), _id("safe")
    graph = _graph((root, helper, safe), (_edge(root, helper, 1), _edge(helper, safe, 2)))
    result = assess_architecture(_subject(), graph, BlockingCallCatalog.create("python-blocking", "1", ()))
    assert result.status is CompatibilityStatus.COMPATIBLE
    assert result.async_paths == ()


def test_uncatalogued_declared_external_in_async_path_is_unknown_not_compatible():
    root = _id("root", NodeKind.ASYNC_METHOD)
    external = _id("vendor.api.maybe", origin=NodeOrigin.DECLARED_EXTERNAL)
    empty = BlockingCallCatalog.create("python-blocking", "1", ())
    result = assess_architecture(_subject(), _graph((root, external), (_edge(root, external, 1),)), empty)
    assert result.status is CompatibilityStatus.UNKNOWN
    assert result.async_paths[0].status is CompatibilityStatus.UNKNOWN
    assert result.async_paths[0].conflict_kind is ConflictKind.UNKNOWN_ASYNC_EXTERNAL_EFFECT
    assert result.async_paths[0].catalog_entry is None


@pytest.mark.parametrize("root_kind", [NodeKind.ASYNC_FUNCTION, NodeKind.ASYNC_METHOD])
def test_both_async_root_kinds_produce_blocking_verdict(root_kind: NodeKind):
    root = _id("root", root_kind)
    blocking = _id("vendor.api.block", origin=NodeOrigin.DECLARED_EXTERNAL)
    result = assess_architecture(_subject(), _graph((root, blocking), (_edge(root, blocking, 1),)), _catalog(blocking))
    assert result.status is CompatibilityStatus.INCOMPATIBLE
    assert result.async_paths[0].source == root
    assert result.async_paths[0].conflict_kind is ConflictKind.BLOCKING_CALL_IN_ASYNC_PATH


def test_observations_are_sorted_carried_and_verdict_neutral():
    root = _id("root", NodeKind.ASYNC_FUNCTION)
    external = _id("vendor.api.maybe", origin=NodeOrigin.DECLARED_EXTERNAL)
    graph = _graph((root, external), (_edge(root, external, 1),))
    catalog = BlockingCallCatalog.create("python-blocking", "1", ())
    baseline = assess_architecture(_subject(), graph, catalog)
    later_source = SourceRef("o/r", "a" * 40, "z.py", "b" * 40, 2, 1, 2, 2)
    earlier_source = SourceRef("o/r", "a" * 40, "a.py", "b" * 40, 1, 1, 1, 2)
    later = EvidenceRef("architecture_observation", later_source.path, "sha256:2", "rule-z", "sha256:z")
    earlier = EvidenceRef("architecture_observation", earlier_source.path, "sha256:1", "rule-a", "sha256:a")
    supplied = (later, earlier)
    observed = assess_architecture(
        _subject(),
        graph,
        catalog,
        logging_observations=supplied,
        error_taxonomy_observations=supplied,
        config_observations=supplied,
        platform_observations=supplied,
    )
    assert observed.status == baseline.status
    assert observed.async_paths == baseline.async_paths
    assert tuple(path for path in observed.async_paths if path.status is CompatibilityStatus.INCOMPATIBLE) == tuple(
        path for path in baseline.async_paths if path.status is CompatibilityStatus.INCOMPATIBLE
    )
    assert tuple(path for path in observed.async_paths if path.status is CompatibilityStatus.UNKNOWN) == tuple(
        path for path in baseline.async_paths if path.status is CompatibilityStatus.UNKNOWN
    )
    assert observed.logging_observations == (earlier, later)
    assert observed.error_taxonomy_observations == (earlier, later)
    assert observed.config_observations == (earlier, later)
    assert observed.platform_observations == (earlier, later)


def test_catalog_digest_tamper_rejects_fail_closed():
    target = _id("vendor.api.block", origin=NodeOrigin.DECLARED_EXTERNAL)
    valid = _catalog(target)
    with pytest.raises(BTSError) as error:
        replace(valid, catalog_digest="sha256:" + "0" * 64)
    assert error.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert error.value.evidence.detail_code == "blocking_catalog_invalid_v1"


def test_catalog_duplicate_and_unsorted_entries_reject():
    first = BlockingCallCatalogEntry.create(_id("a", origin=NodeOrigin.DECLARED_EXTERNAL), "a")
    second = BlockingCallCatalogEntry.create(_id("b", origin=NodeOrigin.DECLARED_EXTERNAL), "b")
    for entries in ((second, first), (first, first)):
        with pytest.raises(BTSError):
            BlockingCallCatalog(CATALOG_SCHEMA_VERSION, CATALOG_AUTHORITY, "id", "1", entries, "invalid")

    duplicate_target = BlockingCallCatalogEntry.create(first.target, "different-effect")
    ordered_same_target = tuple(sorted((first, duplicate_target), key=lambda item: (item.target, item.effect_id, item.catalog_entry_digest)))
    with pytest.raises(BTSError):
        BlockingCallCatalog(CATALOG_SCHEMA_VERSION, CATALOG_AUTHORITY, "id", "1", ordered_same_target, "invalid")


def test_assessment_is_deterministic_across_graph_input_order_and_chooses_canonical_shortest_path():
    root, a, b = _id("root", NodeKind.ASYNC_FUNCTION), _id("a"), _id("b")
    target = _id("vendor.api.block", origin=NodeOrigin.DECLARED_EXTERNAL)
    edges = (_edge(root, b, 4), _edge(b, target, 5), _edge(root, a, 1), _edge(a, target, 2), _edge(root, target, 9))
    left = assess_architecture(_subject(), _graph((root, a, b, target), edges), _catalog(target))
    right = assess_architecture(_subject(), _graph(tuple(reversed((root, a, b, target))), tuple(reversed(edges))), _catalog(target))
    assert left == right
    assert left.async_paths[0].calls == (edges[-1],)


def test_equal_length_paths_choose_edge_key_minimal_path_in_both_input_orders():
    root, a, b = _id("root", NodeKind.ASYNC_FUNCTION), _id("a"), _id("b")
    target = _id("vendor.api.block", origin=NodeOrigin.DECLARED_EXTERNAL)
    via_b = (_edge(root, b, 3), _edge(b, target, 4))
    via_a = (_edge(root, a, 1), _edge(a, target, 2))
    edges = (*via_b, *via_a)
    for ordered_edges in (edges, tuple(reversed(edges))):
        result = assess_architecture(_subject(), _graph((root, a, b, target), ordered_edges), _catalog(target))
        assert result.async_paths[0].calls == via_a

    # AsyncPathEvidence is output-only at this layer, so no consumed path digest
    # can be altered; canonical path selection is the corresponding integrity gate.
    # Edge/Graph constructors structurally reject absent provenance before assessment.


def _budget_cases() -> tuple[tuple[Graph, dict[str, int]], ...]:
    root = _id("root", NodeKind.ASYNC_FUNCTION)
    other_root = _id("other", NodeKind.ASYNC_METHOD)
    helper = _id("helper")
    first = _id("vendor.api.first", origin=NodeOrigin.DECLARED_EXTERNAL)
    second = _id("vendor.api.second", origin=NodeOrigin.DECLARED_EXTERNAL)
    return (
        (_graph((root, helper), ()), {"max_nodes": 1}),
        (_graph((root, other_root), ()), {"max_roots": 1}),
        (_graph((root, helper, first), (_edge(root, helper, 1), _edge(helper, first, 2))), {"max_edges": 1}),
        (_graph((root, helper, first), (_edge(root, helper, 1), _edge(helper, first, 2))), {"max_path_length": 1}),
        (_graph((root, first, second), (_edge(root, first, 1), _edge(root, second, 2))), {"max_paths": 1}),
    )


@pytest.mark.parametrize(("graph", "budget"), _budget_cases())
def test_assessment_limits_reject_fail_closed(graph: Graph, budget: dict[str, int]):
    with pytest.raises(BTSError) as error:
        assess_architecture(_subject(), graph, BlockingCallCatalog.create("python-blocking", "1", ()), **budget)
    assert error.value.reason is BTSRejectReason.REJECT_BUDGET_EXCEEDED
    assert error.value.evidence.detail_code == "architecture_budget_v1"


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_assessment_digest_is_hash_seed_independent(seed: str):
    script = (
        "from tests.test_composition_arch import _fixed_assessment_digest; "
        "import sys; sys.stdout.buffer.write(_fixed_assessment_digest().encode('ascii'))"
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
    assert result.stdout == _fixed_assessment_digest().encode("ascii")


def _fixed_assessment_digest() -> str:
    root, a, b = _id("root", NodeKind.ASYNC_FUNCTION), _id("a"), _id("b")
    external = _id("vendor.api.maybe", origin=NodeOrigin.DECLARED_EXTERNAL)
    graph = _graph((external, b, root, a), (_edge(root, b, 4), _edge(b, external, 5), _edge(root, a, 1), _edge(a, external, 2)))
    result = assess_architecture(_subject(), graph, BlockingCallCatalog.create("python-blocking", "1", ()))
    return result.assessment_digest


def test_unknown_declared_external_cannot_be_silently_omitted():
    root = _id("root", NodeKind.ASYNC_FUNCTION)
    external = _id("vendor.api.unknown", origin=NodeOrigin.DECLARED_EXTERNAL)
    result = assess_architecture(
        _subject(),
        _graph((root, external), (_edge(root, external, 1),)),
        BlockingCallCatalog.create("python-blocking", "1", ()),
    )
    assert len(result.async_paths) == 1
    assert result.async_paths[0].target == external
    assert result.async_paths[0].conflict_kind is ConflictKind.UNKNOWN_ASYNC_EXTERNAL_EFFECT


@pytest.mark.parametrize(
    ("nodes", "expected"),
    [
        ((_id("f"),), "sync"),
        ((_id("f", NodeKind.ASYNC_FUNCTION),), "async"),
        ((_id("f"), _id("a", NodeKind.ASYNC_METHOD)), "mixed"),
        ((_id("module", NodeKind.MODULE),), "unknown"),
    ],
)
def test_concurrency_classification_from_bounded_graph_syntax(nodes: tuple[NodeId, ...], expected: str):
    assert classify_concurrency(_graph(nodes, ())) == expected


def test_declared_concurrency_is_authoritative_and_unknown_remains_unknown():
    graph = _graph((_id("f"),), ())
    assert classify_concurrency(graph, declared_concurrency="async") == "async"
    result = assess_architecture(_subject(), graph, BlockingCallCatalog.create("id", "1", ()), declared_concurrency="unknown")
    assert result.status is CompatibilityStatus.UNKNOWN
