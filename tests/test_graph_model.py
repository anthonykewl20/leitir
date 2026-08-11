from __future__ import annotations

import copy
import os
import subprocess
import sys
import textwrap

import pytest

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
    build_from_api_index,
)


def _source(start_col: int = 0, end_col: int = 4) -> SourceRef:
    return SourceRef("owner/repo", "a" * 40, "pkg/api.py", "b" * 40, 3, start_col, 3, end_col)


def _node(name: str, kind: NodeKind = NodeKind.FUNCTION) -> Node:
    node_id = NodeId(NodeOrigin.DONOR, kind, "pkg.api", f"pkg.api.{name}", f"pkg/api.py:3:{name}")
    return Node(node_id, _source(), "ast")


def _edge(source: Node, target: Node, start_col: int = 0) -> Edge:
    provenance = EdgeProvenance(_source(start_col, start_col + 4), None, "Call", "direct_binding_v1")
    return Edge(EdgeKind.CALLS, source.id, target.id, provenance)


def test_enum_values_pin_the_adr_graph_contract():
    assert [kind.value for kind in NodeKind] == [
        "module", "function", "async_function", "class", "method", "async_method", "constant", "test", "resource"
    ]
    assert [origin.value for origin in NodeOrigin] == ["donor", "stdlib", "declared_external", "test", "resource"]
    assert [kind.value for kind in EdgeKind] == [
        "imports", "inherits", "raises", "calls", "instantiates", "reads", "tested_by"
    ]


def test_build_from_api_index_produces_deterministic_discovery_nodes_without_mutation():
    index = {
        "schema_version": 1,
        "methods": ["ast"],
        "modules": [{"name": "pkg.api", "path": "pkg/api.py", "method": "ast"}],
        "symbols": [
            {"kind": "class", "qualified_name": "pkg.api.Widget", "module": "pkg.api", "path": "pkg/api.py", "line": 8},
            {"kind": "function", "qualified_name": "pkg.api.run", "module": "pkg.api", "path": "pkg/api.py", "line": 2},
            {"kind": "constant", "qualified_name": "pkg.api.LIMIT", "module": "pkg.api", "path": "pkg/api.py", "line": 1},
        ],
    }
    original = copy.deepcopy(index)
    graph = build_from_api_index(index)

    assert index == original
    assert {(node.id.kind, node.id.qualified_name) for node in graph.nodes} == {
        (NodeKind.CLASS, "pkg.api.Widget"),
        (NodeKind.FUNCTION, "pkg.api.run"),
        (NodeKind.CONSTANT, "pkg.api.LIMIT"),
    }
    assert all(node.extraction_method == "api_index" for node in graph.nodes)
    assert graph.edges == ()
    assert graph == build_from_api_index({**index, "symbols": list(reversed(index["symbols"]))})


def test_graph_rejects_duplicate_node_ids_and_duplicate_edges():
    caller = _node("caller")
    callee = _node("callee")
    with pytest.raises(BTSError) as node_error:
        Graph(GRAPH_SCHEMA_VERSION, (caller, caller), (), ())
    assert node_error.value.reason is BTSRejectReason.REJECT_DUPLICATE_RESULT
    assert node_error.value.evidence.detail_code == "record_type=node id"

    edge = _edge(caller, callee)
    with pytest.raises(BTSError) as edge_error:
        Graph(GRAPH_SCHEMA_VERSION, (caller, callee), (edge, edge), ())
    assert edge_error.value.reason is BTSRejectReason.REJECT_DUPLICATE_RESULT


def test_graph_rejects_dangling_endpoint():
    caller = _node("caller")
    edge = _edge(caller, _node("missing"))
    with pytest.raises(BTSError) as error:
        Graph(GRAPH_SCHEMA_VERSION, (caller,), (edge,), ())
    assert error.value.reason is BTSRejectReason.REJECT_UNRESOLVED_EDGE
    assert error.value.evidence.detail_code == "edge_kind=calls"


def test_utf8_byte_columns_distinguish_same_line_call_sites():
    caller = _node("caller")
    callee = _node("callee")
    graph = Graph(GRAPH_SCHEMA_VERSION, (callee, caller), (_edge(caller, callee, 9), _edge(caller, callee, 2)), ())
    assert [(edge.provenance.site.start_col, edge.provenance.site.end_col) for edge in graph.edges] == [(2, 6), (9, 13)]
    assert '"start_col":2' in graph.to_json()


def test_schema_version_is_present_validated_and_json_round_trips():
    graph = Graph(GRAPH_SCHEMA_VERSION, (_node("run"),), (), ())
    assert graph.schema_version == GRAPH_SCHEMA_VERSION
    assert Graph.from_json(graph.to_bytes()).to_bytes() == graph.to_bytes()
    with pytest.raises(BTSError) as error:
        Graph("leitir-bts-graph-v0", (), (), ())
    assert error.value.reason is BTSRejectReason.REJECT_UNRESOLVED_EDGE


@pytest.mark.parametrize("seed", ["0", "1", "42"])
def test_graph_json_is_deterministic_across_pythonhashseed(seed: str):
    script = textwrap.dedent(
        """
        from leitir.graph.model import build_from_api_index

        symbols = {
            ("function", "pkg.api.zed", 9),
            ("class", "pkg.api.Alpha", 2),
            ("constant", "pkg.api.LIMIT", 1),
        }
        index = {"schema_version": 1, "methods": ["ast"], "modules": [], "symbols": [
            {"kind": kind, "qualified_name": name, "module": "pkg.api", "path": "pkg/api.py", "line": line}
            for kind, name, line in symbols
        ]}
        print(build_from_api_index(index).to_json(), end="")
        """
    )
    env = {**os.environ, "PYTHONHASHSEED": seed}
    output = subprocess.check_output([sys.executable, "-c", script], env=env)
    baseline = subprocess.check_output([sys.executable, "-c", script], env={**os.environ, "PYTHONHASHSEED": "0"})
    assert output == baseline
