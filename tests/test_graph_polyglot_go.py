"""Go producer gate.  Regenerate golden with the comment beside its assertion."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from test_graph_polyglot import _lock, _policy, _snapshot

from leitir.bts_errors import BTSError
from leitir.graph import GraphExtractionRequest, make_graph_provider
from leitir.graph.go import PRODUCER_ID, PRODUCER_VERSION, QUERY_ID, QUERY_TEXT, extract_graph
from leitir.graph.policy import requirements_lock_digest
from leitir.graph.ts_kernel import query_sha256

_TREE_SITTER = pytest.mark.skipif(importlib.util.find_spec("tree_sitter") is None, reason="requires tree-sitter extra")
_FIXTURE = Path(__file__).parent / "fixtures" / "graph" / "go"
_GOLDEN = _FIXTURE / "golden.json"


def _files() -> dict[str, bytes]:
    return {
        path.relative_to(_FIXTURE).as_posix(): path.read_bytes()
        for path in sorted(_FIXTURE.rglob("*.go"))
    }


def _provider(tmp_path: Path, **overrides: object):
    snapshot = _snapshot(tmp_path, _files())
    lock = _lock()
    limits: dict[str, object] = {
        "max_file_bytes": 10_000,
        "max_tree_nodes_per_file": 10_000,
        "max_query_matches": 10_000,
        "max_symbols": 10_000,
        "max_edges": 10_000,
    }
    limits.update(overrides)
    policy = _policy("go", requirements_lock_digest=requirements_lock_digest(lock), query_id=QUERY_ID, query_sha256=query_sha256(QUERY_TEXT), producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION, resolution_rule_version="go_tree_sitter_resolution_v1", **limits)
    return snapshot, make_graph_provider(snapshot, "go", policy, requirements_lock_text=lock)


def test_go_query_identity_and_fixtures_are_stable() -> None:
    assert QUERY_ID == "go-graph-query-v1"
    assert query_sha256(QUERY_TEXT) == "8074cea5f202872dfd5665f6cccdb02bc4c5a49948f4046d7543f4a423feeda4"
    assert _FIXTURE.is_dir()
    for path in sorted(_FIXTURE.rglob("*.go")):
        path.read_text(encoding="utf-8")


def test_go_query_drift_rejects_before_native_import(tmp_path: Path) -> None:
    # Use a syntactically valid declared reference; query identity rejects before
    # optional native loading or source reads.
    snapshot = _snapshot(tmp_path, {"x.go": b"package x\n"})
    request = GraphExtractionRequest("go", snapshot.source_root, (_source_ref(snapshot),), _policy("go", query_id=QUERY_ID, query_sha256=query_sha256("(identifier) @x\n"), producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION, resolution_rule_version="go_tree_sitter_resolution_v1"))
    with pytest.raises(BTSError) as rejected:
        extract_graph(request)
    assert rejected.value.evidence.detail_code == "tree_sitter_query_identity_mismatch_v1"


def _source_ref(snapshot):
    from leitir.graph.registry import _build_request

    return _build_request(snapshot, "go", _policy("go", query_id=QUERY_ID, query_sha256=query_sha256(QUERY_TEXT), producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION, resolution_rule_version="go_tree_sitter_resolution_v1")).source_files[0]


@_TREE_SITTER
def test_go_fixture_extracts_only_proven_edges_and_pairs_blockers(tmp_path: Path) -> None:
    snapshot, provider = _provider(tmp_path)
    graph = provider(snapshot.source_root)
    assert {(edge.kind.value, edge.source.qualified_name, edge.target.qualified_name) for edge in graph.edges} == {
        ("imports", "cmd (main)", "internal/eng (eng)"),
        ("imports", "cmd (main)", "internal/side (side)"),
        ("inherits", "internal/eng.Child", "internal/eng.Base"),
        ("inherits", "internal/eng.Wrapped", "internal/eng.Core"),
        ("calls", "cmd.run", "cmd.Local"),
        ("calls", "cmd.run", "internal/eng.Hello"),
    }
    inherits = [edge for edge in graph.edges if edge.kind.value == "inherits"]
    assert [edge.provenance.protocol_base for edge in inherits] == [True, False]
    details = {item.detail_code for item in graph.unresolved}
    assert {"tree_sitter_external_import_v1", "tree_sitter_star_import_v1", "tree_sitter_receiver_dispatch_v1", "tree_sitter_builtin_call_v1", "tree_sitter_type_conversion_v1", "tree_sitter_unresolved_throw_v1", "tree_sitter_ambiguous_callee_binding_v1"} <= details
    assert {(item.detail_code, item.provenance.site.path) for item in graph.unresolved} == {(item.detail_code, item.path) for item in graph.coverage.blockers}
    assert graph.coverage.parsed_files == graph.coverage.files


@_TREE_SITTER
def test_go_package_module_is_singleton_and_import_provenance_uses_importing_file(tmp_path: Path) -> None:
    snapshot, provider = _provider(tmp_path)
    graph = provider(snapshot.source_root)
    modules = [node for node in graph.nodes if node.id.kind.value == "module"]
    assert sum(node.id.module == "internal/eng" for node in modules) == 1
    edge = next(edge for edge in graph.edges if edge.kind.value == "imports" and edge.target.module == "internal/eng")
    assert edge.provenance.site.path == "cmd/main.go"
    assert edge.provenance.site.start_line == 4


@_TREE_SITTER
def test_go_owner_containment_is_per_file_for_overlapping_package_spans(tmp_path: Path) -> None:
    snapshot, provider = _provider(tmp_path)
    graph = provider(snapshot.source_root)
    unresolved = next(item for item in graph.unresolved if item.provenance.site.path == "internal/eng/extra.go" and item.expression == "Missing")
    assert unresolved.source.location_key.startswith("internal/eng/extra.go:")


@_TREE_SITTER
def test_go_fixture_matches_golden_and_tamper_changes_it(tmp_path: Path) -> None:
    # Regenerate: PYTHONPATH=src /tmp/opencode/tsint-venv/bin/python -c 'import runpy,sys,tempfile;from pathlib import Path;sys.path.insert(0,"tests");v=runpy.run_path("tests/test_graph_polyglot_go.py");s,p=v["_provider"](Path(tempfile.mkdtemp()));Path("tests/fixtures/graph/go/golden.json").write_text(p(s.source_root).to_json(),encoding="utf-8")'
    snapshot, provider = _provider(tmp_path)
    assert provider(snapshot.source_root).to_json() == _GOLDEN.read_text(encoding="utf-8")
    files = _files()
    files["cmd/main.go"] += b"\nfunc another() { Local() }\n"
    changed = _snapshot(tmp_path / "changed", files)
    lock = _lock()
    policy = _policy("go", requirements_lock_digest=requirements_lock_digest(lock), query_id=QUERY_ID, query_sha256=query_sha256(QUERY_TEXT), producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION, resolution_rule_version="go_tree_sitter_resolution_v1", max_file_bytes=10_000, max_tree_nodes_per_file=10_000, max_query_matches=10_000, max_symbols=10_000, max_edges=10_000)
    assert make_graph_provider(changed, "go", policy, requirements_lock_text=lock)(changed.source_root).to_json() != _GOLDEN.read_text(encoding="utf-8")


@_TREE_SITTER
def test_go_fixture_is_hash_seed_deterministic(tmp_path: Path) -> None:
    script = textwrap.dedent(f"""
        import runpy
        import sys
        import tempfile
        from pathlib import Path
        sys.path.insert(0, {str(Path(__file__).parent.resolve())!r})
        values = runpy.run_path({str(Path(__file__).resolve())!r})
        snapshot, provider = values["_provider"](Path(tempfile.mkdtemp()))
        print(provider(snapshot.source_root).to_json(), end="")
    """)
    outputs = [subprocess.check_output([sys.executable, "-c", script], env={**os.environ, "PYTHONHASHSEED": seed}) for seed in ("0", "1", "42")]
    assert outputs[0] == outputs[1] == outputs[2] == _GOLDEN.read_bytes()


@_TREE_SITTER
@pytest.mark.parametrize(("field", "value", "detail"), [("max_tree_nodes_per_file", 1, "tree_sitter_max_tree_nodes_v1"), ("max_query_matches", 1, "tree_sitter_max_query_matches_v1")])
def test_go_budgets_fail_without_partial_graph(tmp_path: Path, field: str, value: int, detail: str) -> None:
    snapshot, provider = _provider(tmp_path, **{field: value})
    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)
    assert rejected.value.evidence.detail_code == detail


@_TREE_SITTER
def test_go_abi_mismatch_and_parse_error_are_typed(tmp_path: Path) -> None:
    snapshot, provider = _provider(tmp_path, grammar_abi_version=99)
    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)
    assert rejected.value.evidence.detail_code == "tree_sitter_grammar_abi_mismatch_v1"
    bad = _snapshot(tmp_path / "bad", {"bad.go": b"package bad\nfunc broken( {\n"})
    lock = _lock()
    policy = _policy("go", requirements_lock_digest=requirements_lock_digest(lock), query_id=QUERY_ID, query_sha256=query_sha256(QUERY_TEXT), producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION, resolution_rule_version="go_tree_sitter_resolution_v1", max_file_bytes=10_000)
    graph = make_graph_provider(bad, "go", policy, requirements_lock_text=lock)(bad.source_root)
    assert not graph.nodes and not graph.coverage.parsed_files
    assert [item.detail_code for item in graph.coverage.blockers] == ["tree_sitter_parse_error_v1"]
