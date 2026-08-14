from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from leitir.bts import DonorSnapshot
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph import GraphExtractionPolicy, make_graph_provider
from leitir.graph.policy import (
    GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION,
    SOURCE_SELECTION_VERSION,
    TREE_SITTER_PINS,
    build_graph_extraction_policy,
    requirements_lock_digest,
)
from leitir.graph.ts_kernel import query_sha256
from leitir.graph.typescript import PRODUCER_ID, PRODUCER_VERSION, QUERY_ID, QUERY_TEXT
from leitir.treehash import FULL, TREE_HASH_ALGORITHM, compute_materialized_tree_hash

_TREE_SITTER = pytest.mark.skipif(importlib.util.find_spec("tree_sitter") is None, reason="requires tree-sitter extra")
_FIXTURE = Path(__file__).parent / "fixtures" / "graph" / "typescript"
_GOLDEN = _FIXTURE / "golden.json"


def _legacy_lock() -> str:
    return "\n".join(
        f"{name}=={version} \\\n+    --hash=sha256:{index:064x}"
        for index, (name, version) in enumerate(sorted(TREE_SITTER_PINS.items()), start=1)
    )


def _lock() -> str:
    return "\n".join(
        f"{name}=={version} --hash=sha256:{index:064x}"
        for index, (name, version) in enumerate(sorted(TREE_SITTER_PINS.items()), start=1)
    )


def _snapshot(tmp_path: Path, files: dict[str, bytes]) -> DonorSnapshot:
    source_root = tmp_path / "materialized"
    for relative, content in files.items():
        target = source_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    tree_hash, scope = compute_materialized_tree_hash(source_root)
    assert scope == FULL
    return DonorSnapshot("owner/repo", "a" * 40, "git-commit", "exact", tree_hash, TREE_HASH_ALGORITHM, FULL, tmp_path, source_root)


def _policy(**overrides: object) -> GraphExtractionPolicy:
    values: dict[str, object] = {
        "schema_version": GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION,
        "authority": "leitir-test",
        "policy_id": "typescript-polyglot-test-v1",
        "language": "typescript",
        "requirements_lock_digest": requirements_lock_digest(_lock()),
        "runtime_distribution": "tree-sitter",
        "runtime_version": "0.25.2",
        "grammar_distribution": "tree-sitter-typescript",
        "grammar_version": "0.23.2",
        "grammar_factory": "language_typescript",
        "grammar_abi_version": 14,
        "query_id": QUERY_ID,
        "query_sha256": query_sha256(QUERY_TEXT),
        "producer_id": PRODUCER_ID,
        "producer_version": PRODUCER_VERSION,
        "resolution_rule_version": "typescript_tree_sitter_resolution_v1",
        "source_selection_version": SOURCE_SELECTION_VERSION,
        "max_files": 10,
        "max_file_bytes": 10_000,
        "max_tree_nodes_per_file": 10_000,
        "max_query_matches": 10_000,
        "max_symbols": 10_000,
        "max_edges": 10_000,
        "max_work_units": 100,
    }
    values.update(overrides)
    return build_graph_extraction_policy(**values)


def _fixture_provider(tmp_path: Path, files: dict[str, bytes] | None = None, **policy_overrides: object):
    if files is None:
        files = {path.name: path.read_bytes() for path in sorted(_FIXTURE.glob("*.ts"))}
    snapshot = _snapshot(tmp_path, files)
    return snapshot, make_graph_provider(snapshot, "typescript", _policy(**policy_overrides), requirements_lock_text=_lock())


def test_typescript_query_identity_and_fixtures_are_stable() -> None:
    assert QUERY_ID == "typescript-graph-query-v1"
    assert query_sha256(QUERY_TEXT) == "0f13ccd3f313ab0f60921c1f047a4e01eb5c8ba1437349809be955203ce66620"
    assert _GOLDEN.exists()
    for path in sorted(_FIXTURE.glob("*.ts*")):
        path.read_text(encoding="utf-8")


def test_typescript_query_drift_rejects_before_native_import(tmp_path: Path) -> None:
    from leitir.graph.model import SourceRef
    from leitir.graph.policy import GraphExtractionRequest
    from leitir.graph.typescript import extract_graph

    request = GraphExtractionRequest(
        "typescript",
        tmp_path,
        (SourceRef("owner/repo", "a" * 40, "example.ts", "b" * 40, 1, 0, 1, 0),),
        _policy(query_sha256=query_sha256("(identifier) @x\n")),
    )
    with pytest.raises(BTSError) as rejected:
        extract_graph(request)
    assert rejected.value.reason is BTSRejectReason.REJECT_PROVENANCE_MISMATCH
    assert rejected.value.evidence.detail_code == "tree_sitter_query_identity_mismatch_v1"


@_TREE_SITTER
def test_typescript_fixture_extracts_proven_edges_and_pairs_negative_evidence(tmp_path: Path) -> None:
    snapshot, provider = _fixture_provider(tmp_path)
    graph = provider(snapshot.source_root)

    assert {(edge.kind.value, edge.source.qualified_name, edge.target.qualified_name) for edge in graph.edges} == {
        ("imports", "child", "base"),
        ("imports", "shadow", "base"),
        ("inherits", "child.Child", "base.Base"),
        ("inherits", "child.Child", "base.Runnable"),
        ("calls", "child.Child.run", "base.greet"),
        ("raises", "child.Child.run", "base.Base"),
        ("instantiates", "child.Child.run", "base.Base"),
        ("calls", "shadow.control", "base.greet"),
        ("instantiates", "shadow.control", "base.Base"),
        ("instantiates", "shadow.another", "base.Base"),
        ("instantiates", "shadow.nested", "base.Base"),
    }
    protocol = next(edge for edge in graph.edges if edge.target.qualified_name == "base.Runnable")
    assert protocol.provenance.protocol_base
    details = {item.detail_code for item in graph.unresolved}
    assert {
        "tree_sitter_star_import_v1",
        "tree_sitter_reexport_v1",
        "tree_sitter_dynamic_import_v1",
        "tree_sitter_receiver_dispatch_v1",
        "tree_sitter_unresolved_base_v1",
        "tree_sitter_decorator_v1",
        "tree_sitter_unresolved_throw_v1",
        "tree_sitter_dynamic_instantiation_v1",
    } <= details
    assert {(item.detail_code, item.provenance.site.path, item.provenance.site.start_line) for item in graph.unresolved} == {(item.detail_code, item.path, item.start_line) for item in graph.coverage.blockers}
    unresolved_sites = {(item.provenance.site.path, item.provenance.site.start_line, item.provenance.site.start_col) for item in graph.unresolved}
    assert not any((edge.provenance.site.path, edge.provenance.site.start_line, edge.provenance.site.start_col) in unresolved_sites for edge in graph.edges)
    assert graph.coverage.parsed_files == graph.coverage.files
    instantiates = next(edge for edge in graph.edges if edge.kind.value == "instantiates")
    assert (instantiates.provenance.site.path, instantiates.provenance.site.start_line, instantiates.provenance.site.start_col) == ("child.ts", 7, 8)
    assert (instantiates.provenance.binding.path, instantiates.provenance.binding.start_line) == ("child.ts", 2)
    assert {(item.kind.value, item.detail_code, item.provenance.site.path, item.provenance.site.start_line) for item in graph.unresolved if item.kind.value == "instantiates"} == {
        ("instantiates", "tree_sitter_dynamic_instantiation_v1", "negative.ts", 10),
        ("instantiates", "tree_sitter_unresolved_instantiation_v1", "negative.ts", 11),
        ("instantiates", "tree_sitter_unresolved_instantiation_v1", "negative.ts", 14),
        ("instantiates", "tree_sitter_shadowed_binding_v1", "shadow.ts", 3),
        ("instantiates", "tree_sitter_shadowed_binding_v1", "shadow.ts", 4),
        ("instantiates", "tree_sitter_shadowed_binding_v1", "shadow.ts", 9),
        ("instantiates", "tree_sitter_shadowed_binding_v1", "shadow.ts", 10),
        ("instantiates", "tree_sitter_shadowed_binding_v1", "shadow.ts", 11),
    }


@_TREE_SITTER
def test_typescript_fixture_matches_golden_graph(tmp_path: Path) -> None:
    # Regenerate: PYTHONPATH=src /tmp/opencode/tsint-venv/bin/python -c 'import runpy,tempfile;from pathlib import Path;v=runpy.run_path("tests/test_graph_polyglot_typescript.py");s,p=v["_fixture_provider"](Path(tempfile.mkdtemp()));Path("tests/fixtures/graph/typescript/golden.json").write_text(p(s.source_root).to_json(),encoding="utf-8")'
    snapshot, provider = _fixture_provider(tmp_path)
    assert provider(snapshot.source_root).to_json() == _GOLDEN.read_text(encoding="utf-8")


@_TREE_SITTER
def test_typescript_fixture_tamper_changes_golden_in_expected_way(tmp_path: Path) -> None:
    files = {path.name: path.read_bytes() for path in sorted(_FIXTURE.glob("*.ts"))}
    files["child.ts"] += b'\nimport { Base as AnotherBase } from "./base.ts";\n'
    snapshot, provider = _fixture_provider(tmp_path, files)
    graph = provider(snapshot.source_root)
    assert graph.to_json() != _GOLDEN.read_text(encoding="utf-8")
    assert sum(edge.kind.value == "imports" and edge.source.qualified_name == "child" and edge.target.qualified_name == "base" for edge in graph.edges) == 3


@_TREE_SITTER
def test_typescript_shadowed_bindings_never_resolve_imports(tmp_path: Path) -> None:
    files = {
        "base.ts": b"export class Base {}\nexport function greet(): void {}\n",
        "child.ts": b'''import { Base, greet } from "./base.ts";
function param(Base: unknown): void { new Base(); }
function local(): void { let Base: unknown; new Base(); }
function callShadow(greet: unknown): void { greet(); }
function throwShadow(Base: unknown): void { throw new Base(); }
function control(): void { new Base(); greet(); }
function outer(): void { let Base: unknown; class Local extends Base {} }
''',
    }
    snapshot, provider = _fixture_provider(tmp_path, files)
    graph = provider(snapshot.source_root)
    assert sum(edge.kind.value == "instantiates" and edge.target.qualified_name == "base.Base" for edge in graph.edges) == 1
    assert sum(edge.kind.value == "calls" and edge.target.qualified_name == "base.greet" for edge in graph.edges) == 1
    shadowed = [item for item in graph.unresolved if item.detail_code == "tree_sitter_shadowed_binding_v1"]
    assert {item.kind.value for item in shadowed} == {"calls", "inherits", "instantiates", "raises"}


@_TREE_SITTER
def test_typescript_block_shadow_named_expression_and_inner_wins(tmp_path: Path) -> None:
    snapshot, provider = _fixture_provider(tmp_path)
    graph = provider(snapshot.source_root)
    shadowed_lines = {
        item.provenance.site.start_line
        for item in graph.unresolved
        if item.kind.value == "instantiates" and item.detail_code == "tree_sitter_shadowed_binding_v1" and item.provenance.site.path == "shadow.ts"
    }
    assert {9, 10, 11} <= shadowed_lines
    assert ("instantiates", "shadow.another", "base.Base") in {
        (edge.kind.value, edge.source.qualified_name, edge.target.qualified_name)
        for edge in graph.edges
    }


@_TREE_SITTER
def test_typescript_abstract_class_and_enum_locals_shadow_imported_calls(tmp_path: Path) -> None:
    snapshot, provider = _fixture_provider(tmp_path, {
        "base.ts": b"export function greet(): void {}\n",
        "child.ts": b'''import { greet } from "./base.ts";
function abstractLocal(): void { abstract class greet {} greet(); }
function enumLocal(): void { enum greet { member } greet(); }
''',
    })
    graph = provider(snapshot.source_root)
    assert not any(edge.kind.value == "calls" for edge in graph.edges)
    assert {(item.kind.value, item.detail_code) for item in graph.unresolved} >= {
        ("calls", "tree_sitter_shadowed_binding_v1"),
    }


@_TREE_SITTER
def test_typescript_var_scopes_shadow_imported_calls_without_hoisting_to_root(tmp_path: Path) -> None:
    snapshot, provider = _fixture_provider(tmp_path, {
        "base.ts": b"export function greet(): void {}\n",
        "child.ts": b'''import { greet } from "./base.ts";
namespace N { var greet = (): void => {}; greet(); }
class C { static { var greet = (): void => {}; greet(); } }
var rootGreet = greet; greet();
''',
    })
    graph = provider(snapshot.source_root)

    # The two nested var declarations must shadow only their own owning
    # boundaries.  The true module-root call remains normally resolvable.
    calls = [edge for edge in graph.edges if edge.kind.value == "calls"]
    assert [(edge.source.qualified_name, edge.target.qualified_name) for edge in calls] == [("child", "base.greet")]
    expected_sites = {("child.ts", 2), ("child.ts", 3)}
    unresolved_sites = [
        (item.provenance.site.path, item.provenance.site.start_line)
        for item in graph.unresolved
        if item.kind.value == "calls" and item.detail_code == "tree_sitter_shadowed_binding_v1"
    ]
    blocker_sites = [
        (item.path, item.start_line)
        for item in graph.coverage.blockers
        if item.detail_code == "tree_sitter_shadowed_binding_v1"
    ]
    assert set(unresolved_sites) == expected_sites
    assert set(blocker_sites) == expected_sites
    assert all(unresolved_sites.count(site) == 1 for site in expected_sites)
    assert all(blocker_sites.count(site) == 1 for site in expected_sites)


@_TREE_SITTER
def test_typescript_fixture_json_is_hash_seed_deterministic() -> None:
    script = textwrap.dedent(
        f"""
        import runpy
        import tempfile
        from pathlib import Path
        values = runpy.run_path({str(Path(__file__).resolve())!r})
        snapshot, provider = values["_fixture_provider"](Path(tempfile.mkdtemp()))
        print(provider(snapshot.source_root).to_json(), end="")
        """
    )
    outputs = [subprocess.check_output([sys.executable, "-c", script], env={**os.environ, "PYTHONHASHSEED": seed}) for seed in ("0", "1", "42")]
    assert outputs[0] == outputs[1] == outputs[2] == _GOLDEN.read_bytes()


@_TREE_SITTER
def test_typescript_budget_and_abi_fail_closed(tmp_path: Path) -> None:
    for overrides, detail in (
        ({"max_tree_nodes_per_file": 1}, "tree_sitter_max_tree_nodes_v1"),
        # Exercise QueryCursor.did_exceed_match_limit on the real wheel; this
        # assertion is intentionally independent of capture contents.
        ({"max_query_matches": 1}, "tree_sitter_max_query_matches_v1"),
        ({"max_edges": 1}, "tree_sitter_max_edges_v1"),
        ({"grammar_abi_version": 99}, "tree_sitter_grammar_abi_mismatch_v1"),
    ):
        snapshot, provider = _fixture_provider(tmp_path, **overrides)
        with pytest.raises(BTSError) as rejected:
            provider(snapshot.source_root)
        assert rejected.value.evidence.detail_code == detail


@_TREE_SITTER
def test_tsx_parse_error_excludes_file_from_parsed_coverage(tmp_path: Path) -> None:
    files = {"bad.tsx": (_FIXTURE / "bad.tsx").read_bytes()}
    snapshot, provider = _fixture_provider(tmp_path, files)
    graph = provider(snapshot.source_root)
    assert not graph.nodes
    assert not graph.coverage.parsed_files
    assert [item.detail_code for item in graph.coverage.blockers] == ["tree_sitter_parse_error_v1"]
