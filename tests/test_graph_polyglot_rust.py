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
from leitir.graph import GraphExtractionRequest, make_graph_provider
from leitir.graph.model import SourceRef
from leitir.graph.policy import (
    GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION,
    SOURCE_SELECTION_VERSION,
    TREE_SITTER_PINS,
    build_graph_extraction_policy,
    requirements_lock_digest,
)
from leitir.graph.rust import PRODUCER_ID, PRODUCER_VERSION, QUERY_ID, QUERY_TEXT, extract_graph
from leitir.graph.ts_kernel import query_sha256
from leitir.treehash import FULL, TREE_HASH_ALGORITHM, compute_materialized_tree_hash

_TREE_SITTER = pytest.mark.skipif(importlib.util.find_spec("tree_sitter") is None, reason="requires tree-sitter extra")
_FIXTURE = Path(__file__).parent / "fixtures" / "graph" / "rust"
_GOLDEN = _FIXTURE / "golden.json"


def _lock() -> str:
    return "\n".join(f"{name}=={version} --hash=sha256:{index:064x}" for index, (name, version) in enumerate(sorted(TREE_SITTER_PINS.items()), start=1))


def _policy(**overrides: object):
    values: dict[str, object] = {
        "schema_version": GRAPH_EXTRACTION_POLICY_SCHEMA_VERSION,
        "authority": "leitir-test",
        "policy_id": "rust-graph-test-v1",
        "language": "rust",
        "requirements_lock_digest": requirements_lock_digest(_lock()),
        "runtime_distribution": "tree-sitter",
        "runtime_version": "0.25.2",
        "grammar_distribution": "tree-sitter-rust",
        "grammar_version": "0.24.2",
        "grammar_factory": "language",
        "grammar_abi_version": 15,
        "query_id": QUERY_ID,
        "query_sha256": query_sha256(QUERY_TEXT),
        "producer_id": PRODUCER_ID,
        "producer_version": PRODUCER_VERSION,
        "resolution_rule_version": "rust_tree_sitter_resolution_v1",
        "source_selection_version": SOURCE_SELECTION_VERSION,
        "max_files": 10,
        "max_file_bytes": 10_000,
        "max_tree_nodes_per_file": 10_000,
        "max_query_matches": 10_000,
        "max_symbols": 10_000,
        "max_edges": 10_000,
        "max_work_units": 10_000,
    }
    values.update(overrides)
    return build_graph_extraction_policy(**values)


def _snapshot(tmp_path: Path, files: dict[str, bytes]) -> DonorSnapshot:
    source_root = tmp_path / "source"
    for path, content in files.items():
        target = source_root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    tree_hash, scope = compute_materialized_tree_hash(source_root)
    assert scope == FULL
    return DonorSnapshot("owner/repo", "a" * 40, "git-commit", "exact", tree_hash, TREE_HASH_ALGORITHM, FULL, tmp_path, source_root)


def _fixture_files() -> dict[str, bytes]:
    return {
        path.relative_to(_FIXTURE).as_posix(): path.read_bytes()
        for path in sorted(_FIXTURE.rglob("*.rs"))
    }


def _fixture_provider(tmp_path: Path, **overrides: object):
    snapshot = _snapshot(tmp_path, _fixture_files())
    return snapshot, make_graph_provider(snapshot, "rust", _policy(**overrides), requirements_lock_text=_lock())


def test_rust_query_identity_and_fixtures_are_stable() -> None:
    assert QUERY_ID == "rust-graph-query-v1"
    assert query_sha256(QUERY_TEXT) == "f3234dedfeebc179ca07d7c965182790c1d8a10f726af2fbc6e45117cebc2924"
    assert _GOLDEN.is_file()
    assert ("lib/foo.rs", "lib/mod.rs", "main.rs", "standard/src/foo.rs", "standard/src/lib.rs", "standard/src/main.rs") == tuple(path.relative_to(_FIXTURE).as_posix() for path in sorted(_FIXTURE.rglob("*.rs")))
    for path in sorted(_FIXTURE.rglob("*.rs")):
        path.read_text(encoding="utf-8")


def test_rust_query_drift_rejects_before_native_import(tmp_path: Path) -> None:
    source = SourceRef("owner/repo", "a" * 40, "main.rs", "b" * 40, 1, 0, 1, 0)
    request = GraphExtractionRequest("rust", tmp_path, (source,), _policy(query_sha256=query_sha256("(identifier) @x\n")))
    with pytest.raises(BTSError) as rejected:
        extract_graph(request)
    assert rejected.value.evidence.detail_code == "tree_sitter_query_identity_mismatch_v1"


@_TREE_SITTER
def test_rust_fixture_proves_edges_and_never_guesses(tmp_path: Path) -> None:
    snapshot, provider = _fixture_provider(tmp_path)
    graph = provider(snapshot.source_root)
    assert {(edge.kind.value, edge.source.qualified_name, edge.target.qualified_name) for edge in graph.edges} == {
        ("imports", "main", "lib/foo"),
        ("imports", "standard/src/lib", "standard/src/foo"),
        ("imports", "standard/src/main", "standard/src/foo"),
        ("inherits", "main.Widget", "main.Render"),
        ("calls", "main.run", "lib/foo.foo"),
    }
    inherit = next(edge for edge in graph.edges if edge.kind.value == "inherits")
    assert inherit.provenance.protocol_base
    details = {item.detail_code for item in graph.unresolved}
    assert {
        "tree_sitter_external_use_v1", "tree_sitter_glob_import_v1",
        "tree_sitter_receiver_dispatch_v1", "tree_sitter_macro_call_v1", "tree_sitter_unresolved_path_call_v1",
        "tree_sitter_trait_selection_v1",
    } <= details
    assert {(item.detail_code, item.provenance.site.path, item.provenance.site.start_line) for item in graph.unresolved} == {
        (item.detail_code, item.path, item.start_line) for item in graph.coverage.blockers
    }
    assert not any(edge.kind.value == "raises" for edge in graph.edges)
    assert tuple(item.path for item in graph.coverage.parsed_files) == ("lib/foo.rs", "lib/mod.rs", "main.rs", "standard/src/foo.rs", "standard/src/lib.rs", "standard/src/main.rs")


@_TREE_SITTER
def test_rust_fixture_matches_golden(tmp_path: Path) -> None:
    # Regenerate: PYTHONPATH=src /tmp/opencode/tsint-venv/bin/python -c 'import runpy,tempfile;from pathlib import Path;v=runpy.run_path("tests/test_graph_polyglot_rust.py");s,p=v["_fixture_provider"](Path(tempfile.mkdtemp()));Path("tests/fixtures/graph/rust/golden.json").write_text(p(s.source_root).to_json(),encoding="utf-8")'
    snapshot, provider = _fixture_provider(tmp_path)
    assert provider(snapshot.source_root).to_json() == _GOLDEN.read_text(encoding="utf-8")


@_TREE_SITTER
def test_rust_fixture_tamper_changes_graph(tmp_path: Path) -> None:
    files = _fixture_files()
    files["main.rs"] += b"\nuse crate::lib::foo;\n"
    snapshot = _snapshot(tmp_path, files)
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert graph.to_json() != _GOLDEN.read_text(encoding="utf-8")
    assert sum(edge.kind.value == "imports" for edge in graph.edges) == 6


@_TREE_SITTER
def test_rust_self_import_from_ordinary_file_uses_the_current_semantic_module(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {
        "main.rs": b"mod lib;\n",
        "lib/mod.rs": b"pub mod foo;\n",
        "lib/foo.rs": b"pub mod bar;\nuse self::bar;\n",
        "lib/foo/bar.rs": b"pub fn item() {}\n",
    })
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert ("imports", "lib/foo", "lib/foo/bar") in {(edge.kind.value, edge.source.qualified_name, edge.target.qualified_name) for edge in graph.edges}


@_TREE_SITTER
def test_rust_super_import_uses_the_parent_semantic_module(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {
        "main.rs": b"mod lib;\n",
        "lib/mod.rs": b"pub mod foo; pub mod bar;\n",
        "lib/foo.rs": b"use super::bar;\n",
        "lib/bar.rs": b"pub fn item() {}\n",
    })
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert ("imports", "lib/foo", "lib/bar") in {(edge.kind.value, edge.source.qualified_name, edge.target.qualified_name) for edge in graph.edges}


@_TREE_SITTER
def test_rust_repeated_super_import_pops_each_semantic_module(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {
        "main.rs": b"mod lib;\n",
        "lib/mod.rs": b"pub mod deep; pub mod bar;\n",
        "lib/deep.rs": b"pub mod nested;\n",
        "lib/deep/nested.rs": b"use super::super::bar;\n",
        "lib/bar.rs": b"pub fn item() {}\n",
    })
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert ("imports", "lib/deep/nested", "lib/bar") in {(edge.kind.value, edge.source.qualified_name, edge.target.qualified_name) for edge in graph.edges}


@_TREE_SITTER
def test_rust_crate_root_item_import_resolves_the_root_definition(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {
        "main.rs": b"mod child;\npub fn item() {}\n",
        "child.rs": b"use crate::item;\n",
    })
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert ("imports", "child", "main") in {(edge.kind.value, edge.source.qualified_name, edge.target.qualified_name) for edge in graph.edges}


@_TREE_SITTER
def test_rust_standard_layout_bin_and_lib_roots_anchor_crate_at_src(tmp_path: Path) -> None:
    # Both roots are valid Rust crates and share this declared scope's `src`
    # boundary. `foo.rs` is their grammar-proved child module.
    snapshot = _snapshot(tmp_path, {
        "src/lib.rs": b"pub mod foo;\nuse crate::foo as crate_foo;\n",
        "src/main.rs": b"mod foo;\nuse crate::foo as crate_foo;\n",
        "src/foo.rs": b"pub fn item() {}\n",
    })
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert {
        (edge.kind.value, edge.source.qualified_name, edge.target.qualified_name)
        for edge in graph.edges
    } >= {
        ("imports", "src/lib", "src/foo"),
        ("imports", "src/main", "src/foo"),
    }


@_TREE_SITTER
def test_rust_super_never_crosses_a_declared_crate_root(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {
        "src/lib.rs": b"pub mod foo;\nuse super::foo;\n",
        "src/foo.rs": b"pub fn item() {}\n",
    })
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert not any(edge.kind.value == "imports" for edge in graph.edges)
    assert [item.detail_code for item in graph.unresolved] == ["tree_sitter_super_above_crate_root_v1"]


@_TREE_SITTER
def test_rust_nearest_declared_ancestor_selects_the_nested_crate_root(tmp_path: Path) -> None:
    # Two syntax-valid roots are declared; inner.rs belongs to nested/lib.rs,
    # so crate::sibling must not resolve through the outer src/lib.rs root.
    snapshot = _snapshot(tmp_path, {
        "src/lib.rs": b"pub mod sibling;\n",
        "src/sibling.rs": b"pub fn outer() {}\n",
        "src/nested/lib.rs": b"pub mod sibling; pub mod inner;\n",
        "src/nested/sibling.rs": b"pub fn inner() {}\n",
        "src/nested/inner.rs": b"use crate::sibling;\n",
    })
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert ("imports", "src/nested/inner", "src/nested/sibling") in {
        (edge.kind.value, edge.source.qualified_name, edge.target.qualified_name)
        for edge in graph.edges
    }
    assert ("imports", "src/nested/inner", "src/sibling") not in {
        (edge.kind.value, edge.source.qualified_name, edge.target.qualified_name)
        for edge in graph.edges
    }


@_TREE_SITTER
def test_rust_no_declared_root_fails_closed_for_crate_import(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {
        "orphan/foo.rs": b"use crate::bar;\nuse super::bar;\n",
        "orphan/bar.rs": b"pub fn item() {}\n",
    })
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert not any(edge.kind.value == "imports" for edge in graph.edges)
    assert [item.detail_code for item in graph.unresolved] == ["tree_sitter_unresolved_import_v1"] * 2


@_TREE_SITTER
def test_rust_ambiguous_file_and_mod_module_is_fail_closed(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {
        "lib/mod.rs": b"pub mod foo;\n",
        "lib/foo.rs": b"pub fn one() {}\n",
        "lib/foo/mod.rs": b"pub fn two() {}\n",
        "main.rs": b"mod lib;\nuse crate::lib::foo;\n",
    })
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert any(item.detail_code == "tree_sitter_unresolved_import_v1" for item in graph.unresolved)


@_TREE_SITTER
def test_rust_json_is_hash_seed_deterministic() -> None:
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
@pytest.mark.parametrize(("field", "value", "detail"), [("max_tree_nodes_per_file", 1, "tree_sitter_max_tree_nodes_v1")])
def test_rust_budget_is_typed(tmp_path: Path, field: str, value: int, detail: str) -> None:
    snapshot, provider = _fixture_provider(tmp_path, **{field: value})
    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)
    assert rejected.value.reason is BTSRejectReason.REJECT_EXTRACTION_BUDGET
    assert rejected.value.evidence.detail_code == detail


@_TREE_SITTER
def test_rust_abi_mismatch_is_typed(tmp_path: Path) -> None:
    snapshot, provider = _fixture_provider(tmp_path, grammar_abi_version=99)
    with pytest.raises(BTSError) as rejected:
        provider(snapshot.source_root)
    assert rejected.value.evidence.detail_code == "tree_sitter_grammar_abi_mismatch_v1"


@_TREE_SITTER
def test_rust_parse_error_is_blocker_only(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, {"bad.rs": b"fn broken( {\n"})
    graph = make_graph_provider(snapshot, "rust", _policy(), requirements_lock_text=_lock())(snapshot.source_root)
    assert not graph.nodes
    assert not graph.coverage.parsed_files
    assert [item.detail_code for item in graph.coverage.blockers] == ["tree_sitter_parse_error_v1"]
