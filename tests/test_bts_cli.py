from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.bts import BTSStatus
from leitir.bts_cli import (
    _GRAMMAR_ABI_VERSIONS,
    DEFAULT_MAX_INPUT_BYTES,
    SeedSelector,
    _polyglot_policy,
    load_donor_snapshot,
    load_resolution_policy,
    python_graph_provider,
    resolve_seed,
    run_bts_compute,
    tree_sitter_graph_provider,
    write_artifacts,
)
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.cost import collect_integration_cost_evidence
from leitir.graph.model import GRAPH_SCHEMA_VERSION, Graph, Node, NodeId, NodeKind, NodeOrigin
from leitir.graph.policy import compute_policy_digest
from leitir.graph.python import extract_static_edges
from leitir.graph.ts_kernel import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_QUERY_MATCHES,
    DEFAULT_MAX_SYMBOLS,
    DEFAULT_MAX_TREE_NODES_PER_FILE,
    DEFAULT_MAX_WORK_UNITS,
)
from leitir.materialize import manifest_digest_fields, target_path
from leitir.treehash import compute_materialized_tree_hash

SHA = "a" * 40
FIXTURES = Path(__file__).parent / "fixtures" / "bts_cli"


def _shelf(tmp_path: Path, fixture: str = "donor") -> Path:
    target = target_path(tmp_path, "owner", "donor", SHA)
    shutil.copytree(FIXTURES / fixture, target)
    digest, scope = compute_materialized_tree_hash(target)
    manifest = {
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "fetched_at": "2026-08-15T00:00:00Z",
        "host": "github.com",
        "owner": "owner",
        "repo": "donor",
        "repo_url": "https://github.com/owner/donor",
        "source": "git-commit",
        "parity": "exact",
        "spec": "github:owner/donor",
        "tag": None,
        "verified": True,
        "verified_at": "2026-08-15T00:00:00Z",
    }
    manifest.update(manifest_digest_fields(digest, scope=scope))
    (target / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return target


def _manifest(target: Path) -> dict[str, object]:
    return json.loads((target / "leitir-manifest.json").read_text(encoding="utf-8"))


def _write_manifest(target: Path, manifest: dict[str, object]) -> None:
    (target / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_snapshot_loader_accepts_only_complete_exact_git_shelf(tmp_path: Path) -> None:
    target = _shelf(tmp_path)
    snapshot = load_donor_snapshot(tmp_path, "owner", "donor", SHA)
    assert snapshot.source_root == target
    assert snapshot.materialization_root == target.parent


@pytest.mark.parametrize(
    ("change", "reason", "detail"),
    [
        ({"source": "registry-artifact", "fetch_method": "registry-artifact", "artifact_kind": "sdist", "artifact_checksum": "x"}, BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "bts_cli_source_unsupported_v1"),
        ({"parity": "drift"}, BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "bts_cli_parity_v1"),
        ({"verified": "sampled"}, BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "bts_cli_verification_v1"),
    ],
)
def test_snapshot_loader_rejects_manifest_authority_variants(
    tmp_path: Path, change: dict[str, object], reason: BTSRejectReason, detail: str,
) -> None:
    target = _shelf(tmp_path)
    manifest = _manifest(target)
    manifest.update(change)
    _write_manifest(target, manifest)
    with pytest.raises(BTSError) as caught:
        load_donor_snapshot(tmp_path, "owner", "donor", SHA)
    assert (caught.value.reason, caught.value.evidence.detail_code) == (reason, detail)


def test_snapshot_loader_rejects_unverified_shelf(tmp_path: Path) -> None:
    _shelf(tmp_path)
    (target_path(tmp_path, "owner", "donor", SHA) / "leitir-manifest.json").unlink()
    with pytest.raises(BTSError) as caught:
        load_donor_snapshot(tmp_path, "owner", "donor", SHA)
    assert caught.value.evidence.detail_code == "bts_cli_shelf_unverified_v1"


def test_python_compute_writes_complete_canonical_artifacts(tmp_path: Path) -> None:
    _shelf(tmp_path)
    result = run_bts_compute(tmp_path, "owner", "donor", SHA, seed=SeedSelector("package.policy", "package.policy.normalize_contract"))
    assert result.summary["status"] == "COMPLETE"
    assert result.result.bts is not None
    output = tmp_path / "output"
    write_artifacts(result, output)
    assert (output / "graph.json").read_bytes() == result.graph_bytes
    assert json.loads((output / "summary.json").read_text(encoding="utf-8"))["analysis_digest"] == result.result.report.analysis_digest


def test_python_artifacts_are_hash_seed_independent(tmp_path: Path) -> None:
    script = """
import hashlib, json, pathlib, shutil, sys, tempfile
from leitir.bts_cli import SeedSelector, run_bts_compute
from leitir.materialize import manifest_digest_fields, target_path
from leitir.treehash import compute_materialized_tree_hash
root = pathlib.Path(tempfile.mkdtemp())
target = target_path(root, 'owner', 'donor', 'a' * 40)
shutil.copytree(pathlib.Path(sys.argv[1]), target)
digest, scope = compute_materialized_tree_hash(target)
manifest = {'commit_sha':'a'*40,'fetch_method':'codeload-tarball','fetched_at':'2026-08-15T00:00:00Z','host':'github.com','owner':'owner','repo':'donor','repo_url':'https://github.com/owner/donor','source':'git-commit','parity':'exact','spec':'github:owner/donor','tag':None,'verified':True,'verified_at':'2026-08-15T00:00:00Z'}
manifest.update(manifest_digest_fields(digest, scope=scope))
(target / 'leitir-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
result = run_bts_compute(root, 'owner', 'donor', 'a'*40, seed=SeedSelector('package.policy', 'package.policy.normalize_contract'))
sys.stdout.buffer.write(result.graph_bytes + json.dumps(result.summary, sort_keys=True, separators=(',', ':')).encode() + b'\\n')
"""
    outputs = []
    for hash_seed in ("0", "1", "42"):
        environment = {**os.environ, "PYTHONHASHSEED": hash_seed}
        outputs.append(subprocess.check_output([sys.executable, "-c", script, str(FIXTURES / "donor")], env=environment))
    assert outputs[0] == outputs[1] == outputs[2]


def test_multifile_python_provider_coalesces_identical_global_nodes(tmp_path: Path) -> None:
    _shelf(tmp_path, "donor-multifile")
    snapshot = load_donor_snapshot(tmp_path, "owner", "donor", SHA)

    graph = python_graph_provider(snapshot)(snapshot.source_root)

    assert len([node for node in graph.nodes if node.id.module == "os" and node.id.qualified_name == "os"]) == 1
    assert len([node for node in graph.nodes if node.id.qualified_name == "builtins.Exception"]) == 1


def test_multifile_artifacts_are_hash_seed_independent(tmp_path: Path) -> None:
    policy = json.dumps(
        {"schema_version": "leitir-bts-cli-policy-v1", "stdlib_modules": ["builtins", "os"], "adapters": []},
        sort_keys=True,
    )
    script = """
import json, pathlib, shutil, sys, tempfile
from leitir.bts_cli import SeedSelector, run_bts_compute
from leitir.materialize import manifest_digest_fields, target_path
from leitir.treehash import compute_materialized_tree_hash
root = pathlib.Path(tempfile.mkdtemp())
target = target_path(root, 'owner', 'donor', 'a' * 40)
shutil.copytree(pathlib.Path(sys.argv[1]), target)
digest, scope = compute_materialized_tree_hash(target)
manifest = {'commit_sha':'a'*40,'fetch_method':'codeload-tarball','fetched_at':'2026-08-15T00:00:00Z','host':'github.com','owner':'owner','repo':'donor','repo_url':'https://github.com/owner/donor','source':'git-commit','parity':'exact','spec':'github:owner/donor','tag':None,'verified':True,'verified_at':'2026-08-15T00:00:00Z'}
manifest.update(manifest_digest_fields(digest, scope=scope))
(target / 'leitir-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
policy = root / 'policy.json'
policy.write_text(sys.argv[2], encoding='utf-8')
result = run_bts_compute(root, 'owner', 'donor', 'a'*40, seed=SeedSelector('package.first', 'package.first.run'), policy_path=policy)
sys.stdout.buffer.write(result.graph_bytes + json.dumps(result.summary, sort_keys=True, separators=(',', ':')).encode() + b'\\n')
"""
    outputs = []
    for hash_seed in ("0", "1", "42"):
        environment = {**os.environ, "PYTHONHASHSEED": hash_seed}
        outputs.append(
            subprocess.check_output(
                [sys.executable, "-c", script, str(FIXTURES / "donor-multifile"), policy], env=environment
            )
        )
    assert outputs[0] == outputs[1] == outputs[2]


def test_resolution_policy_allows_stdlib_imports_reached_by_seed(tmp_path: Path) -> None:
    _shelf(tmp_path, "donor-multifile")
    without_policy = run_bts_compute(
        tmp_path, "owner", "donor", SHA, seed=SeedSelector("package.first", "package.first.run")
    )
    assert without_policy.result.status is BTSStatus.REJECT
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {"schema_version": "leitir-bts-cli-policy-v1", "stdlib_modules": ["os"], "adapters": []},
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = run_bts_compute(
        tmp_path,
        "owner",
        "donor",
        SHA,
        seed=SeedSelector("package.first", "package.first.run"),
        policy_path=policy_path,
    )

    assert result.result.status is BTSStatus.COMPLETE


def test_adapter_policy_template_digest_is_literal_bytes_and_cost_accepts_complete_report(tmp_path: Path) -> None:
    _shelf(tmp_path, "donor-multifile")
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "schema_version": "leitir-bts-cli-policy-v1",
                "stdlib_modules": [],
                "adapters": [{"module": "os", "disposition": "adapter"}],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    result = run_bts_compute(
        tmp_path,
        "owner",
        "donor",
        SHA,
        seed=SeedSelector("package.first", "package.first.run"),
        policy_path=policy_path,
    )
    snapshot = load_donor_snapshot(tmp_path, "owner", "donor", SHA)
    catalog = load_resolution_policy(policy_path, python_graph_provider(snapshot)(snapshot.source_root)).adapter_catalog

    assert result.result.status is BTSStatus.COMPLETE
    assert catalog.entries[0].template_bytes_sha256 == "sha256:" + hashlib.sha256(b"module:os").hexdigest()
    evidence = collect_integration_cost_evidence(
        result.result.report,
        (
            "owner/donor", SHA, "package/first.py", "b" * 40, 1, 0, 2, 0,
            "function", "package.first", "package.first.run", "python", "python", "source", "collector", "v1",
        ),
        catalog,
    )
    assert evidence.adapt_instances.value is not None
    assert evidence.adapter_template_physical_lines.value == evidence.adapt_instances.value


def test_python_provider_rejects_oversized_file_before_extraction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _shelf(tmp_path)
    snapshot = load_donor_snapshot(tmp_path, "owner", "donor", SHA)
    monkeypatch.setattr("leitir.bts_cli.DEFAULT_MAX_FILE_BYTES", 1)

    with pytest.raises(BTSError) as caught:
        python_graph_provider(snapshot)(snapshot.source_root)

    assert (caught.value.reason, caught.value.evidence.detail_code) == (
        BTSRejectReason.REJECT_EXTRACTION_BUDGET,
        "bts_cli_max_file_bytes_v1",
    )


def test_python_provider_rejects_file_count_before_extraction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _shelf(tmp_path)
    snapshot = load_donor_snapshot(tmp_path, "owner", "donor", SHA)
    (target / "other.py").write_text("def other():\n    return None\n", encoding="utf-8")
    monkeypatch.setattr("leitir.bts_cli.DEFAULT_MAX_FILES", 1)

    with pytest.raises(BTSError) as caught:
        python_graph_provider(snapshot)(snapshot.source_root)

    assert (caught.value.reason, caught.value.evidence.detail_code) == (
        BTSRejectReason.REJECT_EXTRACTION_BUDGET,
        "bts_cli_max_files_v1",
    )


def test_python_provider_rejects_cumulative_input_before_extraction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _shelf(tmp_path)
    snapshot = load_donor_snapshot(tmp_path, "owner", "donor", SHA)
    original = (target / "package" / "policy.py").read_bytes()
    added = b"def other():\n    return None\n"
    (target / "other.py").write_bytes(added)
    monkeypatch.setattr("leitir.bts_cli.DEFAULT_MAX_INPUT_BYTES", len(original) + len(added) - 1)

    with pytest.raises(BTSError) as caught:
        python_graph_provider(snapshot)(snapshot.source_root)

    assert (caught.value.reason, caught.value.evidence.detail_code) == (
        BTSRejectReason.REJECT_EXTRACTION_BUDGET,
        "bts_cli_max_input_bytes_v1",
    )


def test_python_input_cap_is_derived_from_tree_sitter_limits() -> None:
    assert DEFAULT_MAX_INPUT_BYTES == DEFAULT_MAX_FILES * DEFAULT_MAX_FILE_BYTES


def test_non_python_compute_requires_an_explicit_lock_path(tmp_path: Path) -> None:
    _shelf(tmp_path, "donor-go")

    with pytest.raises(BTSError) as failure:
        run_bts_compute(
            tmp_path,
            "owner",
            "donor",
            SHA,
            language="go",
            seed=SeedSelector(".", "..Normalize"),
        )
    assert failure.value.evidence.detail_code == "bts_cli_lock_required_v1"


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"schema_version": "wrong", "stdlib_modules": [], "adapters": []},
        {"schema_version": "leitir-bts-cli-policy-v1", "stdlib_modules": ["os", "os"], "adapters": []},
        {"schema_version": "leitir-bts-cli-policy-v1", "stdlib_modules": ["os"], "adapters": [{"module": "", "disposition": "adapter"}]},
        {"schema_version": "leitir-bts-cli-policy-v1", "stdlib_modules": [], "adapters": [{"module": "remote", "disposition": "guess"}]},
    ],
)
def test_resolution_policy_rejects_invalid_closed_schema(tmp_path: Path, value: dict[str, object]) -> None:
    _shelf(tmp_path, "donor-multifile")
    snapshot = load_donor_snapshot(tmp_path, "owner", "donor", SHA)
    graph = python_graph_provider(snapshot)(snapshot.source_root)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(BTSError) as failure:
        load_resolution_policy(policy_path, graph)
    assert failure.value.evidence.detail_code == "bts_cli_policy_invalid_v1"


def test_bts_cli_pinned_polyglot_values_match_their_owners() -> None:
    from leitir.graph import go, javascript, rust, typescript

    assert _GRAMMAR_ABI_VERSIONS == {
        "go": go.GRAMMAR_ABI_VERSION,
        "javascript": javascript.GRAMMAR_ABI_VERSION,
        "rust": rust.GRAMMAR_ABI_VERSION,
        "typescript": typescript.GRAMMAR_ABI_VERSION,
    }
    policy = _polyglot_policy("go", (Path(__file__).resolve().parents[1] / "requirements-tree-sitter.lock").read_text(encoding="utf-8"))
    assert (
        policy.max_files,
        policy.max_file_bytes,
        policy.max_tree_nodes_per_file,
        policy.max_query_matches,
        policy.max_symbols,
        policy.max_edges,
        policy.max_work_units,
    ) == (
        DEFAULT_MAX_FILES,
        DEFAULT_MAX_FILE_BYTES,
        DEFAULT_MAX_TREE_NODES_PER_FILE,
        DEFAULT_MAX_QUERY_MATCHES,
        DEFAULT_MAX_SYMBOLS,
        DEFAULT_MAX_EDGES,
        DEFAULT_MAX_WORK_UNITS,
    )


def test_seed_resolution_requires_exactly_one_node() -> None:
    selector = SeedSelector("pkg", "pkg.f")
    first = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "pkg", "pkg.f", "a")
    assert resolve_seed(Graph(GRAPH_SCHEMA_VERSION, (Node(first, None, "test"),), (), ()), selector) == first
    with pytest.raises(BTSError, match="matched no donor definition") as missing:
        resolve_seed(Graph(GRAPH_SCHEMA_VERSION, (), (), ()), selector)
    assert missing.value.evidence.detail_code == "bts_cli_seed_not_found_v1"
    second = NodeId(NodeOrigin.DONOR, NodeKind.METHOD, "pkg", "pkg.f", "b")
    with pytest.raises(BTSError, match="matched multiple donor definitions") as duplicate:
        resolve_seed(Graph(GRAPH_SCHEMA_VERSION, (Node(first, None, "test"), Node(second, None, "test")), (), ()), selector)
    assert duplicate.value.reason is BTSRejectReason.REJECT_DUPLICATE_RESULT


def test_seed_resolution_ignores_declared_external_placeholders_and_lists_candidates() -> None:
    selector = SeedSelector("pkg", "pkg.f")
    donor = NodeId(NodeOrigin.DONOR, NodeKind.FUNCTION, "pkg", "pkg.f", "pkg.py:1")
    imported = NodeId(NodeOrigin.DECLARED_EXTERNAL, NodeKind.FUNCTION, "pkg", "pkg.f", "external:pkg.f")
    graph = Graph(GRAPH_SCHEMA_VERSION, (Node(donor, None, "test"), Node(imported, None, "test")), (), ())
    assert resolve_seed(graph, selector) == donor
    with pytest.raises(BTSError) as missing:
        resolve_seed(graph, SeedSelector("pkg", "pkg.missing"))
    assert "pkg.f (donor)" in missing.value.evidence.message
    with pytest.raises(BTSError) as external_only:
        resolve_seed(Graph(GRAPH_SCHEMA_VERSION, (Node(imported, None, "test"),), (), ()), selector)
    assert external_only.value.evidence.detail_code == "bts_cli_seed_not_found_v1"


def test_luhn_shaped_donor_definition_imported_by_its_test_resolves_once() -> None:
    donor = extract_static_edges(
        b"def checksum(value):\n    return value\n",
        slug="owner/luhn", commit_sha=SHA, path="luhn.py", blob_sha="a" * 40,
        package_root="",
    )
    test = extract_static_edges(
        b"from luhn import checksum\n\ndef test_checksum():\n    assert checksum(1) == 1\n",
        slug="owner/luhn", commit_sha=SHA, path="test.py", blob_sha="b" * 40,
        package_root="",
    )
    graph = Graph(GRAPH_SCHEMA_VERSION, (*donor.nodes, *test.nodes), (*donor.edges, *test.edges), (*donor.unresolved, *test.unresolved))
    selected = resolve_seed(graph, SeedSelector("luhn", "luhn.checksum"))
    assert selected.origin is NodeOrigin.DONOR


def test_python_provider_rejects_symlinked_source(tmp_path: Path) -> None:
    target = _shelf(tmp_path)
    snapshot = load_donor_snapshot(tmp_path, "owner", "donor", SHA)
    link = target / "package" / "linked.py"
    try:
        link.symlink_to(target / "package" / "policy.py")
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")
    with pytest.raises(BTSError) as caught:
        python_graph_provider(snapshot)(snapshot.source_root)
    assert caught.value.evidence.detail_code == "bts_cli_source_symlink_v1"


def test_polyglot_policy_is_pinned_and_wheel_less_provider_rejects_on_invoke(tmp_path: Path) -> None:
    _shelf(tmp_path, "donor-go")
    lock = Path(__file__).resolve().parents[1] / "requirements-tree-sitter.lock"
    policy = _polyglot_policy("go", lock.read_text(encoding="utf-8"))
    assert policy.policy_digest == compute_policy_digest(policy)
    if importlib.util.find_spec("tree_sitter") is not None:
        pytest.skip("wheel-less missing-extra assertion requires no tree_sitter installation")
    snapshot = load_donor_snapshot(tmp_path, "owner", "donor", SHA)
    provider = tree_sitter_graph_provider(snapshot, "go", lock_path=lock)
    with pytest.raises(BTSError) as caught:
        provider(snapshot.source_root)
    assert (caught.value.reason, caught.value.evidence.detail_code) == (BTSRejectReason.REJECT_UNSUPPORTED_EXTRA, "tree_sitter_extra_missing_v1")


@pytest.mark.skipif(importlib.util.find_spec("tree_sitter") is None, reason="requires tree-sitter extra")
def test_go_compute_is_partial_until_non_python_donor_line_accounting_is_ratified(tmp_path: Path) -> None:
    _shelf(tmp_path, "donor-go")
    lock = Path(__file__).resolve().parents[1] / "requirements-tree-sitter.lock"
    result = run_bts_compute(
        tmp_path, "owner", "donor", SHA, language="go", lock_path=lock,
        seed=SeedSelector(".", "..Normalize"),
    )
    # bts._total_donor_lines intentionally counts only .py files in ADR-0012
    # stage 1, so the Go graph cannot yet pass the max_donor_source_bps gate.
    assert result.result.status is BTSStatus.PARTIAL
    assert result.summary["detail_code"] == "bts_walk_budget_v1"


def test_artifacts_refuse_nonempty_output_directory(tmp_path: Path) -> None:
    _shelf(tmp_path)
    result = run_bts_compute(tmp_path, "owner", "donor", SHA, seed=SeedSelector("package.policy", "package.policy.normalize_contract"))
    output = tmp_path / "output"
    output.mkdir()
    (output / "old.json").write_text("old", encoding="utf-8")
    with pytest.raises(BTSError) as caught:
        write_artifacts(result, output)
    assert caught.value.evidence.detail_code == "bts_cli_output_conflict_v1"
