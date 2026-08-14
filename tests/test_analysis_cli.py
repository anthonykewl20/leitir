from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from leitir.analysis_cli import (
    DEFAULT_BLOCKING_CATALOG,
    load_blocking_catalog,
    load_graph_artifact,
    run_architecture_assessment,
    validate_lineage_manifest,
)
from leitir.bts_errors import BTSError, BTSRejectReason
from leitir.graph.model import GRAPH_SCHEMA_VERSION, EdgeKind, NodeOrigin

FIXTURES = Path(__file__).parent / "fixtures" / "analysis_cli"
GRAPH_FIXTURE = FIXTURES / "graph.json"
LINEAGE_FIXTURE = FIXTURES / "lineage.json"

# graph.json was generated with:
# PYTHONPATH=src python -c "from leitir.graph.python import extract_static_edges; source=b'import remote\\nasync def run():\\n    remote.block()\\n'; print(extract_static_edges(source, slug='owner/repo', commit_sha='a'*40, path='src/pkg/mod.py', blob_sha='b'*40, package_root='src').to_graph().to_json(), end='')"
EXPECTED_ARCHITECTURE_SUMMARY: dict[str, object] = {
    "schema_version": "leitir-analysis-cli-architecture-v1",
    "architecture_algorithm_version": "leitir-architecture-v1",
    "subject": {
        "candidate_key": ["fixture-subject"],
        "bts_digest": "sha256:b674f65fb7cf46ecd8969909566089f6ca1f8320ccc470247eff6cd8c988970b",
        "candidate_manifest_digest": "sha256:980e7b40c31399f68ca68582da3fcc157c9fb9129c49badab50ec70aa1e6b204",
        "graph_digest": "sha256:b4f6df2108221d20a8af1c7735cd4c1dc4def96635f90ad7c23cd5edbabd0197",
    },
    "status": "unknown",
    "concurrency_model": "mixed",
    "async_paths": [
        {
            "subject": {
                "candidate_key": ["fixture-subject"],
                "bts_digest": "sha256:b674f65fb7cf46ecd8969909566089f6ca1f8320ccc470247eff6cd8c988970b",
                "candidate_manifest_digest": "sha256:980e7b40c31399f68ca68582da3fcc157c9fb9129c49badab50ec70aa1e6b204",
                "graph_digest": "sha256:b4f6df2108221d20a8af1c7735cd4c1dc4def96635f90ad7c23cd5edbabd0197",
            },
            "source": {
                "origin": "donor",
                "kind": "async_function",
                "module": "pkg.mod",
                "qualified_name": "pkg.mod.run",
                "location_key": "src/pkg/mod.py:2:pkg.mod.run",
            },
            "target": {
                "origin": "declared_external",
                "kind": "function",
                "module": "remote",
                "qualified_name": "remote.block",
                "location_key": "external:remote.block",
            },
            "calls": [
                {
                    "kind": "calls",
                    "source": {
                        "origin": "donor",
                        "kind": "async_function",
                        "module": "pkg.mod",
                        "qualified_name": "pkg.mod.run",
                        "location_key": "src/pkg/mod.py:2:pkg.mod.run",
                    },
                    "target": {
                        "origin": "declared_external",
                        "kind": "function",
                        "module": "remote",
                        "qualified_name": "remote.block",
                        "location_key": "external:remote.block",
                    },
                    "provenance": {
                        "site": {
                            "slug": "owner/repo",
                            "commit_sha": "a" * 40,
                            "path": "src/pkg/mod.py",
                            "blob_sha": "b" * 40,
                            "start_line": 3,
                            "start_col": 4,
                            "end_line": 3,
                            "end_col": 16,
                        },
                        "binding": {
                            "slug": "owner/repo",
                            "commit_sha": "a" * 40,
                            "path": "src/pkg/mod.py",
                            "blob_sha": "b" * 40,
                            "start_line": 1,
                            "start_col": 7,
                            "end_line": 1,
                            "end_col": 13,
                        },
                        "ast_kind": "Attribute",
                        "resolution_rule": "import_binding_v1",
                        "protocol_base": False,
                    },
                }
            ],
            "status": "unknown",
            "conflict_kind": "unknown_async_external_effect",
            "catalog_entry": None,
            "evidence_digest": "sha256:80b41b813fc4d23df3595515b7c98b3f3a933c98f845849e055cf8ab6fbcf06b",
        }
    ],
    "logging_observations": [],
    "error_taxonomy_observations": [],
    "config_observations": [],
    "platform_observations": [],
    "assessment_digest": "sha256:bd20cac703dde3f4711032892cb230d3293843866790062841c86972ac6b5ffa",
}


def test_load_graph_artifact_accepts_real_producer_bytes() -> None:
    graph = load_graph_artifact(GRAPH_FIXTURE)

    assert graph.schema_version == GRAPH_SCHEMA_VERSION
    assert any(edge.kind is EdgeKind.CALLS for edge in graph.edges)


@pytest.mark.parametrize(
    "contents",
    [b'{"schema_version":', b'{"schema_version":"not-a-graph","nodes":[],"edges":[],"unresolved":[],"coverage":{"files":[],"parsed_files":[],"blockers":[]}}'],
)
def test_load_graph_artifact_rejects_malformed_and_wrong_schema(tmp_path: Path, contents: bytes) -> None:
    artifact = tmp_path / "graph.json"
    artifact.write_bytes(contents)

    with pytest.raises(BTSError) as failure:
        load_graph_artifact(artifact)
    assert failure.value.reason is BTSRejectReason.REJECT_BUNDLE_INVALID
    assert failure.value.evidence.detail_code == "analysis_cli_graph_invalid_v1"


def test_load_graph_artifact_rejects_oversized_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = tmp_path / "large.json"
    artifact.write_bytes(b"x" * 5)
    monkeypatch.setattr("leitir.analysis_cli.MAX_ARTIFACT_BYTES", 4)

    with pytest.raises(BTSError) as failure:
        load_graph_artifact(artifact)
    assert failure.value.reason is BTSRejectReason.REJECT_BUDGET_EXCEEDED
    assert failure.value.evidence.detail_code == "analysis_cli_artifact_read_v1"


@pytest.mark.parametrize(
    "contents",
    [
        b"\n" + GRAPH_FIXTURE.read_bytes(),
        b'{"schema_version":"leitir-bts-graph-v1","schema_version":"leitir-bts-graph-v1",' + GRAPH_FIXTURE.read_bytes()[1:],
        json.dumps(
            {
                key: json.loads(GRAPH_FIXTURE.read_text())[key]
                for key in ("schema_version", "unresolved", "nodes", "edges", "coverage")
            },
            separators=(",", ":"),
        ).encode(),
    ],
)
def test_load_graph_artifact_rejects_noncanonical_or_duplicate_key_json(tmp_path: Path, contents: bytes) -> None:
    artifact = tmp_path / "graph.json"
    artifact.write_bytes(contents)

    with pytest.raises(BTSError) as failure:
        load_graph_artifact(artifact)

    assert failure.value.reason is BTSRejectReason.REJECT_BUNDLE_INVALID
    assert failure.value.evidence.detail_code == "analysis_cli_graph_invalid_v1"


def test_default_catalog_is_pinned_empty_and_yields_unknown_external_effect() -> None:
    graph = load_graph_artifact(GRAPH_FIXTURE)
    summary = run_architecture_assessment(GRAPH_FIXTURE, subject="fixture-subject")

    assert load_blocking_catalog(None) is DEFAULT_BLOCKING_CATALOG
    assert DEFAULT_BLOCKING_CATALOG.entries == ()
    assert summary["status"] == "unknown"
    assert summary["concurrency_model"] == "mixed"
    assert any(node.id.origin is NodeOrigin.DECLARED_EXTERNAL for node in graph.nodes)


def test_custom_catalog_is_used_for_a_blocking_async_call(tmp_path: Path) -> None:
    graph = load_graph_artifact(GRAPH_FIXTURE)
    target = next(edge.target for edge in graph.edges if edge.kind is EdgeKind.CALLS)
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(
        json.dumps(
            {
                "schema_version": "leitir-blocking-call-catalog-v1",
                "authority": "leitir-maintainers",
                "catalog_id": "fixture-blocking",
                "catalog_version": "1",
                "entries": [
                    {
                        "target": {
                            "origin": target.origin.value,
                            "kind": target.kind.value,
                            "module": target.module,
                            "qualified_name": target.qualified_name,
                            "location_key": target.location_key,
                        },
                        "effect_id": "blocking-io",
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    catalog = load_blocking_catalog(catalog_path)
    summary = run_architecture_assessment(GRAPH_FIXTURE, subject="fixture-subject", catalog_path=catalog_path)

    assert catalog.entries[0].target == target
    assert summary["status"] == "incompatible"
    assert summary["async_paths"][0]["catalog_entry"]["effect_id"] == "blocking-io"  # type: ignore[index]


@pytest.mark.parametrize(
    "value",
    [
        {"schema_version": "leitir-blocking-call-catalog-v1", "authority": "leitir-maintainers", "catalog_id": "x", "catalog_version": "1", "entries": [], "unknown": True},
        {"schema_version": "wrong", "authority": "leitir-maintainers", "catalog_id": "x", "catalog_version": "1", "entries": []},
    ],
)
def test_catalog_rejects_unknown_fields_and_wrong_version(tmp_path: Path, value: dict[str, object]) -> None:
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(BTSError) as failure:
        load_blocking_catalog(catalog_path)
    assert failure.value.reason is BTSRejectReason.REJECT_HARD_GATE_FAILED
    assert failure.value.evidence.detail_code == "analysis_cli_catalog_invalid_v1"


def test_architecture_assessment_summary_is_pinned_and_complete() -> None:
    # Regenerate the pinned value with the command in the graph fixture comment
    # followed by run_architecture_assessment(..., subject="fixture-subject").
    assert run_architecture_assessment(GRAPH_FIXTURE, subject="fixture-subject") == EXPECTED_ARCHITECTURE_SUMMARY


def test_architecture_summary_is_hash_seed_independent() -> None:
    script = (
        "import json; from pathlib import Path; from leitir.analysis_cli import run_architecture_assessment; "
        "print(json.dumps(run_architecture_assessment(Path('tests/fixtures/analysis_cli/graph.json'), "
        "subject='fixture-subject'), sort_keys=True, separators=(',', ':')))"
    )
    outputs = []
    for seed in ("0", "1", "42"):
        environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH="src")
        outputs.append(subprocess.check_output([sys.executable, "-c", script], cwd=Path(__file__).parents[1], env=environment))
    assert len(set(outputs)) == 1


def test_validate_lineage_manifest_returns_non_resolving_summary() -> None:
    assert validate_lineage_manifest(LINEAGE_FIXTURE) == {
        "schema_version": "leitir-analysis-cli-lineage-validation-v1",
        "lineage_schema_version": "leitir-lineage-v1",
        "member_count": 1,
        "tracked_ref": {
            "repository_id": "example/donor",
            "ref_name": "refs/heads/main",
            "observed_commit_sha": "1" * 40,
            "resolver_id": "fake-git",
            "resolver_version": "1",
        },
        "digests": {
            "bts_digest": "sha256:" + "a" * 64,
            "lineage_digest": "sha256:eaf0444ae10b7c2a94e171af5db35a77fab6389f25a4f6650a1df2f956be15cd",
            "predecessor_bundle_digests": ["sha256:" + "b" * 64],
            "member_bytes_sha256": ["sha256:aecc013c518523ca22b7e3780f87002f5cae13fabc369f2f59a1faf7058f8c76"],
        },
    }


def test_validate_lineage_manifest_rejects_tampered_bytes(tmp_path: Path) -> None:
    tampered = bytearray(LINEAGE_FIXTURE.read_bytes())
    tampered[tampered.index(b"eaf0444a")] ^= 1
    path = tmp_path / "tampered-lineage.json"
    path.write_bytes(tampered)

    with pytest.raises(BTSError) as failure:
        validate_lineage_manifest(path)
    assert failure.value.reason is BTSRejectReason.REJECT_BUNDLE_INVALID
    assert failure.value.evidence.detail_code == "analysis_cli_lineage_invalid_v1"
