from __future__ import annotations

import json

from leitir.lockfiles import dependency_closures


def _closure(tmp_path, ecosystem):
    return next(item for item in dependency_closures(tmp_path) if item.ecosystem == ecosystem)


def test_npm_v2_v3_nested_closure_is_complete_and_deduplicated(tmp_path):
    payload = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/a": {"version": "1.0.0", "integrity": "sha512-abc"},
            "node_modules/a/node_modules/b": {"version": "2.0.0"},
            "node_modules/b": {"version": "2.0.0"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(payload))
    closure = _closure(tmp_path, "npm")
    assert closure.graph == "complete"
    assert [edge.spec for edge in closure.deps] == ["npm:a@1.0.0", "npm:b@2.0.0"]
    assert closure.deps[0].resolved_sha == "sha512-abc"
    assert closure.deps[1].resolved_sha is None


def test_npm_v2_dependencies_tree_fallback(tmp_path):
    payload = {
        "lockfileVersion": 2,
        "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}},
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(payload))
    assert [edge.name for edge in _closure(tmp_path, "npm").deps] == ["a", "b"]


def test_npm_duplicate_prefers_recorded_identity(tmp_path):
    payload = {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/x/node_modules/a": {"version": "1.0.0", "integrity": "sha512-known"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(payload))
    assert [edge.resolved_sha for edge in _closure(tmp_path, "npm").deps] == ["sha512-known"]


def test_cargo_closure_records_checksum_and_omits_project_root(tmp_path):
    (tmp_path / "Cargo.lock").write_text(
        'version = 3\n[[package]]\nname="app"\nversion="0.1.0"\ndependencies=["serde"]\n'
        '[[package]]\nname="serde"\nversion="1.0.0"\nsource="registry+x"\nchecksum="abc"\n'
    )
    closure = _closure(tmp_path, "crates")
    assert closure.graph == "complete"
    assert [edge.as_dict() for edge in closure.deps] == [{
        "name": "serde", "version": "1.0.0", "resolved_sha": "abc", "spec": "crates:serde@1.0.0"
    }]


def test_go_module_graph_and_pseudo_version_revision(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example/app\nrequire (\n github.com/a/one v1.2.3\n"
        " github.com/b/two v0.0.0-20240102030405-abcdef123456 // indirect\n)\n"
    )
    closure = _closure(tmp_path, "go")
    assert closure.graph == "complete"
    assert [edge.resolved_sha for edge in closure.deps] == [None, "abcdef123456"]


def test_go_pseudo_version_after_prior_release_records_revision(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module example/app\nrequire github.com/a/one v1.2.4-0.20240102030405-abcdef123456\n"
    )
    assert _closure(tmp_path, "go").deps[0].resolved_sha == "abcdef123456"


def test_python_sources_are_direct_only_and_deduplicated(tmp_path):
    (tmp_path / "requirements.txt").write_text("Requests==2.31.0\nrange>=1\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies=["requests==2.31.0", "Other_Pkg==1.2.0", "loose>=2"]\n'
    )
    closure = _closure(tmp_path, "pypi")
    assert closure.graph == "direct-only"
    assert [edge.spec for edge in closure.deps] == ["pypi:other-pkg@1.2.0", "pypi:requests@2.31.0"]
    assert all(edge.resolved_sha is None for edge in closure.deps)
