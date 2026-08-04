"""Offline coverage for ADR-004 M6 documentation pointers."""

from __future__ import annotations

import json

import pytest

from leitir.corpus import _upsert, remove_source
from leitir.docpointers import (
    POINTERS_NAME,
    PRIMARY_REFERENCE,
    discover_entry_points,
    extract_docs_urls,
    regenerate_pointers,
)

SHA_A = "a" * 40
SHA_B = "b" * 40


def test_pypi_priority_is_case_insensitive_and_skips_non_http_urls():
    payload = {
        "info": {
            "project_urls": {
                "HOME": "https://example.test/home",
                "dOcS": "https://example.test/docs",
                "DOCUMENTATION": "mailto:docs@example.test",
            },
            "home_page": "https://example.test/fallback",
        }
    }
    assert extract_docs_urls("pypi", payload) == ["https://example.test/docs"]


def test_pypi_home_page_is_fallback_and_non_http_is_rejected():
    assert extract_docs_urls(
        "pypi", {"info": {"project_urls": {}, "home_page": "http://example.test"}}
    ) == ["http://example.test"]
    assert extract_docs_urls("pypi", {"info": {"home_page": "ftp://example.test"}}) == []


@pytest.mark.parametrize(
    ("ecosystem", "payload", "version", "expected"),
    [
        (
            "crates",
            {"version": {"documentation": "https://docs.rs/demo", "homepage": "https://demo.test"}},
            None,
            ["https://docs.rs/demo"],
        ),
        (
            "crates",
            {"version": {"documentation": "git://bad", "homepage": "http://demo.test"}},
            None,
            ["http://demo.test"],
        ),
        (
            "npm",
            {"versions": {"1.0": {"homepage": "https://v1.test"}}, "homepage": "https://top.test"},
            "1.0",
            ["https://v1.test"],
        ),
        (
            "npm",
            {"versions": {"1.0": {"homepage": "file:///bad"}}, "homepage": "https://top.test"},
            "1.0",
            ["https://top.test"],
        ),
    ],
)
def test_registry_docs_fallbacks(ecosystem, payload, version, expected):
    assert extract_docs_urls(ecosystem, payload, version=version) == expected


def test_go_uses_conventional_versioned_pkg_go_dev_url():
    assert extract_docs_urls(
        "go", name="github.com/acme/demo", version="v1.2.3"
    ) == ["https://pkg.go.dev/github.com/acme/demo@v1.2.3"]


def test_repository_without_registry_metadata_has_no_docs_urls():
    assert extract_docs_urls("repo", {"homepage": "https://not-used.test"}) == []


def test_entry_point_discovery_matrix_and_ordering(tmp_path):
    for name in ("README", "readme.MD", "ReadMe.rSt", "README.TXT"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    for name in ("DOCS", "example", "Examples", "test", "TESTS"):
        (tmp_path / name).mkdir()
    package = tmp_path / "package"
    package.mkdir()
    (package / "README.md").write_text("nested", encoding="utf-8")
    (package / "examples").mkdir()
    deep = package / "src"
    deep.mkdir()
    (deep / "README.md").write_text("too deep", encoding="utf-8")

    assert discover_entry_points(tmp_path) == [
        "DOCS/",
        "example/",
        "Examples/",
        "package/examples/",
        "package/README.md",
        "README",
        "readme.MD",
        "ReadMe.rSt",
        "README.TXT",
        "test/",
        "TESTS/",
    ]


def test_entry_point_discovery_absent_is_empty(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "module.py").write_text("", encoding="utf-8")
    assert discover_entry_points(tmp_path) == []


def test_entry_points_include_a_declared_monorepo_subpath(tmp_path):
    package = tmp_path / "packages" / "demo"
    package.mkdir(parents=True)
    (package / "README.md").write_text("demo", encoding="utf-8")
    (package / "tests").mkdir()
    assert discover_entry_points(tmp_path, "packages/demo") == [
        "packages/demo/README.md",
        "packages/demo/tests/",
    ]


def _source(root, name, sha, *, docs_urls, entry_points, version=None):
    relative = f"repos/github.com/acme/{name}/{sha}"
    target = root / relative
    target.mkdir(parents=True)
    manifest = {
        "docs_urls": docs_urls,
        "entry_points": entry_points,
        "version": version,
    }
    (target / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return {
        "name": name,
        "host": "github.com",
        "owner": "acme",
        "repo": name,
        "commit_sha": sha,
        "path": relative,
        "fetched_at": "2026-08-03T00:00:00Z",
    }


def test_pointers_content_is_deterministic_and_sorted(tmp_path):
    zebra = _source(
        tmp_path,
        "zebra",
        SHA_B,
        docs_urls=["https://zebra.test/docs"],
        entry_points=["README.md", "examples/"],
        version="2.0",
    )
    alpha = _source(
        tmp_path, "alpha", SHA_A, docs_urls=[], entry_points=[], version=None
    )
    pointer = regenerate_pointers(tmp_path, [zebra, alpha])
    first = pointer.read_bytes()
    regenerate_pointers(tmp_path, [alpha, zebra])
    assert pointer.read_bytes() == first
    text = first.decode()
    assert text.index("## alpha") < text.index("## zebra")
    assert "- Version: `2.0`" in text
    assert f"- Commit SHA: `{SHA_B}`" in text
    assert "- Local path: `repos/github.com/acme/zebra/" in text
    assert "https://zebra.test/docs" in text
    assert "`examples/`" in text
    assert PRIMARY_REFERENCE in text


def test_pointers_links_existing_api_and_examples_indexes(tmp_path):
    alpha = _source(
        tmp_path, "alpha", SHA_A, docs_urls=[], entry_points=[], version="1.0"
    )
    api = tmp_path / "api/github.com/alpha/1.0/index.json"
    examples = tmp_path / "examples/github.com/alpha/1.0/index.json"
    api.parent.mkdir(parents=True)
    examples.parent.mkdir(parents=True)
    api.write_text("{}", encoding="utf-8")
    examples.write_text("{}", encoding="utf-8")

    text = regenerate_pointers(tmp_path, [alpha]).read_text(encoding="utf-8")

    assert "- API surface:" in text
    assert "`api/github.com/alpha/1.0/index.json`" in text
    assert "`examples/github.com/alpha/1.0/index.json`" in text
    assert text.index("Practice entry points") < text.index("API surface")


def test_pointers_omits_api_surface_when_indexes_are_absent(tmp_path):
    alpha = _source(tmp_path, "alpha", SHA_A, docs_urls=[], entry_points=[])
    text = regenerate_pointers(tmp_path, [alpha]).read_text(encoding="utf-8")
    assert "API surface" not in text


def test_pointers_backfill_only_legacy_manifests(tmp_path):
    legacy = _source(
        tmp_path, "legacy", SHA_A, docs_urls=["https://legacy.test/docs"], entry_points=[]
    )
    scanned = _source(tmp_path, "scanned", SHA_B, docs_urls=[], entry_points=[])
    legacy_target = tmp_path / legacy["path"]
    scanned_target = tmp_path / scanned["path"]
    (legacy_target / "README.md").write_text("legacy", encoding="utf-8")
    (legacy_target / "docs").mkdir()
    (scanned_target / "README.md").write_text("already scanned", encoding="utf-8")

    legacy_manifest_path = legacy_target / "leitir-manifest.json"
    legacy_manifest = json.loads(legacy_manifest_path.read_text())
    legacy_manifest.pop("entry_points")
    legacy_manifest["subpath"] = None
    legacy_manifest_path.write_text(json.dumps(legacy_manifest), encoding="utf-8")

    pointer = regenerate_pointers(tmp_path, [legacy, scanned])

    updated_legacy = json.loads(legacy_manifest_path.read_text())
    assert updated_legacy["entry_points"] == ["docs/", "README.md"]
    assert updated_legacy["docs_urls"] == ["https://legacy.test/docs"]
    assert json.loads(
        (scanned_target / "leitir-manifest.json").read_text()
    )["entry_points"] == []
    text = pointer.read_text(encoding="utf-8")
    legacy_section, scanned_section = text.split("## legacy", 1)[1].split("## scanned", 1)
    assert "Practice entry points: none found" not in legacy_section
    assert "`README.md`" in legacy_section
    assert "`docs/`" in legacy_section
    assert "Practice entry points: none found" in scanned_section


def test_pointers_regenerate_after_index_add_and_remove(tmp_path):
    alpha = _source(tmp_path, "alpha", SHA_A, docs_urls=[], entry_points=[])
    beta = _source(tmp_path, "beta", SHA_B, docs_urls=[], entry_points=[])
    _upsert(tmp_path, beta)
    _upsert(tmp_path, alpha)
    pointer = tmp_path / POINTERS_NAME
    assert "## alpha" in pointer.read_text(encoding="utf-8")
    assert "## beta" in pointer.read_text(encoding="utf-8")

    assert remove_source(tmp_path, "acme", "alpha", SHA_A)
    text = pointer.read_text(encoding="utf-8")
    assert "## alpha" not in text
    assert "## beta" in text
