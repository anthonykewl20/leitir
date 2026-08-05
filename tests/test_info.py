from __future__ import annotations

import json

from leitir.corpus import write_sources
from leitir.info import (
    TOP_SYMBOLS_LIMIT,
    _top_symbols,
    _valid_api,
    _valid_examples,
    build_info,
)
from leitir.materialize import MANIFEST_NAME


SHA = "c" * 40
SPEC = f"acme/context@{SHA}"


def _source(root, *, with_content=True):
    relative = f"repos/github.com/acme/context/{SHA}"
    target = root / relative
    target.mkdir(parents=True)
    if with_content:
        (target / "context.py").write_text(
            "def connect(value: str):\n    return value\n", encoding="utf-8"
        )
        (target / "README.md").write_text(
            "```python\nconnect('ok')\n```\n", encoding="utf-8"
        )
        (target / "LICENSE-MIT").write_text(
            "SPDX-License-Identifier: MIT\n", encoding="utf-8"
        )
    manifest = {
        "host": "github.com",
        "owner": "acme",
        "repo": "context",
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "spec": SPEC,
        "repo_url": "https://github.com/acme/context",
        "fetched_at": "2026-08-04T00:00:00Z",
        "verified": False,
        "verified_at": None,
        "source": "git-commit",
        "version": "1.2.3",
        "version_source": "explicit",
        "parity": "unknown",
        "files_compared": 0,
        "only_in_git": 0,
        "only_in_artifact": 0,
        "docs_urls": [],
        "entry_points": ["README.md"] if with_content else [],
    }
    (target / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    write_sources(
        root,
        [{
            "name": "acme/context",
            "host": "github.com",
            "owner": "acme",
            "repo": "context",
            "commit_sha": SHA,
            "path": relative,
            "fetched_at": manifest["fetched_at"],
        }],
    )
    return target


def test_top_symbols_are_priority_sorted_and_bounded():
    symbols = [
        {
            "kind": "function",
            "name": f"function_{index:02d}",
            "qualified_name": f"module.function_{index:02d}",
            "path": "module.py",
            "line": index + 1,
            "signature": "()",
            "docstring": None,
        }
        for index in range(TOP_SYMBOLS_LIMIT + 1)
    ]
    symbols.extend([
        {
            "kind": "unknown",
            "name": "unknown",
            "qualified_name": "module.unknown",
            "path": "module.py",
            "line": 1,
            "signature": None,
            "docstring": None,
        },
        {
            "kind": "class",
            "name": "Public",
            "qualified_name": "module.Public",
            "path": "module.py",
            "line": 100,
            "signature": None,
            "docstring": "Public class.",
        },
    ])

    projected = _top_symbols({"symbols": list(reversed(symbols))})

    assert len(projected) == TOP_SYMBOLS_LIMIT
    assert projected[0]["qualified_name"] == "module.Public"
    assert projected[1]["qualified_name"] == "module.function_00"
    assert all(item["kind"] != "unknown" for item in projected)


def test_top_symbols_order_is_total_under_tied_keys():
    tied = [
        {
            "kind": "unknown",
            "name": "b",
            "qualified_name": "module.same",
            "path": "module.py",
            "line": None,
            "signature": None,
            "docstring": None,
        },
        {
            "kind": "unknown",
            "name": "a",
            "qualified_name": "module.same",
            "path": "module.py",
            "line": 0,
            "signature": None,
            "docstring": None,
        },
        {
            "kind": [],
            "name": "c",
            "qualified_name": "module.same",
            "path": "module.py",
            "line": [],
            "signature": None,
            "docstring": None,
        },
    ]

    forward = _top_symbols({"symbols": [dict(item) for item in tied]})
    backward = _top_symbols({"symbols": [dict(item) for item in reversed(tied)]})

    assert forward == backward


def test_build_info_rebuilds_api_cache_with_unhashable_values(tmp_path):
    _source(tmp_path)
    first = build_info(SPEC, corpus_root=tmp_path)
    cache_path = first["paths"]["api_index"]
    malformed = {
        "schema_version": 1,
        "methods": [[]],
        "modules": [],
        "symbols": [{"kind": [], "qualified_name": "bad"}],
    }
    assert not _valid_api({**malformed, "symbols": []})
    assert not _valid_api({**malformed, "methods": ["ast"]})
    with open(cache_path, "w", encoding="utf-8") as cache_file:
        json.dump(malformed, cache_file)

    rebuilt = build_info(SPEC, corpus_root=tmp_path)

    assert rebuilt["api"]["symbols"] == 1
    assert rebuilt["api"]["top_symbols"][0]["qualified_name"] == "context.connect"


def test_examples_validator_rejects_unhashable_scalar_values():
    assert not _valid_examples(
        {
            "schema_version": 1,
            "symbols_source": [],
            "snippets": [{"path": [], "line": [], "language": [], "code": [], "symbols": [[]]}],
        }
    )


def test_build_info_fills_all_sections_and_is_deterministic(tmp_path):
    target = _source(tmp_path)

    first = build_info(SPEC, corpus_root=tmp_path)
    second = build_info(SPEC, corpus_root=tmp_path)

    assert first == second
    assert list(first) == [
        "schema_version", "spec", "provenance", "parity", "license", "api",
        "examples", "trust", "paths",
    ]
    assert first["schema_version"] == 1
    assert first["provenance"]["commit_sha"] == SHA
    assert first["license"] == {
        "identifier": "MIT", "method": "license-file", "confidence": "high"
    }
    assert first["api"]["symbols"] == 1
    assert first["api"]["by_kind"]["function"] == 1
    assert first["api"]["method"] == "ast"
    assert first["api"]["top_symbols"] == [{
        "kind": "function",
        "name": "connect",
        "qualified_name": "context.connect",
        "path": "context.py",
        "line": 1,
        "signature": "(value: str)",
        "docstring": None,
    }]
    assert first["examples"]["count"] == 1
    assert first["examples"]["top"] == [{
        "path": "README.md", "line": 2, "language": "python",
        "code": "connect('ok')", "symbols": ["connect"]
    }]
    assert first["examples"]["top"][0]["code"] == "connect('ok')"
    assert [item["factor"] for item in first["trust"]["breakdown"]] == sorted(
        item["factor"] for item in first["trust"]["breakdown"]
    )
    assert first["paths"]["tree"] == str(target.absolute())
    assert first["paths"]["api_index"].endswith("/api/github.com/acme/context/1.2.3/index.json")
    assert first["paths"]["examples_index"].endswith(
        "/examples/github.com/acme/context/1.2.3/index.json"
    )


def test_build_info_renders_missing_analysis_honestly(tmp_path):
    _source(tmp_path, with_content=False)

    document = build_info(SPEC, corpus_root=tmp_path)

    assert document["license"] == {
        "identifier": None, "method": "unknown", "confidence": "low"
    }
    assert document["api"]["symbols"] == 0
    assert document["api"]["method"] is None
    assert document["api"]["top_symbols"] == []
    assert document["examples"]["count"] == 0
    assert document["examples"]["top"] == []
