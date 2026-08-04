from __future__ import annotations

import json

from leitir.corpus import write_sources
from leitir.info import build_info
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
    assert first["examples"]["count"] == 1
    assert first["examples"]["top"] == [{
        "path": "README.md", "line": 2, "language": "python", "symbols": ["connect"]
    }]
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
    assert document["examples"]["count"] == 0
    assert document["examples"]["top"] == []
