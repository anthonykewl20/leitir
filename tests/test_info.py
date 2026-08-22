from __future__ import annotations

import io
import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from leitir.corpus import write_sources
from leitir.info import (
    TOP_SYMBOLS_LIMIT,
    _top_symbols,
    _valid_api,
    _valid_examples,
    build_info,
    source_routing,
)
from leitir.materialize import MANIFEST_NAME
from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields

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
    digest, scope = compute_materialized_tree_hash(target)
    manifest.update(manifest_digest_fields(digest, scope=scope))
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
        "schema_version", "spec", "provenance", "parity", "license", "routing",
        "api", "examples", "trust", "paths",
    ]
    assert first["schema_version"] == 1
    assert first["provenance"]["commit_sha"] == SHA
    assert first["license"] == {
        "identifier": "MIT", "method": "license-file", "confidence": "high"
    }
    assert first["routing"] == {"verdict": "transplant-ok", "reason": "permissive:MIT"}
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
    assert Path(first["paths"]["api_index"]).parts[-6:] == (
        "api", "github.com", "acme", "context", "1.2.3", "index.json"
    )
    assert Path(first["paths"]["examples_index"]).parts[-6:] == (
        "examples", "github.com", "acme", "context", "1.2.3", "index.json"
    )


def test_build_info_renders_missing_analysis_honestly(tmp_path):
    _source(tmp_path, with_content=False)

    document = build_info(SPEC, corpus_root=tmp_path)

    assert document["license"] == {
        "identifier": None, "method": "unknown", "confidence": "low"
    }
    assert document["routing"] == {"verdict": "study-only", "reason": "license-undetermined"}
    assert document["api"]["symbols"] == 0
    assert document["api"]["method"] is None
    assert document["api"]["top_symbols"] == []
    assert document["examples"]["count"] == 0
    assert document["examples"]["top"] == []


def test_source_routing_warns_on_normal_and_error_inconclusive_paths(
    tmp_path, monkeypatch, caplog
):
    caplog.set_level(logging.WARNING, logger="leitir.info")

    normal = source_routing(tmp_path / "missing", None)

    assert normal == {"verdict": "study-only", "reason": "license-undetermined"}
    assert "license routing inconclusive" in caplog.text

    caplog.clear()

    def fail(_target):
        raise RuntimeError("scripted routing failure")

    monkeypatch.setattr("leitir.info._routing_signal_bytes", fail)
    error = source_routing(tmp_path, None)

    assert error == {"verdict": "study-only", "reason": "license-undetermined"}
    assert "license routing evaluation failed" in caplog.text


def test_build_info_locks_license_and_trust_manifest_updates(tmp_path, monkeypatch):
    import leitir.info as info

    target = _source(tmp_path)
    calls: list[tuple[object, object, object]] = []

    @contextmanager
    def tracking_lock(root, locked_target, commit_sha):
        calls.append((root, locked_target, commit_sha))
        yield

    monkeypatch.setattr(info, "_target_lock", tracking_lock)

    build_info(SPEC, corpus_root=tmp_path)

    assert calls == [(tmp_path, target, SHA)]


# Live corpus-maintainer journey (issue #190 G-3/G-4): read-only public repos,
# no host-side mutation. tinode/chat is GPL-3.0 (canonical FSF GPLv3 header in
# the root LICENSE); psf/requests is Apache-2.0 (permissive control donor).
TINODE_V0_25_3 = "22a7c18e9cd695e9a061bf1b8c84175196ef5a15"
REQUESTS_V2_34_2 = "6e83187b8feb273ed4c6cdab5efd8d54901dfab3"


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live license-routing verification",
)
def test_live_tinode_routes_study_only(tmp_path):
    from leitir.cli import _corpus_list, _corpus_routings, _write_summary
    from leitir.materialize import materialize_github_repo
    from leitir.search import (
        Coverage,
        CoverageStatus,
        PredicateKind,
        Resolution,
        ResolutionStrategy,
        SearchReport,
        SourceMatch,
        SourceRef,
    )

    entries = []
    for owner, repo, sha in (
        ("tinode", "chat", TINODE_V0_25_3),
        ("psf", "requests", REQUESTS_V2_34_2),
    ):
        target = materialize_github_repo(
            tmp_path, f"{owner}/{repo}@{sha}", owner, repo, sha, verify=False
        )
        manifest = json.loads(
            (target / MANIFEST_NAME).read_text(encoding="utf-8")
        )
        entries.append(
            {
                "name": f"{owner}/{repo}",
                "host": "github.com",
                "owner": owner,
                "repo": repo,
                "commit_sha": sha,
                "path": target.relative_to(tmp_path).as_posix(),
                "fetched_at": manifest["fetched_at"],
            }
        )
    write_sources(tmp_path, entries)

    # Journey 1: corpus list — every surfaced source carries routing.
    out = io.StringIO()
    _corpus_list(tmp_path, as_json=False, out=out)
    rendered = out.getvalue()
    assert "routing=study-only/copyleft:GPL-3.0" in rendered
    assert "routing=transplant-ok/permissive:Apache-2.0" in rendered
    json_out = io.StringIO()
    _corpus_list(tmp_path, as_json=True, out=json_out)
    payload = json.loads(json_out.getvalue())
    assert len(payload) == 2
    assert {item["repo"]: item["routing"]["verdict"] for item in payload} == {
        "chat": "study-only",
        "requests": "transplant-ok",
    }

    # Journey 2: info — the routing key routes tinode study-only/copyleft.
    document = build_info(f"tinode/chat@{TINODE_V0_25_3}", corpus_root=tmp_path)
    assert document["routing"] == {"verdict": "study-only", "reason": "copyleft:GPL-3.0"}

    # Journey 3: search rendering — corpus-derived routing on the match.
    report = SearchReport(
        spec_digest="b" * 64,
        coverage=Coverage(
            status=CoverageStatus.INDETERMINATE_GLOBAL,
            files_eligible=1,
            files_indexed=1,
            files_excluded=0,
        ),
        matches=(
            SourceMatch(
                source=SourceRef(
                    slug="tinode/chat",
                    commit_sha=TINODE_V0_25_3,
                    path="server/db/db.go",
                    blob_sha="0" * 40,
                    start_line=1,
                    end_line=1,
                ),
                score=1.0,
                matched_kinds=(PredicateKind.EXACT_TEXT,),
            ),
        ),
        resolution=Resolution(
            strategy=ResolutionStrategy.INDEXED_COMMIT, as_of="2026-08-20T00:00:00Z"
        ),
    )
    summary = io.StringIO()
    _write_summary(report, file=summary, routings=_corpus_routings(tmp_path))
    assert "routing=study-only/copyleft:GPL-3.0" in summary.getvalue()
