from __future__ import annotations

import io
import json
import logging
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
from test_offline_cached_resolution import SHA_A, _DeadRegistryResolver, _invoke

from leitir.cli import ExitCode
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


def test_valid_api_accepts_a_freshly_extracted_index(tmp_path):
    from leitir.apisurface import extract_api_surface

    _source(tmp_path)
    scan_path = tmp_path / f"repos/github.com/acme/context/{SHA}"
    fresh = extract_api_surface(scan_path, None)

    assert _valid_api(fresh)


def test_valid_api_rejects_wrong_schema_version():
    good = {"schema_version": 1, "methods": [], "modules": [], "symbols": []}
    assert _valid_api(good)
    assert not _valid_api({**good, "schema_version": 2})
    assert not _valid_api({**good, "schema_version": 0})


def test_valid_examples_accepts_a_freshly_extracted_index(tmp_path):
    from leitir.apisurface import extract_api_surface
    from leitir.examples import extract_examples

    _source(tmp_path)
    scan_path = tmp_path / f"repos/github.com/acme/context/{SHA}"
    api_index = extract_api_surface(scan_path, None)
    fresh = extract_examples(scan_path, api_index)

    assert _valid_examples(fresh)


def test_valid_examples_rejects_wrong_schema_version():
    good = {"schema_version": 2, "symbols_source": "api_index", "snippets": []}
    assert _valid_examples(good)
    # schema_version 1 predates the classification-bearing v2 shape (#67):
    # a genuinely stale on-disk cache from before that change must still be
    # invalidated, not silently accepted.
    assert not _valid_examples({**good, "schema_version": 1})
    assert not _valid_examples({**good, "schema_version": 3})


def test_build_info_reuses_a_freshly_written_cache_on_second_call(tmp_path):
    """The core fix under test: with the schema-version checks corrected,
    a second build_info() call over the same source must hit the cache
    instead of unconditionally re-extracting and rewriting it."""
    _source(tmp_path)

    first = build_info(SPEC, corpus_root=tmp_path)
    api_path = Path(first["paths"]["api_index"])
    examples_path = Path(first["paths"]["examples_index"])
    api_bytes_before = api_path.read_bytes()
    examples_bytes_before = examples_path.read_bytes()
    api_mtime_before = api_path.stat().st_mtime_ns
    examples_mtime_before = examples_path.stat().st_mtime_ns

    second = build_info(SPEC, corpus_root=tmp_path)

    assert second == first
    assert api_path.read_bytes() == api_bytes_before
    assert examples_path.read_bytes() == examples_bytes_before
    assert api_path.stat().st_mtime_ns == api_mtime_before
    assert examples_path.stat().st_mtime_ns == examples_mtime_before


def test_build_info_invalidates_a_genuinely_stale_examples_cache(tmp_path):
    """A cache on disk written under the pre-v2 (#67) examples schema -- no
    classification field, schema_version 1 -- must be detected as stale and
    regenerated to the current v2 shape, not served as-is."""
    _source(tmp_path)
    first = build_info(SPEC, corpus_root=tmp_path)
    examples_cache_path = first["paths"]["examples_index"]

    stale = {"schema_version": 1, "symbols_source": "api_index", "snippets": []}
    with open(examples_cache_path, "w", encoding="utf-8") as cache_file:
        json.dump(stale, cache_file)

    rebuilt = build_info(SPEC, corpus_root=tmp_path)

    with open(examples_cache_path, encoding="utf-8") as cache_file:
        on_disk = json.load(cache_file)
    assert on_disk["schema_version"] == 2
    assert rebuilt["examples"] is not None


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
    tmp_path, monkeypatch
):
    records: list[logging.LogRecord] = []

    class RecordHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("leitir")
    handler = RecordHandler()
    logger.addHandler(handler)
    try:
        normal = source_routing(tmp_path / "missing", None)

        assert normal == {"verdict": "study-only", "reason": "license-undetermined"}
        assert any(
            "license routing inconclusive" in record.getMessage()
            for record in records
        )

        records.clear()

        def fail(_target):
            raise RuntimeError("scripted routing failure")

        monkeypatch.setattr("leitir.info._routing_signal_bytes", fail)
        error = source_routing(tmp_path, None)

        assert error == {"verdict": "study-only", "reason": "license-undetermined"}
        assert any(
            "license routing evaluation failed" in record.getMessage()
            for record in records
        )
    finally:
        logger.removeHandler(handler)


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


# --- `leitir info --brief` (issue #266 A2) ---------------------------------
#
# `--brief` must be a purely subtractive projection of the full payload: an
# agent must be able to trust that a field present in both documents never
# disagrees between them. These tests drive the public `info` CLI offline
# (issue #245's cached-shelf path), the same way test_offline_cached_
# resolution.py exercises other spec commands without a live registry.


def _shelve_with_source(tmp_path: Path) -> tuple[Path, str]:
    """A cached, verified shelf with real API symbols and a fenced example,
    reachable offline via the exact-pin cache path (issue #245).

    Mirrors ``_shelve_package`` but writes the source files *before* hashing
    the tree, since ``_shelve_package`` pins its digest over a single
    ``payload.txt`` and adding files afterward would fail load-time tree
    verification.
    """

    relative = f"repos/github.com/acme/demo/{SHA_A}"
    source = tmp_path / relative
    source.mkdir(parents=True)
    (source / "context.py").write_text(
        "def connect(value: str):\n    return value\n\n"
        "def disconnect(value: str) -> None:\n    pass\n",
        encoding="utf-8",
    )
    (source / "README.md").write_text("```python\nconnect('ok')\n```\n", encoding="utf-8")
    (source / "LICENSE-MIT").write_text("SPDX-License-Identifier: MIT\n", encoding="utf-8")
    digest, scope = compute_materialized_tree_hash(source)
    manifest: dict[str, object] = {
        "spec": "pypi:demo",
        "ecosystem": "pypi",
        "name": "demo",
        "version": "1.0.0",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA_A,
        "fetch_method": "registry-artifact",
        "source": "registry-artifact",
        "repo_url": "https://github.com/acme/demo",
        "registry_url": "https://pypi.org/project/demo/1.0.0/",
        "artifact_kind": "sdist",
        "artifact_checksum": "sha256:" + "1" * 64,
        "docs_urls": ["https://demo.example/docs"],
        "fetched_at": "2026-08-23T00:00:00Z",
        "verified": True,
        "verified_at": "2026-08-23T00:00:00Z",
        "tag": "v1.0.0",
        **manifest_digest_fields(digest, scope=scope),
    }
    (source / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    entry = {
        "name": "demo",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA_A,
        "path": relative,
        "fetched_at": "2026-08-23T00:00:00Z",
    }
    write_sources(tmp_path, [entry])
    return source, "pypi:demo@1.0.0"


def test_brief_emits_provenance_signatures_one_example_and_trust_score(tmp_path):
    _source, spec = _shelve_with_source(tmp_path)

    code, out, err = _invoke(
        ["info", spec, "--brief", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, err
    lines = out.splitlines()
    assert lines[0].startswith(f"{spec} acme/demo@{SHA_A}")
    assert any(line.strip().startswith("function context.connect") for line in lines)
    assert any(line.strip().startswith("example: README.md:") for line in lines)
    assert any(re.fullmatch(r"trust: \d{1,3}/100", line) for line in lines)
    assert lines[-1].startswith("# Per ") and lines[-1].endswith(":")


def test_brief_and_json_compose(tmp_path):
    _source, spec = _shelve_with_source(tmp_path)

    code, out, err = _invoke(
        ["info", spec, "--brief", "--json", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, err
    brief = json.loads(out)
    assert set(brief) == {
        "schema_version", "spec", "provenance", "api", "examples", "trust", "citation",
    }
    assert isinstance(brief["trust"], int)
    assert len(brief["examples"]["top"]) == 1


def test_brief_fields_are_byte_identical_projections_of_full_payload(tmp_path):
    _source, spec = _shelve_with_source(tmp_path)

    code_full, out_full, err_full = _invoke(
        ["info", spec, "--json", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )
    assert code_full == ExitCode.SUCCESS, err_full
    full = json.loads(out_full)

    code_brief, out_brief, err_brief = _invoke(
        ["info", spec, "--brief", "--json", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )
    assert code_brief == ExitCode.SUCCESS, err_brief
    brief = json.loads(out_brief)

    # The provenance anchor (spec + resolved commit) is never dropped, and is
    # byte-identical to the full payload's provenance -- never recomputed.
    assert brief["schema_version"] == full["schema_version"]
    assert brief["spec"] == full["spec"]
    assert brief["provenance"] == full["provenance"]
    assert brief["provenance"]["commit_sha"] == SHA_A

    # Top signatures: a byte-identical prefix of the full ranked list.
    assert brief["api"]["method"] == full["api"]["method"]
    kept = len(brief["api"]["top_symbols"])
    assert 0 < kept <= 5
    assert brief["api"]["top_symbols"] == full["api"]["top_symbols"][:kept]

    # One ranked example, byte-identical to the full payload's top example.
    assert brief["examples"]["top"] == full["examples"]["top"][:1]

    # Trust score as a bare number, identical to the full payload's score.
    assert brief["trust"] == full["trust"]["score"]

    # Sections purely dropped from brief, never recomputed as something else.
    for dropped in ("parity", "license", "routing", "paths"):
        assert dropped not in brief

    # `citation` is new to brief, not a reformatting of an existing field.
    assert "citation" not in full


def test_default_info_output_is_unchanged_by_the_brief_addition(tmp_path):
    _source, spec = _shelve_with_source(tmp_path)

    code, out, err = _invoke(
        ["info", spec, "--json", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )

    assert code == ExitCode.SUCCESS, err
    document = json.loads(out)
    assert set(document) == {
        "schema_version", "spec", "provenance", "parity", "license", "routing",
        "api", "examples", "trust", "paths",
    }
    assert "citation" not in document
    assert isinstance(document["trust"], dict) and "breakdown" in document["trust"]

    code_text, out_text, err_text = _invoke(
        ["info", spec, "--root", str(tmp_path)], resolver=_DeadRegistryResolver()
    )
    assert code_text == ExitCode.SUCCESS, err_text
    assert "citation" not in out_text.lower()
    for expected_prefix in (
        "tree:", "version:", "license:", "routing:", "parity:", "api:", "examples:", "trust:",
    ):
        assert any(line.startswith(expected_prefix) for line in out_text.splitlines()), out_text


def test_citation_line_matches_the_documented_owner_repo_file_at_sha_shape(tmp_path):
    _source, spec = _shelve_with_source(tmp_path)

    code, out, err = _invoke(
        ["info", spec, "--brief", "--json", "--root", str(tmp_path)],
        resolver=_DeadRegistryResolver(),
    )
    assert code == ExitCode.SUCCESS, err
    brief = json.loads(out)

    citation = brief["citation"]
    # SKILL.md documents `<owner>/<repo>/<file>@<commit-SHA>`, paste-ready as
    # a "# Per ...:" comment line (SKILL.md's own worked example).
    assert citation.startswith("# Per ")
    assert citation.endswith(":")
    body = citation[len("# Per "):-1]
    location, _, _line_anchor = body.partition("#")
    owner_repo_file, _, sha = location.rpartition("@")
    assert sha == SHA_A
    assert owner_repo_file == "acme/demo/README.md"
    assert re.fullmatch(r"L\d+(-L\d+)?", _line_anchor)


def test_brief_is_deterministic_across_hash_seeds(tmp_path):
    _source(tmp_path)
    script = (
        "import json; from pathlib import Path; from leitir.info import build_brief_info; "
        f"print(json.dumps(build_brief_info({SPEC!r}, corpus_root=Path({str(tmp_path)!r})), "
        "sort_keys=True, separators=(',', ':')))"
    )
    outputs = []
    for seed in ("0", "1", "42", "1000003"):
        environment = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH="src")
        outputs.append(
            subprocess.check_output(
                [sys.executable, "-c", script],
                cwd=Path(__file__).parents[1],
                env=environment,
            )
        )
    assert len(set(outputs)) == 1
