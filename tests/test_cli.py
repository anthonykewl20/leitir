"""Operator-boundary tests for the leitir search CLI (ADR-001 P4)."""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from _http_server import json_body, routed_server

from leitir.bts_errors import BTSRejectReason
from leitir.cli import ExitCode, main
from leitir.search import (
    Coverage,
    CoverageStatus,
    PredicateKind,
    RepoScope,
    Resolution,
    ResolutionStrategy,
    SearchMode,
    SearchReport,
    SearchSpec,
    SourceMatch,
    SourceRef,
)

SHA = "a" * 40
BLOB = "b" * 40
_BTS_FIXTURES = Path(__file__).parent / "fixtures" / "bts_cli"
_ANALYSIS_FIXTURES = Path(__file__).parent / "fixtures" / "analysis_cli"
_EXIT_CORPUS_FIXTURES = Path(__file__).parent / "fixtures" / "exit_corpus"


def test_invalid_log_level_keeps_redaction_installed(monkeypatch):
    from argparse import Namespace

    from leitir.cli import _configure_logging_from_env
    from leitir.logging import RedactingFilter, register_secret

    stderr = io.StringIO()
    secret = "sentinel-cli-secret"
    register_secret(secret)
    monkeypatch.setenv("LEITIR_LOG_LEVEL", "not-a-level")

    _configure_logging_from_env(Namespace(debug=False), stderr)
    namespace_logger = logging.getLogger("leitir")
    namespace_logger.warning("credential=%s", secret)

    assert any(isinstance(item, RedactingFilter) for item in namespace_logger.filters)
    assert secret not in stderr.getvalue()
    assert "[REDACTED]" in stderr.getvalue()


def _report(**overrides) -> SearchReport:
    base = dict(
        spec_digest="c" * 64,
        coverage=Coverage(
            status=CoverageStatus.COMPLETE_FOR_DECLARED_UNIVERSE,
            files_eligible=1,
            files_indexed=1,
            files_excluded=0,
        ),
        matches=(
            SourceMatch(
                source=SourceRef("python/cpython", SHA, "Lib/urllib/parse.py", BLOB, 1, 5),
                score=2.0,
                matched_kinds=(PredicateKind.SYMBOL_DEFINITION,),
            ),
        ),
        resolution=Resolution(
            ResolutionStrategy.DECLARED_SCOPE, "2026-08-06T12:00:00Z"
        ),
    )
    base.update(overrides)
    return SearchReport(**base)


class FakeSearcher:
    def __init__(self, report: SearchReport | None = None, error: Exception | None = None):
        self.report = report or _report()
        self.error = error
        self.specs: list[SearchSpec] = []

    def search(self, spec: SearchSpec) -> SearchReport:
        self.specs.append(spec)
        if self.error:
            raise self.error
        return self.report


class FakeResolver:
    def __init__(self, scope: RepoScope | None = None, error: Exception | None = None):
        self.scope = scope or RepoScope("psf/requests", SHA)
        self.error = error
        self.calls: list = []

    def resolve(self, ref):
        self.calls.append(ref)
        if self.error:
            raise self.error
        from leitir.resolver import ResolvedPackage

        return ResolvedPackage(
            ref=ref,
            scope=self.scope,
            tag="v1.0",
            registry_url="https://pypi.org/project/x/1.0/",
        )


def invoke(argv, *, searcher=None, resolver=None):
    searcher = searcher or FakeSearcher()
    resolver = resolver or FakeResolver()
    out = io.StringIO()
    err = io.StringIO()
    code = main(
        argv,
        tree_source_factory=lambda _token: object(),
        resolver_factory=lambda _token: resolver,
        searcher_factory=lambda _ts: searcher,
        stdout=out,
        stderr=err,
    )
    return code, out.getvalue(), err.getvalue(), searcher, resolver


def _bts_shelf(root: Path) -> None:
    from leitir.materialize import manifest_digest_fields, target_path
    from leitir.treehash import compute_materialized_tree_hash

    target = target_path(root, "owner", "donor", SHA)
    shutil.copytree(_BTS_FIXTURES / "donor", target)
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


def test_bts_compute_cli_writes_artifacts_and_rejects_bad_seed(tmp_path: Path):
    root = tmp_path / "corpus"
    _bts_shelf(root)
    output = tmp_path / "artifacts"

    code, stdout, _stderr, _, _ = invoke(
        [
            "bts-compute",
            f"owner/donor@{SHA}",
            "--root",
            str(root),
            "--seed-module",
            "package.policy",
            "--seed-name",
            "package.policy.normalize_contract",
            "--out",
            str(output),
            "--json",
        ]
    )

    assert code == ExitCode.SUCCESS
    assert json.loads(stdout)["status"] == "COMPLETE"
    assert (output / "graph.json").is_file()
    assert (output / "summary.json").is_file()

    code, stdout, stderr, _, _ = invoke(
        [
            "bts-compute",
            f"owner/donor@{SHA}",
            "--root",
            str(root),
            "--seed-module",
            "package.policy",
            "--seed-name",
            "missing",
            "--out",
            str(tmp_path / "bad-artifacts"),
            "--json",
        ]
    )

    assert code == ExitCode.CORPUS_FAILURE
    assert stdout == ""
    error = json.loads(stderr.removeprefix("leitir: error: "))
    assert error["reason"] == "reject_unresolved_edge"
    assert error["evidence"]["detail_code"] == "bts_cli_seed_not_found_v1"


def test_bts_compute_cli_passes_policy_path_to_the_closed_schema_loader(tmp_path: Path):
    root = tmp_path / "corpus"
    _bts_shelf(root)
    policy = tmp_path / "invalid-policy.json"
    policy.write_text("{}", encoding="utf-8")

    code, stdout, stderr, _, _ = invoke(
        [
            "bts-compute",
            f"owner/donor@{SHA}",
            "--root",
            str(root),
            "--seed-module",
            "package.policy",
            "--seed-name",
            "package.policy.normalize_contract",
            "--policy",
            str(policy),
            "--out",
            str(tmp_path / "artifacts"),
            "--json",
        ]
    )

    assert code == ExitCode.CORPUS_FAILURE
    assert stdout == ""
    error = json.loads(stderr.removeprefix("leitir: error: "))
    assert error["evidence"]["detail_code"] == "bts_cli_policy_invalid_v1"


@pytest.mark.parametrize("spec", [f"own@er/donor@{SHA}", f"owner/don@or@{SHA}"])
def test_bts_compute_cli_rejects_at_sign_in_owner_or_repo(spec: str) -> None:
    code, _stdout, stderr, _, _ = invoke(
        ["bts-compute", spec, "--seed-module", "package.policy", "--seed-name", "package.policy.normalize_contract", "--out", "output"]
    )

    assert code == ExitCode.MALFORMED_USAGE
    assert stderr == ""


def test_analysis_architecture_cli_emits_pinned_json_summary():
    code, stdout, _stderr, _, _ = invoke(
        [
            "analysis-architecture",
            str(_ANALYSIS_FIXTURES / "graph.json"),
            "--subject",
            "fixture-subject",
            "--json",
        ]
    )

    assert code == ExitCode.SUCCESS
    payload = json.loads(stdout)
    assert payload["schema_version"] == "leitir-analysis-cli-architecture-v1"
    assert payload["status"] == "unknown"
    assert payload["concurrency_model"] == "mixed"
    assert payload["subject"]["provenance"] == "caller-declared-label"
    assert payload["assessment_digest"] == (
        "sha256:bd20cac703dde3f4711032892cb230d3293843866790062841c86972ac6b5ffa"
    )


@pytest.mark.parametrize("subject", ["", "has spaces", "not!slug"])
def test_analysis_architecture_cli_rejects_non_slug_subjects(subject: str) -> None:
    assert main(
        [
            "analysis-architecture",
            str(_ANALYSIS_FIXTURES / "graph.json"),
            "--subject",
            subject,
        ]
    ) == ExitCode.MALFORMED_USAGE


def test_analysis_lineage_cli_emits_validation_summary():
    code, stdout, _stderr, _, _ = invoke(
        ["analysis-lineage", str(_ANALYSIS_FIXTURES / "lineage.json"), "--json"]
    )

    assert code == ExitCode.SUCCESS
    assert json.loads(stdout)["member_count"] == 1
    assert json.loads(stdout)["lineage_schema_version"] == "leitir-lineage-v1"


def test_exit_gate_validate_cli_reports_valid_corpus_and_rejects_minimum_donors(
    tmp_path: Path,
):
    valid = _EXIT_CORPUS_FIXTURES / "corpus-valid.json"
    code, stdout, _stderr, _, _ = invoke(["exit-gate-validate", str(valid), "--json"])

    assert code == ExitCode.SUCCESS
    payload = json.loads(stdout)
    assert payload["validation"]["case_count"] == 5
    assert payload["cross_check_against_gate"]["valid"] is True

    tampered = json.loads(valid.read_text(encoding="utf-8"))
    tampered["cases"] = tampered["cases"][:4]
    target = tmp_path / "four-donors.json"
    target.write_text(
        json.dumps(tampered, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    code, stdout, stderr, _, _ = invoke(
        ["exit-gate-validate", str(target), "--json"]
    )

    assert code == ExitCode.CORPUS_FAILURE
    assert stdout == ""
    error = json.loads(stderr.removeprefix("leitir: error: "))
    assert error["evidence"]["detail_code"] == "exit_corpus_min_donors_v1"


def test_exit_gate_validate_cli_missing_file_names_path_and_os_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing-corpus.json"

    code, stdout, stderr, _, _ = invoke(["exit-gate-validate", str(missing), "--json"])

    assert code == ExitCode.CORPUS_FAILURE
    assert stdout == ""
    error = json.loads(stderr.removeprefix("leitir: error: "))
    assert error["reason"] == BTSRejectReason.REJECT_PROVENANCE_MISMATCH.value
    assert error["evidence"]["detail_code"] == "exit_corpus_read_v1"
    assert str(missing) in error["evidence"]["message"]


def test_help_lists_search_without_side_effects(capsys):
    assert main(["--help"]) == ExitCode.SUCCESS
    output = capsys.readouterr().out
    assert "search" in output


def test_search_help_lists_both_input_modes(capsys):
    code = main(["search", "--help"])
    assert code == ExitCode.SUCCESS
    output = capsys.readouterr().out
    assert "--repo" in output
    assert "--package" in output
    assert "--must" in output


def test_coverage_help_documents_coverage_semantics(capsys):
    """AC-3/G-0-ii: the help states the coverage bound mechanism, not a dead end."""

    code = main(["search", "--help"])
    assert code == ExitCode.SUCCESS
    output = capsys.readouterr().out
    assert "indeterminate" not in output
    assert "--global" in output
    assert "pages fetched" in output
    assert "matches returned" in output
    assert "incomplete flag" in output


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["search"],
        ["search", "--repo", "python/cpython"],
        ["search", "--package", "requests"],
        ["search", "--package", "requests", "--version", "2.28.1"],
        ["search", "--repo", "python/cpython", "--commit", SHA, "--must", "bad"],
        ["search", "--repo", "python/cpython", "--commit", SHA, "--must", "nope:x"],
    ],
)
def test_malformed_usage_has_distinct_exit_code(argv, capsys):
    code = main(argv)
    assert code == ExitCode.MALFORMED_USAGE


def test_explicit_scope_wires_spec_to_searcher():
    code, out, err, searcher, _ = invoke(
        [
            "search",
            "--repo", "python/cpython",
            "--commit", SHA,
            "--must", "symbol_definition:urlencode:python",
        ]
    )
    assert code == ExitCode.SUCCESS
    assert len(searcher.specs) == 1
    spec = searcher.specs[0]
    assert spec.scopes[0].slug == "python/cpython"
    assert spec.scopes[0].commit_sha == SHA
    assert spec.must[0].kind is PredicateKind.SYMBOL_DEFINITION
    assert spec.must[0].value == "urlencode"
    assert spec.must[0].language == "python"


def test_search_uses_passed_root_for_verified_local_shelf(tmp_path: Path):
    import hashlib

    from leitir.materialize import manifest_digest_fields, target_path
    from leitir.tree import GitHubTreeSource
    from leitir.treehash import compute_materialized_tree_hash

    data = b"def urlencode(query):\n    return str(query)\n"
    blob_sha = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    shelf = target_path(tmp_path, "python", "cpython", SHA)
    shelf.mkdir(parents=True)
    path = shelf / "Lib/urllib/parse.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    digest, scope = compute_materialized_tree_hash(shelf)
    manifest = {
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "fetched_at": "2026-08-14T00:00:00Z",
        "host": "github.com",
        "owner": "python",
        "repo": "cpython",
        "repo_url": "https://github.com/python/cpython",
        "source": "git-commit",
        "spec": "github:python/cpython",
        "tag": None,
        "verified": True,
        "verified_at": "2026-08-14T00:00:00Z",
    }
    manifest.update(manifest_digest_fields(digest, scope=scope))
    (shelf / "leitir-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    tree_path = f"/repos/python/cpython/git/trees/{SHA}"
    with routed_server(
        {
            tree_path: (
                200,
                {"Content-Type": "application/json"},
                json_body(
                    {
                        "sha": SHA,
                        "truncated": False,
                        "tree": [
                            {
                                "path": "Lib/urllib/parse.py",
                                "type": "blob",
                                "sha": blob_sha,
                                "size": len(data),
                            }
                        ],
                    }
                ),
            )
        }
    ) as server:
        code = main(
            [
                "search",
                "--repo",
                "python/cpython",
                "--commit",
                SHA,
                "--must",
                "identifier:urlencode",
                "--root",
                str(tmp_path),
            ],
            tree_source_factory=lambda _token: GitHubTreeSource(
                base_url=server.base_url, max_attempts=1
            ),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )

    assert code == ExitCode.SUCCESS
    assert server.state.request_paths == []


def test_package_resolution_wires_resolver_then_searcher():
    scope = RepoScope("psf/requests", SHA)
    resolver = FakeResolver(scope=scope)
    code, out, err, searcher, _ = invoke(
        [
            "search",
            "--package", "requests",
            "--version", "2.28.1",
            "--ecosystem", "pypi",
            "--must", "identifier:Session",
        ],
        resolver=resolver,
    )
    assert code == ExitCode.SUCCESS
    assert len(resolver.calls) == 1
    assert resolver.calls[0].name == "requests"
    assert resolver.calls[0].version == "2.28.1"
    spec = searcher.specs[0]
    assert spec.scopes[0].slug == "psf/requests"
    assert spec.scopes[0].commit_sha == SHA


def test_stdout_is_valid_json_report():
    code, out, err, _, _ = invoke(
        [
            "search",
            "--repo", "python/cpython",
            "--commit", SHA,
            "--must", "identifier:urlencode",
        ]
    )
    assert code == ExitCode.SUCCESS
    payload = json.loads(out)
    assert payload["spec_digest"] == "c" * 64
    assert payload["coverage"]["status"] == "complete_for_declared_universe"
    assert len(payload["matches"]) == 1
    assert payload["matches"][0]["source"]["slug"] == "python/cpython"


def test_stderr_has_human_summary():
    code, out, err, _, _ = invoke(
        [
            "search",
            "--repo", "python/cpython",
            "--commit", SHA,
            "--must", "identifier:urlencode",
        ]
    )
    assert "coverage=complete_for_declared_universe" in err
    assert "matches=1" in err
    assert "Lib/urllib/parse.py" in err


def test_should_and_must_not_predicates_threaded():
    code, _, _, searcher, _ = invoke(
        [
            "search",
            "--repo", "python/cpython",
            "--commit", SHA,
            "--must", "identifier:urlencode",
            "--should", "identifier:doseq",
            "--must-not", "identifier:deprecated",
        ]
    )
    assert code == ExitCode.SUCCESS
    spec = searcher.specs[0]
    assert len(spec.should) == 1
    assert spec.should[0].kind is PredicateKind.IDENTIFIER
    assert len(spec.must_not) == 1
    assert spec.must_not[0].value == "deprecated"


def test_whole_file_flag_changes_scoped_matching_and_digest():
    import hashlib

    from leitir.adapters import PythonAdapter
    from leitir.engine import ScopedSearcher
    from leitir.tree import BlobEntry

    data = b"def build():\n    pass\nrun()\n"
    blob_sha = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()

    class Tree:
        def list_blobs(self, slug, commit_sha):
            return (BlobEntry("x.py", blob_sha, len(data)),)

        def list_blobs_ex(self, slug, commit_sha):
            return self.list_blobs(slug, commit_sha), False

        def read_blob(self, slug, requested_blob_sha):
            return data

    argv = [
        "search", "--repo", "owner/repo", "--commit", SHA,
        "--must", "symbol_definition:build", "--must", "call:run",
    ]

    default_searcher = ScopedSearcher(Tree(), (PythonAdapter(),))
    default_code, default_out, _, _, _ = invoke(argv, searcher=default_searcher)
    whole_searcher = ScopedSearcher(Tree(), (PythonAdapter(),))
    whole_code, whole_out, _, _, _ = invoke(
        [*argv, "--whole-file"], searcher=whole_searcher
    )

    default_report = json.loads(default_out)
    whole_report = json.loads(whole_out)
    assert default_code == whole_code == ExitCode.SUCCESS
    assert default_report["matches"] == []
    assert [match["source"]["start_line"] for match in whole_report["matches"]] == [
        1, 3
    ]
    assert default_report["spec_digest"] != whole_report["spec_digest"]


def test_whole_file_flag_threads_to_global_spec():
    gs = FakeGlobalSearcher()
    code = main(
        ["search", "--global", "--whole-file", "--must", "identifier:x"],
        code_search_factory=lambda _token: object(),
        global_searcher_factory=lambda cs, ts, mr, mp: gs,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == ExitCode.SUCCESS
    assert gs.specs[0].whole_file_must is True


def test_infrastructure_error_on_searcher_failure():
    searcher = FakeSearcher(error=RuntimeError("network down"))
    code, out, err, _, _ = invoke(
        [
            "search",
            "--repo", "python/cpython",
            "--commit", SHA,
            "--must", "identifier:urlencode",
        ],
        searcher=searcher,
    )
    assert code == ExitCode.INFRASTRUCTURE_FAILURE
    assert "network down" in err
    assert out == ""


def test_infrastructure_error_on_resolver_failure():
    resolver = FakeResolver(error=RuntimeError("registry unreachable"))
    code, out, err, _, _ = invoke(
        [
            "search",
            "--package", "requests",
            "--version", "2.28.1",
            "--ecosystem", "pypi",
            "--must", "identifier:Session",
        ],
        resolver=resolver,
    )
    assert code == ExitCode.INFRASTRUCTURE_FAILURE
    assert "registry unreachable" in err


def test_invalid_commit_sha_is_infrastructure_failure():
    code, out, err, _, _ = invoke(
        [
            "search",
            "--repo", "python/cpython",
            "--commit", "tooshort",
            "--must", "identifier:urlencode",
        ]
    )
    assert code == ExitCode.INFRASTRUCTURE_FAILURE
    assert "40-char" in err or "commit_sha" in err


def test_no_matches_is_still_success():
    empty = _report(matches=())
    searcher = FakeSearcher(report=empty)
    code, out, err, _, _ = invoke(
        [
            "search",
            "--repo", "python/cpython",
            "--commit", SHA,
            "--must", "identifier:zzz_absent",
        ],
        searcher=searcher,
    )
    assert code == ExitCode.SUCCESS
    payload = json.loads(out)
    assert payload["matches"] == []
    assert "matches=0" in err


def test_predicate_kind_validation():
    code = main(
        ["search", "--repo", "o/r", "--commit", SHA, "--must", "bogus_kind:x"]
    )
    assert code == ExitCode.MALFORMED_USAGE


class FakeGlobalSearcher:
    def __init__(self, report=None, error=None):
        self.report = report or _report(
            coverage=Coverage(
                status=CoverageStatus.INDETERMINATE_GLOBAL,
                files_eligible=10,
                files_indexed=1,
                files_excluded=0,
            ),
        )
        self.error = error
        self.specs: list[SearchSpec] = []

    def search(self, spec: SearchSpec) -> SearchReport:
        self.specs.append(spec)
        if self.error:
            raise self.error
        return self.report


def test_global_flag_wires_global_searcher():
    gs = FakeGlobalSearcher()
    out = io.StringIO()
    err = io.StringIO()
    code = main(
        ["search", "--global", "--must", "identifier:urlencode:python"],
        code_search_factory=lambda _token: object(),
        global_searcher_factory=lambda cs, ts, mr, mp: gs,
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.SUCCESS
    assert len(gs.specs) == 1
    assert gs.specs[0].mode is SearchMode.GLOBAL_DISCOVERY
    assert gs.specs[0].scopes == ()
    payload = json.loads(out.getvalue())
    assert payload["coverage"]["status"] == "indeterminate_global"


def test_global_budgets_are_passed_to_factory():
    gs = FakeGlobalSearcher()
    received: list[tuple[int, int]] = []

    def factory(cs, ts, max_results, max_pages):
        received.append((max_results, max_pages))
        return gs

    code = main(
        [
            "search", "--global", "--max-results", "5", "--max-pages", "1",
            "--must", "identifier:x",
        ],
        code_search_factory=lambda _token: object(),
        global_searcher_factory=factory,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == ExitCode.SUCCESS
    assert received == [(5, 1)]


def test_global_language_is_canonicalized_in_must_predicates_and_digest():
    js = FakeGlobalSearcher()
    python = FakeGlobalSearcher()

    def run(language, searcher):
        code = main(
            [
                "search", "--global", "--language", language,
                "--must", "identifier:foo", "--must", "path:src",
            ],
            code_search_factory=lambda _token: object(),
            global_searcher_factory=lambda cs, ts, mr, mp: searcher,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert code == ExitCode.SUCCESS
        return searcher.specs[0]

    js_spec = run("JS", js)
    python_spec = run("python", python)

    assert all(predicate.language == "javascript" for predicate in js_spec.must)
    assert js_spec.digest() != python_spec.digest()


def test_global_language_aliases_produce_identical_canonical_digest():
    specs = []
    for language in ("js", "javascript", "JavaScript"):
        searcher = FakeGlobalSearcher()
        code = main(
            ["search", "--global", "--language", language, "--must", "identifier:foo"],
            code_search_factory=lambda _token: object(),
            global_searcher_factory=lambda cs, ts, mr, mp: searcher,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert code == ExitCode.SUCCESS
        specs.append(searcher.specs[0])

    assert {spec.must[0].language for spec in specs} == {"javascript"}
    assert len({spec.digest() for spec in specs}) == 1


def test_global_language_equal_to_required_predicate_remains_valid():
    searcher = FakeGlobalSearcher()

    code = main(
        [
            "search", "--global", "--language", "js",
            "--must", "identifier:foo:js",
        ],
        code_search_factory=lambda _token: object(),
        global_searcher_factory=lambda cs, ts, mr, mp: searcher,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == ExitCode.SUCCESS
    assert searcher.specs[0].must[0].language == "javascript"


@pytest.mark.parametrize(
    "argv",
    [
        ["search", "--global", "--max-results", "0", "--must", "identifier:x"],
        ["search", "--global", "--max-results", "-3", "--must", "identifier:x"],
        ["search", "--global", "--max-results", "nope", "--must", "identifier:x"],
        ["search", "--global", "--max-results", "--must", "identifier:x"],
        ["search", "--global", "--max-pages", "0", "--must", "identifier:x"],
        ["search", "--global", "--max-pages", "-3", "--must", "identifier:x"],
        ["search", "--global", "--max-pages", "nope", "--must", "identifier:x"],
        ["search", "--global", "--max-pages", "--must", "identifier:x"],
        ["search", "--global", "--max-results", "1001", "--must", "identifier:x"],
        ["search", "--global", "--max-pages", "101", "--must", "identifier:x"],
        ["search", "--global", "--language", "", "--must", "identifier:x"],
        ["search", "--global", "--language", "  ", "--must", "identifier:x"],
        [
            "search", "--max-results", "5", "--repo", "owner/repo",
            "--commit", SHA, "--must", "identifier:x",
        ],
        [
            "search", "--max-pages", "1", "--package", "requests",
            "--version", "1.0", "--ecosystem", "pypi", "--must", "identifier:x",
        ],
        [
            "search", "--global", "--language", "js",
            "--must", "identifier:x:python",
        ],
        [
            "search", "--language", "js", "--repo", "owner/repo",
            "--commit", SHA, "--must", "identifier:x",
        ],
    ],
)
def test_global_only_options_reject_malformed_usage_before_transport(argv):
    def unexpected_transport(_token):
        raise AssertionError("transport must not be constructed")

    code = main(
        argv,
        tree_source_factory=unexpected_transport,
        resolver_factory=unexpected_transport,
        code_search_factory=unexpected_transport,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == ExitCode.MALFORMED_USAGE


def test_global_budget_boundaries_are_accepted_by_cli():
    searcher = FakeGlobalSearcher()
    received = []

    def factory(cs, ts, max_results, max_pages):
        received.append((max_results, max_pages))
        return searcher

    code = main(
        [
            "search", "--global", "--max-results", "1000", "--max-pages", "100",
            "--must", "identifier:x",
        ],
        code_search_factory=lambda _token: object(),
        global_searcher_factory=factory,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == ExitCode.SUCCESS
    assert received == [(1000, 100)]


def test_global_options_are_deterministic_across_pythonhashseed_values():
    script = textwrap.dedent(
        """
        import io
        from leitir.cli import main
        from leitir.search import Coverage, CoverageStatus, Resolution, ResolutionStrategy, SearchReport

        class Searcher:
            def search(self, spec):
                return SearchReport(
                    spec_digest=spec.digest(),
                    coverage=Coverage(
                        status=CoverageStatus.INDETERMINATE_GLOBAL,
                        files_eligible=0,
                        files_indexed=0,
                        files_excluded=0,
                    ),
                    matches=(),
                    resolution=Resolution(
                        ResolutionStrategy.INDEXED_COMMIT,
                        "2026-08-06T12:00:00Z",
                    ),
                )

        out = io.StringIO()
        err = io.StringIO()
        code = main(
            ["search", "--global", "--language", "js", "--max-results", "3", "--max-pages", "1", "--must", "identifier:foo"],
            tree_source_factory=lambda token: object(),
            code_search_factory=lambda token: object(),
            global_searcher_factory=lambda cs, ts, mr, mp: Searcher(),
            stdout=out,
            stderr=err,
        )
        print(code)
        print(out.getvalue(), end="")
        print(err.getvalue(), end="")
        """
    )
    results = []
    for seed in ("0", "1", "42"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        env["LEITIR_NO_UPDATE_CHECK"] = "1"
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).parents[1],
            env=env,
            capture_output=True,
            check=False,
        )
        results.append((completed.returncode, completed.stdout, completed.stderr))

    assert results[0] == results[1] == results[2]
    assert results[0][0] == 0


def test_global_and_repo_mutually_exclusive():
    code = main([
        "search", "--global", "--repo", "o/r", "--commit", SHA,
        "--must", "identifier:x",
    ])
    assert code == ExitCode.MALFORMED_USAGE


def test_global_and_package_mutually_exclusive():
    code = main([
        "search", "--global", "--package", "requests",
        "--version", "1.0", "--ecosystem", "pypi",
        "--must", "identifier:x",
    ])
    assert code == ExitCode.MALFORMED_USAGE


def test_no_scope_flag_is_malformed():
    code = main(
        ["search", "--must", "identifier:x"],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert code == ExitCode.MALFORMED_USAGE


def test_global_searcher_error_is_infrastructure_failure():
    gs = FakeGlobalSearcher(error=RuntimeError("api down"))
    out = io.StringIO()
    err = io.StringIO()
    code = main(
        ["search", "--global", "--must", "identifier:x"],
        code_search_factory=lambda _token: object(),
        global_searcher_factory=lambda cs, ts, mr, mp: gs,
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.INFRASTRUCTURE_FAILURE
    assert "api down" in err.getvalue()


class TestDiscoveryPinsLatestStableTag:
    """CLI donor discovery pins immutable tags by default (issue #189)."""

    PINNED = "c" * 39 + "1"        # peeled commit of the annotated v2.3.0 tag
    TAG_OBJECT = "d" * 39 + "2"    # annotated tag object (never a commit pin)
    HEAD = "e" * 39 + "3"
    BRANCH = "5" * 39 + "a"
    LEGACY = "6" * 39 + "b"
    FIXED_CLOCK = "2026-08-19T00:00:00+00:00"

    @staticmethod
    def _tarball(commit_sha: str) -> bytes:
        import io as _io
        import tarfile

        data = _io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            member = tarfile.TarInfo(f"donor-{commit_sha}/proof.txt")
            content = b"proof\n"
            member.size = len(content)
            archive.addfile(member, _io.BytesIO(content))
        return data.getvalue()

    @classmethod
    def _routes(
        cls, *, tags: list[dict[str, object]]
    ) -> dict[str, tuple[int, dict[str, str], bytes]]:
        return {
            "/repos/acme/donor/tags": (
                200,
                {"Content-Type": "application/json"},
                json_body(tags),
            ),
            "/repos/acme/donor/git/ref/tags/v2.3.0": (
                200,
                {"Content-Type": "application/json"},
                json_body(
                    {
                        "ref": "refs/tags/v2.3.0",
                        "object": {"type": "tag", "sha": cls.TAG_OBJECT},
                    }
                ),
            ),
            f"/repos/acme/donor/git/tags/{cls.TAG_OBJECT}": (
                200,
                {"Content-Type": "application/json"},
                json_body(
                    {"tag": "v2.3.0", "object": {"type": "commit", "sha": cls.PINNED}}
                ),
            ),
            "/repos/acme/donor/commits": (
                200,
                {"Content-Type": "application/json"},
                json_body([{"sha": cls.HEAD}]),
            ),
        }

    @classmethod
    def _stable_tag_routes(cls) -> dict[str, tuple[int, dict[str, str], bytes]]:
        routes = cls._routes(
            tags=[
                {"name": "v1.0.0", "commit": {"sha": "f" * 40}},
                {"name": "v2.2.0", "commit": {"sha": "0" * 40}},
                {"name": "v2.3.0", "commit": {"sha": cls.PINNED}},
                {"name": "v2.4.0-rc.1", "commit": {"sha": "1" * 40}},
            ]
        )
        routes[f"/acme/donor/tar.gz/{cls.PINNED}"] = (
            200,
            {"Content-Type": "application/gzip"},
            cls._tarball(cls.PINNED),
        )
        return routes

    def _invoke(self, routes, argv, *, heads_factory=None, monkeypatch):
        from leitir.discovery_search import GitHubCodeSearchTransport

        out, err = io.StringIO(), io.StringIO()
        with routed_server(routes) as server:
            monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)
            if heads_factory is None:

                def heads_factory(token: str | None) -> object:
                    return GitHubCodeSearchTransport(
                        base_url=server.base_url,
                        raw_base_url=server.base_url,
                        clock=lambda: self.FIXED_CLOCK,
                    )

            code = main(
                argv,
                resolver_factory=lambda _token: object(),
                code_search_factory=heads_factory,
                stdout=out,
                stderr=err,
            )
        return code, out.getvalue(), err.getvalue()

    def test_get_without_ref_pins_latest_stable_tag(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
        code, out, err = self._invoke(
            self._stable_tag_routes(),
            ["get", "acme/donor", "--json", "--no-verify"],
            monkeypatch=monkeypatch,
        )
        assert code == ExitCode.SUCCESS, err
        payload = json.loads(out)
        assert payload["results"][0]["commit_sha"] == self.PINNED
        assert (
            f"pin acme/donor -> tag v2.3.0 commit {self.PINNED} "
            f"(immutable; resolved {self.FIXED_CLOCK})"
        ) in err
        assert self.TAG_OBJECT not in err and self.TAG_OBJECT not in out

        manifest = json.loads(
            (Path(payload["results"][0]["path"]) / "leitir-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        assert manifest["commit_sha"] == self.PINNED
        assert manifest["tag"] == "v2.3.0"

    def test_get_tagless_repo_announces_non_immutable_head(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
        routes = self._routes(tags=[])
        routes[f"/acme/donor/tar.gz/{self.HEAD}"] = (
            200,
            {"Content-Type": "application/gzip"},
            self._tarball(self.HEAD),
        )
        code, out, err = self._invoke(
            routes,
            ["get", "acme/donor", "--json", "--no-verify"],
            monkeypatch=monkeypatch,
        )
        assert code == ExitCode.SUCCESS, err
        payload = json.loads(out)
        assert payload["results"][0]["commit_sha"] == self.HEAD
        assert (
            f"pin acme/donor -> HEAD commit {self.HEAD} "
            f"(non-immutable: no stable release tag found within the crawl "
            f"window (first 300 tags); resolved {self.FIXED_CLOCK})"
        ) in err

        manifest = json.loads(
            (Path(payload["results"][0]["path"]) / "leitir-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        assert manifest["commit_sha"] == self.HEAD
        assert manifest["tag"] is None

    def test_explicit_branch_is_honored_and_labeled_non_immutable(
        self, tmp_path, monkeypatch
    ):
        import re as _re

        monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
        routes = self._routes(tags=[])
        routes["/repos/acme/donor/commits"] = (
            200,
            {"Content-Type": "application/json"},
            json_body([{"sha": self.BRANCH}]),
        )
        routes[f"/acme/donor/tar.gz/{self.BRANCH}"] = (
            200,
            {"Content-Type": "application/gzip"},
            self._tarball(self.BRANCH),
        )
        code, out, err = self._invoke(
            routes,
            ["get", "acme/donor#develop", "--json", "--no-verify"],
            monkeypatch=monkeypatch,
        )
        assert code == ExitCode.SUCCESS, err
        payload = json.loads(out)
        assert payload["results"][0]["commit_sha"] == self.BRANCH
        assert _re.search(
            rf"pin acme/donor#develop -> branch develop commit {self.BRANCH} "
            rf"\(non-immutable: branch head; resolved \S+\)",
            err,
        )

    def test_legacy_heads_transport_keeps_head_resolution(self, tmp_path, monkeypatch):
        class _LegacyHeads:
            def __init__(self, sha: str) -> None:
                self._sha = sha

            def resolve_head_sha(self, slug: str, branch: str | None = None) -> str:
                assert slug == "acme/donor"
                return self._sha

        monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
        routes = self._routes(tags=[])
        routes[f"/acme/donor/tar.gz/{self.LEGACY}"] = (
            200,
            {"Content-Type": "application/gzip"},
            self._tarball(self.LEGACY),
        )
        code, out, err = self._invoke(
            routes,
            ["get", "acme/donor", "--json", "--no-verify"],
            heads_factory=lambda _token: _LegacyHeads(self.LEGACY),
            monkeypatch=monkeypatch,
        )
        assert code == ExitCode.SUCCESS, err
        payload = json.loads(out)
        assert payload["results"][0]["commit_sha"] == self.LEGACY
        assert "pin acme/donor ->" not in err
