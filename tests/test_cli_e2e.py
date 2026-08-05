"""Offline e2e gate for the CLI shell (ADR-001 P4).

Runs without network. Drives the full ``leitir search`` command through both
input modes using the real GitHub-verified provenance from fixtures_real and
fixtures_resolver, served by in-memory fakes. Proves the CLI wires
resolver -> engine -> report correctly and emits valid JSON + summary.
"""

from __future__ import annotations

import io
import json

from leitir.adapters import PythonAdapter, RustAdapter, GoAdapter
from leitir.cli import ExitCode, main
from leitir.engine import ScopedSearcher
from leitir.resolver import (
    CratesResolver,
    Ecosystem,
    GoResolver,
    MultiResolver,
    PackageRef,
    PyPIResolver,
    ResolutionError,
    TagAbsentError,
    ResolvedPackage,
)
from leitir.search import RepoScope
from leitir.tree import BlobEntry

import fixtures_real as fx
import fixtures_resolver as rfx

REPRESENTATIVE_CONTENT = """\
def urlencode(query, doseq=False, safe='', encoding=None, errors=None,
              quote_via=quote_plus):
    if doseq:
        for k, v in query:
            if isinstance(v, (str, bytes)):
                v = quote_via(v, safe, encoding, errors)
            else:
                v = quote_via(str(v), safe, encoding, errors)
            l.append(k + '=' + v)
    else:
        if isinstance(query, bytes):
            query = query.decode(encoding, errors)
        query = quote_via(query, safe, encoding, errors)
    return '&'.join(l)
"""


class _RealFixtureTree:
    def list_blobs(self, slug: str, commit_sha: str) -> tuple[BlobEntry, ...]:
        if slug == fx.REPO_SLUG and commit_sha == fx.COMMIT_SHA:
            return (
                BlobEntry(fx.PATH, fx.BLOB_SHA, fx.BLOB_SIZE),
                BlobEntry("README.rst", "c" * 40, 100),
            )
        return ()

    def read_blob(self, slug: str, blob_sha: str) -> bytes:
        if blob_sha == fx.BLOB_SHA:
            return REPRESENTATIVE_CONTENT.encode()
        return b"not python"


class _FakeTagResolver:
    _TABLE = {
        (rfx.PYPI_SLUG, rfx.PYPI_TAG): rfx.PYPI_COMMIT_SHA,
        (rfx.CRATES_SLUG, rfx.CRATES_TAG): rfx.CRATES_COMMIT_SHA,
        (rfx.GO_SLUG, rfx.GO_TAG): rfx.GO_COMMIT_SHA,
    }

    def resolve_tag_to_sha(self, slug: str, tag: str) -> str:
        key = (slug, tag)
        if key in self._TABLE:
            return self._TABLE[key]
        raise TagAbsentError(f"tag {tag!r} not found in {slug}")


class _FakePyPIResolver(PyPIResolver):
    def __init__(self):
        super().__init__(tag_resolver=_FakeTagResolver())

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        if ref.ecosystem is not Ecosystem.PYPI:
            raise ResolutionError("only pypi")
        if ref.name != rfx.PYPI_NAME or ref.version != rfx.PYPI_VERSION:
            raise ResolutionError(f"unknown {ref.name}=={ref.version}")
        tag, sha = self._resolve_first_tag(rfx.PYPI_SLUG, ref.version)
        return ResolvedPackage(
            ref=ref,
            scope=RepoScope(rfx.PYPI_SLUG, sha),
            tag=tag,
            registry_url=f"https://pypi.org/project/{ref.name}/{ref.version}/",
        )


class _FakeMultiResolver:
    def __init__(self):
        self._pypi = _FakePyPIResolver()

    def resolve(self, ref: PackageRef) -> ResolvedPackage:
        if ref.ecosystem is Ecosystem.PYPI:
            return self._pypi.resolve(ref)
        raise ResolutionError(f"no resolver for {ref.ecosystem}")


def _tree_factory(_token):
    return _RealFixtureTree()


def _resolver_factory(_token):
    return _FakeMultiResolver()


def _searcher_factory(tree_source):
    return ScopedSearcher(
        tree_source=tree_source,
        adapters=(PythonAdapter(), RustAdapter(), GoAdapter()),
    )


def _invoke(argv):
    out = io.StringIO()
    err = io.StringIO()
    code = main(
        argv,
        tree_source_factory=_tree_factory,
        resolver_factory=_resolver_factory,
        searcher_factory=_searcher_factory,
        stdout=out,
        stderr=err,
    )
    return code, out.getvalue(), err.getvalue()


class TestExplicitScopeMode:
    def test_finds_urlencode_with_real_provenance(self):
        code, out, err = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", fx.COMMIT_SHA,
            "--must", "symbol_definition:urlencode:python",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert len(payload["matches"]) > 0
        top = payload["matches"][0]
        assert top["source"]["slug"] == fx.REPO_SLUG
        assert top["source"]["commit_sha"] == fx.COMMIT_SHA
        assert top["source"]["path"] == fx.PATH
        assert top["source"]["blob_sha"] == fx.BLOB_SHA

    def test_permalink_in_json_output(self):
        code, out, _ = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", fx.COMMIT_SHA,
            "--must", "symbol_definition:urlencode:python",
        ])
        payload = json.loads(out)
        permalink = payload["matches"][0]["source"]["permalink"]
        assert f"/blob/{fx.COMMIT_SHA}/" in permalink
        assert fx.PATH in permalink

    def test_coverage_is_complete(self):
        code, out, _ = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", fx.COMMIT_SHA,
            "--must", "symbol_definition:urlencode:python",
        ])
        payload = json.loads(out)
        assert payload["coverage"]["status"] == "complete_for_declared_universe"
        assert payload["coverage"]["files_eligible"] == 1
        assert payload["coverage"]["files_indexed"] == 1

    def test_should_predicate_boosts_score(self):
        code, out, _ = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", fx.COMMIT_SHA,
            "--must", "symbol_definition:urlencode:python",
            "--should", "identifier:doseq:python",
        ])
        payload = json.loads(out)
        assert payload["matches"][0]["score"] >= 2.0

    def test_no_match_for_absent_symbol(self):
        code, out, err = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", fx.COMMIT_SHA,
            "--must", "identifier:zzz_absent_xyz",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert payload["matches"] == []
        assert "matches=0" in err

    def test_stderr_summary_present(self):
        code, _, err = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", fx.COMMIT_SHA,
            "--must", "symbol_definition:urlencode:python",
        ])
        assert "coverage=" in err
        assert "matches=" in err


class TestPackageResolutionMode:
    def test_pypi_package_resolves_and_searches(self):
        code, out, err = _invoke([
            "search",
            "--package", rfx.PYPI_NAME,
            "--version", rfx.PYPI_VERSION,
            "--ecosystem", "pypi",
            "--must", "symbol_definition:urlencode:python",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert payload["matches"] == []
        assert payload["coverage"]["files_eligible"] == 0

    def test_unknown_package_is_infrastructure_failure(self):
        code, out, err = _invoke([
            "search",
            "--package", "nonexistent_pkg_xyz",
            "--version", "0.0.1",
            "--ecosystem", "pypi",
            "--must", "identifier:foo",
        ])
        assert code == ExitCode.INFRASTRUCTURE_FAILURE
        assert "unknown" in err or "nonexistent" in err


class TestSadPaths:
    def test_well_formed_but_unknown_commit_yields_empty_results(self):
        code, out, err = _invoke([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", "0" * 40,
            "--must", "identifier:urlencode",
        ])
        assert code == ExitCode.SUCCESS
        payload = json.loads(out)
        assert payload["matches"] == []

    def test_malformed_predicate_rejected(self):
        code = main([
            "search",
            "--repo", fx.REPO_SLUG,
            "--commit", fx.COMMIT_SHA,
            "--must", "not_a_kind:value",
        ])
        assert code == ExitCode.MALFORMED_USAGE

    def test_missing_must_predicate_rejected(self):
        code = main(
            ["search", "--repo", fx.REPO_SLUG, "--commit", fx.COMMIT_SHA],
            tree_source_factory=_tree_factory,
            resolver_factory=_resolver_factory,
            searcher_factory=_searcher_factory,
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        assert code == ExitCode.MALFORMED_USAGE
