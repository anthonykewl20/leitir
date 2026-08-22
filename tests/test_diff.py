from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import leitir.corpus
import leitir.materialize
from leitir.apisurface import diff_api_indexes, extract_api_surface
from leitir.cli import ExitCode, main
from leitir.corpus import write_sources
from leitir.diff import (
    DiffReport,
    FileDiff,
    GitHubReleaseNotes,
    VersionIdentity,
    diff_file_trees,
    diff_packages,
)
from leitir.resolver import ResolutionError, ResolvedPackage
from leitir.search import RepoScope


def test_file_diff_added_removed_modified_and_manifest_excluded(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    (before / "removed.txt").write_bytes(b"gone")
    (before / "same.txt").write_bytes(b"same")
    (before / "changed.bin").write_bytes(b"old\x00")
    (before / "leitir-manifest.json").write_text("old", encoding="utf-8")
    (after / "added.txt").write_bytes(b"new")
    (after / "same.txt").write_bytes(b"same")
    (after / "changed.bin").write_bytes(b"new\x00")
    (after / "leitir-manifest.json").write_text("new", encoding="utf-8")

    result = diff_file_trees(before, after)

    assert result == FileDiff(
        added=("added.txt",), removed=("removed.txt",), modified=("changed.bin",)
    )
    assert diff_file_trees(before, after) == result


def test_api_diff_added_removed_and_changed_signature(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    (before / "api.py").write_text(
        "def changed(value: int):\n    pass\n\ndef removed():\n    pass\n",
        encoding="utf-8",
    )
    (after / "api.py").write_text(
        "def changed(value: str):\n    pass\n\ndef added(flag=False):\n    pass\n",
        encoding="utf-8",
    )

    result = diff_api_indexes(
        extract_api_surface(before, "python"), extract_api_surface(after, "python")
    )

    assert [item["qualified_name"] for item in result.added] == ["api.added"]
    assert [item["qualified_name"] for item in result.removed] == ["api.removed"]
    assert [item.qualified_name for item in result.changed] == ["api.changed"]
    assert result.changed[0].before == "(value: int)"
    assert result.changed[0].after == "(value: str)"


def test_api_diff_is_conservative_for_missing_or_ambiguous_signatures():
    base = {
        "symbols": [
            {"qualified_name": "a", "signature": None},
            {"qualified_name": "duplicate", "signature": "(a)"},
            {"qualified_name": "duplicate", "signature": "(b)"},
        ]
    }
    changed = {
        "symbols": [
            {"qualified_name": "a", "signature": "()"},
            {"qualified_name": "duplicate", "signature": "(c)"},
        ]
    }
    assert diff_api_indexes(base, changed).changed == ()


def test_cli_json_shape_and_empty_diff_exits_zero(tmp_path, monkeypatch):
    import leitir.diff

    identity = VersionIdentity("npm:demo@1", "demo", "1", "acme/demo", "a" * 40)
    report = DiffReport(
        before=identity,
        after=identity,
        files=FileDiff((), (), ()),
        api=diff_api_indexes({"symbols": []}, {"symbols": []}),
    )
    monkeypatch.setattr(leitir.diff, "diff_packages", lambda *args, **kwargs: report)
    stdout = io.StringIO()
    stderr = io.StringIO()

    code = main(
        ["diff", "npm:demo@1", "npm:demo@1", "--json", "--root", str(tmp_path)],
        resolver_factory=lambda _token: object(),
        code_search_factory=lambda _token: object(),
        stdout=stdout,
        stderr=stderr,
    )

    assert code == ExitCode.SUCCESS
    assert json.loads(stdout.getvalue()) == {
        "schema_version": 1,
        "before": identity.as_dict(),
        "after": identity.as_dict(),
        "files": {"added": [], "removed": [], "modified": []},
        "api": {"added": [], "removed": [], "changed": []},
    }
    assert stderr.getvalue() == ""


def test_report_json_is_deterministic_and_omits_unavailable_notes():
    identity = VersionIdentity("pypi:x@1", "x", "1", "acme/x", "b" * 40)
    report = DiffReport(
        identity,
        identity,
        FileDiff(("b",), ("a",), ("c",)),
        diff_api_indexes({"symbols": []}, {"symbols": []}),
    )
    assert report.to_json() == report.to_json()
    assert "release_notes" not in report.as_dict()


@pytest.mark.parametrize("token", ["bad\x00token", "bad\x7ftoken"])
def test_release_notes_token_control_character_is_rejected_without_disclosure(token):
    with pytest.raises(ValueError) as error:
        GitHubReleaseNotes(token=token).fetch("acme/demo", "v1", "1")
    assert token not in str(error.value)


# --- report identity equals the materialized pin (issue #218) ---

_PIN_ONE = "1" * 40
_PIN_TWO = "3" * 40
_MOVED_ONE = "2" * 40
_MOVED_TWO = "4" * 40
_PIN_TAG_ONE = "5" * 40
_PIN_TAG_TWO = "6" * 40
_MOVED_TAG_ONE = "7" * 40
_MOVED_TAG_TWO = "8" * 40
_PIN_DEMO_ONE = "9" * 40
_PIN_DEMO_TWO = "a" * 40
_PIN_SHA_SPEC = "b" * 40


class _MovingHeads:
    """Heads transport whose ref moves after its first resolution."""

    def __init__(self, first, later):
        self._first = first
        self._later = later
        self.calls = {}

    def resolve_head_sha(self, slug, ref=None):
        count = self.calls.get(slug, 0) + 1
        self.calls[slug] = count
        return self._first[slug] if count == 1 else self._later[slug]


class _StableHeads:
    """Heads transport pinned for every call (deterministic resolution)."""

    def __init__(self, shas):
        self._shas = shas

    def resolve_head_sha(self, slug, ref=None):
        return self._shas[slug]


class _MovingTagResolver:
    """Resolver whose tag pointer moves after its first resolution."""

    def __init__(self, first, later):
        self._first = first
        self._later = later
        self.calls = {}

    def resolve_tag_to_sha(self, name, tag, host=None):
        key = (name, tag)
        count = self.calls.get(key, 0) + 1
        self.calls[key] = count
        return self._first[key] if count == 1 else self._later[key]


class _EcosystemResolver:
    """Deterministic registry resolver for ecosystem specs."""

    def resolve(self, ref):
        digit = _PIN_DEMO_ONE if ref.version == "1.0.0" else _PIN_DEMO_TWO
        return ResolvedPackage(
            ref,
            RepoScope("acme/demo", digit),
            f"v{ref.version}",
            f"https://example.invalid/demo/{ref.version}",
        )


def _shelf_tree(target):
    target.mkdir(parents=True, exist_ok=True)
    (target / "demo.py").write_text("def api():\n    pass\n", encoding="utf-8")


def _install_cli_diff_stubs(monkeypatch):
    """Recreate the issue #218 seam: CLI-side materialization records the
    true pin while load-time manifest verification returns a non-SHA stub,
    so an identity routed through ``read_valid_manifest`` cannot pass."""

    materialized = {}

    def fake_materialize_source(
        raw,
        resolved,
        *,
        root,
        name,
        tag=None,
        version_source=None,
        host="github.com",
        repository_resolver=None,
        on_fetch=None,
        **options,
    ):
        scope = getattr(resolved, "scope", resolved)
        materialized[name] = scope.commit_sha
        root_path = Path(root)
        target = root_path / "repos" / "github.com" / name / scope.commit_sha
        _shelf_tree(target)
        (target / "leitir-manifest.json").write_text(
            json.dumps(
                {"ecosystem": "pypi", "version": "1", "fetched_at": "2026-08-19T00:00:00Z"}
            ),
            encoding="utf-8",
        )
        index_path = root_path / "sources.json"
        entries = (
            json.loads(index_path.read_text(encoding="utf-8"))
            if index_path.exists()
            else []
        )
        owner, repo = name.split("/", 1)
        entries.append(
            {
                "name": name,
                "host": "github.com",
                "owner": owner,
                "repo": repo,
                "commit_sha": scope.commit_sha,
                "path": target.relative_to(root_path).as_posix(),
                "fetched_at": "2026-08-19T00:00:00Z",
            }
        )
        write_sources(root_path, entries)
        return target

    monkeypatch.setattr(leitir.corpus, "materialize_source", fake_materialize_source)
    monkeypatch.setattr(
        leitir.materialize,
        "read_valid_manifest",
        lambda *args, **kwargs: {"commit_sha": "patched"},
    )
    return materialized


def _run_cli_diff(spec_a, spec_b, tmp_path, *, resolver, heads):
    stdout, stderr = io.StringIO(), io.StringIO()
    code = main(
        [
            "diff",
            spec_a,
            spec_b,
            "--json",
            "--root",
            str(tmp_path),
        ],
        resolver_factory=lambda _token: resolver,
        code_search_factory=lambda _token: heads,
        stdout=stdout,
        stderr=stderr,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_cli_diff_reports_materialized_pin_not_moved_head(tmp_path, monkeypatch):
    """AC-1 / G-0 pytest form: a head that moves between the CLI-side
    resolution and ``_prepare``'s re-resolution must never leak the moved
    SHA into the report identity."""
    materialized = _install_cli_diff_stubs(monkeypatch)
    heads = _MovingHeads(
        {"acme/one": _PIN_ONE, "acme/two": _PIN_TWO},
        {"acme/one": _MOVED_ONE, "acme/two": _MOVED_TWO},
    )

    code, out, _err = _run_cli_diff(
        "acme/one", "acme/two", tmp_path, resolver=object(), heads=heads
    )

    assert code == ExitCode.SUCCESS
    assert materialized == {"acme/one": _PIN_ONE, "acme/two": _PIN_TWO}
    report = json.loads(out)
    assert report["before"]["commit_sha"] == _PIN_ONE
    assert report["after"]["commit_sha"] == _PIN_TWO
    assert _MOVED_ONE not in out
    assert _MOVED_TWO not in out


def test_cli_diff_reports_first_tag_pin_when_tag_moves_mid_run(tmp_path, monkeypatch):
    """AC-2: a force-moved tag re-resolves to a different SHA inside
    ``_prepare``; the report keeps the first (materialized) tag pin."""
    _install_cli_diff_stubs(monkeypatch)
    resolver = _MovingTagResolver(
        {("acme/one", "v1"): _PIN_TAG_ONE, ("acme/two", "v1"): _PIN_TAG_TWO},
        {("acme/one", "v1"): _MOVED_TAG_ONE, ("acme/two", "v1"): _MOVED_TAG_TWO},
    )

    code, out, _err = _run_cli_diff(
        "acme/one@v1", "acme/two@v1", tmp_path, resolver=resolver, heads=object()
    )

    assert code == ExitCode.SUCCESS
    report = json.loads(out)
    assert report["before"]["commit_sha"] == _PIN_TAG_ONE
    assert report["after"]["commit_sha"] == _PIN_TAG_TWO
    assert _MOVED_TAG_ONE not in out
    assert _MOVED_TAG_TWO not in out


def test_cli_diff_identical_specs_report_one_shelf_and_identical_identities(
    tmp_path, monkeypatch
):
    """SP-3: identical raw specs resolve to a single prepared shelf whose
    before/after identities are identical."""
    materialized = _install_cli_diff_stubs(monkeypatch)

    code, out, _err = _run_cli_diff(
        "acme/one",
        "acme/one",
        tmp_path,
        resolver=object(),
        heads=_StableHeads({"acme/one": _PIN_ONE}),
    )

    assert code == ExitCode.SUCCESS
    assert set(materialized.values()) == {_PIN_ONE}
    report = json.loads(out)
    assert report["before"] == report["after"]
    assert report["before"]["commit_sha"] == _PIN_ONE


def test_cli_diff_pinned_sha_spec_reports_pinned_identity(tmp_path, monkeypatch):
    """C-3: a pinned 40-hex spec never consults a transport and its
    identity equals the materialized pin."""
    materialized = _install_cli_diff_stubs(monkeypatch)

    class ExplodingHeads:
        def resolve_head_sha(self, slug, ref=None):
            raise AssertionError("pinned sha spec must not resolve a head")

    code, out, _err = _run_cli_diff(
        f"acme/one@{_PIN_SHA_SPEC}",
        f"acme/one@{_PIN_SHA_SPEC}",
        tmp_path,
        resolver=object(),
        heads=ExplodingHeads(),
    )

    assert code == ExitCode.SUCCESS
    assert materialized == {"acme/one": _PIN_SHA_SPEC}
    report = json.loads(out)
    assert report["before"]["commit_sha"] == _PIN_SHA_SPEC
    assert report["after"]["commit_sha"] == _PIN_SHA_SPEC


def test_diff_prepare_surfaces_heads_resolution_error(tmp_path):
    """SP-2: a heads failure during ``_prepare`` keeps its typed error."""

    class FailingHeads:
        def resolve_head_sha(self, slug, ref=None):
            raise ResolutionError("scripted heads failure")

    with pytest.raises(ResolutionError, match="scripted heads failure"):
        diff_packages(
            "acme/one",
            "acme/two",
            corpus_root=tmp_path,
            resolver=object(),
            heads=FailingHeads(),
        )


def _pin_recording_materializer(entry_pin=None, manifest_pin=None):
    """Injected materializer for the pure-library path; records the scope it
    was fed and optionally writes index/manifest pins of either shape."""

    fed = {}

    def materializer(spec, resolved, *, root, name, **options):
        scope = getattr(resolved, "scope", resolved)
        fed[name] = scope.commit_sha
        root_path = Path(root)
        target = root_path / "repos" / "github.com" / name / scope.commit_sha
        _shelf_tree(target)
        recorded = {}
        if manifest_pin is not None:
            (target / "leitir-manifest.json").write_text(
                json.dumps({"commit_sha": manifest_pin(name)}), encoding="utf-8"
            )
            recorded["manifest"] = manifest_pin(name)
        index_path = root_path / "sources.json"
        entries = (
            json.loads(index_path.read_text(encoding="utf-8"))
            if index_path.exists()
            else []
        )
        if entry_pin is not None:
            owner, repo = name.split("/", 1)
            entries.append(
                {
                    "name": name,
                    "host": "github.com",
                    "owner": owner,
                    "repo": repo,
                    "commit_sha": entry_pin(name),
                    "path": target.relative_to(root_path).as_posix(),
                    "fetched_at": "2026-08-19T00:00:00Z",
                }
            )
            recorded["entry"] = entry_pin(name)
        if entries:
            write_sources(root_path, entries)
        return target

    return materializer, fed


def test_pure_library_diff_reports_scope_fed_to_materializer(tmp_path):
    """C-4 regression guard: with the default-style materializer the shelf
    records exactly the scope that fed it, so the identity is unchanged."""
    materializer, fed = _pin_recording_materializer(
        entry_pin=lambda name: {"acme/one": _PIN_ONE, "acme/two": _PIN_TWO}[name]
    )
    heads = _StableHeads({"acme/one": _PIN_ONE, "acme/two": _PIN_TWO})

    report = diff_packages(
        "acme/one",
        "acme/two",
        corpus_root=tmp_path,
        resolver=object(),
        heads=heads,
        materializer=materializer,
    )

    assert fed == {"acme/one": _PIN_ONE, "acme/two": _PIN_TWO}
    assert report.before.commit_sha == _PIN_ONE
    assert report.after.commit_sha == _PIN_TWO


@pytest.mark.parametrize(
    "bad_pin",
    ["not-a-sha", "0" * 41, ("a" * 40).upper()],
)
def test_diff_falls_back_to_feeding_scope_when_no_usable_pin(tmp_path, bad_pin):
    """SP-1: a shelf without a usable pin falls back to the scope that fed
    the materializer in the same ``_prepare`` call; a malformed recorded
    value is never normalized, reported, or guessed into a pin."""

    def bad(name):
        return bad_pin

    materializer, fed = _pin_recording_materializer(entry_pin=bad, manifest_pin=bad)
    heads = _StableHeads({"acme/one": _PIN_ONE, "acme/two": _PIN_TWO})

    report = diff_packages(
        "acme/one",
        "acme/two",
        corpus_root=tmp_path,
        resolver=object(),
        heads=heads,
        materializer=materializer,
    )

    assert fed == {"acme/one": _PIN_ONE, "acme/two": _PIN_TWO}
    assert report.before.commit_sha == _PIN_ONE
    assert report.after.commit_sha == _PIN_TWO


@pytest.mark.parametrize("bad_pin", ["", "not-a-sha", "0" * 41])
def test_diff_ignores_malformed_manifest_pin_without_index(tmp_path, bad_pin):
    """SP-1 manifest arm: a malformed manifest pin with no corpus index
    still reports the scope that fed the materializer."""

    def bad(name):
        return bad_pin

    materializer, fed = _pin_recording_materializer(manifest_pin=bad)
    heads = _StableHeads({"acme/one": _PIN_ONE, "acme/two": _PIN_TWO})

    report = diff_packages(
        "acme/one",
        "acme/two",
        corpus_root=tmp_path,
        resolver=object(),
        heads=heads,
        materializer=materializer,
    )

    assert fed == {"acme/one": _PIN_ONE, "acme/two": _PIN_TWO}
    assert report.before.commit_sha == _PIN_ONE
    assert report.after.commit_sha == _PIN_TWO


def test_diff_bare_shelf_without_manifest_or_index_reports_feeding_scope(tmp_path):
    """SP-1 embedding arm: no manifest and no corpus index at all."""

    def materializer(spec, resolved, *, root, name, **options):
        scope = getattr(resolved, "scope", resolved)
        target = Path(root) / "repos" / "github.com" / name / scope.commit_sha
        _shelf_tree(target)
        return target

    report = diff_packages(
        "acme/one",
        "acme/two",
        corpus_root=tmp_path,
        resolver=object(),
        heads=_StableHeads({"acme/one": _PIN_ONE, "acme/two": _PIN_TWO}),
        materializer=materializer,
    )

    assert report.before.commit_sha == _PIN_ONE
    assert report.after.commit_sha == _PIN_TWO


def test_ecosystem_diff_identity_equals_registry_pin(tmp_path):
    """C-3: ecosystem specs keep reporting the deterministic registry pin."""

    def materializer(spec, resolved, *, root, name, **options):
        scope = resolved.scope
        target = Path(root) / "repos" / "github.com" / name / scope.commit_sha
        _shelf_tree(target)
        return target

    report = diff_packages(
        "pypi:demo@1.0.0",
        "pypi:demo@2.0.0",
        corpus_root=tmp_path,
        resolver=_EcosystemResolver(),
        heads=object(),
        materializer=materializer,
    )

    assert report.before.commit_sha == _PIN_DEMO_ONE
    assert report.after.commit_sha == _PIN_DEMO_TWO
    assert report.before.repository == report.after.repository == "acme/demo"
