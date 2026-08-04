"""Unit coverage for the M2 corpus CLI boundary."""

from __future__ import annotations

import io
import json

import pytest

from leitir.cli import ExitCode, _ensure_local_gitignore, main, parse_corpus_spec
from leitir.corpus import write_sources

SHA = "a" * 40


@pytest.mark.parametrize(
    ("raw", "ecosystem", "name", "version", "kind"),
    [
        ("owner/repo", None, "owner/repo", None, "head"),
        ("owner/repo@v1", None, "owner/repo", None, "tag"),
        (f"owner/repo@{SHA}", None, "owner/repo", None, "sha"),
        ("owner/repo#main", None, "owner/repo", None, "branch"),
        ("pypi:requests@2.0", "pypi", "requests", "2.0", None),
        ("pypi:requests", "pypi", "requests", None, None),
        ("crates:serde@1.0", "crates", "serde", "1.0", None),
        ("crates:serde", "crates", "serde", None, None),
        ("go:github.com/acme/demo@v1.0.0", "go", "github.com/acme/demo", "v1.0.0", None),
        ("go:github.com/acme/demo", "go", "github.com/acme/demo", None, None),
    ],
)
def test_parse_m2_specs(raw, ecosystem, name, version, kind):
    parsed = parse_corpus_spec(raw)
    assert (parsed.ecosystem, parsed.name, parsed.version, parsed.ref_kind) == (
        ecosystem,
        name,
        version,
        kind,
    )


@pytest.mark.parametrize("raw", ["https://github.com.attacker.example/o/r", "o/r#", "pypi:"])
def test_unknown_specs_name_supported_forms(raw):
    with pytest.raises(ValueError, match="supported forms"):
        parse_corpus_spec(raw)


def test_gitignore_append_is_idempotent_and_preserves_rules(tmp_path):
    ignore = tmp_path / ".gitignore"
    ignore.write_text("dist/\n# keep this\n", encoding="utf-8")
    assert "appended" in _ensure_local_gitignore(tmp_path)
    first = ignore.read_text(encoding="utf-8")
    assert first == "dist/\n# keep this\n.leitir-refs/\n"
    assert "already covers" in _ensure_local_gitignore(tmp_path)
    assert ignore.read_text(encoding="utf-8") == first


def test_gitignore_is_created_when_missing(tmp_path):
    assert "created" in _ensure_local_gitignore(tmp_path)
    assert (tmp_path / ".gitignore").read_text(encoding="utf-8") == ".leitir-refs/\n"


def _fabricate(root):
    relative = f"repos/github.com/acme/demo/{SHA}"
    source = root / relative
    source.mkdir(parents=True)
    (source / "leitir-manifest.json").write_text(json.dumps({"version": "1.2.3"}))
    entry = {
        "name": "demo",
        "host": "github.com",
        "owner": "acme",
        "repo": "demo",
        "commit_sha": SHA,
        "path": relative,
        "fetched_at": "2026-08-03T00:00:00Z",
    }
    write_sources(root, [entry])
    return source, entry


def _invoke(argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_list_human_and_json(tmp_path, monkeypatch):
    monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
    source, entry = _fabricate(tmp_path)
    code, out, _ = _invoke(["list"])
    assert code == ExitCode.SUCCESS
    assert "demo 1.2.3" in out
    assert f"acme/demo@{SHA}" in out
    assert str(source) in out
    assert "2026-08-03T00:00:00Z" in out
    assert "unverified" in out

    code, out, _ = _invoke(["list", "--json"])
    assert code == ExitCode.SUCCESS
    assert json.loads(out) == [dict(entry, verification="unverified")]


@pytest.mark.parametrize(
    ("verified", "label"),
    [(True, "verified"), ("sampled", "sampled"), (False, "unverified")],
)
def test_list_renders_each_verification_state(tmp_path, monkeypatch, verified, label):
    monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
    source, entry = _fabricate(tmp_path)
    (source / "leitir-manifest.json").write_text(
        json.dumps({"version": "1.2.3", "verified": verified}), encoding="utf-8"
    )

    code, out, _ = _invoke(["list"])
    assert code == ExitCode.SUCCESS
    assert label in out
    code, out, _ = _invoke(["list", "--json"])
    assert code == ExitCode.SUCCESS
    assert json.loads(out) == [dict(entry, verification=label)]


def test_remove_and_clean_fabricated_corpus(tmp_path, monkeypatch):
    monkeypatch.setenv("LEITIR_HOME", str(tmp_path))
    source, _ = _fabricate(tmp_path)
    code, out, err = _invoke(["remove", f"acme/demo@{SHA}"])
    assert code == ExitCode.SUCCESS
    assert out == ""
    assert "removed" in err
    assert not source.exists()

    _fabricate(tmp_path)
    (tmp_path / "POINTERS.md").write_text("stale", encoding="utf-8")
    code, out, err = _invoke(["clean", "--repos"])
    assert code == ExitCode.SUCCESS
    assert out == ""
    assert not (tmp_path / "repos").exists()
    assert not (tmp_path / "sources.json").exists()
    assert not (tmp_path / "POINTERS.md").exists()


def test_lock_emits_machine_json_and_progress_on_stderr(tmp_path, monkeypatch):
    import leitir.corpus

    project = tmp_path / "project"
    project.mkdir()
    corpus = tmp_path / "corpus"
    seen = {}

    def fake_lock(directory, resolver, **options):
        seen.update(directory=directory, resolver=resolver, options=options)
        options["on_resolve"]("npm:a@1.0.0")
        options["on_fetch"]("npm:a@1.0.0")
        return [{"spec": "npm:a@1.0.0", "path": "/cache/a", "graph": "complete"}]

    resolver = object()
    monkeypatch.setattr(leitir.corpus, "lock_project", fake_lock)
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["lock", "--cwd", str(project), "--root", str(corpus)],
        resolver_factory=lambda _token: resolver,
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.SUCCESS
    assert json.loads(out.getvalue()) == {
        "cwd": str(project),
        "dependencies": [{"spec": "npm:a@1.0.0", "path": "/cache/a", "graph": "complete"}],
    }
    assert "resolving npm:a@1.0.0" in err.getvalue()
    assert "materializing npm:a@1.0.0" in err.getvalue()
    assert seen["directory"] == project
    assert seen["resolver"] is resolver


def test_lock_best_effort_emits_failures_and_reports_each_one(tmp_path, monkeypatch):
    import leitir.corpus

    project = tmp_path / "project"
    project.mkdir()

    def fake_lock(directory, resolver, **options):
        options["on_failure"]("npm:z@1.0.0", "unavailable")
        options["failures"].append({"spec": "npm:z@1.0.0", "error": "unavailable"})
        return [{"spec": "npm:a@1.0.0", "path": "/cache/a", "graph": "complete"}]

    monkeypatch.setattr(leitir.corpus, "lock_project", fake_lock)
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["lock", "--best-effort", "--cwd", str(project), "--root", str(tmp_path / "corpus")],
        resolver_factory=lambda _token: object(),
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.SUCCESS
    assert json.loads(out.getvalue())["failures"] == [
        {"spec": "npm:z@1.0.0", "error": "unavailable"}
    ]
    assert "leitir: failed npm:z@1.0.0: unavailable" in err.getvalue()


def test_lock_best_effort_returns_failure_when_nothing_materialized(tmp_path, monkeypatch):
    import leitir.corpus

    project = tmp_path / "project"
    project.mkdir()

    def fake_lock(directory, resolver, **options):
        options["on_failure"]("npm:z@1.0.0", "unavailable")
        options["failures"].append({"spec": "npm:z@1.0.0", "error": "unavailable"})
        return []

    monkeypatch.setattr(leitir.corpus, "lock_project", fake_lock)
    out, err = io.StringIO(), io.StringIO()
    code = main(
        ["lock", "--best-effort", "--cwd", str(project), "--root", str(tmp_path / "corpus")],
        resolver_factory=lambda _token: object(),
        stdout=out,
        stderr=err,
    )
    assert code == ExitCode.CORPUS_FAILURE
    assert json.loads(out.getvalue())["dependencies"] == []
    assert json.loads(out.getvalue())["failures"] == [
        {"spec": "npm:z@1.0.0", "error": "unavailable"}
    ]


def test_sbom_emits_machine_json_and_progress_on_stderr(tmp_path, monkeypatch):
    import leitir.sbom

    corpus = tmp_path / "corpus"
    project = tmp_path / "project"
    project.mkdir()
    seen = {}

    def fake_generate(root, directory, format):
        seen.update(root=root, directory=directory, format=format)
        return {"bomFormat": "CycloneDX"}

    monkeypatch.setattr(leitir.sbom, "generate_sbom", fake_generate)
    code, out, err = _invoke([
        "sbom", "--format", "cyclonedx", "--cwd", str(project), "--root", str(corpus)
    ])
    assert code == ExitCode.SUCCESS
    assert json.loads(out) == {"bomFormat": "CycloneDX"}
    assert "generated cyclonedx SBOM" in err
    assert seen == {"root": corpus, "directory": project, "format": "cyclonedx"}


def test_api_materializes_extracts_and_prints_cache_path(tmp_path, monkeypatch):
    import leitir.corpus

    corpus = tmp_path / "corpus"

    def fake_materialize(spec, resolved, **options):
        source = corpus / f"repos/github.com/acme/demo/{SHA}"
        source.mkdir(parents=True)
        (source / "demo.py").write_text("def public(value: int):\n    pass\n", encoding="utf-8")
        (source / "leitir-manifest.json").write_text(
            json.dumps({"version": "1.0.0"}), encoding="utf-8"
        )
        write_sources(
            corpus,
            [{
                "name": "acme/demo", "host": "github.com", "owner": "acme",
                "repo": "demo", "commit_sha": SHA,
                "path": f"repos/github.com/acme/demo/{SHA}",
                "fetched_at": "2026-08-04T00:00:00Z",
            }],
        )
        return source

    monkeypatch.setattr(leitir.corpus, "materialize_source", fake_materialize)
    code, out, err = _invoke(["api", f"acme/demo@{SHA}", "--root", str(corpus)])

    expected = corpus / f"api/github.com/acme/demo/1.0.0/index.json"
    assert code == ExitCode.SUCCESS
    assert out.strip() == str(expected)
    assert "resolving" in err and "extracting API surface" in err
    payload = json.loads(expected.read_text(encoding="utf-8"))
    assert payload["methods"] == ["ast"]
    assert payload["symbols"][0]["qualified_name"] == "demo.public"


def test_examples_materializes_ensures_api_and_prints_cache_path(tmp_path, monkeypatch):
    import leitir.corpus

    corpus = tmp_path / "corpus"

    def fake_materialize(spec, resolved, **options):
        source = corpus / f"repos/github.com/acme/demo/{SHA}"
        (source / "examples").mkdir(parents=True)
        (source / "demo.py").write_text("def public(value: int):\n    pass\n", encoding="utf-8")
        (source / "examples" / "use.py").write_text("public(1)\n", encoding="utf-8")
        (source / "leitir-manifest.json").write_text(
            json.dumps({"version": "1.0.0", "entry_points": ["examples/"]}),
            encoding="utf-8",
        )
        write_sources(
            corpus,
            [{
                "name": "acme/demo", "host": "github.com", "owner": "acme",
                "repo": "demo", "commit_sha": SHA,
                "path": f"repos/github.com/acme/demo/{SHA}",
                "fetched_at": "2026-08-04T00:00:00Z",
            }],
        )
        return source

    monkeypatch.setattr(leitir.corpus, "materialize_source", fake_materialize)
    code, out, err = _invoke(["examples", f"acme/demo@{SHA}", "--root", str(corpus)])

    expected = corpus / "examples/github.com/acme/demo/1.0.0/index.json"
    assert code == ExitCode.SUCCESS
    assert out.strip() == str(expected)
    assert "extracting API surface" in err and "extracting examples" in err
    payload = json.loads(expected.read_text(encoding="utf-8"))
    assert payload["snippets"][0]["path"] == "examples/use.py"
    pointers = (corpus / "POINTERS.md").read_text(encoding="utf-8")
    assert "api/github.com/acme/demo/1.0.0/index.json" in pointers
    assert "examples/github.com/acme/demo/1.0.0/index.json" in pointers
