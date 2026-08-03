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
