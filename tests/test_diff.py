from __future__ import annotations

import io
import json

from leitir.apisurface import diff_api_indexes, extract_api_surface
from leitir.cli import ExitCode, main
from leitir.diff import DiffReport, FileDiff, VersionIdentity, diff_file_trees


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
