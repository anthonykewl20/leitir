"""Tests for the deterministic Conventional-Commit changelog generator."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "sync_changelog.py"


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sync_changelog", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


sync_changelog = _load_tool()
Commit = sync_changelog.Commit


def test_changelog_is_in_sync_with_conventional_commits() -> None:
    result = subprocess.run(
        [sys.executable, str(TOOL), "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "CHANGELOG.md is out of sync with conventional commits; run "
        "`python tools/sync_changelog.py` and commit the result\n"
        f"{result.stdout}{result.stderr}"
    )


def test_parser_maps_types_security_and_omits_non_conventional() -> None:
    commits = [
        Commit("4", "not conventional"),
        Commit("3", "perf(cache): reduce repeated work"),
        Commit("2", "fix(security): reject leaked credentials"),
        Commit("1", "feat(cli): add concise output"),
    ]
    grouped = sync_changelog.group_changes(commits)["Unreleased"]
    assert [change.subject for change in grouped["### Added"]] == ["add concise output"]
    assert [change.subject for change in grouped["### Changed"]] == ["reduce repeated work"]
    assert [change.subject for change in grouped["### Security"]] == ["reject leaked credentials"]


def test_breaking_internal_commit_is_included_but_other_internal_types_are_omitted() -> None:
    commits = [
        Commit("1", "docs: explain normal behavior"),
        Commit("2", "chore!: remove deprecated configuration"),
        Commit("3", "test(api): update fixtures", "BREAKING CHANGE: fixture contract changed"),
    ]
    grouped = sync_changelog.group_changes(commits)["Unreleased"]
    assert list(grouped) == ["### ⚠ BREAKING CHANGES"]
    assert [change.subject for change in grouped["### ⚠ BREAKING CHANGES"]] == [
        "remove deprecated configuration",
        "update fixtures",
    ]


def test_grouping_deduplicates_and_sorts_independently_of_input_order() -> None:
    commits = [
        Commit("1", "fix(zeta): Zebra issue", release="0.1.0"),
        Commit("2", "feat(beta): same subject"),
        Commit("3", "feat(alpha): Same subject"),
        Commit("4", "feat(beta): same subject"),
    ]
    forward = sync_changelog.group_changes(commits)
    reverse = sync_changelog.group_changes(reversed(commits))
    assert forward == reverse
    assert [(change.subject, change.scope) for change in forward["Unreleased"]["### Added"]] == [
        ("Same subject", "alpha"),
        ("same subject", "beta"),
    ]
    assert [change.subject for change in forward["0.1.0"]["### Fixed"]] == ["Zebra issue"]


def test_render_uses_subject_only_and_scoped_suffix() -> None:
    rendered = sync_changelog.render_managed_region(
        [Commit("1", "feat(parser): parse arrays", "Author: must not appear")],
        [],
    )
    assert "- parse arrays (`parser`)" in rendered
    assert "feat(parser)" not in rendered
    assert "Author" not in rendered


def test_collection_rejects_shallow_history(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sync_changelog, "_run_git", lambda arguments, cwd: "true\n")
    with pytest.raises(RuntimeError, match="incomplete Git history"):
        sync_changelog.collect_commits(cwd=ROOT, from_ref=None, to_ref="HEAD")
