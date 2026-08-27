"""Tests for the docs-truth CI gate (issue #266).

``tools/check_docs_truth.py`` is deliberately standalone (imports no leitir
package code), so these tests import it directly via its file path rather
than through the ``leitir`` package.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "check_docs_truth.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_docs_truth", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


docs_truth = _load_module()


def _write_cli(tmp_path: Path) -> Path:
    """A minimal cli.py fixture exercising the constant and for-loop cases."""
    cli_path = tmp_path / "cli.py"
    cli_path.write_text(
        "import argparse\n"
        "\n"
        "def build_parser():\n"
        "    parser = argparse.ArgumentParser()\n"
        "    commands = parser.add_subparsers(dest='command')\n"
        "    commands.add_parser('search', help='search')\n"
        "    commands.add_parser('doctor', help='doctor')\n"
        "    for command, help_text in (\n"
        "        ('get', 'get help'),\n"
        "        ('fetch', 'fetch help'),\n"
        "    ):\n"
        "        commands.add_parser(command, help=help_text)\n"
        "    return parser\n",
        encoding="utf-8",
    )
    return cli_path


class TestExtractRegisteredVerbs:
    def test_collects_constant_and_for_loop_verbs(self, tmp_path: Path) -> None:
        cli_path = _write_cli(tmp_path)
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        assert verbs == frozenset({"search", "doctor", "get", "fetch"})

    def test_raises_on_no_add_parser_calls(self) -> None:
        with pytest.raises(docs_truth.CliParseError):
            docs_truth.extract_registered_verbs("x = 1\n")

    def test_matches_real_cli_verb_set(self) -> None:
        """Ground truth: cli.py alone now registers no verbs directly."""
        real_cli = (REPO_ROOT / "src" / "leitir" / "cli.py").read_text(encoding="utf-8")
        # Post-#271, cli.py itself is a thin registry that calls into
        # per-verb-group modules (cli_corpus.py, cli_bts.py, cli_ask.py,
        # cli_search.py, cli_diagnostics.py) rather than calling
        # add_parser() directly, so extract_registered_verbs() on cli.py
        # alone now finds nothing (and raises, per its own no-verbs-found
        # contract) -- see test_matches_real_cli_verb_set_across_cli_modules
        # below for the tree-wide ground truth this test used to assert
        # directly.
        with pytest.raises(docs_truth.CliParseError):
            docs_truth.extract_registered_verbs(real_cli)

    def test_matches_real_cli_verb_set_across_cli_modules(self) -> None:
        """Ground truth: the real cli*.py modules must parse and yield known
        verbs, unioned across every verb-group module (issue #271)."""
        verbs = docs_truth.extract_registered_verbs_from_cli_modules(
            REPO_ROOT / "src" / "leitir"
        )
        for expected in ("search", "doctor", "get", "fetch", "bench", "usage"):
            assert expected in verbs
        # The historically-removed command must not resurface.
        assert "eval" not in verbs


class TestCheckDeadCommands:
    def _make_tree(self, tmp_path: Path, doc_body: str) -> tuple[Path, Path, Path]:
        cli_path = _write_cli(tmp_path)
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        readme = tmp_path / "README.md"
        readme.write_text(doc_body, encoding="utf-8")
        return cli_path, readme, docs_dir

    def test_detects_fake_verb_in_fenced_block(self, tmp_path: Path) -> None:
        cli_path, readme, docs_dir = self._make_tree(
            tmp_path,
            "# Quick start\n\n```bash\nleitir launch --foo\n```\n",
        )
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        findings = docs_truth.check_dead_commands([readme], docs_dir, verbs)
        assert len(findings) == 1
        assert findings[0].path == readme
        assert findings[0].line == 4
        assert "leitir launch" in findings[0].message

    def test_detects_fake_verb_in_inline_code(self, tmp_path: Path) -> None:
        cli_path, readme, docs_dir = self._make_tree(
            tmp_path,
            "Run `leitir launch` to start.\n",
        )
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        findings = docs_truth.check_dead_commands([readme], docs_dir, verbs)
        assert len(findings) == 1
        assert findings[0].line == 1

    def test_real_verbs_pass_clean(self, tmp_path: Path) -> None:
        cli_path, readme, docs_dir = self._make_tree(
            tmp_path,
            "Run `leitir search` or:\n\n```bash\nleitir get npm:zod@3.22.0\nleitir fetch npm:zod@3.22.0\n```\n",
        )
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        findings = docs_truth.check_dead_commands([readme], docs_dir, verbs)
        assert findings == []

    def test_prose_mention_outside_code_context_is_ignored(self, tmp_path: Path) -> None:
        """Narrative text ("the leitir project") must never be parsed as an
        invocation -- only fenced/inline code spans are scanned."""
        cli_path, readme, docs_dir = self._make_tree(
            tmp_path,
            "Welcome to the leitir project overview.\n",
        )
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        findings = docs_truth.check_dead_commands([readme], docs_dir, verbs)
        assert findings == []

    def test_historical_doc_dirs_are_skipped(self, tmp_path: Path) -> None:
        cli_path = _write_cli(tmp_path)
        docs_dir = tmp_path / "docs"
        adr_dir = docs_dir / "adr"
        adr_dir.mkdir(parents=True)
        adr_file = adr_dir / "0001-example.md"
        adr_file.write_text("Retire the old `leitir eval` entry point.\n", encoding="utf-8")
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        findings = docs_truth.check_dead_commands([adr_file], docs_dir, verbs)
        assert findings == []

    def test_archived_marked_doc_is_skipped_by_check1(self, tmp_path: Path) -> None:
        cli_path, _, docs_dir = self._make_tree(tmp_path, "")
        archived = docs_dir / "old-feature.md"
        archived.write_text(
            "# Old feature (Removed)\n\n"
            "> **ARCHIVED** -- this was deleted.\n\n"
            "```bash\n# ARCHIVED -- DO NOT RUN\nleitir launch --foo\n```\n",
            encoding="utf-8",
        )
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        findings = docs_truth.check_dead_commands([archived], docs_dir, verbs)
        assert findings == []


class TestCheckUnguardedArchivedInstructions:
    def test_unguarded_dead_verb_in_archived_doc_is_flagged(self, tmp_path: Path) -> None:
        cli_path = _write_cli(tmp_path)
        doc = tmp_path / "old-feature.md"
        doc.write_text(
            "# Old feature (Removed)\n\n"
            "> **ARCHIVED** -- this was deleted.\n\n"
            "```bash\nleitir launch --foo\n```\n",
            encoding="utf-8",
        )
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        findings = docs_truth.check_unguarded_archived_instructions([doc], verbs)
        assert len(findings) == 1
        assert "unguarded" in findings[0].message

    def test_guarded_dead_verb_in_archived_doc_passes(self, tmp_path: Path) -> None:
        cli_path = _write_cli(tmp_path)
        doc = tmp_path / "old-feature.md"
        doc.write_text(
            "# Old feature (Removed)\n\n"
            "> **ARCHIVED** -- this was deleted.\n\n"
            "```bash\n# ARCHIVED -- DO NOT RUN\nleitir launch --foo\n```\n",
            encoding="utf-8",
        )
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        findings = docs_truth.check_unguarded_archived_instructions([doc], verbs)
        assert findings == []

    def test_non_archived_doc_is_never_checked(self, tmp_path: Path) -> None:
        cli_path = _write_cli(tmp_path)
        doc = tmp_path / "current.md"
        doc.write_text("```bash\nleitir launch --foo\n```\n", encoding="utf-8")
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        findings = docs_truth.check_unguarded_archived_instructions([doc], verbs)
        assert findings == []


class TestRealRepoTree:
    def test_run_checks_exits_clean_on_real_tree(self) -> None:
        findings = docs_truth.run_checks()
        assert findings == [], [f.render() for f in findings]

    def test_smoke_evaluation_doc_passes(self) -> None:
        """The motivating example: docs/smoke-evaluation.md documents the
        removed `leitir eval` command but must not be flagged, because it
        both self-marks as archived and guards its one runnable line."""
        registered = docs_truth.extract_registered_verbs_from_cli_modules(
            REPO_ROOT / "src" / "leitir"
        )
        doc = REPO_ROOT / "docs" / "smoke-evaluation.md"
        dead = docs_truth.check_dead_commands([doc], REPO_ROOT / "docs", registered)
        unguarded = docs_truth.check_unguarded_archived_instructions([doc], registered)
        assert dead == []
        assert unguarded == []

    def test_cli_module_exits_zero_with_check_flag(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TOOL_PATH), "--check"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr


class TestPyprojectVersionClaims:
    def test_wrong_current_version_claim_is_flagged(self, tmp_path: Path) -> None:
        readme = tmp_path / "README.md"
        readme.write_text("`pyproject.toml` is 0.1.4. Everything else is fine.\n", encoding="utf-8")
        findings = docs_truth.check_pyproject_version_claims([readme], "0.1.6")
        assert len(findings) == 1
        assert findings[0].line == 1
        assert "0.1.4" in findings[0].message
        assert "0.1.6" in findings[0].message

    def test_matching_current_version_claim_passes(self, tmp_path: Path) -> None:
        readme = tmp_path / "README.md"
        readme.write_text("`pyproject.toml` is 0.1.6.\n", encoding="utf-8")
        findings = docs_truth.check_pyproject_version_claims([readme], "0.1.6")
        assert findings == []

    def test_historical_version_statement_is_not_flagged(self, tmp_path: Path) -> None:
        """'v0.1.4 was the first `v*` tag' is a true historical statement --
        it must never be mistaken for a current-version claim, even though
        the real version has since moved on."""
        readme = tmp_path / "README.md"
        readme.write_text(
            "v0.1.4 was the first `v*` tag (2026-08-17); the current version is now 0.1.6.\n",
            encoding="utf-8",
        )
        findings = docs_truth.check_pyproject_version_claims([readme], "0.1.6")
        assert findings == []

    def test_past_tense_pyproject_statement_is_not_flagged(self, tmp_path: Path) -> None:
        """A past-tense 'pyproject.toml was X before the bump' is out of
        scope for this narrow, present-tense-only pattern."""
        readme = tmp_path / "README.md"
        readme.write_text(
            "`pyproject.toml` was 0.1.4 before it was bumped to 0.1.6.\n", encoding="utf-8"
        )
        findings = docs_truth.check_pyproject_version_claims([readme], "0.1.6")
        assert findings == []

    def test_alternate_phrasings_are_matched(self, tmp_path: Path) -> None:
        readme = tmp_path / "README.md"
        readme.write_text(
            "pyproject version 0.1.4.\npyproject.toml's version is 0.1.4.\n",
            encoding="utf-8",
        )
        findings = docs_truth.check_pyproject_version_claims([readme], "0.1.6")
        assert len(findings) == 2

    def test_real_repo_pyproject_version_matches_readme_claim(self) -> None:
        """The real tree should pass -- README was just corrected to 0.1.6."""
        real_version = docs_truth.read_pyproject_version(REPO_ROOT / "pyproject.toml")
        findings = docs_truth.check_pyproject_version_claims(
            [REPO_ROOT / "README.md"], real_version
        )
        assert findings == []


class TestInstallTag:
    def test_nonexistent_tag_is_flagged(self, tmp_path: Path) -> None:
        readme = tmp_path / "README.md"
        readme.write_text(
            "pip install git+https://github.com/x/leitir.git@v9.9.9\n", encoding="utf-8"
        )
        findings = docs_truth.check_install_tag([readme], ["v0.1.4", "v0.1.5", "v0.1.6"])
        assert len(findings) == 1
        assert "does not exist" in findings[0].message

    def test_stale_but_existing_tag_is_flagged(self, tmp_path: Path) -> None:
        readme = tmp_path / "README.md"
        readme.write_text(
            "pip install git+https://github.com/x/leitir.git@v0.1.4\n", encoding="utf-8"
        )
        findings = docs_truth.check_install_tag([readme], ["v0.1.4", "v0.1.5", "v0.1.6"])
        assert len(findings) == 1
        assert "not the latest" in findings[0].message
        assert "v0.1.6" in findings[0].message

    def test_latest_tag_passes(self, tmp_path: Path) -> None:
        readme = tmp_path / "README.md"
        readme.write_text(
            "pip install git+https://github.com/x/leitir.git@v0.1.6\n", encoding="utf-8"
        )
        findings = docs_truth.check_install_tag([readme], ["v0.1.4", "v0.1.5", "v0.1.6"])
        assert findings == []

    def test_no_tags_skips_cleanly(self, tmp_path: Path) -> None:
        readme = tmp_path / "README.md"
        readme.write_text(
            "pip install git+https://github.com/x/leitir.git@v9.9.9\n", encoding="utf-8"
        )
        findings = docs_truth.check_install_tag([readme], None)
        assert findings == []

    def test_get_git_tags_returns_none_when_git_binary_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError("git not found")

        monkeypatch.setattr(docs_truth.subprocess, "run", fake_run)
        assert docs_truth.get_git_tags(tmp_path) is None

    def test_get_git_tags_returns_none_when_repo_has_no_tags(self, tmp_path: Path) -> None:
        """A shallow clone / source tarball with no `v*` tag refs must skip
        cleanly, never crash or fail the gate."""
        subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        assert docs_truth.get_git_tags(tmp_path) is None

    def test_real_repo_readme_install_tag_is_current(self) -> None:
        tags = docs_truth.get_git_tags(REPO_ROOT)
        findings = docs_truth.check_install_tag([REPO_ROOT / "README.md"], tags)
        assert findings == []


class TestDeterminism:
    def test_output_is_sorted_and_stable_across_calls(self, tmp_path: Path) -> None:
        cli_path, readme, docs_dir = TestCheckDeadCommands()._make_tree(
            tmp_path,
            "```bash\nleitir zeta --x\nleitir alpha --y\n```\n",
        )
        verbs = docs_truth.extract_registered_verbs(cli_path.read_text(encoding="utf-8"))
        first = [
            f.render() for f in docs_truth.check_dead_commands([readme], docs_dir, verbs)
        ]
        second = [
            f.render() for f in docs_truth.check_dead_commands([readme], docs_dir, verbs)
        ]
        assert first == second
        assert first == sorted(first)

    def test_cli_output_byte_identical_across_hash_seeds(self) -> None:
        outputs = []
        for seed in ("0", "1", "42"):
            result = subprocess.run(
                [sys.executable, str(TOOL_PATH), "--check"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
                env={"PYTHONHASHSEED": seed, "PATH": __import__("os").environ.get("PATH", "")},
            )
            outputs.append((result.returncode, result.stdout, result.stderr))
        assert len({o[1] for o in outputs}) == 1
        assert len({o[0] for o in outputs}) == 1
