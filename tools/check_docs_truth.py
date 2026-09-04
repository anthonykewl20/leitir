#!/usr/bin/env python3
"""Docs-truth gate: catch documentation that claims things the CLI cannot do.

This standalone module intentionally imports no Leitir package code, mirroring
``tools/score_engine.py`` -- it parses ``src/leitir/cli.py`` as text/AST
rather than importing it, so it works even when the package is broken or
uninstalled.

Four checks:

Check 1 -- dead command references.  Every ``leitir <verb>`` invocation that
appears in *code context* (a fenced code block, or an inline ``` `...` ```
span) in README.md, AGENTS.md, a *non-historical* doc under docs/, or a
markdown file under skills/ must name a verb that is actually registered as
an argparse subcommand in ``src/leitir/cli*.py``. The authoritative verb list
is extracted by parsing the ``cli*.py`` modules with the ``ast`` module and
collecting every ``commands.add_parser("<name>", ...)`` call -- including the
one case where the literal name is a for-loop variable (``get``/``fetch``
share one ``add_parser(command, ...)`` call site) -- rather than hardcoding a
list.

The ``skills/**.md`` files are the agent-facing skill: the rules and command
lines AI agents are actually taught. A stale instruction there misdirects
agents directly, so it is verified with exactly the same strictness as
README -- it is never treated as historical-by-convention.

ADR, evidence, and research documents (``docs/adr/**``, ``docs/evidence/**``,
``docs/research/**``) are historical-by-convention records: an ADR documents
the decision made at the time and is not rewritten as the CLI evolves, so
phrases like "retire the old `leitir eval` entry point" or "there will be no
`leitir score` command" are correct historical statements, not stale
instructions. Check 1 therefore does not scan those directories. A doc file
outside those directories that explicitly self-marks as historical/archived
(see Check 2 below) is likewise skipped by Check 1 -- it hands off entirely to
Check 2's stricter, guard-aware rule. Everything else that gives a user or
agent literal, actionable command text is in scope.

Check 2 -- unguarded historical instructions.  A doc file that marks itself
explicitly historical/archived (an H1 title tagged ``(Removed)``/``(Archived)``
or a bold ``**ARCHIVED`` marker near the top) is allowed to mention dead verbs
in prose, but any fenced code block that still contains a runnable
``leitir <dead-verb>`` invocation must carry an explicit in-block "do not run"
style guard comment. ``docs/smoke-evaluation.md`` is the motivating example:
it documents the removed ``leitir eval`` command but guards the one runnable
line with ``# ARCHIVED -- DO NOT RUN``.

Checks 1 and 2 are pure text/AST analysis: no network, no subprocess, no
import of the leitir package.

Check 3 -- declared version consistency.  A doc sentence that asserts the
*current* value of ``pyproject.toml``'s version (e.g. "`pyproject.toml` is
0.1.6") must match the real ``version = "..."`` in ``pyproject.toml``,
parsed with the stdlib ``tomllib``. The matching pattern is deliberately
narrow: it only fires on present-tense "pyproject(.toml) is/version is/is
version X.Y.Z" phrasing, so a historical statement like "v0.1.4 was the
first `v*` tag" -- which does not even mention "pyproject" -- is never in
scope, and a past-tense "pyproject.toml *was* 0.1.4 before the bump" is
deliberately ignored too (see ``_PYPROJECT_VERSION_CLAIM_RE``).

Check 4 -- advertised install tag is real and current.  Any
``pip install git+...@vX.Y.Z``-shaped instruction in README.md must name a
tag that both exists in ``git tag --list`` and sorts as the latest ``v*``
tag (README-only by design: it is the one document install instructions
point at). Tags are read via one ``git tag --list 'v*'`` subprocess call. If
git is unavailable (``FileNotFoundError``), the call fails (non-repo /
shallow checkout with no tag refs), or the repo simply has no ``v*`` tags,
Check 4 skips cleanly and reports nothing -- it never fails the gate on
git/tag absence, only on a genuine stale/nonexistent tag reference.

All four checks are deterministic and PYTHONHASHSEED-independent (all
collections are sorted before being reported).
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI_PATH = REPO_ROOT / "src" / "leitir" / "cli.py"

# Directories under docs/ that are historical-by-convention and therefore
# exempt from Check 1 (dead-verb references in prose/history are expected).
_HISTORICAL_DOC_DIRS = ("adr", "evidence", "research")

# Matches "leitir <verb>", capturing the verb token. The verb must start with
# a letter so flags (--foo), env-var assignments, and bare "leitir" mentions
# never match.
_INVOCATION_RE = re.compile(r"\bleitir\s+([A-Za-z][A-Za-z0-9_-]*)")

# A fenced code block delimiter: ``` or ~~~, optionally with a language tag.
_FENCE_RE = re.compile(r"^\s*(```|~~~)")

# An inline code span on a single line: `...` (no backticks inside).
_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")

_ARCHIVE_TITLE_RE = re.compile(r"^#\s.*\((Removed|Archived)\)\s*$", re.IGNORECASE)
_ARCHIVE_BADGE_RE = re.compile(r"\*\*ARCHIVED\b", re.IGNORECASE)
_GUARD_COMMENT_RE = re.compile(
    r"#.*\b(do not run|don't run|archived|no longer (exist|work|run)|removed)\b",
    re.IGNORECASE,
)

# Check 3: a *present-tense* claim about pyproject.toml's current version,
# e.g. "`pyproject.toml` is 0.1.6", "pyproject version 0.1.6", "pyproject.toml's
# version is 0.1.6". Requires the literal word "pyproject" plus one of
# "is"/"version"/"is version"/"version is" immediately before the number --
# so it matches only present-state assertions and never a past-tense
# "pyproject.toml *was* 0.1.4" (no "is"/"version is"/"is version"/bare
# "version" connector matches "was") or a bare tag mention like "v0.1.4 was
# the first tag" (which does not contain the word "pyproject" at all).
_PYPROJECT_VERSION_CLAIM_RE = re.compile(
    r"`?pyproject(?:\.toml)?`?(?:'s)?\s+(?:is\s+version|version\s+is|version|is)"
    r"\s+v?(\d+\.\d+\.\d+)\b",
    re.IGNORECASE,
)

# Check 4: an install instruction naming a git tag, e.g.
# "pip install git+https://.../leitir.git@v0.1.6". Only matches an explicit
# ``@vX.Y.Z`` tag ref on a ``git+`` URL -- a bare
# "pip install git+https://.../leitir.git" (no ``@tag``, i.e. "install from
# the default branch") is intentionally not in scope, since it makes no tag
# claim to verify.
_INSTALL_TAG_RE = re.compile(r"git\+\S+?@(v\d+\.\d+\.\d+)\b")

_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


class PyprojectParseError(RuntimeError):
    """Raised when pyproject.toml cannot be parsed for its version."""


@dataclass(frozen=True)
class Invocation:
    """One ``leitir <verb>`` reference found in a code context."""

    path: Path
    line: int
    verb: str
    text: str


@dataclass(frozen=True)
class Finding:
    """One reportable problem, already formatted for stable sorted output."""

    path: Path
    line: int
    message: str

    def render(self) -> str:
        rel = self.path
        if self.path.is_absolute():
            try:
                rel = self.path.relative_to(REPO_ROOT)
            except ValueError:
                rel = self.path
        return f"{rel}:{self.line}: {self.message}"


class CliParseError(RuntimeError):
    """Raised when cli.py cannot be parsed into a verb list."""


def extract_registered_verbs(cli_source: str) -> frozenset[str]:
    """Parse cli.py with ``ast`` and collect every ``add_parser`` verb name.

    Resolves the one case where the first positional argument is a Name bound
    by an enclosing ``for`` loop over a literal tuple/list of string
    constants (the ``for command, help_text in (("get", ...), ("fetch",
    ...))`` loop), so no verb has to be hardcoded here.
    """
    try:
        tree = ast.parse(cli_source)
    except SyntaxError as exc:  # pragma: no cover - defensive
        raise CliParseError(f"cli.py failed to parse: {exc}") from exc

    verbs: set[str] = set()
    scope_stack: list[dict[str, list[str]]] = []

    def resolve(node: ast.expr) -> list[str] | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.Name):
            for scope in reversed(scope_stack):
                if node.id in scope:
                    return scope[node.id]
        return None

    def literal_str_elements(seq: ast.expr) -> list[str] | None:
        if not isinstance(seq, (ast.List, ast.Tuple)):
            return None
        values: list[str] = []
        for elt in seq.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                values.append(elt.value)
            else:
                return None
        return values

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_parser"
                and node.args
            ):
                resolved = resolve(node.args[0])
                if resolved:
                    verbs.update(resolved)
            self.generic_visit(node)

        def visit_For(self, node: ast.For) -> None:
            pushed: dict[str, list[str]] = {}
            if isinstance(node.target, ast.Name):
                values = literal_str_elements(node.iter)
                if values is not None:
                    pushed[node.target.id] = values
            elif isinstance(node.target, ast.Tuple) and isinstance(
                node.iter, (ast.List, ast.Tuple)
            ):
                target_names = [
                    elt.id if isinstance(elt, ast.Name) else None
                    for elt in node.target.elts
                ]
                columns: list[list[str]] = [[] for _ in target_names]
                consistent = True
                for row in node.iter.elts:
                    if not (
                        isinstance(row, (ast.Tuple, ast.List))
                        and len(row.elts) == len(target_names)
                    ):
                        consistent = False
                        break
                    for idx, cell in enumerate(row.elts):
                        if isinstance(cell, ast.Constant) and isinstance(
                            cell.value, str
                        ):
                            columns[idx].append(cell.value)
                if consistent:
                    for name, column in zip(target_names, columns, strict=True):
                        if name is not None and len(column) == len(node.iter.elts):
                            pushed[name] = column
            scope_stack.append(pushed)
            self.generic_visit(node)
            scope_stack.pop()

    Visitor().visit(tree)
    if not verbs:
        raise CliParseError("no add_parser(...) calls found in cli.py")
    return frozenset(verbs)


def extract_registered_verbs_from_cli_modules(cli_dir: Path) -> frozenset[str]:
    """Union of :func:`extract_registered_verbs` over every ``cli*.py`` module.

    Issue #271 split ``cli.py``'s per-verb ``argparse`` construction out into
    sibling modules -- ``cli_corpus.py``, ``cli_bts.py``, ``cli_ask.py``,
    ``cli_search.py``, and ``cli_diagnostics.py`` each own a slice of the
    ``add_parser()`` calls that used to all live in ``cli.py``, which is now
    a thin registry that calls into them instead of calling
    ``add_parser()`` itself. The authoritative verb list is therefore the
    union across every ``src/leitir/cli*.py`` file, not just ``cli.py``
    alone. A module with zero ``add_parser()`` calls (``cli.py`` itself,
    post-#271; ``cli_support.py``, which owns no parser construction at all)
    is skipped rather than treated as an error -- only an empty union across
    every matching file is a real problem.
    """
    verbs: set[str] = set()
    matched_any = False
    for path in sorted(cli_dir.glob("cli*.py")):
        try:
            file_verbs = extract_registered_verbs(path.read_text(encoding="utf-8"))
        except CliParseError:
            continue
        verbs.update(file_verbs)
        matched_any = True
    if not matched_any:
        raise CliParseError(
            f"no add_parser(...) calls found in any {cli_dir}/cli*.py module"
        )
    return frozenset(verbs)


def _iter_doc_files(
    readme: Path, agents: Path, docs_dir: Path, skills_dir: Path
) -> list[Path]:
    files = [p for p in (readme, agents) if p.is_file()]
    if docs_dir.is_dir():
        files.extend(sorted(docs_dir.rglob("*.md")))
    if skills_dir.is_dir():
        files.extend(sorted(skills_dir.rglob("*.md")))
    return sorted(set(files))


def _is_historical_dir(path: Path, docs_dir: Path) -> bool:
    try:
        rel = path.relative_to(docs_dir)
    except ValueError:
        return False
    return bool(rel.parts) and rel.parts[0] in _HISTORICAL_DOC_DIRS


def _is_marked_archived(lines: Sequence[str]) -> bool:
    for line in lines[:40]:
        if _ARCHIVE_TITLE_RE.match(line) or _ARCHIVE_BADGE_RE.search(line):
            return True
    return False


def _iter_code_context_invocations(path: Path, lines: Sequence[str]) -> Iterator[Invocation]:
    """Yield leitir invocations found inside fenced blocks or inline code."""
    in_fence = False
    for lineno, raw_line in enumerate(lines, start=1):
        if _FENCE_RE.match(raw_line):
            in_fence = not in_fence
            continue
        if in_fence:
            for match in _INVOCATION_RE.finditer(raw_line):
                yield Invocation(path, lineno, match.group(1), raw_line.strip())
            continue
        for span_match in _INLINE_CODE_RE.finditer(raw_line):
            span = span_match.group(1)
            for match in _INVOCATION_RE.finditer(span):
                yield Invocation(path, lineno, match.group(1), span.strip())


def _iter_fenced_blocks(lines: Sequence[str]) -> Iterator[tuple[int, list[str]]]:
    """Yield (start_line, block_lines) for each fenced code block."""
    start: int | None = None
    block: list[str] = []
    for lineno, raw_line in enumerate(lines, start=1):
        if _FENCE_RE.match(raw_line):
            if start is None:
                start = lineno
                block = []
            else:
                yield start, block
                start = None
                block = []
            continue
        if start is not None:
            block.append(raw_line)


def check_dead_commands(
    doc_files: Sequence[Path], docs_dir: Path, registered_verbs: frozenset[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for path in doc_files:
        if _is_historical_dir(path, docs_dir):
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        if _is_marked_archived(lines):
            # A file that marks itself historical/archived is exempt from
            # Check 1 (dead verbs are expected there); Check 2 instead
            # verifies any runnable instruction it still gives is guarded.
            continue
        for inv in _iter_code_context_invocations(path, lines):
            if inv.verb not in registered_verbs:
                findings.append(
                    Finding(
                        path,
                        inv.line,
                        f"references `leitir {inv.verb}`, which is not a registered "
                        f"subcommand in src/leitir/cli.py (found: {inv.text!r})",
                    )
                )
    return findings


def check_unguarded_archived_instructions(
    doc_files: Sequence[Path], registered_verbs: frozenset[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for path in doc_files:
        lines = path.read_text(encoding="utf-8").splitlines()
        if not _is_marked_archived(lines):
            continue
        for start, block in _iter_fenced_blocks(lines):
            has_guard = any(_GUARD_COMMENT_RE.search(line) for line in block)
            for offset, raw_line in enumerate(block):
                for match in _INVOCATION_RE.finditer(raw_line):
                    verb = match.group(1)
                    if verb in registered_verbs:
                        continue
                    if has_guard:
                        continue
                    findings.append(
                        Finding(
                            path,
                            start + offset + 1,
                            "archived doc gives an unguarded runnable instruction for "
                            f"dead command `leitir {verb}` -- add a '# ARCHIVED' / "
                            "'# do not run' comment in the same code block "
                            f"(found: {raw_line.strip()!r})",
                        )
                    )
    return findings


def read_pyproject_version(pyproject_path: Path) -> str:
    """Parse ``version = "..."`` out of ``[project]`` in pyproject.toml."""
    try:
        with pyproject_path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PyprojectParseError(f"{pyproject_path} failed to parse: {exc}") from exc
    version = data.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise PyprojectParseError(
            f"{pyproject_path} has no [project] version string"
        )
    return version


def check_pyproject_version_claims(
    doc_files: Sequence[Path], real_version: str
) -> list[Finding]:
    """Check 3: flag present-tense doc claims of pyproject.toml's version
    that disagree with the real version in pyproject.toml."""
    findings: list[Finding] = []
    for path in doc_files:
        lines = path.read_text(encoding="utf-8").splitlines()
        for lineno, raw_line in enumerate(lines, start=1):
            for match in _PYPROJECT_VERSION_CLAIM_RE.finditer(raw_line):
                claimed = match.group(1)
                if claimed != real_version:
                    findings.append(
                        Finding(
                            path,
                            lineno,
                            f"claims pyproject.toml's version is {claimed}, but "
                            f"pyproject.toml actually declares version = "
                            f"{real_version!r} (found: {raw_line.strip()!r})",
                        )
                    )
    return findings


def get_git_tags(repo_root: Path) -> list[str] | None:
    """Return sorted ``v*`` tags via ``git tag --list``, or ``None`` if git
    or tag refs are unavailable (no git binary, not a repo, shallow clone
    with no tags, or a source tarball with no ``.git`` at all)."""
    try:
        result = subprocess.run(
            ["git", "tag", "--list", "v*"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    tags = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not tags:
        return None
    return tags


def _semver_key(tag: str) -> tuple[int, int, int] | None:
    match = _SEMVER_RE.match(tag)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def check_install_tag(doc_files: Sequence[Path], tags: Sequence[str] | None) -> list[Finding]:
    """Check 4: flag an advertised install tag that doesn't exist, or that
    exists but isn't the latest released tag. Skips cleanly (returns no
    findings) when ``tags`` is ``None`` (git/tags unavailable)."""
    if tags is None:
        return []
    valid_tags = {tag: key for tag in tags if (key := _semver_key(tag)) is not None}
    if not valid_tags:
        return []
    latest_tag = max(valid_tags, key=lambda t: valid_tags[t])
    findings: list[Finding] = []
    for path in doc_files:
        lines = path.read_text(encoding="utf-8").splitlines()
        for lineno, raw_line in enumerate(lines, start=1):
            for match in _INSTALL_TAG_RE.finditer(raw_line):
                claimed_tag = match.group(1)
                if claimed_tag not in tags:
                    findings.append(
                        Finding(
                            path,
                            lineno,
                            f"install instructions reference tag {claimed_tag!r}, "
                            f"which does not exist in `git tag --list` "
                            f"(found: {raw_line.strip()!r})",
                        )
                    )
                elif claimed_tag != latest_tag:
                    findings.append(
                        Finding(
                            path,
                            lineno,
                            f"install instructions reference tag {claimed_tag!r}, "
                            f"which is not the latest released tag "
                            f"({latest_tag!r}) (found: {raw_line.strip()!r})",
                        )
                    )
    return findings


def run_checks(
    *,
    repo_root: Path = REPO_ROOT,
    cli_path: Path = CLI_PATH,
) -> list[Finding]:
    registered_verbs = extract_registered_verbs_from_cli_modules(cli_path.parent)
    docs_dir = repo_root / "docs"
    doc_files = _iter_doc_files(
        repo_root / "README.md",
        repo_root / "AGENTS.md",
        docs_dir,
        repo_root / "skills",
    )
    real_version = read_pyproject_version(repo_root / "pyproject.toml")
    tags = get_git_tags(repo_root)
    findings = [
        *check_dead_commands(doc_files, docs_dir, registered_verbs),
        *check_unguarded_archived_instructions(doc_files, registered_verbs),
        *check_pyproject_version_claims(doc_files, real_version),
        *check_install_tag([p for p in doc_files if p.name == "README.md"], tags),
    ]
    return sorted(findings, key=lambda f: (str(f.path), f.line, f.message))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check that docs only reference real leitir CLI subcommands."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero and print findings if any doc references a dead command",
    )
    args = parser.parse_args(argv)

    try:
        findings = run_checks()
    except (CliParseError, PyprojectParseError) as exc:
        print(f"check_docs_truth: {exc}", file=sys.stderr)
        return 1

    if get_git_tags(REPO_ROOT) is None:
        print(
            "check_docs_truth: note: no git tags found (shallow clone, "
            "tarball, or no `v*` tags) -- Check 4 (install tag) skipped",
            file=sys.stderr,
        )

    if not findings:
        print("check_docs_truth: OK (no dead command references found)")
        return 0

    for finding in findings:
        print(finding.render())

    if args.check:
        print(f"check_docs_truth: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
