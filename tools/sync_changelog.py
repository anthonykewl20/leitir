#!/usr/bin/env python3
"""Generate CHANGELOG.md's managed region from Conventional Commits."""

from __future__ import annotations

import argparse
import difflib
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

MARKER = "<!-- leitir-sync-changelog start -->"
REPOSITORY_URL = "https://github.com/anthonykewl20/leitir"
SECTION_ORDER = (
    "### ⚠ BREAKING CHANGES",
    "### Added",
    "### Changed",
    "### Fixed",
    "### Security",
)
TYPE_SECTIONS = {"feat": "### Added", "fix": "### Fixed", "perf": "### Changed"}
INTERNAL_TYPES = frozenset({"refactor", "docs", "test", "style", "chore", "ci", "build"})
CONVENTIONAL_SUBJECT = re.compile(
    r"^(?P<type>[A-Za-z][A-Za-z0-9-]*)(?:\((?P<scope>[^()\r\n]+)\))?(?P<bang>!)?: (?P<subject>\S.*)$"
)
BREAKING_FOOTER = re.compile(r"^BREAKING(?: CHANGE|-CHANGE): .+", re.MULTILINE)
SECURITY_FLAVOR = re.compile(
    r"\b(?:security|vulnerabilit(?:y|ies)|cve-\d+|credentials?|secrets?|tamper(?:ing|ed)?|integrity|plaintext|redact(?:ion|ed)?)\b",
    re.IGNORECASE,
)
VERSION_TAG = re.compile(r"^v(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>[0-9]{3}|0|[1-9][0-9]*)$")


@dataclass(frozen=True)
class Commit:
    """The deterministic commit data used by the generator."""

    commit_id: str
    subject: str
    body: str = ""
    release: str = "Unreleased"


@dataclass(frozen=True)
class Change:
    """A parsed user-facing change."""

    commit_type: str
    scope: str | None
    subject: str
    release: str
    breaking: bool
    security: bool


@dataclass(frozen=True)
class VersionTag:
    """A reachable vX.Y.Z tag and its semantic sort key."""

    name: str
    version: str
    key: tuple[int, int, int]
    distance: int


def parse_commit(commit: Commit) -> Change | None:
    """Parse one Conventional Commit, silently rejecting other subjects."""
    match = CONVENTIONAL_SUBJECT.fullmatch(commit.subject)
    if match is None:
        return None
    commit_type = match.group("type").lower()
    scope = match.group("scope")
    subject = match.group("subject")
    breaking = match.group("bang") is not None or BREAKING_FOOTER.search(commit.body) is not None
    if commit_type not in TYPE_SECTIONS and commit_type not in INTERNAL_TYPES and not breaking:
        return None
    security_text = " ".join(part for part in (scope, subject, commit.body) if part)
    security = commit_type == "fix" and (
        (scope is not None and scope.casefold() == "security") or SECURITY_FLAVOR.search(security_text) is not None
    )
    return Change(commit_type, scope, subject, commit.release, breaking, security)


def group_changes(commits: Iterable[Commit]) -> dict[str, dict[str, list[Change]]]:
    """Parse, deduplicate, and sort commits by release and changelog section."""
    deduplicated: dict[tuple[str, str, str | None, str], Change] = {}
    for commit in commits:
        change = parse_commit(commit)
        if change is None:
            continue
        key = (change.release, change.commit_type, change.scope, change.subject)
        previous = deduplicated.get(key)
        if previous is None:
            deduplicated[key] = change
        else:
            deduplicated[key] = replace(
                previous,
                breaking=previous.breaking or change.breaking,
                security=previous.security or change.security,
            )

    grouped: dict[str, dict[str, list[Change]]] = {}
    for change in deduplicated.values():
        if change.breaking:
            section = SECTION_ORDER[0]
        elif change.commit_type in INTERNAL_TYPES:
            continue
        elif change.security:
            section = "### Security"
        else:
            section = TYPE_SECTIONS[change.commit_type]
        grouped.setdefault(change.release, {}).setdefault(section, []).append(change)

    for sections in grouped.values():
        for changes in sections.values():
            changes.sort(key=_change_sort_key)
    return grouped


def _change_sort_key(change: Change) -> tuple[str, str, str, str, str]:
    scope = change.scope or ""
    return (change.subject.casefold(), scope.casefold(), change.commit_type, change.subject, scope)


def _run_git(arguments: Sequence[str], *, cwd: Path) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(arguments)} failed: {error}")
    return completed.stdout.decode("utf-8", errors="strict")


def _git_commits(revisions: Sequence[str], *, cwd: Path, release: str) -> list[Commit]:
    output = _run_git(
        ["log", "--no-merges", "--format=%H%x00%s%x00%b%x00", *revisions],
        cwd=cwd,
    )
    fields = output.split("\x00")
    if fields and fields[-1].strip() == "":
        fields.pop()
    if len(fields) % 3 != 0:
        raise RuntimeError("git log returned malformed NUL-delimited output")
    return [
        Commit(fields[index].lstrip("\n"), fields[index + 1], fields[index + 2], release)
        for index in range(0, len(fields), 3)
    ]


def _version_tags(*, cwd: Path, to_ref: str, from_ref: str | None) -> list[VersionTag]:
    names = _run_git(["tag", "--merged", to_ref, "--list", "v*"], cwd=cwd).splitlines()
    tags: list[VersionTag] = []
    for name in names:
        match = VERSION_TAG.fullmatch(name)
        if match is None:
            continue
        if from_ref is not None:
            ancestor = subprocess.run(
                ["git", "merge-base", "--is-ancestor", name, from_ref],
                cwd=cwd,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            if ancestor.returncode == 0:
                continue
            if ancestor.returncode != 1:
                error = ancestor.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(f"could not compare {name} with {from_ref}: {error}")
        version_key = (
            int(match.group("major")),
            int(match.group("minor")),
            int(match.group("patch")),
        )
        distance = int(_run_git(["rev-list", "--count", f"{name}..{to_ref}"], cwd=cwd).strip())
        tags.append(VersionTag(name, name.removeprefix("v"), version_key, distance))
    return sorted(tags, key=lambda tag: (tag.distance, tuple(-part for part in tag.key), tag.name))


def collect_commits(*, cwd: Path, from_ref: str | None, to_ref: str) -> tuple[list[Commit], list[VersionTag]]:
    """Collect non-merge commits in deterministic release ranges."""
    shallow = _run_git(["rev-parse", "--is-shallow-repository"], cwd=cwd).strip()
    if shallow != "false":
        raise RuntimeError("refusing to generate from incomplete Git history; fetch the full history and tags first")
    tags = _version_tags(cwd=cwd, to_ref=to_ref, from_ref=from_ref)
    lower_exclusion = [f"^{from_ref}"] if from_ref is not None else []
    commits: list[Commit] = []
    seen: set[str] = set()

    newest_boundary = tags[0].name if tags else from_ref
    unreleased_revisions = [to_ref, *( [f"^{newest_boundary}"] if newest_boundary is not None else [] )]
    for commit in _git_commits(unreleased_revisions, cwd=cwd, release="Unreleased"):
        if commit.commit_id not in seen:
            commits.append(commit)
            seen.add(commit.commit_id)

    for index, tag in enumerate(tags):
        older_boundary = tags[index + 1].name if index + 1 < len(tags) else None
        revisions = [tag.name]
        if older_boundary is not None:
            revisions.append(f"^{older_boundary}")
        revisions.extend(lower_exclusion)
        for commit in _git_commits(revisions, cwd=cwd, release=tag.version):
            if commit.commit_id not in seen:
                commits.append(commit)
                seen.add(commit.commit_id)
    return commits, tags


def render_managed_region(commits: Iterable[Commit], tags: Sequence[VersionTag]) -> str:
    """Render all generated headings, entries, and reference links."""
    grouped = group_changes(commits)
    releases = ["Unreleased", *(tag.version for tag in tags)]
    lines: list[str] = []
    for release in releases:
        lines.append(f"## [{release}]")
        sections = grouped.get(release, {})
        for section in SECTION_ORDER:
            changes = sections.get(section)
            if not changes:
                continue
            lines.extend(("", section))
            for change in changes:
                scope = f" (`{change.scope}`)" if change.scope is not None else ""
                lines.append(f"- {change.subject}{scope}")
        lines.append("")

    if tags:
        lines.append(f"[Unreleased]: {REPOSITORY_URL}/compare/{tags[0].name}...HEAD")
        for index, tag in enumerate(tags):
            if index + 1 < len(tags):
                target = f"compare/{tags[index + 1].name}...{tag.name}"
            else:
                target = f"releases/tag/{tag.name}"
            lines.append(f"[{tag.version}]: {REPOSITORY_URL}/{target}")
    else:
        lines.append(f"[Unreleased]: {REPOSITORY_URL}/commits/HEAD")
    return "\n".join(lines) + "\n"


def synchronize(existing: str, managed_region: str) -> str:
    """Preserve the preamble and replace (or insert) the managed region."""
    marker_index = existing.find(MARKER)
    if marker_index >= 0:
        line_end = existing.find("\n", marker_index)
        prefix = existing[: marker_index + len(MARKER)] if line_end < 0 else existing[:line_end]
    else:
        heading = re.search(r"^## ", existing, re.MULTILINE)
        prefix = existing[: heading.start() if heading is not None else len(existing)].rstrip("\n")
        prefix = f"{prefix}\n\n{MARKER}"
    return f"{prefix}\n\n{managed_region}"


def _write_atomic(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="fail and print a diff when CHANGELOG.md is stale")
    modes.add_argument("--dry-run", action="store_true", help="print generated content without writing")
    parser.add_argument("--from-ref", help="exclude commits reachable from this revision")
    parser.add_argument("--to-ref", default="HEAD", help="generate through this revision (default: HEAD)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    changelog_path = root / "CHANGELOG.md"
    try:
        existing = changelog_path.read_text(encoding="utf-8")
        commits, tags = collect_commits(cwd=root, from_ref=args.from_ref, to_ref=args.to_ref)
        generated = synchronize(existing, render_managed_region(commits, tags))
    except (OSError, RuntimeError, UnicodeError) as error:
        print(f"sync_changelog: {error}", file=sys.stderr)
        return 2

    if args.dry_run:
        sys.stdout.write(generated)
        return 0
    if args.check:
        if generated == existing:
            return 0
        sys.stdout.writelines(
            difflib.unified_diff(
                existing.splitlines(keepends=True),
                generated.splitlines(keepends=True),
                fromfile="CHANGELOG.md (current)",
                tofile="CHANGELOG.md (generated)",
            )
        )
        return 1
    _write_atomic(changelog_path, generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
