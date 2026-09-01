"""The corpus-family verb group: parser construction and dispatch (issue #271).

Covers ``get``/``fetch``, ``list``, ``upgrade-cache``, ``trust``, ``remove``,
``clean``, ``lock``, ``sbom``, ``api``, ``examples``, ``info``, ``diff``,
``export``, ``import``, ``gc``, and ``index`` -- the largest verb family,
sharing one dispatcher (``_run_corpus_command``) in the pre-#271
``leitir.cli`` implementation, moved here verbatim. Purely structural: no
behavior, flag, or output change.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO, TypedDict, cast

from .cli_support import (
    _UPGRADE_CACHE_DESCRIPTION,
    ExitCode,
    _BaseUrlOptions,
    _CachedFirstResolverFacade,
    _corpus_root,
    _FetchOptions,
    _github_token,
    _LocalFirstLockResolver,
    _require_authenticated_manifest,
    logger,
    mark_successful,
)
from .logging import redact
from .search import RepoScope, SearchSpecError
from .spec import CorpusSpec, parse_corpus_spec

if TYPE_CHECKING:
    from .resolver import ResolvedPackage
    from .warm import WarmSession

if TYPE_CHECKING:
    from .diff import DiffReport, ImpactReport
    from .trust import TrustScore


class _WarmSessionOptions(TypedDict, total=False):
    """Optional warm-session keyword forwarded to compatible owners."""

    session: WarmSession

def register_index(commands: argparse._SubParsersAction) -> None:
    index_command = commands.add_parser(
        "index", help="explicitly build or refresh local trigram index shelves"
    )
    index_command.add_argument("scopes", nargs="*", metavar="scope")
    index_command.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication on every shelved source before indexing",
    )
    index_command.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )
    index_roots = index_command.add_mutually_exclusive_group()
    index_roots.add_argument("--root", default=None, help="corpus root directory")
    index_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")

def register_get_fetch(commands: argparse._SubParsersAction) -> None:
    for command, help_text in (
        ("get", "materialize sources and print their local paths"),
        ("fetch", "materialize sources without printing their paths"),
    ):
        corpus_command = commands.add_parser(command, help=help_text)
        corpus_command.add_argument("specs", nargs="+", metavar="spec")
        roots = corpus_command.add_mutually_exclusive_group()
        roots.add_argument("--root", default=None, help="corpus root directory")
        roots.add_argument(
            "--local",
            action="store_true",
            help="use ./.leitir-refs and ensure it is gitignored",
        )
        corpus_command.add_argument(
            "--cwd",
            default=None,
            help="project directory used for lockfile resolution",
        )
        corpus_command.add_argument(
            "--no-verify",
            action="store_true",
            help="skip Git tree verification and record the source as unverified",
        )
        if command == "get":
            corpus_command.add_argument("--json", action="store_true", dest="as_json")
        corpus_command.add_argument(
            "--require-manifest-auth",
            action="store_true",
            help="require opt-in publisher authentication; never accepts unsigned shelves",
        )
        corpus_command.add_argument(
            "--trusted-keys",
            default=None,
            help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
        )


def register_list(commands: argparse._SubParsersAction) -> None:
    list_command = commands.add_parser("list", help="list materialized sources")
    list_command.add_argument("--json", action="store_true", dest="as_json")
    list_roots = list_command.add_mutually_exclusive_group()
    list_roots.add_argument("--root", default=None, help="corpus root directory")
    list_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    list_command.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication on every listed shelf; never lists unsigned shelves",
    )
    list_command.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )

def register_upgrade(commands: argparse._SubParsersAction) -> None:
    upgrade = commands.add_parser(
        "upgrade-cache",
        help=_UPGRADE_CACHE_DESCRIPTION,
        description=_UPGRADE_CACHE_DESCRIPTION,
    )
    upgrade.add_argument("--dry-run", action="store_true")
    upgrade.add_argument(
        "--recompute-git-parity",
        action="store_true",
        help="reprove raw Git-blob parity for eligible GitHub Git-commit shelves; current thresholds can downgrade exact to drift",
    )
    upgrade_roots = upgrade.add_mutually_exclusive_group()
    upgrade_roots.add_argument("--root", default=None, help="corpus root directory")
    upgrade_roots.add_argument(
        "--local", action="store_true", help="use ./.leitir-refs"
    )

def register_trust(commands: argparse._SubParsersAction) -> None:
    trust = commands.add_parser(
        "trust", help="compute cached trust evidence for a source"
    )
    trust.add_argument("spec")
    trust.add_argument("--json", action="store_true", dest="as_json")
    trust_roots = trust.add_mutually_exclusive_group()
    trust_roots.add_argument("--root", default=None, help="corpus root directory")
    trust_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    trust.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication on every shelved source before scoring trust",
    )
    trust.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )

def register_remove(commands: argparse._SubParsersAction) -> None:
    remove = commands.add_parser("remove", help="remove a materialized source")
    remove.add_argument("spec")
    remove_roots = remove.add_mutually_exclusive_group()
    remove_roots.add_argument("--root", default=None, help="corpus root directory")
    remove_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")

def register_clean(commands: argparse._SubParsersAction) -> None:
    clean = commands.add_parser("clean", help="empty the source corpus")
    clean.add_argument("--repos", action="store_true")
    clean_roots = clean.add_mutually_exclusive_group()
    clean_roots.add_argument("--root", default=None, help="corpus root directory")
    clean_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")

def register_lock(commands: argparse._SubParsersAction) -> None:
    lock = commands.add_parser(
        "lock", help="materialize the project's dependency closure"
    )
    lock.add_argument(
        "--cwd", default=None, help="project directory containing lockfiles"
    )
    lock_roots = lock.add_mutually_exclusive_group()
    lock_roots.add_argument("--root", default=None, help="corpus root directory")
    lock_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    lock.add_argument(
        "--no-verify", action="store_true", help="skip Git tree verification"
    )
    lock.add_argument(
        "--best-effort",
        action="store_true",
        help="continue when individual dependencies cannot be materialized",
    )

def register_sbom(commands: argparse._SubParsersAction) -> None:
    sbom = commands.add_parser("sbom", help="emit an SBOM for the materialized corpus")
    sbom.add_argument("--format", choices=("spdx", "cyclonedx"), default="spdx")
    sbom.add_argument(
        "--cwd", default=None, help="project directory containing lockfiles"
    )
    sbom_roots = sbom.add_mutually_exclusive_group()
    sbom_roots.add_argument("--root", default=None, help="corpus root directory")
    sbom_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    sbom.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication on every shelved source before generating the SBOM",
    )
    sbom.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )

def register_api(commands: argparse._SubParsersAction) -> None:
    api = commands.add_parser("api", help="extract and cache a materialized source API")
    api.add_argument("spec")
    api.add_argument("--json", action="store_true", dest="as_json")
    api_roots = api.add_mutually_exclusive_group()
    api_roots.add_argument("--root", default=None, help="corpus root directory")
    api_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    api.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication; never accepts unsigned shelves",
    )
    api.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )
    api.set_defaults(cwd=None, no_verify=False)

def register_examples(commands: argparse._SubParsersAction) -> None:
    examples = commands.add_parser(
        "examples", help="extract and cache materialized source examples"
    )
    examples.add_argument("spec")
    examples.add_argument("--json", action="store_true", dest="as_json")
    examples_roots = examples.add_mutually_exclusive_group()
    examples_roots.add_argument("--root", default=None, help="corpus root directory")
    examples_roots.add_argument(
        "--local", action="store_true", help="use ./.leitir-refs"
    )
    examples.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication; never accepts unsigned shelves",
    )
    examples.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )
    examples.set_defaults(cwd=None, no_verify=False)

def register_info(commands: argparse._SubParsersAction) -> None:
    info = commands.add_parser("info", help="materialize and describe one dependency")
    info.add_argument("spec")
    info.add_argument("--json", action="store_true", dest="as_json")
    info.add_argument(
        "--brief",
        action="store_true",
        help=(
            "smaller payload: provenance, top signatures, one example, bare "
            "trust score, and a ready-to-paste citation line"
        ),
    )
    info_roots = info.add_mutually_exclusive_group()
    info_roots.add_argument("--root", default=None, help="corpus root directory")
    info_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    info.add_argument(
        "--cwd", default=None, help="project directory used for lockfile resolution"
    )
    info.add_argument(
        "--no-verify", action="store_true", help="skip Git tree verification"
    )
    info.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require opt-in publisher authentication; never accepts unsigned shelves",
    )
    info.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )

def register_diff(commands: argparse._SubParsersAction) -> None:
    diff = commands.add_parser("diff", help="diff two resolved source versions")
    diff.add_argument("spec_a")
    diff.add_argument("spec_b")
    diff.add_argument("--json", action="store_true", dest="as_json")
    diff.add_argument(
        "--cwd", default=None, help="project directory used for lockfile resolution"
    )
    diff.add_argument(
        "--impact",
        default=None,
        metavar="PATH",
        help=(
            "Python consumer source file or directory: intersect the "
            "removed/changed symbol delta with actual usage and report "
            "which removals affect it (additive; default diff output is "
            "unchanged without this flag)"
        ),
    )
    diff_roots = diff.add_mutually_exclusive_group()
    diff_roots.add_argument("--root", default=None, help="corpus root directory")
    diff_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    diff.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require opt-in publisher authentication; never accepts unsigned shelves",
    )
    diff.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )

def register_export_import(commands: argparse._SubParsersAction) -> None:
    """Register ``export`` and ``import`` together: they share a trailing
    ``--root``/``--local`` mutually-exclusive-group loop in the pre-#271
    ``build_parser()``, so splitting them would either duplicate that loop
    or require passing parser objects between two functions -- moved here
    verbatim as one unit instead.
    """
    export = commands.add_parser("export", help="export an immutable corpus snapshot")
    export.add_argument(
        "-o",
        "--output",
        default="corpus.lock",
        help=(
            "path for the lock file (default: corpus.lock in the current "
            "working directory; the accompanying tarball is written "
            "alongside it as corpus.tar.gz)"
        ),
    )
    export.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication on every shelved source before exporting",
    )
    export.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )
    import_command = commands.add_parser(
        "import", help="import an immutable corpus snapshot"
    )
    import_command.add_argument("lock")
    import_command.add_argument(
        "--lock-sha256",
        required=True,
        help="trusted SHA-256 of the exact corpus.lock bytes (required)",
    )
    for snapshot_command in (export, import_command):
        snapshot_roots = snapshot_command.add_mutually_exclusive_group()
        snapshot_roots.add_argument(
            "--root", default=None, help="corpus root directory"
        )
        snapshot_roots.add_argument(
            "--local", action="store_true", help="use ./.leitir-refs"
        )

def register_gc(commands: argparse._SubParsersAction) -> None:
    gc = commands.add_parser(
        "gc", help="remove abandoned materialization staging directories"
    )
    gc_roots = gc.add_mutually_exclusive_group()
    gc_roots.add_argument("--root", default=None, help="corpus root directory")
    gc_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")


def _write_diff_human(report: DiffReport, out: TextIO) -> None:
    for heading, file_values in (
        ("Added files", report.files.added),
        ("Removed files", report.files.removed),
        ("Modified files", report.files.modified),
    ):
        print(f"{heading} ({len(file_values)}):", file=out)
        for path in file_values:
            print(f"  {path}", file=out)
    for heading, symbol_values in (
        ("Added symbols", report.api.added),
        ("Removed symbols", report.api.removed),
    ):
        print(f"{heading} ({len(symbol_values)}):", file=out)
        for symbol in symbol_values:
            print(f"  {symbol['qualified_name']}", file=out)
    print(f"Changed signatures ({len(report.api.changed)}):", file=out)
    for change in report.api.changed:
        print(
            f"  {change.qualified_name}: {change.before} -> {change.after}", file=out
        )
    if report.release_notes:
        print(f"Release notes ({len(report.release_notes)}):", file=out)
        for note in report.release_notes:
            print(f"  {note.tag}: {note.url}", file=out)
            print(note.body, file=out)
    if report.impact is not None:
        _write_impact_human(report.impact, out)


def _write_impact_human(impact: ImpactReport, out: TextIO) -> None:
    print(
        f"Impact against {impact.against} "
        f"({len(impact.impacted)} of {impact.removed_total} removed symbols used):",
        file=out,
    )
    for symbol in impact.impacted:
        print(f"  {symbol.qualified_name} ({len(symbol.sites)} call sites):", file=out)
        for site in symbol.sites:
            print(f"    {site.file}:{site.line}:{site.col}", file=out)
    if impact.not_impacted:
        print(f"  not used ({len(impact.not_impacted)}):", file=out)
        for name in impact.not_impacted:
            print(f"    {name}", file=out)
    print(
        f"  sites: examined={impact.sites_examined} unresolved={impact.sites_unresolved}",
        file=out,
    )
    if impact.status == "no_sites_examined":
        print(
            "  WARNING: 0 sites examined -- impact could not be determined "
            "for this package (see known import-root-mismatch limitation, "
            "issue #269); this is NOT evidence that no removed symbol is used",
            file=out,
        )


def _print_diff_impact_summary(impact: ImpactReport, err: TextIO) -> None:
    print(
        f"leitir: impact against {impact.against}: "
        f"removed={impact.removed_total} impacted={len(impact.impacted)} "
        f"not_impacted={len(impact.not_impacted)} sites_examined={impact.sites_examined} "
        f"sites_unresolved={impact.sites_unresolved} status={impact.status}",
        file=err,
    )
    if impact.status == "no_sites_examined":
        print(
            f"leitir: WARNING: 0 sites examined for {impact.package_name!r} "
            "-- impact could not be determined (import root mismatch? see "
            "issue #269's known limitation for renamed distributions); "
            "this is NOT evidence that no removed symbol is used",
            file=err,
        )


def _require_all_shelves_authenticated(
    root: Path,
    args: argparse.Namespace,
    *,
    err: TextIO,
    session: WarmSession | None = None,
) -> None:
    """Fail closed if any shelved source lacks a valid publisher signature.

    Used by corpus-wide read commands (``export``, ``sbom``… ) so a
    signed-shelves-only policy is enforceable over the whole corpus, not
    just the shelves a spec-based command happens to touch.
    """

    from .corpus import load_sources
    from .materialize import read_valid_manifest

    # issue #268: strict. A corrupt catalog read back as empty would make
    # this loop iterate zero times and return normally -- a false "every
    # shelf is authenticated" verdict (vacuously true over nothing) for a
    # policy whose whole point is to hold over the entire corpus.
    for entry in load_sources(root, strict=True):
        target = root / entry["path"]
        manifest = (
            read_valid_manifest(
                target,
                entry["owner"],
                entry["repo"],
                entry["commit_sha"],
                host=entry["host"],
                session=session,
            )
            if session is not None
            else read_valid_manifest(
                target,
                entry["owner"],
                entry["repo"],
                entry["commit_sha"],
                host=entry["host"],
            )
        )
        if manifest is None:
            raise ValueError(
                "materialized source failed load-time verification: "
                f"{target}"
            )
        _require_authenticated_manifest(
            manifest,
            target,
            trusted_keys=getattr(args, "trusted_keys", None),
            err=err,
        )


def _corpus_list(
    root: Path,
    *,
    as_json: bool,
    out: TextIO,
    err: TextIO | None = None,
    require_auth: bool = False,
    trusted_keys: str | None = None,
    session: WarmSession | None = None,
) -> None:
    from .corpus import load_sources
    from .info import source_routing
    from .materialize import read_valid_manifest

    # issue #268: deliberately non-strict. `list`'s whole job is to show a
    # human what the corpus currently contains; a corrupt catalog rendered
    # as an empty list is exactly what a human inspecting the corpus needs
    # to see next, and `load_sources` already surfaces a `RuntimeWarning`
    # and -- since #268 P1 -- leaves the corrupt file itself in place as a
    # durable forensic trail, rather than renaming it away. Unlike
    # export/sbom/index, nothing here is asserted as a complete or
    # authoritative artefact -- there is no destructive action downstream.
    entries = load_sources(root)
    rendered = []
    filtered = 0
    for entry in entries:
        manifest = (
            read_valid_manifest(
                root / entry["path"],
                entry["owner"],
                entry["repo"],
                entry["commit_sha"],
                host=entry["host"],
                session=session,
            )
            if session is not None
            else read_valid_manifest(
                root / entry["path"],
                entry["owner"],
                entry["repo"],
                entry["commit_sha"],
                host=entry["host"],
            )
        )
        if manifest is None:
            if require_auth:
                # Under a signed-shelves-only policy a shelf that fails
                # load-time verification must fail the command, not be
                # silently omitted — otherwise `list --require-manifest-auth`
                # reports a false green on a tampered corpus (reviewer
                # 2026-08-23).
                raise ValueError(
                    "materialized source failed load-time verification: "
                    f"{root / entry['path']}"
                )
            filtered += 1
            continue
        if require_auth:
            _require_authenticated_manifest(
                manifest,
                root / entry["path"],
                trusted_keys=trusted_keys,
                err=err,
            )
        version = manifest.get("version")
        verification = "unverified"
        if manifest.get("verified") is True:
            verification = "verified"
        elif manifest.get("verified") == "sampled":
            verification = "sampled"
        elif manifest.get("verified") == "archive-only":
            verification = "archive-only"
        trust_score = manifest.get("trust_score")
        if (
            not isinstance(trust_score, int)
            or isinstance(trust_score, bool)
            or not 0 <= trust_score <= 100
        ):
            trust_score = None
        # Advisory transplant-vs-study license routing (issue #190).
        routing = source_routing(root / entry["path"], manifest.get("license_identifier"))
        rendered.append((entry, version, verification, trust_score, routing))
    if filtered:
        logger.warning(
            "%d corpus entries were excluded because they failed manifest validation. "
            "Run `leitir upgrade-cache` to migrate legacy verified shelves, or "
            "inspect with `--json` for per-entry diagnostics.",
            filtered,
        )
    if as_json:
        payload = []
        for entry, _, verification, trust_score, routing in rendered:
            item = dict(entry, verification=verification, routing=routing)
            if trust_score is not None:
                item["trust_score"] = trust_score
            payload.append(item)
        print(json.dumps(payload, indent=2, sort_keys=True), file=out)
        return
    for entry, version, verification, trust_score, routing in rendered:
        version_text = f" {version}" if version else ""
        path = (root / entry["path"]).absolute()
        print(
            f"{entry['name']}{version_text} {entry['owner']}/{entry['repo']}@{entry['commit_sha']} "
            f"{verification} trust={trust_score if trust_score is not None else 'unknown'} "
            f"routing={routing['verdict']}/{routing['reason']} "
            f"{path} {entry['fetched_at']}",
            file=out,
        )


def _upgrade_cache(
    root: Path,
    *,
    dry_run: bool,
    recompute_git_parity: bool,
    out: TextIO,
    session: WarmSession | None = None,
) -> int:
    """Backfill integrity anchors; parity recomputation can downgrade exact to drift."""
    from .materialize import MANIFEST_NAME, _target_lock, _write_manifest
    from .treehash import (
        TreeHashError,
        compute_materialized_tree_hash,
        manifest_digest_fields,
    )

    upgraded = skipped = failed = 0
    for manifest_path in sorted(root.rglob(MANIFEST_NAME)):
        target = manifest_path.parent
        if session is not None and not dry_run:
            # This command can amend any manifest it encounters. Invalidate
            # before inspecting it so no memo survives a partial writer run.
            session.invalidate(target)
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("manifest must be an object")
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("could not load cache manifest %s: %s", manifest_path, exc)
            failed += 1
            continue
        if payload.get("materialized_tree_hash") is not None:
            skipped += 1
            continue
        if payload.get("verified") not in (True, "sampled", "archive-only"):
            continue
        try:
            digest, scope = compute_materialized_tree_hash(target)
        except TreeHashError as exc:
            logger.warning("could not upgrade cache shelf %s: %s", target, exc)
            failed += 1
            continue
        upgraded += 1
        if not dry_run:
            payload.update(manifest_digest_fields(digest, scope=scope))
            # ADR-0006/#282: serialize this published-shelf rewrite with the
            # target sweep that owns its sibling manifest staging debris.
            # `target.name` (not a commit SHA) makes `_sweep_target_debris`'s `.{name}.tmp-*` glob agree with the manifest staging prefix `.{name}.tmp-manifest-` for non-canonical shelf directory names.
            with _target_lock(root, target, target.name):
                _write_manifest(manifest_path, payload)
    print(
        f"Upgraded {upgraded} shelves, skipped {skipped} (already had digest), "
        f"failed {failed} (see warnings)",
        file=out,
    )
    if recompute_git_parity:
        from .materialize import recompute_github_git_parity
        from .tree import GitHubTreeSource

        github_api = os.environ.get("LEITIR_GITHUB_API_BASE_URL")
        tree_source = GitHubTreeSource(
            token=_github_token(),
            base_url=github_api or "https://api.github.com",
        )
        parity_updated, parity_skipped, parity_failed = recompute_github_git_parity(
            root, tree_source=tree_source, dry_run=dry_run
        )
        print(
            f"Recomputed Git parity for {parity_updated} shelves, skipped "
            f"{parity_skipped}, failed {parity_failed} (see warnings)",
            file=out,
        )
        failed += parity_failed
    return int(ExitCode.SUCCESS if failed == 0 else ExitCode.CORPUS_FAILURE)


def _gc_abandoned_staging(root: Path) -> int:
    """Remove writer staging/backup directories while holding their target lock."""
    from .materialize import (
        MANIFEST_NAME,
        MaterializationError,
        _assert_target_confinement,
        _file_lock,
        _fsync_directory,
        read_valid_manifest,
    )

    root = root.expanduser().absolute()
    if root.is_symlink():
        raise MaterializationError(f"corpus root is a symbolic link: {root}")
    root.mkdir(parents=True, exist_ok=True)
    _assert_target_confinement(root, root / ".locks")
    (root / ".locks").mkdir(exist_ok=True)
    removed = 0
    candidates: list[tuple[Path, Path, str]] = []
    repos_root = root / "repos"
    if not repos_root.exists():
        return 0
    _assert_target_confinement(root, repos_root)
    for parent, directories, _files in os.walk(
        repos_root, topdown=True, followlinks=False
    ):
        directories.sort()
        parent_path = Path(parent)
        is_repo_target_parent = len(parent_path.relative_to(repos_root).parts) == 3
        retained: list[str] = []
        for name in directories:
            path = parent_path / name
            if path.is_symlink():
                if is_repo_target_parent and (".tmp-" in name or ".old-" in name):
                    raise MaterializationError(
                        f"refusing symbolic-link staging candidate: {path}"
                    )
                retained.append(name)
                continue
            if not is_repo_target_parent:
                retained.append(name)
                continue
            marker = (
                ".tmp-" if ".tmp-" in name else ".old-" if ".old-" in name else None
            )
            if marker is None or not name.startswith("."):
                retained.append(name)
                continue
            commit_sha = name[1:].split(marker, 1)[0]
            if len(commit_sha) != 40 or any(
                ch not in "0123456789abcdef" for ch in commit_sha
            ):
                retained.append(name)
                continue
            candidates.append((path, parent_path / commit_sha, marker))
        directories[:] = retained

    generations: dict[Path, list[tuple[Path, str]]] = {}
    for candidate, target, marker in candidates:
        generations.setdefault(target, []).append((candidate, marker))

    ordered_candidates = sorted(candidates, key=lambda item: item[0].as_posix())
    # Remove incomplete staging generations first. A real interrupted publish
    # can leave both staging and backup, and the backup must then be considered
    # as the sole surviving complete generation in this same invocation.
    ordered_candidates.sort(key=lambda item: 0 if item[2] == ".tmp-" else 1)
    for candidate, target, marker in ordered_candidates:
        _assert_target_confinement(root, candidate)
        identity = os.path.normcase(
            str(target.absolute().relative_to(root))
        ).encode("utf-8")
        lock_path = root / ".locks" / f"{hashlib.sha256(identity).hexdigest()}.lock"
        with _file_lock(lock_path):
            _assert_target_confinement(root, candidate)
            if marker == ".old-" and not target.exists():
                # A crash after target -> backup but before staging -> target
                # leaves this as the only valid cache generation. Restore only
                # one intact, fully load-time-verified generation.
                surviving = [
                    path
                    for path, kind in generations[target]
                    if kind == ".old-" and path.exists()
                ]
                if surviving != [candidate]:
                    continue
                try:
                    payload = json.loads(
                        (candidate / MANIFEST_NAME).read_text(encoding="utf-8")
                    )
                except (OSError, UnicodeError, json.JSONDecodeError):
                    continue
                if not isinstance(payload, dict):
                    continue
                owner = payload.get("owner")
                repo = payload.get("repo")
                host = payload.get("host")
                commit_sha_value = payload.get("commit_sha")
                if not (
                    isinstance(owner, str)
                    and isinstance(repo, str)
                    and isinstance(host, str)
                    and isinstance(commit_sha_value, str)
                ):
                    continue
                commit_sha = commit_sha_value
                if (
                    commit_sha != target.name
                    or read_valid_manifest(
                        candidate,
                        owner,
                        repo,
                        commit_sha,
                        host=host,
                    )
                    is None
                ):
                    continue
                os.replace(candidate, target)
                _fsync_directory(target.parent)
                continue
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                # A concurrent writer or gc already removed it.
                continue
            if stat.S_ISLNK(metadata.st_mode):
                raise MaterializationError(
                    f"refusing symbolic-link staging candidate: {candidate}"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                raise MaterializationError(
                    f"refusing non-directory staging candidate: {candidate}"
                )
            shutil.rmtree(candidate)
            removed += 1
    return removed


def _run_corpus_command(
    args: argparse.Namespace,
    *,
    resolver_factory: Callable[[str | None], object],
    code_search_factory: Callable[[str | None], object],
    out: TextIO,
    err: TextIO,
    session: WarmSession | None = None,
) -> int:
    # Looked up dynamically through the ``leitir.cli`` module object (rather
    # than imported by name) so that ``monkeypatch.setattr("leitir.cli.
    # _resolve_corpus_spec", ...)`` -- used by tests/test_corpus_cli.py --
    # keeps working after this function moved out of cli.py (issue #271).
    from . import cli as _cli_mod
    from .corpus import INDEX_NAME, materialize_source, remove_source
    from .docpointers import POINTERS_NAME

    try:
        require_manifest_authentication = False
        if getattr(args, "require_manifest_auth", False):
            require_manifest_authentication = True
        root = _corpus_root(args, err)
        if args.command == "list":
            list_options: _WarmSessionOptions = {}
            if session is not None:
                list_options["session"] = session
            _corpus_list(
                root,
                as_json=args.as_json,
                out=out,
                err=err,
                require_auth=require_manifest_authentication,
                trusted_keys=getattr(args, "trusted_keys", None),
                **list_options,
            )
            return int(ExitCode.SUCCESS)
        if args.command == "upgrade-cache":
            return _upgrade_cache(
                root,
                dry_run=args.dry_run,
                recompute_git_parity=args.recompute_git_parity,
                out=out,
                session=session,
            )
        if args.command == "gc":
            removed = _gc_abandoned_staging(root)
            print(
                json.dumps({"removed": removed, "root": str(root)}, sort_keys=True),
                file=out,
            )
            return int(ExitCode.SUCCESS)
        if args.command == "index":
            from .index.builder import (
                build_shelf_index,
                ineligible_shelf_conditions,
                shelves_from_corpus,
            )

            # issue #268: deliberately not `strict=True` here. A corrupt
            # catalog makes `shelves_from_corpus` return an empty tuple,
            # which the very next line already turns into a raised
            # `ValueError` -- the command fails either way (never a false
            # success), this only affects the wording of the error. Left
            # as the existing default rather than duplicating the check
            # `_require_all_shelves_authenticated` below already performs
            # strictly when `--require-manifest-auth` is set.
            shelves = shelves_from_corpus(root, tuple(args.scopes))
            if not shelves:
                raise ValueError("the corpus has no materialized shelves to index")
            if require_manifest_authentication:
                if session is None:
                    _require_all_shelves_authenticated(root, args, err=err)
                else:
                    _require_all_shelves_authenticated(root, args, err=err, session=session)
            built_paths: list[str] = []
            skipped_ineligible: list[dict[str, object]] = []
            hard_errors: list[dict[str, object]] = []
            for shelf in shelves:
                identity = {
                    "commit": shelf.commit,
                    "host": shelf.host,
                    "owner": shelf.owner,
                    "repo": shelf.repo,
                }
                specification = f"{shelf.host}:{shelf.slug}@{shelf.commit}"
                try:
                    conditions = ineligible_shelf_conditions(root, shelf)
                except Exception as exc:
                    message = redact(str(exc))
                    hard_errors.append(
                        {"error": message, "shelf": identity, "spec": specification}
                    )
                    print(f"leitir: error: could not inspect shelf {specification}: {message}", file=err)
                    continue
                if conditions:
                    skipped_ineligible.append(
                        {
                            "conditions": list(conditions),
                            "shelf": identity,
                            "spec": specification,
                        }
                    )
                    print(
                        f"leitir: skipped ineligible shelf {specification}: "
                        + ", ".join(conditions),
                        file=err,
                    )
                    continue
                try:
                    built_paths.append(str(build_shelf_index(root, shelf).absolute()))
                except Exception as exc:
                    message = redact(str(exc))
                    hard_errors.append(
                        {"error": message, "shelf": identity, "spec": specification}
                    )
                    print(f"leitir: error: could not index shelf {specification}: {message}", file=err)
            print(
                json.dumps(
                    {
                        "count": len(built_paths),
                        "hard_errors": hard_errors,
                        "indexes": built_paths,
                        "schema_version": 1,
                        "skipped_ineligible": skipped_ineligible,
                    },
                    sort_keys=True,
                ),
                file=out,
            )
            if hard_errors:
                return int(ExitCode.CORPUS_FAILURE)
            if built_paths:
                return int(ExitCode.SUCCESS)
            # Every shelf was deterministically skipped as ineligible: a
            # clean no-op with named reasons, not a failure (audit
            # 2026-08-23 P3 — previously exit 1 with no summary line, which
            # read like an error).
            print(
                f"leitir: nothing to index: {len(skipped_ineligible)} shelf(s) "
                "skipped as ineligible (see skipped_ineligible above); "
                "no errors occurred — this is exit code 4 (NOTHING_INDEXED), "
                "not a failure",
                file=err,
            )
            return int(ExitCode.NOTHING_INDEXED)
        if args.command == "trust":
            from .corpus import record_trust

            if require_manifest_authentication:
                if session is None:
                    _require_all_shelves_authenticated(root, args, err=err)
                else:
                    _require_all_shelves_authenticated(root, args, err=err, session=session)
            if session is None:
                entry, untyped_result, target = record_trust(args.spec, root)
            else:
                entry, untyped_result, target = record_trust(args.spec, root, session=session)
            result = cast("TrustScore", untyped_result)
            payload = dict(
                result.as_dict(),
                schema_version=1,
                spec=args.spec,
                name=entry["name"],
                path=str(target.absolute()),
            )
            if args.as_json:
                print(json.dumps(payload, indent=2, sort_keys=True), file=out)
            else:
                print(f"{entry['name']} trust={result.score}", file=out)
                for factor in result.breakdown:
                    print(
                        f"  {factor['factor']}: {factor['score']}/100 "
                        f"weight={factor['weight']} evidence={json.dumps(factor['evidence'], sort_keys=True)}",
                        file=out,
                    )
            return int(ExitCode.SUCCESS)
        if args.command == "diff":
            from .check import CheckIndexError, UnsupportedLanguageError
            from .corpus import materialize_source
            from .diff import GitHubReleaseNotes, diff_packages
            from .materialize import _target_lock, read_valid_manifest

            token = _github_token()
            resolver = resolver_factory(token)
            heads = code_search_factory(token)
            cwd = Path(args.cwd or Path.cwd()).expanduser().absolute()
            impact_path = (
                Path(args.impact).expanduser().absolute()
                if getattr(args, "impact", None)
                else None
            )
            fetch_options: _FetchOptions = {}
            if os.environ.get("LEITIR_CODELOAD_BASE_URL"):
                fetch_options["base_url"] = os.environ["LEITIR_CODELOAD_BASE_URL"]
            if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
                fetch_options["tree_base_url"] = os.environ[
                    "LEITIR_GITHUB_API_BASE_URL"
                ]
            writer_session: _WarmSessionOptions = (
                {"session": session} if session is not None else {}
            )
            notes_options: _BaseUrlOptions = {}
            if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
                notes_options["base_url"] = os.environ["LEITIR_GITHUB_API_BASE_URL"]
            # An injected diff implementation is an explicit test/embedding
            # seam and may not consume shelf bytes at all. Only the built-in
            # implementation needs leitir's target-lock orchestration.
            if diff_packages.__module__ != "leitir.diff":
                try:
                    report = diff_packages(
                        args.spec_a,
                        args.spec_b,
                        corpus_root=root,
                        resolver=resolver,
                        heads=heads,
                        cwd=cwd,
                        release_notes=GitHubReleaseNotes(token, **notes_options),
                        fetch_options=fetch_options,
                        impact_path=impact_path,
                    )
                except (UnsupportedLanguageError, FileNotFoundError) as exc:
                    print(f"leitir: error: {redact(str(exc))}", file=err)
                    return int(ExitCode.MALFORMED_USAGE)
                except CheckIndexError as exc:
                    print(f"leitir: error: {redact(str(exc))}", file=err)
                    return int(ExitCode.CORPUS_FAILURE)
                if args.as_json:
                    print(report.to_json(), file=out)
                else:
                    _write_diff_human(report, out)
                if report.impact is not None:
                    _print_diff_impact_summary(report.impact, err)
                return int(ExitCode.SUCCESS)
            prepared: dict[str, tuple[Path, RepoScope, str]] = {}
            pinned_resolutions: dict[tuple[str, str, str], object] = {}
            for raw in (args.spec_a, args.spec_b):
                parsed = parse_corpus_spec(raw)
                resolved, tag, version_source, _detection = _cli_mod._resolve_corpus_spec(
                    parsed, resolver, heads, cwd, err, root
                )
                scope = cast(RepoScope, getattr(resolved, "scope", resolved))
                materialize_host = (
                    parsed.host or "github.com"
                    if parsed.ecosystem is None
                    else getattr(resolved, "host", "github.com")
                )
                def announce_fetch(raw_spec: str = raw) -> None:
                    print(f"leitir: materializing {raw_spec}", file=err)

                path = materialize_source(
                    raw,
                    resolved,
                    root=root,
                    name=parsed.name,
                    tag=tag,
                    version_source=version_source,
                    host=materialize_host,
                    repository_resolver=(
                        getattr(resolver, "_repository_resolvers", {}).get(
                            materialize_host
                        )
                        if materialize_host != "github.com"
                        else None
                    ),
                    on_fetch=announce_fetch,
                    **writer_session,
                    **fetch_options,
                )
                prepared[raw] = (path, scope, materialize_host)
                pinned_ref = getattr(resolved, "ref", None)
                pinned_version = getattr(pinned_ref, "version", None)
                if (
                    parsed.ecosystem is not None
                    and isinstance(pinned_version, str)
                ):
                    pinned_resolutions[
                        (parsed.ecosystem, parsed.name, pinned_version)
                    ] = resolved

            with ExitStack() as diff_locks:
                unique = {
                    path.absolute().as_posix(): (path, scope, materialize_host)
                    for path, scope, materialize_host in prepared.values()
                }
                for _identity, (path, scope, materialize_host) in sorted(
                    unique.items()
                ):
                    diff_locks.enter_context(_target_lock(root, path, scope.commit_sha))
                    owner, repo = scope.slug.rsplit("/", 1)
                    if materialize_host == "git.sr.ht" and not owner.startswith("~"):
                        owner = f"~{owner}"
                    if (
                        read_valid_manifest(
                            path,
                            owner,
                            repo,
                            scope.commit_sha,
                            host=materialize_host,
                        )
                        is None
                    ):
                        raise ValueError(
                            f"materialized source failed load-time verification: {path}"
                        )
                    if require_manifest_authentication:
                        checked_manifest = read_valid_manifest(
                            path, owner, repo, scope.commit_sha, host=materialize_host
                        )
                        if checked_manifest is None:
                            raise ValueError(
                                f"materialized source failed load-time verification: {path}"
                            )
                        _require_authenticated_manifest(
                            checked_manifest,
                            path,
                            trusted_keys=args.trusted_keys,
                            err=err,
                        )

                def locked_materializer(
                    raw: str, *_args: object, **_kwargs: object
                ) -> Path:
                    return prepared[raw][0]

                try:
                    report = diff_packages(
                        args.spec_a,
                        args.spec_b,
                        corpus_root=root,
                        resolver=(
                            _CachedFirstResolverFacade(resolver, pinned_resolutions)
                            if pinned_resolutions
                            else resolver
                        ),
                        heads=heads,
                        cwd=cwd,
                        materializer=locked_materializer,
                        release_notes=GitHubReleaseNotes(token, **notes_options),
                        fetch_options=fetch_options,
                        on_resolve=lambda spec: print(
                            f"leitir: resolving {spec} (cwd={cwd})", file=err
                        ),
                        impact_path=impact_path,
                    )
                except (UnsupportedLanguageError, FileNotFoundError) as exc:
                    print(f"leitir: error: {redact(str(exc))}", file=err)
                    return int(ExitCode.MALFORMED_USAGE)
                except CheckIndexError as exc:
                    print(f"leitir: error: {redact(str(exc))}", file=err)
                    return int(ExitCode.CORPUS_FAILURE)
            if args.as_json:
                print(report.to_json(), file=out)
            else:
                _write_diff_human(report, out)
            if report.impact is not None:
                _print_diff_impact_summary(report.impact, err)
            return int(ExitCode.SUCCESS)
        if args.command == "remove":
            parsed = parse_corpus_spec(args.spec)
            materialize_host = parsed.host or "github.com"
            if parsed.ecosystem is None and parsed.ref_kind == "head":
                owner, repo = parsed.name.split("/", 1)
                sha = None
            else:
                token = _github_token()
                resolver = resolver_factory(token)
                heads = code_search_factory(token)
                resolved, _, _, _ = _cli_mod._resolve_corpus_spec(
                    parsed, resolver, heads, Path.cwd(), err, root
                )
                typed_scope = cast(RepoScope, getattr(resolved, "scope", resolved))
                owner, repo = typed_scope.slug.split("/", 1)
                sha = typed_scope.commit_sha
                if parsed.ecosystem is not None:
                    materialize_host = getattr(resolved, "host", "github.com")
            removed = remove_source(
                root, owner, repo, sha, host=materialize_host
            )
            print(
                f"leitir: {'removed' if removed else 'not found'} {args.spec}", file=err
            )
            return int(ExitCode.SUCCESS)
        if args.command == "clean":
            shutil.rmtree(root / "repos", ignore_errors=True)
            shutil.rmtree(root / "api", ignore_errors=True)
            shutil.rmtree(root / "examples", ignore_errors=True)
            (root / INDEX_NAME).unlink(missing_ok=True)
            (root / POINTERS_NAME).unlink(missing_ok=True)
            print(f"leitir: cleaned {root}", file=err)
            return int(ExitCode.SUCCESS)
        if args.command == "export":
            from .snapshot import export_corpus

            if require_manifest_authentication:
                if session is None:
                    _require_all_shelves_authenticated(root, args, err=err)
                else:
                    _require_all_shelves_authenticated(root, args, err=err, session=session)
            lock_path, tarball_path = export_corpus(args.output, root=root)
            lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
            print(
                json.dumps(
                    {
                        "lock": str(lock_path),
                        "lock_sha256": lock_sha256,
                        "tarball": str(tarball_path),
                    },
                    sort_keys=True,
                ),
                file=out,
            )
            print(f"leitir: exported {lock_path}", file=err)
            return int(ExitCode.SUCCESS)
        if args.command == "import":
            from .snapshot import import_corpus

            entries = import_corpus(
                args.lock,
                root=root,
                expected_lock_sha256=args.lock_sha256,
            )
            print(
                json.dumps(
                    {"root": str(root), "sources": len(entries)}, sort_keys=True
                ),
                file=out,
            )
            print(f"leitir: imported {len(entries)} source(s) into {root}", file=err)
            return int(ExitCode.SUCCESS)
        if args.command == "sbom":
            from .corpus import load_sources
            from .materialize import (
                _assert_target_confinement,
                _file_lock,
                _target_lock,
            )
            from .sbom import generate_sbom

            cwd = Path(args.cwd or Path.cwd()).expanduser().absolute()
            # issue #268: strict, and deliberately the *first* read of this
            # invocation. A non-strict read here would silently treat a
            # corrupt catalog as `[]` and let the command proceed as if
            # the corpus were empty. Failing here first (before any SBOM
            # content is assembled) is what rules that out; the unlocked
            # non-strict re-read below is a *different*, narrower use (see
            # its own comment) that relies on equality-comparison, not on
            # `strict`, to catch corruption in the lock-acquisition window.
            entries = load_sources(root, strict=True)
            targets: dict[str, tuple[Path, str]] = {}
            for entry in entries:
                relative = Path(entry["path"])
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"invalid shelved source path: {entry['path']!r}")
                target = root / relative
                _assert_target_confinement(root, target)
                if require_manifest_authentication:
                    from .materialize import read_valid_manifest

                    auth_manifest = read_valid_manifest(
                        target,
                        entry["owner"],
                        entry["repo"],
                        entry["commit_sha"],
                        host=entry["host"],
                    )
                    if auth_manifest is None:
                        raise ValueError(
                            f"materialized source failed load-time verification: {target}"
                        )
                    _require_authenticated_manifest(
                        auth_manifest,
                        target,
                        trusted_keys=getattr(args, "trusted_keys", None),
                        err=err,
                    )
                targets[target.absolute().as_posix()] = (
                    target,
                    str(entry["commit_sha"]),
                )
            with ExitStack() as sbom_locks:
                for _identity, (target, commit_sha) in sorted(targets.items()):
                    sbom_locks.enter_context(_target_lock(root, target, commit_sha))
                sbom_locks.enter_context(_file_lock(root / ".sources.lock"))
                # Deliberately non-strict: this re-read only ever feeds an
                # equality check against the already-validated `entries`
                # above. If the catalog were to become corrupt in the
                # narrow window between the two reads, the non-strict
                # recovery still returns `[]`, which differs from the
                # non-empty `entries` and trips the mismatch check below --
                # corruption here is caught by the comparison, not by
                # `strict`.
                if load_sources(root) != entries:
                    raise ValueError(
                        "corpus index changed while acquiring SBOM read locks"
                    )
                document = generate_sbom(root, cwd, args.format)
            print(json.dumps(document, indent=2, sort_keys=True), file=out)
            print(f"leitir: generated {args.format} SBOM from {root}", file=err)
            return int(ExitCode.SUCCESS)

        token = _github_token()
        resolver = resolver_factory(token)
        if args.command == "lock":
            from .corpus import lock_project

            cwd = Path(args.cwd or Path.cwd()).expanduser().absolute()
            fetch_options = cast(_FetchOptions, {"verify": not args.no_verify})
            if os.environ.get("LEITIR_CODELOAD_BASE_URL"):
                fetch_options["base_url"] = os.environ["LEITIR_CODELOAD_BASE_URL"]
            if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
                fetch_options["tree_base_url"] = os.environ[
                    "LEITIR_GITHUB_API_BASE_URL"
                ]
            failures: list[dict[str, str]] = []
            summary = lock_project(
                cwd,
                _LocalFirstLockResolver(resolver, root, err),
                root=root,
                on_resolve=lambda spec: print(f"leitir: resolving {spec}", file=err),
                on_fetch=lambda spec: print(f"leitir: materializing {spec}", file=err),
                on_failure=lambda spec, reason: print(
                    f"leitir: failed {spec}: {redact(reason)}", file=err
                ),
                best_effort=args.best_effort,
                failures=failures,
                **fetch_options,
            )
            lock_payload: dict[str, object] = {
                "cwd": str(cwd),
                "dependencies": summary,
            }
            if args.best_effort:
                lock_payload["failures"] = failures
            print(json.dumps(lock_payload, sort_keys=True), file=out)
            if args.best_effort and not summary and failures:
                return int(ExitCode.CORPUS_FAILURE)
            return int(ExitCode.SUCCESS)
        heads = code_search_factory(token)
        cwd = Path(args.cwd or Path.cwd()).expanduser().absolute()
        paths: list[tuple[Path, str | None, dict[str, object], str, str]] = []
        fetch_options = cast(_FetchOptions, {})
        if os.environ.get("LEITIR_CODELOAD_BASE_URL"):
            fetch_options["base_url"] = os.environ["LEITIR_CODELOAD_BASE_URL"]
        fetch_options["verify"] = not args.no_verify
        if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
            fetch_options["tree_base_url"] = os.environ["LEITIR_GITHUB_API_BASE_URL"]
        materializer_session: _WarmSessionOptions = (
            {"session": session} if session is not None else {}
        )
        raw_specs = args.specs if hasattr(args, "specs") else [args.spec]
        index_paths: list[Path] = []
        index_payloads: list[dict[str, object]] = []
        seen_targets: dict[
            str, tuple[Path, str | None, dict[str, object], str]
        ] = {}
        resolved_requests: list[
            tuple[
                str,
                CorpusSpec,
                RepoScope | ResolvedPackage,
                str | None,
                str | None,
                str,
                RepoScope,
            ]
        ] = []
        for raw in raw_specs:
            print(f"leitir: resolving {raw} (cwd={cwd})", file=err)
            parsed = parse_corpus_spec(raw)
            resolved, tag, version_source, detection_source = _cli_mod._resolve_corpus_spec(
                parsed, resolver, heads, cwd, err, root
            )
            if version_source == "lockfile":
                resolved_package = cast(Any, resolved)
                print(
                    f"leitir: {parsed.name}: version {resolved_package.ref.version} from {detection_source}",
                    file=err,
                )
            materialize_host = (
                parsed.host or "github.com"
                if parsed.ecosystem is None
                else getattr(resolved, "host", "github.com")
            )
            scope = cast(RepoScope, getattr(resolved, "scope", resolved))
            resolved_requests.append(
                (
                    raw,
                    parsed,
                    resolved,
                    tag,
                    version_source,
                    materialize_host,
                    scope,
                )
            )

        resolved_specs: list[
            tuple[
                str,
                CorpusSpec,
                RepoScope | ResolvedPackage,
                str | None,
                str | None,
                str,
                RepoScope,
                Path,
            ]
        ] = []
        materialized_targets: dict[str, Path] = {}
        for request in resolved_requests:
            raw, parsed, resolved, tag, version_source, materialize_host, scope = (
                request
            )
            from .materialize import target_path

            scope_owner, scope_repo = scope.slug.rsplit("/", 1)
            if materialize_host == "git.sr.ht" and not scope_owner.startswith("~"):
                scope_owner = f"~{scope_owner}"
            expected_path = target_path(
                root,
                scope_owner,
                scope_repo,
                scope.commit_sha,
                host=materialize_host,
            ).absolute()
            # Hosted repository identities are case-insensitive even when the
            # local filesystem is not. Collapse aliases before any writer runs.
            target_identity = os.path.normcase(str(expected_path)).casefold()
            materialized_path = materialized_targets.get(target_identity)
            if materialized_path is None:
                commit_published_at = None
                timestamp_resolver = getattr(
                    resolver, "published_at_for_commit", None
                )
                if (
                    parsed.ecosystem is None
                    and materialize_host == "github.com"
                    and parsed.ref_kind != "sha"
                    and callable(timestamp_resolver)
                ):
                    from .resolver import ResolutionError

                    try:
                        commit_published_at = timestamp_resolver(
                            scope.slug, scope.commit_sha
                        )
                    except ResolutionError as exc:
                        logger.warning(
                            "commit publication timestamp unavailable for %s@%s: %s",
                            scope.slug,
                            scope.commit_sha,
                            exc,
                        )
                def announce_fetch(raw_spec: str = raw) -> None:
                    print(f"leitir: materializing {raw_spec}", file=err)

                materialized_path = materialize_source(
                    raw,
                    resolved,
                    root=root,
                    name=parsed.name,
                    tag=tag,
                    version_source=version_source,
                    published_at=commit_published_at,
                    host=materialize_host,
                    repository_resolver=(
                        getattr(resolver, "_repository_resolvers", {}).get(
                            materialize_host
                        )
                        if materialize_host != "github.com"
                        else None
                    ),
                    on_fetch=announce_fetch,
                    **materializer_session,
                    **fetch_options,
                )
                materialized_targets[target_identity] = materialized_path
            resolved_specs.append(
                (
                    raw,
                    parsed,
                    resolved,
                    tag,
                    version_source,
                    materialize_host,
                    scope,
                    materialized_path,
                )
            )

        from .materialize import _target_lock, read_valid_manifest

        with ExitStack() as read_locks:
            # Every process acquires each unique target lock in one global order.
            # Materialization above holds at most one writer lock at a time.
            locks = sorted(
                (
                    (identity, path.name, path)
                    for identity, path in materialized_targets.items()
                ),
                key=lambda item: (item[0], item[1]),
            )
            for _lock_identity, commit_sha, path in locks:
                read_locks.enter_context(_target_lock(root, path, commit_sha))

            for (
                raw,
                _parsed,
                _resolved,
                _tag,
                _version_source,
                materialize_host,
                scope,
                path,
            ) in resolved_specs:
                target_identity = os.path.normcase(str(path.absolute())).casefold()
                duplicate = seen_targets.get(target_identity)
                if duplicate is not None:
                    duplicate_path, subpath, manifest, commit_sha = duplicate
                    paths.append((duplicate_path, subpath, manifest, raw, commit_sha))
                    continue
                manifest_owner, manifest_repo = scope.slug.rsplit("/", 1)
                if materialize_host == "git.sr.ht" and not manifest_owner.startswith(
                    "~"
                ):
                    manifest_owner = f"~{manifest_owner}"
                valid_manifest = read_valid_manifest(
                    path,
                    manifest_owner,
                    manifest_repo,
                    scope.commit_sha,
                    host=materialize_host,
                )
                if valid_manifest is None:
                    raise ValueError(
                        f"materialized source failed load-time verification: {path}"
                    )
                manifest = valid_manifest
                if require_manifest_authentication:
                    _require_authenticated_manifest(
                        manifest,
                        path,
                        trusted_keys=args.trusted_keys,
                        err=err,
                    )
                recorded_subpath = manifest.get("subpath")
                cached_subpath = (
                    recorded_subpath if isinstance(recorded_subpath, str) else None
                )
                seen_targets[target_identity] = (
                    path.absolute(),
                    cached_subpath,
                    manifest,
                    scope.commit_sha,
                )
                if args.command == "info":
                    from .info import build_brief_info, build_info

                    print(
                        f"leitir: ensuring analysis indexes and trust for {raw}",
                        file=err,
                    )
                    if args.brief:
                        brief_document = (
                            build_brief_info(raw, corpus_root=root, session=session)
                            if session is not None
                            else build_brief_info(raw, corpus_root=root)
                        )
                        if args.as_json:
                            print(
                                json.dumps(brief_document, indent=2, sort_keys=True),
                                file=out,
                            )
                        else:
                            brief_provenance = cast(
                                dict[str, Any], brief_document["provenance"]
                            )
                            brief_api = cast(dict[str, Any], brief_document["api"])
                            brief_examples = cast(
                                dict[str, Any], brief_document["examples"]
                            )
                            print(
                                f"{raw} {brief_provenance['owner']}/{brief_provenance['repo']}"
                                f"@{brief_provenance['commit_sha']}",
                                file=out,
                            )
                            for symbol in brief_api["top_symbols"]:
                                print(
                                    f"  {symbol['kind']} {symbol['qualified_name']}"
                                    f"{symbol['signature'] or ''}",
                                    file=out,
                                )
                            if brief_examples["top"]:
                                example = brief_examples["top"][0]
                                print(
                                    f"  example: {example['path']}:{example['line']}",
                                    file=out,
                                )
                            print(f"trust: {brief_document['trust']}/100", file=out)
                            print(brief_document["citation"], file=out)
                        continue
                    document = (
                        build_info(raw, corpus_root=root, session=session)
                        if session is not None
                        else build_info(raw, corpus_root=root)
                    )
                    if args.as_json:
                        print(json.dumps(document, indent=2, sort_keys=True), file=out)
                    else:
                        provenance = cast(dict[str, Any], document["provenance"])
                        api = cast(dict[str, Any], document["api"])
                        examples = cast(dict[str, Any], document["examples"])
                        trust = cast(dict[str, Any], document["trust"])
                        license_info = cast(dict[str, Any], document["license"])
                        license_routing = cast(dict[str, Any], document["routing"])
                        parity = cast(dict[str, Any], document["parity"])
                        document_paths = cast(dict[str, Any], document["paths"])
                        print(
                            f"{raw} {provenance['owner']}/{provenance['repo']}@{provenance['commit_sha']}",
                            file=out,
                        )
                        print(f"tree: {document_paths['tree']}", file=out)
                        print(
                            f"version: {provenance['version'] or 'unknown'} "
                            f"source: {provenance['source'] or 'unknown'} "
                            f"verified: {provenance['verified'] if provenance['verified'] is not None else 'unknown'}",
                            file=out,
                        )
                        print(
                            f"license: {license_info['identifier'] or 'unknown'} "
                            f"({license_info['method']}, {license_info['confidence']})",
                            file=out,
                        )
                        print(
                            f"routing: {license_routing['verdict']} "
                            f"({license_routing['reason']})",
                            file=out,
                        )
                        print(f"parity: {parity['parity']}", file=out)
                        print(
                            f"api: {api['symbols']} symbols ({api['method'] or 'unknown'}) "
                            f"{api['index_path']}",
                            file=out,
                        )
                        for symbol in api["top_symbols"][:5]:
                            print(
                                f"  {symbol['kind']} {symbol['qualified_name']}"
                                f"{symbol['signature'] or ''}",
                                file=out,
                            )
                        print(
                            f"examples: {examples['count']} {examples['index_path']}",
                            file=out,
                        )
                        if examples["top"]:
                            example = examples["top"][0]
                            print(
                                f"  example: {example['path']}:{example['line']}",
                                file=out,
                            )
                        print(f"trust: {trust['score']}/100", file=out)
                    continue
                if args.command in {"api", "examples"}:
                    from .apisurface import extract_api_surface
                    from .corpus import load_sources, read_api_index, write_api_index

                    # issue #268: deliberately non-strict. `path` was
                    # produced moments earlier in this same command by
                    # `materialize_source`, which always ends by upserting
                    # into the catalog with `strict=True` -- a corrupt
                    # catalog would already have aborted the command before
                    # reaching here. If it were somehow corrupted in the
                    # narrow window since, `next()` raises `StopIteration`
                    # (no entry can match an empty list), which still fails
                    # the command rather than succeeding falsely.
                    entry = next(
                        entry
                        for entry in load_sources(root)
                        if (root / entry["path"]).absolute() == path.absolute()
                    )
                    recorded_subpath = manifest.get("subpath")
                    scan_path = (
                        path / recorded_subpath
                        if isinstance(recorded_subpath, str)
                        else path
                    )
                    language_hint = manifest.get("ecosystem")
                    index = read_api_index(root, entry, manifest)
                    if index is None or args.command == "api":
                        print(f"leitir: extracting API surface for {raw}", file=err)
                        index = extract_api_surface(
                            scan_path,
                            str(language_hint)
                            if language_hint in {"pypi", "npm"}
                            else None,
                        )
                        api_path = write_api_index(root, entry, manifest, index)
                    else:
                        from .corpus import api_index_path

                        api_path = api_index_path(root, entry, manifest).absolute()
                    if args.command == "api":
                        from .info import _top_symbols

                        index_paths.append(api_path)
                        symbols = index.get("symbols")
                        records = symbols if isinstance(symbols, list) else []
                        by_kind = {
                            kind: sum(
                                1
                                for symbol in records
                                if isinstance(symbol, dict)
                                and symbol.get("kind") == kind
                            )
                            for kind in ("function", "class", "method", "constant")
                        }
                        methods = index.get("methods")
                        known_methods = (
                            sorted(
                                item for item in methods if item in {"ast", "heuristic"}
                            )
                            if isinstance(methods, list)
                            else []
                        )
                        index_payloads.append(
                            {
                                "schema_version": 1,
                                "index_path": str(api_path.absolute()),
                                "symbols": len(records),
                                "by_kind": by_kind,
                                "method": (
                                    "ast"
                                    if known_methods == ["ast"]
                                    else "heuristic"
                                    if known_methods
                                    else None
                                ),
                                "top_symbols": _top_symbols(index),
                            }
                        )
                    else:
                        from .corpus import write_examples_index
                        from .docpointers import regenerate_pointers
                        from .examples import extract_examples

                        print(f"leitir: extracting examples for {raw}", file=err)
                        examples_index = extract_examples(path, index)
                        examples_path = write_examples_index(
                            root, entry, manifest, examples_index
                        )
                        index_paths.append(examples_path)
                        snippets = examples_index.get("snippets")
                        index_payloads.append(
                            {
                                "schema_version": 1,
                                "index_path": str(examples_path.absolute()),
                                "count": len(snippets)
                                if isinstance(snippets, list)
                                else 0,
                                "snippets": snippets
                                if isinstance(snippets, list)
                                else [],
                            }
                        )
                        regenerate_pointers(root)
                    continue
                recorded_subpath = manifest.get("subpath")
                subpath = (
                    recorded_subpath if isinstance(recorded_subpath, str) else None
                )
                paths.append(
                    (path.absolute(), subpath, manifest, raw, scope.commit_sha)
                )
            if args.command in {"api", "examples"}:
                if args.command == "api":
                    from .docpointers import regenerate_pointers

                    regenerate_pointers(root)
                if args.as_json:
                    for payload in index_payloads:
                        print(json.dumps(payload, indent=2, sort_keys=True), file=out)
                else:
                    for index_path, payload in zip(
                        index_paths, index_payloads, strict=False
                    ):
                        print(index_path, file=out)
                        if args.command == "api":
                            top_symbols = cast(
                                list[dict[str, Any]], payload["top_symbols"]
                            )
                            for symbol in top_symbols[:5]:
                                print(
                                    f"{symbol['kind']} {symbol['qualified_name']}"
                                    f"{symbol['signature'] or ''}",
                                    file=out,
                                )
            elif args.command == "get":
                results = []
                for path, subpath, manifest, raw, commit_sha in paths:
                    selected = path
                    if subpath is None:
                        pass
                    else:
                        package_path = path / subpath
                        inside_target = package_path.resolve().is_relative_to(
                            path.resolve()
                        )
                        if inside_target and package_path.exists():
                            selected = package_path
                        else:
                            print(
                                f"leitir: warning: recorded subpath {subpath!r} does not exist "
                                f"inside {path}; using repository root",
                                file=err,
                            )
                    results.append(
                        {
                            "spec": raw,
                            "path": str(selected),
                            "commit_sha": commit_sha,
                            "source": manifest.get("source"),
                            "verified": manifest.get("verified"),
                        }
                    )
                    if not args.as_json:
                        print(selected, file=out)
                if args.as_json:
                    print(
                        json.dumps(
                            {"schema_version": 1, "results": results},
                            indent=2,
                            sort_keys=True,
                        ),
                        file=out,
                    )
            return int(ExitCode.SUCCESS)
    except SearchSpecError as exc:
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.MALFORMED_USAGE)
    except Exception as exc:
        from .manifest_auth import ManifestAuthError

        if isinstance(exc, ManifestAuthError) and getattr(args, "as_json", False):
            print(f"leitir: error: {exc.to_json()}", file=err)
            return int(ExitCode.CORPUS_FAILURE)
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.CORPUS_FAILURE)


def run(
    args: argparse.Namespace,
    *,
    resolver_factory: Callable[[str | None], object],
    code_search_factory: Callable[[str | None], object],
    out: TextIO,
    err: TextIO,
    session: WarmSession | None = None,
) -> int:
    """Dispatch one of the corpus-family verbs and report its outcome.

    Extracted verbatim from the ``if args.command in {"get", "fetch", ...}``
    branch of the pre-#271 ``leitir.cli._main_impl``.
    """
    result = _run_corpus_command(
        args,
        resolver_factory=resolver_factory,
        code_search_factory=code_search_factory,
        out=out,
        err=err,
        session=session,
    )
    if result == int(ExitCode.SUCCESS):
        return mark_successful()
    return result
