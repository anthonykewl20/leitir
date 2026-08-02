"""Thin command-line boundary for Leitir's deterministic code-search kernel."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from enum import IntEnum
import os
import sys
from typing import Protocol, TextIO

from .logging import redact
from .search import (
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchReport,
    SearchSpec,
)


class ExitCode(IntEnum):
    """Stable process outcomes for automation."""

    SUCCESS = 0
    MALFORMED_USAGE = 2
    INFRASTRUCTURE_FAILURE = 3


class TreeSourceFactory(Protocol):
    def __call__(self, token: str | None) -> object: ...


class ResolverFactory(Protocol):
    def __call__(self, token: str | None) -> object: ...


class SearcherFactory(Protocol):
    def __call__(self, tree_source: object) -> object: ...


def _github_token() -> str | None:
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")


def _parse_predicate(raw: str) -> Predicate:
    parts = raw.split(":", 2)
    if len(parts) < 2:
        raise argparse.ArgumentTypeError(
            f"predicate must be kind:value, got {raw!r}"
        )
    kind_str, value = parts[0], parts[1]
    language = parts[2] if len(parts) == 3 else None
    try:
        kind = PredicateKind(kind_str)
    except ValueError:
        valid = ", ".join(k.value for k in PredicateKind)
        raise argparse.ArgumentTypeError(
            f"unknown predicate kind {kind_str!r}; valid kinds: {valid}"
        ) from None
    return Predicate(kind=kind, value=value, language=language)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leitir",
        description="Leitir deterministic code-search kernel",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    search = commands.add_parser("search", help="search a pinned code corpus")

    scope_group = search.add_mutually_exclusive_group(required=False)
    scope_group.add_argument(
        "--repo",
        default=None,
        help="repository slug (owner/repo); requires --commit",
    )
    scope_group.add_argument(
        "--package",
        default=None,
        help="package name; requires --version and --ecosystem",
    )
    scope_group.add_argument(
        "--global",
        action="store_true",
        default=False,
        dest="global_search",
        help="global discovery via GitHub Code Search (coverage is indeterminate)",
    )

    search.add_argument("--commit", default=None, help="40-char git SHA")
    search.add_argument("--version", default=None, help="exact package version")
    search.add_argument(
        "--ecosystem",
        default=None,
        choices=("pypi", "crates", "go"),
        help="package ecosystem",
    )

    search.add_argument(
        "--must",
        type=_parse_predicate,
        action="append",
        default=[],
        dest="must",
        help="required predicate (kind:value[:language])",
    )
    search.add_argument(
        "--should",
        type=_parse_predicate,
        action="append",
        default=[],
        dest="should",
        help="optional boosting predicate (kind:value[:language])",
    )
    search.add_argument(
        "--must-not",
        type=_parse_predicate,
        action="append",
        default=[],
        dest="must_not",
        help="exclusion predicate (kind:value[:language])",
    )

    return parser


def _validate_scope_args(args: argparse.Namespace) -> str | None:
    if args.global_search:
        return None
    if args.repo is not None:
        if args.commit is None:
            return "--repo requires --commit"
        return None
    if args.package is not None:
        if args.version is None:
            return "--package requires --version"
        if args.ecosystem is None:
            return "--package requires --ecosystem"
        return None
    return "one of --repo, --package, or --global is required"


def _build_default_tree_source(token: str | None) -> object:
    from .tree import GitHubTreeSource

    return GitHubTreeSource(token=token)


def _build_default_resolver(token: str | None) -> object:
    from .resolver import (
        CratesResolver,
        GitHubTagResolver,
        GoResolver,
        MultiResolver,
        PyPIResolver,
    )

    tag_resolver = GitHubTagResolver(token=token)
    return MultiResolver(
        pypi=PyPIResolver(tag_resolver),
        crates=CratesResolver(tag_resolver),
        go=GoResolver(tag_resolver),
    )


def _build_default_searcher(tree_source: object) -> object:
    from .adapters import GoAdapter, PythonAdapter, RustAdapter
    from .engine import ScopedSearcher

    return ScopedSearcher(
        tree_source=tree_source,
        adapters=(PythonAdapter(), RustAdapter(), GoAdapter()),
    )


def _build_default_global_searcher(
    code_search: object, tree_source: object
) -> object:
    from .adapters import GoAdapter, PythonAdapter, RustAdapter
    from .discovery_search import GlobalSearcher

    return GlobalSearcher(
        code_search=code_search,
        tree_source=tree_source,
        adapters=(PythonAdapter(), RustAdapter(), GoAdapter()),
        head_resolver=code_search.resolve_head_sha,
        blob_reader=code_search.read_blob_by_path,
    )


def _build_default_code_search(token: str | None) -> object:
    from .discovery_search import GitHubCodeSearchTransport

    return GitHubCodeSearchTransport(token=token)


def _resolve_scope_via_package(
    resolver: object,
    package: str,
    version: str,
    ecosystem: str,
) -> RepoScope:
    from .resolver import Ecosystem, PackageRef

    ref = PackageRef(
        ecosystem=Ecosystem(ecosystem),
        name=package,
        version=version,
    )
    resolved = resolver.resolve(ref)
    return resolved.scope


def _write_summary(report: SearchReport, *, file: TextIO) -> None:
    cov = report.coverage
    print(
        f"coverage={cov.status.value} "
        f"eligible={cov.files_eligible} "
        f"indexed={cov.files_indexed} "
        f"excluded={cov.files_excluded} "
        f"matches={len(report.matches)}",
        file=file,
    )
    for match in report.matches[:10]:
        src = match.source
        kinds = ",".join(k.value for k in match.matched_kinds)
        print(
            f"  {src.path}:{src.start_line}-{src.end_line} "
            f"score={match.score:.1f} [{kinds}] "
            f"{src.slug}@{src.commit_sha[:12]}",
            file=file,
        )
    if len(report.matches) > 10:
        print(f"  ... and {len(report.matches) - 10} more", file=file)


def main(
    argv: Sequence[str] | None = None,
    *,
    tree_source_factory: Callable[[str | None], object] = _build_default_tree_source,
    resolver_factory: Callable[[str | None], object] = _build_default_resolver,
    searcher_factory: Callable[[object], object] = _build_default_searcher,
    code_search_factory: Callable[[str | None], object] = _build_default_code_search,
    global_searcher_factory: Callable[[object, object], object] = _build_default_global_searcher,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Parse one command and wire resolver -> engine -> report."""

    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    scope_error = _validate_scope_args(args)
    if scope_error:
        print(f"leitir: error: {scope_error}", file=err)
        return int(ExitCode.MALFORMED_USAGE)

    if not args.must:
        print("leitir: error: at least one --must predicate is required", file=err)
        return int(ExitCode.MALFORMED_USAGE)

    token = _github_token()

    try:
        if args.global_search:
            spec = SearchSpec(
                mode=SearchMode.GLOBAL_DISCOVERY,
                must=tuple(args.must),
                should=tuple(args.should),
                must_not=tuple(args.must_not),
            )
            code_search = code_search_factory(token)
            tree_source = tree_source_factory(token)
            searcher = global_searcher_factory(code_search, tree_source)
            report = searcher.search(spec)
        else:
            if args.repo is not None:
                scope = RepoScope(slug=args.repo, commit_sha=args.commit)
            else:
                resolver = resolver_factory(token)
                scope = _resolve_scope_via_package(
                    resolver, args.package, args.version, args.ecosystem
                )

            spec = SearchSpec(
                mode=SearchMode.SCOPED_EXHAUSTIVE,
                must=tuple(args.must),
                should=tuple(args.should),
                must_not=tuple(args.must_not),
                scopes=(scope,),
            )

            tree_source = tree_source_factory(token)
            searcher = searcher_factory(tree_source)
            report = searcher.search(spec)
    except Exception as exc:
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.INFRASTRUCTURE_FAILURE)

    print(report.to_json(), file=out)
    _write_summary(report, file=err)
    return int(ExitCode.SUCCESS)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ExitCode",
    "build_parser",
    "main",
]
