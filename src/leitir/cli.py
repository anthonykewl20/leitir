"""Command-line boundary for search and local source materialization.

For offline integration tests, the corpus wiring honors
``LEITIR_CODELOAD_BASE_URL``, ``LEITIR_GITHUB_API_BASE_URL``,
``LEITIR_NPM_BASE_URL``, ``LEITIR_PYPI_BASE_URL``, ``LEITIR_CRATES_BASE_URL``, and
``LEITIR_GO_PROXY_BASE_URL``. Production defaults remain the official HTTPS
services.
"""

from __future__ import annotations

import argparse
import dataclasses
import errno
import hashlib
import importlib.metadata
import json
import logging
import os
import shutil
import stat
import sys
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, TextIO, TypedDict, cast

from .credentials import github_token_from_env
from .logging import redact
from .search import (
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchReport,
    SearchSpec,
    SearchSpecError,
)
from .spec import CorpusSpec, parse_corpus_spec

if TYPE_CHECKING:
    from .diff import DiffReport
    from .resolver import ResolvedPackage, _CorpusResolver, _HeadResolver
    from .trust import TrustScore

logger = logging.getLogger(__name__)

_UPGRADE_CACHE_DESCRIPTION = (
    "Compute and persist load-time tree digests for legacy verified shelves. "
    "NOTE: the digest is computed from the bytes currently on disk. Run this "
    "only on a corpus whose existing contents you already trust (e.g., "
    "immediately after materialization, before any external process could "
    "modify the cache). To re-materialize a suspicious shelf instead, remove "
    "it first with `leitir remove <spec>` and then run `leitir get <spec>`."
)


class ExitCode(IntEnum):
    """Stable process outcomes for automation."""

    SUCCESS = 0
    CORPUS_FAILURE = 1
    MALFORMED_USAGE = 2
    INFRASTRUCTURE_FAILURE = 3


def _is_broken_pipe_error(exc: OSError) -> bool:
    """Return whether an output failure means the pipe reader has gone away."""
    return (
        isinstance(exc, BrokenPipeError)
        or exc.errno == errno.EPIPE
        or (os.name == "nt" and exc.errno == errno.EINVAL)
        or getattr(exc, "winerror", None) in (109, 232)
    )


class _BrokenPipeSafeStdout:
    """Proxy process stdout while suppressing only broken-pipe failures."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def write(self, text: str) -> int:
        try:
            return self._stream.write(text)
        except OSError as exc:
            if not _is_broken_pipe_error(exc):
                raise
            return len(text)

    def flush(self) -> None:
        try:
            self._stream.flush()
        except OSError as exc:
            if not _is_broken_pipe_error(exc):
                raise

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def _protect_stdout_shutdown(out: TextIO) -> TextIO:
    """Keep CPython's shutdown flush from turning a closed pipe into exit 120."""
    if out is not sys.stdout or isinstance(out, _BrokenPipeSafeStdout):
        return out
    protected = cast(TextIO, _BrokenPipeSafeStdout(out))
    sys.stdout = protected
    return protected


def _installed_version() -> str:
    try:
        return importlib.metadata.version("leitir")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


class TreeSourceFactory(Protocol):
    def __call__(self, token: str | None) -> object: ...


class ResolverFactory(Protocol):
    def __call__(self, token: str | None) -> object: ...


class SearcherFactory(Protocol):
    def __call__(self, tree_source: object) -> object: ...


class _EndpointOptions(TypedDict, total=False):
    base_url: str
    allow_insecure_http_for_tests: bool


class _BaseUrlOptions(TypedDict, total=False):
    base_url: str


class _FetchOptions(TypedDict, total=False):
    base_url: str
    tree_base_url: str
    verify: bool


class _Searcher(Protocol):
    def search(self, spec: SearchSpec) -> SearchReport: ...


class _BenchmarkRun(Protocol):
    benchmark_id: str
    tasks: Sequence[Any]

    def to_json(self) -> str: ...

    def digest(self) -> str: ...


class _BenchmarkRunner(Protocol):
    def run(self, manifest: object) -> _BenchmarkRun: ...


def _github_token() -> str | None:
    return github_token_from_env()


def _parse_predicate(raw: str) -> Predicate:
    parts = raw.split(":", 2)
    if len(parts) < 2:
        raise argparse.ArgumentTypeError(f"predicate must be kind:value, got {raw!r}")
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


def _bounded_search_budget(raw: str, *, maximum: int) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"must be an integer from 1 to {maximum}"
        ) from None
    if not 1 <= value <= maximum:
        raise argparse.ArgumentTypeError(f"must be an integer from 1 to {maximum}")
    return value


def _search_result_budget(raw: str) -> int:
    from .discovery_search import MAX_SEARCH_RESULTS

    return _bounded_search_budget(raw, maximum=MAX_SEARCH_RESULTS)


def _search_page_budget(raw: str) -> int:
    from .discovery_search import MAX_SEARCH_PAGES

    return _bounded_search_budget(raw, maximum=MAX_SEARCH_PAGES)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leitir",
        description="Leitir deterministic code-search kernel",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="emit detailed redacted diagnostics to stderr",
    )
    parser.add_argument(
        "--version", action="version", version=f"leitir {_installed_version()}"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser(
        "doctor", help="diagnose the leitir environment and cache integrity"
    )
    doctor.add_argument("--json", action="store_true", dest="as_json")
    doctor.add_argument("--quiet", action="store_true")
    doctor.add_argument("--no-network", action="store_true")
    search = commands.add_parser("search", help="search a pinned code corpus")
    index_command = commands.add_parser(
        "index", help="explicitly build or refresh local trigram index shelves"
    )
    index_command.add_argument("scopes", nargs="*", metavar="scope")
    index_roots = index_command.add_mutually_exclusive_group()
    index_roots.add_argument("--root", default=None, help="corpus root directory")
    index_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    bench = commands.add_parser(
        "bench",
        help="run the pinned search benchmark",
    )
    bench.add_argument(
        "--manifest",
        default=None,
        help="local manifest or packaged benchmark id (default: search-v1)",
    )

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

    list_command = commands.add_parser("list", help="list materialized sources")
    list_command.add_argument("--json", action="store_true", dest="as_json")
    list_roots = list_command.add_mutually_exclusive_group()
    list_roots.add_argument("--root", default=None, help="corpus root directory")
    list_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    upgrade = commands.add_parser(
        "upgrade-cache",
        help=_UPGRADE_CACHE_DESCRIPTION,
        description=_UPGRADE_CACHE_DESCRIPTION,
    )
    upgrade.add_argument("--dry-run", action="store_true")
    upgrade_roots = upgrade.add_mutually_exclusive_group()
    upgrade_roots.add_argument("--root", default=None, help="corpus root directory")
    upgrade_roots.add_argument(
        "--local", action="store_true", help="use ./.leitir-refs"
    )
    trust = commands.add_parser(
        "trust", help="compute cached trust evidence for a source"
    )
    trust.add_argument("spec")
    trust.add_argument("--json", action="store_true", dest="as_json")
    trust_roots = trust.add_mutually_exclusive_group()
    trust_roots.add_argument("--root", default=None, help="corpus root directory")
    trust_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    remove = commands.add_parser("remove", help="remove a materialized source")
    remove.add_argument("spec")
    clean = commands.add_parser("clean", help="empty the source corpus")
    clean.add_argument("--repos", action="store_true")
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
    sbom = commands.add_parser("sbom", help="emit an SBOM for the materialized corpus")
    sbom.add_argument("--format", choices=("spdx", "cyclonedx"), default="spdx")
    sbom.add_argument(
        "--cwd", default=None, help="project directory containing lockfiles"
    )
    sbom_roots = sbom.add_mutually_exclusive_group()
    sbom_roots.add_argument("--root", default=None, help="corpus root directory")
    sbom_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    api = commands.add_parser("api", help="extract and cache a materialized source API")
    api.add_argument("spec")
    api.add_argument("--json", action="store_true", dest="as_json")
    api_roots = api.add_mutually_exclusive_group()
    api_roots.add_argument("--root", default=None, help="corpus root directory")
    api_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    api.set_defaults(cwd=None, no_verify=False)
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
    examples.set_defaults(cwd=None, no_verify=False)
    info = commands.add_parser("info", help="materialize and describe one dependency")
    info.add_argument("spec")
    info.add_argument("--json", action="store_true", dest="as_json")
    info_roots = info.add_mutually_exclusive_group()
    info_roots.add_argument("--root", default=None, help="corpus root directory")
    info_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    info.add_argument(
        "--cwd", default=None, help="project directory used for lockfile resolution"
    )
    info.add_argument(
        "--no-verify", action="store_true", help="skip Git tree verification"
    )
    diff = commands.add_parser("diff", help="diff two resolved source versions")
    diff.add_argument("spec_a")
    diff.add_argument("spec_b")
    diff.add_argument("--json", action="store_true", dest="as_json")
    diff.add_argument(
        "--cwd", default=None, help="project directory used for lockfile resolution"
    )
    diff_roots = diff.add_mutually_exclusive_group()
    diff_roots.add_argument("--root", default=None, help="corpus root directory")
    diff_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    export = commands.add_parser("export", help="export an immutable corpus snapshot")
    export.add_argument("-o", "--output", default="corpus.lock")
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
    gc = commands.add_parser(
        "gc", help="remove abandoned materialization staging directories"
    )
    gc_roots = gc.add_mutually_exclusive_group()
    gc_roots.add_argument("--root", default=None, help="corpus root directory")
    gc_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")

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
        choices=("npm", "pypi", "crates", "go"),
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
    search.add_argument(
        "--whole-file",
        action="store_true",
        default=False,
        dest="whole_file",
        help="match required predicates anywhere in the same file (not just the same line)",
    )
    search.add_argument(
        "--ast",
        action="store_true",
        default=False,
        dest="ast",
        help="use the Python AST adapter (opt-in structural matching)",
    )
    search.add_argument(
        "--max-results",
        type=_search_result_budget,
        default=None,
        help="global search result/candidate budget (requires --global)",
    )
    search.add_argument(
        "--max-pages",
        type=_search_page_budget,
        default=None,
        help="global search page budget (requires --global)",
    )
    search.add_argument(
        "--language",
        default=None,
        help="global search language filter, copied into every required predicate (requires --global)",
    )
    search.add_argument(
        "--index",
        action="store_true",
        dest="use_index",
        help="use verified local trigram indexes with scoped fallback",
    )
    search.add_argument(
        "--require-index",
        action="store_true",
        help="fail closed unless a verified index covers every scope",
    )
    search_roots = search.add_mutually_exclusive_group()
    search_roots.add_argument("--root", default=None, help="corpus root directory for indexed search")
    search_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs for indexed search")

    return parser


def _configure_logging_from_env(
    args: argparse.Namespace, stderr: TextIO = sys.stderr
) -> None:
    """Route warnings to CLI stderr and enable diagnostics when requested."""
    debug_env = os.environ.get("LEITIR_DEBUG", "").casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }
    level_value = os.environ.get("LEITIR_LOG_LEVEL", "")
    level_name = level_value.upper()
    if args.debug or debug_env:
        level_name = "DEBUG"
    import logging

    configured_level = (
        logging.WARNING
        if not level_name
        else logging.getLevelNamesMapping().get(level_name)
    )
    invalid_level = configured_level is None
    level = logging.WARNING if configured_level is None else configured_level
    from .logging import configure_logging

    namespace_logger = logging.getLogger("leitir")
    for existing in tuple(namespace_logger.handlers):
        if getattr(existing, "_leitir_cli_handler", False):
            namespace_logger.removeHandler(existing)
    handler = logging.StreamHandler(stderr)
    handler._leitir_cli_handler = True  # type: ignore[attr-defined]
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter("leitir %(levelname)s %(name)s: %(message)s")
    )
    configure_logging(level, handler=handler)
    if invalid_level:
        logger.warning("ignoring unknown LEITIR_LOG_LEVEL=%r", level_value)


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
        BitbucketResolver,
        CratesResolver,
        GitHubTagResolver,
        GitLabResolver,
        GoResolver,
        MultiResolver,
        NpmResolver,
        PyPIResolver,
    )

    def endpoint_options(value: str) -> _EndpointOptions:
        from urllib.parse import urlsplit

        hostname = urlsplit(value).hostname
        return {
            "base_url": value,
            "allow_insecure_http_for_tests": hostname
            in {"127.0.0.1", "localhost", "::1"},
        }

    tag_options: _EndpointOptions = {}
    github_api = os.environ.get("LEITIR_GITHUB_API_BASE_URL")
    if github_api:
        tag_options.update(endpoint_options(github_api))
    tag_resolver = GitHubTagResolver(token=token, **tag_options)
    pypi_options: _EndpointOptions = {}
    npm_options: _EndpointOptions = {}
    crates_options: _EndpointOptions = {}
    go_options: _EndpointOptions = {}
    if os.environ.get("LEITIR_PYPI_BASE_URL"):
        pypi_options.update(endpoint_options(os.environ["LEITIR_PYPI_BASE_URL"]))
    if os.environ.get("LEITIR_NPM_BASE_URL"):
        npm_options.update(endpoint_options(os.environ["LEITIR_NPM_BASE_URL"]))
    if os.environ.get("LEITIR_CRATES_BASE_URL"):
        crates_options.update(endpoint_options(os.environ["LEITIR_CRATES_BASE_URL"]))
    if os.environ.get("LEITIR_GO_PROXY_BASE_URL"):
        go_options.update(endpoint_options(os.environ["LEITIR_GO_PROXY_BASE_URL"]))
    return MultiResolver(
        pypi=PyPIResolver(tag_resolver, **pypi_options),
        crates=CratesResolver(tag_resolver, **crates_options),
        go=GoResolver(tag_resolver, **go_options),
        npm=NpmResolver(tag_resolver, **npm_options),
        gitlab=GitLabResolver(),
        bitbucket=BitbucketResolver(),
    )


def _build_default_searcher(
    tree_source: object, ast_python: bool = False
) -> object:
    from .adapters.registry import build_adapters
    from .engine import ScopedSearcher
    from .tree import TreeSource

    return ScopedSearcher(
        tree_source=cast(TreeSource, tree_source),
        adapters=build_adapters(ast_python=ast_python),
    )


def _build_default_benchmark_runner(searcher: object) -> object:
    from .bench import BenchmarkRunner

    return BenchmarkRunner(cast(_Searcher, searcher))


def _load_benchmark_manifest(path: str | None) -> object:
    from .bench import load_manifest

    return load_manifest(path)


def _build_default_global_searcher(
    code_search: object,
    tree_source: object,
    max_results: int,
    max_pages: int,
    ast_python: bool = False,
) -> object:
    from .adapters.registry import build_adapters
    from .discovery_search import CodeSearchPort, GlobalSearcher
    from .tree import TreeSource

    typed_code_search = cast(CodeSearchPort, code_search)

    return GlobalSearcher(
        code_search=typed_code_search,
        tree_source=cast(TreeSource, tree_source),
        adapters=build_adapters(ast_python=ast_python),
        blob_reader=cast(Any, code_search).read_blob_by_path,
        max_results=max_results,
        max_pages=max_pages,
    )


def _build_default_code_search(token: str | None) -> object:
    from .discovery_search import GitHubCodeSearchTransport

    options: _BaseUrlOptions = {}
    github_api = os.environ.get("LEITIR_GITHUB_API_BASE_URL")
    if github_api:
        options["base_url"] = github_api
    return GitHubCodeSearchTransport(token=token, **options)


def _ensure_local_gitignore(cwd: Path) -> str:
    gitignore = cwd / ".gitignore"
    line = ".leitir-refs/"
    try:
        existing = gitignore.read_text(encoding="utf-8")
    except FileNotFoundError:
        gitignore.write_text(line + "\n", encoding="utf-8")
        return f"created {gitignore} with {line}"
    rules = {
        item.strip()
        for item in existing.splitlines()
        if item.strip() and not item.lstrip().startswith("#")
    }
    if rules.intersection(
        {line, ".leitir-refs", "/.leitir-refs/", "/.leitir-refs", ".leitir-refs/**"}
    ):
        return f"{gitignore} already covers {line}"
    separator = "" if not existing or existing.endswith("\n") else "\n"
    with gitignore.open("a", encoding="utf-8") as handle:
        handle.write(separator + line + "\n")
    return f"appended {line} to {gitignore}"


def _corpus_root(args: argparse.Namespace, err: TextIO) -> Path:
    from .corpus import resolve_root

    if getattr(args, "local", False):
        cwd = Path.cwd()
        print(f"leitir: {_ensure_local_gitignore(cwd)}", file=err)
        return (cwd / ".leitir-refs").absolute()
    return resolve_root(getattr(args, "root", None))


def _resolve_corpus_spec(
    parsed: CorpusSpec, resolver: object, heads: object, cwd: Path
) -> tuple[RepoScope | ResolvedPackage, str | None, str | None, str | None]:
    from .resolver import resolve_corpus_spec

    return resolve_corpus_spec(
        parsed,
        cast("_CorpusResolver", resolver),
        cast("_HeadResolver", heads),
        cwd,
    )


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


def _corpus_list(root: Path, *, as_json: bool, out: TextIO) -> None:
    from .corpus import load_sources
    from .materialize import read_valid_manifest

    entries = load_sources(root)
    rendered = []
    filtered = 0
    for entry in entries:
        manifest = read_valid_manifest(
            root / entry["path"],
            entry["owner"],
            entry["repo"],
            entry["commit_sha"],
            host=entry["host"],
        )
        if manifest is None:
            filtered += 1
            continue
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
        rendered.append((entry, version, verification, trust_score))
    if filtered:
        logger.warning(
            "%d corpus entries were excluded because they failed manifest validation. "
            "Run `leitir upgrade-cache` to migrate legacy verified shelves, or "
            "inspect with `--json` for per-entry diagnostics.",
            filtered,
        )
    if as_json:
        payload = []
        for entry, _, verification, trust_score in rendered:
            item = dict(entry, verification=verification)
            if trust_score is not None:
                item["trust_score"] = trust_score
            payload.append(item)
        print(json.dumps(payload, indent=2, sort_keys=True), file=out)
        return
    for entry, version, verification, trust_score in rendered:
        version_text = f" {version}" if version else ""
        path = (root / entry["path"]).absolute()
        print(
            f"{entry['name']}{version_text} {entry['owner']}/{entry['repo']}@{entry['commit_sha']} "
            f"{verification} trust={trust_score if trust_score is not None else 'unknown'} "
            f"{path} {entry['fetched_at']}",
            file=out,
        )


def _upgrade_cache(root: Path, *, dry_run: bool, out: TextIO) -> int:
    """Backfill integrity anchors on verified legacy shelves under ``root``."""
    from .materialize import MANIFEST_NAME, _write_manifest
    from .treehash import (
        TreeHashError,
        compute_materialized_tree_hash,
        manifest_digest_fields,
    )

    upgraded = skipped = failed = 0
    for manifest_path in sorted(root.rglob(MANIFEST_NAME)):
        target = manifest_path.parent
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
            _write_manifest(manifest_path, payload)
    print(
        f"Upgraded {upgraded} shelves, skipped {skipped} (already had digest), "
        f"failed {failed} (see warnings)",
        file=out,
    )
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
) -> int:
    from .corpus import INDEX_NAME, materialize_source, remove_source
    from .docpointers import POINTERS_NAME

    try:
        root = _corpus_root(args, err)
        if args.command == "list":
            _corpus_list(root, as_json=args.as_json, out=out)
            return int(ExitCode.SUCCESS)
        if args.command == "upgrade-cache":
            return _upgrade_cache(root, dry_run=args.dry_run, out=out)
        if args.command == "gc":
            removed = _gc_abandoned_staging(root)
            print(
                json.dumps({"removed": removed, "root": str(root)}, sort_keys=True),
                file=out,
            )
            return int(ExitCode.SUCCESS)
        if args.command == "index":
            from .index.builder import build_shelf_index, shelves_from_corpus

            shelves = shelves_from_corpus(root, tuple(args.scopes))
            if not shelves:
                raise ValueError("the corpus has no materialized shelves to index")
            built_paths = [str(build_shelf_index(root, shelf).absolute()) for shelf in shelves]
            print(
                json.dumps(
                    {"count": len(built_paths), "indexes": built_paths, "schema_version": 1},
                    sort_keys=True,
                ),
                file=out,
            )
            return int(ExitCode.SUCCESS)
        if args.command == "trust":
            from .corpus import record_trust

            entry, untyped_result, target = record_trust(args.spec, root)
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
            from .corpus import materialize_source
            from .diff import GitHubReleaseNotes, diff_packages
            from .materialize import _target_lock, read_valid_manifest

            token = _github_token()
            resolver = resolver_factory(token)
            heads = code_search_factory(token)
            cwd = Path(args.cwd or Path.cwd()).expanduser().absolute()
            fetch_options: _FetchOptions = {}
            if os.environ.get("LEITIR_CODELOAD_BASE_URL"):
                fetch_options["base_url"] = os.environ["LEITIR_CODELOAD_BASE_URL"]
            if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
                fetch_options["tree_base_url"] = os.environ[
                    "LEITIR_GITHUB_API_BASE_URL"
                ]
            notes_options: _BaseUrlOptions = {}
            if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
                notes_options["base_url"] = os.environ["LEITIR_GITHUB_API_BASE_URL"]
            # An injected diff implementation is an explicit test/embedding
            # seam and may not consume shelf bytes at all. Only the built-in
            # implementation needs leitir's target-lock orchestration.
            if diff_packages.__module__ != "leitir.diff":
                report = diff_packages(
                    args.spec_a,
                    args.spec_b,
                    corpus_root=root,
                    resolver=resolver,
                    heads=heads,
                    cwd=cwd,
                    release_notes=GitHubReleaseNotes(token, **notes_options),
                    fetch_options=fetch_options,
                )
                if args.as_json:
                    print(report.to_json(), file=out)
                else:
                    _write_diff_human(report, out)
                return int(ExitCode.SUCCESS)
            prepared: dict[str, tuple[Path, RepoScope, str]] = {}
            for raw in (args.spec_a, args.spec_b):
                parsed = parse_corpus_spec(raw)
                resolved, tag, version_source, _detection = _resolve_corpus_spec(
                    parsed, resolver, heads, cwd
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
                    **fetch_options,
                )
                prepared[raw] = (path, scope, materialize_host)

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

                def locked_materializer(
                    raw: str, *_args: object, **_kwargs: object
                ) -> Path:
                    return prepared[raw][0]

                report = diff_packages(
                    args.spec_a,
                    args.spec_b,
                    corpus_root=root,
                    resolver=resolver,
                    heads=heads,
                    cwd=cwd,
                    materializer=locked_materializer,
                    release_notes=GitHubReleaseNotes(token, **notes_options),
                    fetch_options=fetch_options,
                    on_resolve=lambda spec: print(
                        f"leitir: resolving {spec} (cwd={cwd})", file=err
                    ),
                )
            if args.as_json:
                print(report.to_json(), file=out)
            else:
                _write_diff_human(report, out)
            return int(ExitCode.SUCCESS)
        if args.command == "remove":
            parsed = parse_corpus_spec(args.spec)
            if parsed.ecosystem is None and parsed.ref_kind == "head":
                owner, repo = parsed.name.split("/", 1)
                sha = None
            else:
                token = _github_token()
                resolver = resolver_factory(token)
                heads = code_search_factory(token)
                resolved, _, _, _ = _resolve_corpus_spec(
                    parsed, resolver, heads, Path.cwd()
                )
                typed_scope = cast(RepoScope, getattr(resolved, "scope", resolved))
                owner, repo = typed_scope.slug.split("/", 1)
                sha = typed_scope.commit_sha
            removed = remove_source(
                root, owner, repo, sha, host=parsed.host or "github.com"
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
            entries = load_sources(root)
            targets: dict[str, tuple[Path, str]] = {}
            for entry in entries:
                relative = Path(entry["path"])
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"invalid shelved source path: {entry['path']!r}")
                target = root / relative
                _assert_target_confinement(root, target)
                targets[target.absolute().as_posix()] = (
                    target,
                    str(entry["commit_sha"]),
                )
            with ExitStack() as sbom_locks:
                for _identity, (target, commit_sha) in sorted(targets.items()):
                    sbom_locks.enter_context(_target_lock(root, target, commit_sha))
                sbom_locks.enter_context(_file_lock(root / ".sources.lock"))
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
                resolver,
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
            resolved, tag, version_source, detection_source = _resolve_corpus_spec(
                parsed, resolver, heads, cwd
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
                    from .info import build_info

                    print(
                        f"leitir: ensuring analysis indexes and trust for {raw}",
                        file=err,
                    )
                    document = build_info(raw, corpus_root=root)
                    if args.as_json:
                        print(json.dumps(document, indent=2, sort_keys=True), file=out)
                    else:
                        provenance = cast(dict[str, Any], document["provenance"])
                        api = cast(dict[str, Any], document["api"])
                        examples = cast(dict[str, Any], document["examples"])
                        trust = cast(dict[str, Any], document["trust"])
                        license_info = cast(dict[str, Any], document["license"])
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
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.CORPUS_FAILURE)


def _resolve_scope_via_package(
    resolver: object,
    package: str,
    version: str,
    ecosystem: str,
) -> RepoScope:
    from .resolver import Ecosystem, PackageRef, PackageResolver

    ref = PackageRef(
        ecosystem=Ecosystem(ecosystem),
        name=package,
        version=version,
    )
    resolved = cast(PackageResolver, resolver).resolve(ref)
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
    searcher_factory: Callable[..., object] = _build_default_searcher,
    code_search_factory: Callable[[str | None], object] = _build_default_code_search,
    global_searcher_factory: Callable[..., object] = _build_default_global_searcher,
    benchmark_runner_factory: Callable[
        [object], object
    ] = _build_default_benchmark_runner,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    _exit_windows_doctor_success: bool = False,
) -> int:
    """Parse one command and wire resolver -> engine -> report."""

    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(cast(int, exc.code))

    _configure_logging_from_env(args, err)

    from ._update_check import maybe_emit_update_notice, maybe_start_update_check

    maybe_start_update_check(
        json_mode=bool(getattr(args, "as_json", False)),
        quiet=bool(getattr(args, "quiet", False)),
    )

    def successful() -> int:
        maybe_emit_update_notice()
        return int(ExitCode.SUCCESS)

    if args.command == "doctor":
        from .doctor import run_doctor

        exit_process = _exit_windows_doctor_success and os.name == "nt"
        result = int(ExitCode.INFRASTRUCTURE_FAILURE)
        try:
            if stdout is None:
                out = _protect_stdout_shutdown(out)
            result = run_doctor(
                as_json=args.as_json,
                quiet=args.quiet,
                no_network=args.no_network,
                stdout=out,
            )
            if result == int(ExitCode.SUCCESS):
                try:
                    result = successful()
                except OSError as exc:
                    if not _is_broken_pipe_error(exc):
                        raise
            return result
        finally:
            if exit_process:
                # Py_RunMain changes the status to 120 when Py_FinalizeEx
                # cannot flush Windows stdout.  Exit with doctor's actual
                # result (or infrastructure failure if it raised) first.
                error = sys.exception()
                try:
                    if error is not None:
                        sys.excepthook(type(error), error, error.__traceback__)
                finally:
                    os._exit(result)

    if args.command == "bench":
        token = _github_token()
        try:
            manifest = _load_benchmark_manifest(args.manifest)
            from .corpus_bench import CorpusBenchmarkManifest, CorpusBenchmarkRunner

            if isinstance(manifest, CorpusBenchmarkManifest):
                corpus_runner = CorpusBenchmarkRunner(
                    resolver_factory(token), code_search_factory(token), token
                )
                run = cast(_BenchmarkRun, corpus_runner.run(manifest))
            else:
                tree_source = tree_source_factory(token)
                searcher = searcher_factory(tree_source)
                runner = cast(_BenchmarkRunner, benchmark_runner_factory(searcher))
                run = runner.run(manifest)
        except Exception as exc:
            print(f"leitir: error: {redact(str(exc))}", file=err)
            return int(ExitCode.INFRASTRUCTURE_FAILURE)

        print(run.to_json(), file=out)
        result_count = sum(len(task.results) for task in run.tasks)
        print(
            f"benchmark={run.benchmark_id} "
            f"tasks={len(run.tasks)} results={result_count} "
            f"artifact_sha256={run.digest()}",
            file=err,
        )
        return successful()

    if args.command in {
        "get",
        "fetch",
        "list",
        "upgrade-cache",
        "gc",
        "index",
        "trust",
        "remove",
        "clean",
        "lock",
        "export",
        "import",
        "sbom",
        "api",
        "examples",
        "info",
        "diff",
    }:
        result = _run_corpus_command(
            args,
            resolver_factory=resolver_factory,
            code_search_factory=code_search_factory,
            out=out,
            err=err,
        )
        if result == int(ExitCode.SUCCESS):
            return successful()
        return result

    scope_error = _validate_scope_args(args)
    if scope_error:
        print(f"leitir: error: {scope_error}", file=err)
        return int(ExitCode.MALFORMED_USAGE)

    if not args.must:
        print("leitir: error: at least one --must predicate is required", file=err)
        return int(ExitCode.MALFORMED_USAGE)

    global_only_used = any(
        value is not None
        for value in (args.max_results, args.max_pages, args.language)
    )
    if not args.global_search and global_only_used:
        print(
            "leitir: error: --max-results, --max-pages, and --language require --global",
            file=err,
        )
        return int(ExitCode.MALFORMED_USAGE)
    if args.global_search and (args.use_index or args.require_index):
        print("leitir: error: --index and --require-index require a scoped search", file=err)
        return int(ExitCode.MALFORMED_USAGE)

    must = tuple(args.must)
    try:
        if args.language is not None:
            from .adapters.languages import canonicalize_language

            if not args.language.strip():
                raise ValueError("--language must be non-empty text")
            requested = canonicalize_language(args.language.strip())
            if any(
                p.language is not None
                and canonicalize_language(p.language) != requested
                for p in must
            ):
                raise ValueError(
                    "--language conflicts with a required predicate language"
                )
            must = tuple(dataclasses.replace(p, language=requested) for p in must)
    except ValueError as exc:
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.MALFORMED_USAGE)

    token = _github_token()

    try:
        if args.global_search:
            spec = SearchSpec(
                mode=SearchMode.GLOBAL_DISCOVERY,
                must=must,
                should=tuple(args.should),
                must_not=tuple(args.must_not),
                whole_file_must=args.whole_file,
            )
            code_search = code_search_factory(token)
            tree_source = tree_source_factory(token)
            max_results = args.max_results if args.max_results is not None else 30
            max_pages = args.max_pages if args.max_pages is not None else 10
            if args.ast:
                searcher = cast(
                    _Searcher,
                    global_searcher_factory(
                        code_search,
                        tree_source,
                        max_results,
                        max_pages,
                        ast_python=True,
                    ),
                )
            else:
                searcher = cast(
                    _Searcher,
                    global_searcher_factory(
                        code_search, tree_source, max_results, max_pages
                    ),
                )
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
                whole_file_must=args.whole_file,
            )

            tree_source = tree_source_factory(token)
            searcher = cast(
                _Searcher,
                searcher_factory(tree_source, ast_python=True)
                if args.ast
                else searcher_factory(tree_source),
            )
            if args.use_index or args.require_index:
                from .adapters.registry import build_adapters
                from .engine import ScopedSearcher
                from .index.query import IndexedSearcher

                adapters = build_adapters(ast_python=args.ast)
                if not isinstance(searcher, ScopedSearcher):
                    raise ValueError("indexed search requires a ScopedSearcher fallback")
                searcher = IndexedSearcher(
                    _corpus_root(args, err),
                    searcher,
                    adapters,
                    require_index=args.require_index,
                )
            report = searcher.search(spec)
    except SearchSpecError as exc:
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.MALFORMED_USAGE)
    except Exception as exc:
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.INFRASTRUCTURE_FAILURE)

    print(report.to_json(), file=out)
    _write_summary(report, file=err)
    return successful()


def _process_main() -> int:
    """Run the CLI with process-only shutdown handling enabled."""
    return main(_exit_windows_doctor_success=True)


if __name__ == "__main__":
    raise SystemExit(_process_main())


__all__ = [
    "ExitCode",
    "build_parser",
    "main",
]
