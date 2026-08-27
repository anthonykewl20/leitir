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
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, TextIO, TypedDict, cast

from .credentials import github_token_from_env
from .logging import redact
from .materialize import VerificationError
from .search import (
    CorpusSearchReport,
    Predicate,
    PredicateKind,
    RepoScope,
    SearchMode,
    SearchReport,
    SearchSpec,
    SearchSpecError,
    canonical_predicates,
)
from .spec import CorpusSpec, SpecParseError, parse_corpus_spec

if TYPE_CHECKING:
    from .diff import DiffReport
    from .discovery_search import CoverageBounds
    from .parity import ArtifactInfo as ArtifactInfoLike
    from .resolver import Ecosystem, ResolvedPackage, _CorpusResolver, _HeadResolver
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
    # Audit 2026-08-23 P3: a completed command whose entire input set was
    # deterministically skipped (e.g. ``index`` over only-ineligible
    # shelves) is a clean no-op, not a corpus failure — but it is not
    # success either, so automation can still distinguish it from both.
    NOTHING_INDEXED = 4


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


def _parse_bts_compute_spec(raw: str) -> tuple[str, str, str]:
    """Parse the exact ``owner/repo@commit`` shelf identity used by BTS."""

    try:
        slug, commit_sha = raw.rsplit("@", 1)
        owner, repo = slug.split("/", 1)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "BTS spec must be owner/repo@40-character-lowercase-commit-sha"
        ) from exc
    if (
        not owner
        or not repo
        or "@" in owner
        or "@" in repo
        or "/" in repo
        or len(commit_sha) != 40
        or any(character not in "0123456789abcdef" for character in commit_sha)
    ):
        raise argparse.ArgumentTypeError(
            "BTS spec must be owner/repo@40-character-lowercase-commit-sha"
        )
    return owner, repo, commit_sha


def _analysis_subject(raw: str) -> str:
    """Accept a bounded caller-declared analysis label, never a free-form claim."""

    if not raw or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for character in raw):
        raise argparse.ArgumentTypeError(
            "architecture subject must contain only letters, digits, '-', '_', or '.'"
        )
    return raw


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
    search = commands.add_parser(
        "search",
        help="search a pinned code corpus",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "predicate matching and comments/strings:\n"
            "  On every non-Python language (JavaScript, TypeScript, Java, C, C++), content\n"
            "  predicates (exact_text, regex, identifier, token_sequence, signature, call,\n"
            "  import, symbol_definition, symbol_reference) are matched against source with\n"
            "  comments and string/template literals masked out first -- an occurrence that\n"
            "  exists only inside a comment or a string literal is never returned, even\n"
            "  though a plain-text tool like grep would report it.\n"
            "  Python does not mask: the default heuristic Python adapter matches raw,\n"
            "  unmasked source lines, so a predicate CAN match inside a Python string\n"
            "  literal or '#' comment. `--ast`'s structural predicate kinds\n"
            "  (symbol_definition, symbol_reference, call, import, signature) consult the\n"
            "  parsed AST instead and so cannot match inside a comment, but any other\n"
            "  content predicate on a Python file (e.g. exact_text, regex) still falls back\n"
            "  to the same raw, unmasked line scan.\n"
            "  If a diff against grep looks like leitir is 'missing' matches on a non-Python\n"
            "  file, check whether they are inside a comment or string literal first --\n"
            "  that is expected, by-design behavior. See docs/search-capabilities.md.\n"
        ),
    )
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
    bench = commands.add_parser(
        "bench",
        help="run the pinned search benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "runtime:\n"
            "  The default search-v1 manifest scoped-exhaustively searches 32 tasks\n"
            "  across 8 real, pinned repositories (including python/cpython and\n"
            "  microsoft/TypeScript), materializing each repo's full tree once. On a\n"
            "  cold cache this downloads several hundred MB and commonly takes tens of\n"
            "  minutes even with a valid GH_TOKEN; a warm cache (same LEITIR_HOME, same\n"
            "  pinned commits) reuses the on-disk shelves and is much faster. Progress\n"
            "  (task N/total, elapsed time) is printed to stderr as it runs -- it has\n"
            "  not hung. The repo set and commits are pinned for determinism and are not\n"
            "  configurable via a flag; pass --manifest to point at a different manifest\n"
            "  file or packaged benchmark id entirely.\n"
        ),
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
    remove = commands.add_parser("remove", help="remove a materialized source")
    remove.add_argument("spec")
    remove_roots = remove.add_mutually_exclusive_group()
    remove_roots.add_argument("--root", default=None, help="corpus root directory")
    remove_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    clean = commands.add_parser("clean", help="empty the source corpus")
    clean.add_argument("--repos", action="store_true")
    clean_roots = clean.add_mutually_exclusive_group()
    clean_roots.add_argument("--root", default=None, help="corpus root directory")
    clean_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
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
    ask = commands.add_parser(
        "ask",
        help="one-call task answer: pin a version from the project's lockfile "
        "and return ranked examples, verified signatures, and citations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "version resolution:\n"
            "  --pin points at the project directory (or a lockfile inside it)\n"
            "  whose lockfile supplies the EXACT installed version of --package.\n"
            "  ask never falls back to the registry 'latest' version and never\n"
            "  searches the ambient filesystem: an absent, unparseable, or\n"
            "  non-matching lockfile is rejected outright.\n"
            "\n"
            "query compilation:\n"
            "  The task description is compiled into deterministic search\n"
            "  predicates (see leitir.ask.compile_task_predicates) -- never by a\n"
            "  model or embeddings (ADR-001). The compiled predicates are always\n"
            "  printed, along with a literal 'leitir search' command that\n"
            "  reproduces them by hand. When no predicate can be compiled with\n"
            "  reasonable confidence, ask says so and returns the package's\n"
            "  brief info instead of guessing.\n"
        ),
    )
    ask.add_argument("task", help="free-text description of what you want to do")
    ask.add_argument("--package", required=True, help="package name")
    ask.add_argument(
        "--ecosystem",
        required=True,
        choices=("npm", "pypi", "crates", "go"),
        help="package ecosystem",
    )
    ask.add_argument(
        "--pin",
        required=True,
        help="project directory (or a lockfile inside it) to resolve the exact "
        "version of --package from",
    )
    ask.add_argument("--json", action="store_true", dest="as_json")
    ask_roots = ask.add_mutually_exclusive_group()
    ask_roots.add_argument("--root", default=None, help="corpus root directory")
    ask_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    ask.add_argument(
        "--no-verify", action="store_true", help="skip Git tree verification"
    )
    ask.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require opt-in publisher authentication; never accepts unsigned shelves",
    )
    ask.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
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
    check = commands.add_parser(
        "check",
        help="validate written Python code against a materialized source's API surface",
    )
    check.add_argument("path", help="Python source file or directory to check")
    check.add_argument(
        "--against",
        required=True,
        help="corpus spec of the pinned source to check against, e.g. pypi:flask@3.0.3",
    )
    check.add_argument("--json", action="store_true", dest="as_json")
    check.add_argument(
        "--cwd", default=None, help="project directory used for lockfile resolution"
    )
    check_roots = check.add_mutually_exclusive_group()
    check_roots.add_argument("--root", default=None, help="corpus root directory")
    check_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    check.add_argument(
        "--no-verify", action="store_true", help="skip Git tree verification"
    )

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
    gc = commands.add_parser(
        "gc", help="remove abandoned materialization staging directories"
    )
    gc_roots = gc.add_mutually_exclusive_group()
    gc_roots.add_argument("--root", default=None, help="corpus root directory")
    gc_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")

    bts_compute = commands.add_parser(
        "bts-compute",
        help="compute a Behavioral Transplant Set from an exact verified shelf",
    )
    bts_compute.add_argument(
        "spec", type=_parse_bts_compute_spec, metavar="owner/repo@commit"
    )
    bts_roots = bts_compute.add_mutually_exclusive_group()
    bts_roots.add_argument("--root", default=None, help="corpus root directory")
    bts_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    bts_compute.add_argument(
        "--language",
        choices=("python", "javascript", "typescript", "rust", "go"),
        default="python",
    )
    bts_compute.add_argument(
        "--lock",
        default="requirements-tree-sitter.lock",
        help="tree-sitter requirements lock (resolved from the current directory)",
    )
    bts_compute.add_argument(
        "--policy",
        default=None,
        help="closed-schema BTS resolution policy JSON; without it the pinned empty policy is used, so COMPLETE typically requires policy coverage for stdlib or external usage",
    )
    bts_compute.add_argument("--seed-module")
    bts_compute.add_argument("--seed-name")
    bts_compute.add_argument("--out", help="empty artifact output directory")
    bts_compute.add_argument("--list-seeds", action="store_true", help="list selectable donor definition seeds without computing a BTS")
    bts_compute.add_argument("--allow-reject", action="store_true", help="return success after writing a REJECT BTS result")
    bts_compute.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication on the donor shelf before computing",
    )
    bts_compute.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )
    bts_compute.add_argument("--json", action="store_true", dest="as_json")

    architecture = commands.add_parser(
        "analysis-architecture",
        help="assess a canonical graph artifact for architecture compatibility",
    )
    architecture.add_argument("graph", metavar="graph.json")
    architecture.add_argument("--subject", required=True, type=_analysis_subject)
    architecture.add_argument("--catalog", default=None)
    architecture.add_argument(
        "--declared-concurrency",
        choices=("sync", "async", "mixed", "unknown"),
        default=None,
    )
    architecture.add_argument("--json", action="store_true", dest="as_json")

    lineage = commands.add_parser(
        "analysis-lineage", help="validate a canonical lineage manifest"
    )
    lineage.add_argument("manifest", metavar="manifest.json")
    lineage.add_argument("--json", action="store_true", dest="as_json")

    exit_gate = commands.add_parser(
        "exit-gate-validate", help="validate pinned exit-corpus manifest evidence"
    )
    exit_gate.add_argument("corpus", metavar="corpus.json")
    exit_gate.add_argument("--json", action="store_true", dest="as_json")

    funnel = commands.add_parser(
        "bts-funnel", help="run the recorded capability-to-candidate BTS funnel"
    )
    funnel.add_argument("--spec", required=True, help="canonical capability spec JSON")
    funnel.add_argument(
        "--recipient-manifest", required=True, help="closed recipient input manifest JSON"
    )
    funnel.add_argument("--stages", required=True, help="recorded discovery stages JSON")
    funnel.add_argument("--json", action="store_true", dest="as_json")

    bts_run = commands.add_parser(
        "bts-run", help="run the contained Python BTS pipeline from a verified shelf"
    )
    bts_run.add_argument("spec", type=_parse_bts_compute_spec, metavar="owner/repo@commit")
    bts_run_roots = bts_run.add_mutually_exclusive_group()
    bts_run_roots.add_argument("--root", default=None, help="corpus root directory")
    bts_run_roots.add_argument("--local", action="store_true", help="use ./.leitir-refs")
    bts_run.add_argument("--seed-module", required=True)
    bts_run.add_argument("--seed-name", required=True)
    bts_run.add_argument("--policy", default=None, help="closed-schema BTS resolution policy JSON")
    bts_run.add_argument("--contract-spec", required=True, help="contract-tests JSON")
    bts_run.add_argument("--out", required=True, help="empty artifact output directory")
    bts_run.add_argument("--recipient-package", required=True)
    bts_run.add_argument(
        "--nsjail-sha256", default=None,
        help="measured sha256:<hex> of /usr/bin/nsjail (default: resolved from --containment-environment)",
    )
    bts_run.add_argument(
        "--nsjail-version", default=None,
        help="nsjail@<commit> build identity (default: resolved from --containment-environment)",
    )
    bts_run.add_argument(
        "--nsjail-build-identity", default=None,
        help="derived nsjail release/build identity digest (default: resolved from --containment-environment)",
    )
    bts_run.add_argument(
        "--config-schema-digest", default=None,
        help="pinned containment config schema digest (default: resolved from --containment-environment)",
    )
    bts_run.add_argument(
        "--rootfs-source", default=None,
        help="local containment-rootfs-v1 materialization directory (default: $LEITIR_ROOTFS_SOURCE or ~/.leitir/containment-rootfs-v1)",
    )
    bts_run.add_argument(
        "--rootfs-digest", default=None,
        help="canonical sha256:<hex> tree digest of --rootfs-source (default: resolved from --containment-environment)",
    )
    bts_run.add_argument(
        "--containment-environment", default=None, metavar="ENVIRONMENT.json",
        help=(
            "committed, self-verified containment environment descriptor used to resolve any of the five "
            "containment-substrate flags left unset (default: installed package directory); "
            "an explicit flag always overrides the descriptor for that field"
        ),
    )
    bts_run.add_argument("--emit-packets", default=None, metavar="PACKET_INPUTS.json")
    bts_run.add_argument(
        "--require-manifest-auth",
        action="store_true",
        help="require publisher authentication on the donor shelf before running the pipeline",
    )
    bts_run.add_argument(
        "--trusted-keys",
        default=None,
        help="out-of-band trusted-keys.json path (default: ~/.leitir/trusted-keys.json)",
    )
    bts_run.add_argument("--json", action="store_true", dest="as_json")

    exit_run = commands.add_parser(
        "exit-gate-run",
        help="run a v1.1 runnable exit corpus under measured containment; phase A publishes corpus_manifest_digest, phase C requires its out-of-band ratified_runtime_digest",
    )
    exit_run.add_argument("corpus", metavar="corpus-v1.1.json")
    exit_run.add_argument("--corpus-root", required=True, help="root containing committed contract tests")
    exit_run.add_argument(
        "--donors-dir", default=None,
        help="root containing verified donor shelves and baseline sidecars (default: --corpus-root)",
    )
    exit_run.add_argument("--out", default=None, help="gate-report output directory")
    exit_run.add_argument("--substrate-nsjail-sha", required=True, help="measured sha256:<hex> of /usr/bin/nsjail")
    exit_run.add_argument("--substrate-rootfs-digest", required=True, help="measured sha256:<hex> canonical rootfs tree digest")
    exit_run.add_argument("--nsjail-version", required=True)
    exit_run.add_argument("--nsjail-build-identity", required=True)
    exit_run.add_argument("--config-schema-digest", required=True)
    exit_run.add_argument("--rootfs-source", required=True)
    exit_run.add_argument("--trusted-keys", default=None, help="out-of-band trusted-keys.json required when ratified_runtime_digest is set")
    exit_run.add_argument("--ratification-sidecar", default=None, help="detached Ed25519 ratification record (default: corpus directory/ratification-v1.json)")
    exit_run.add_argument("--json", action="store_true", dest="as_json")

    occupied_validate = commands.add_parser(
        "occupied-validate", help="validate a canonical occupied-recipient attachment artifact"
    )
    occupied_validate.add_argument("artifact", metavar="artifact.json")
    occupied_validate.add_argument("--json", action="store_true", dest="as_json")

    usage_cmd = commands.add_parser(
        "usage",
        help="assemble, verify, or replay a local usage evidence bundle (fully offline)",
    )
    usage_cmd.add_argument(
        "action",
        choices=["assemble", "verify", "replay"],
        help=(
            "assemble: build report.json (to --out) from an assemble-plan.json by calling "
            "assemble_usage_evidence, self-verifying the produced report before it is written; "
            "verify: parse/validate report.json; "
            "replay: also recompute digests against on-disk corpus bytes and confirm each "
            "reference's recorded span (not the whole source file) is byte-identical to what "
            "is on disk"
        ),
    )
    usage_cmd.add_argument("report", metavar="report.json", help="report.json for verify/replay; assemble-plan.json for assemble")
    usage_cmd.add_argument(
        "--corpus-root", default=None,
        help=(
            "consumer source root the report's references resolve against (required for replay; "
            "optional for assemble, where it backs the advisory per-file license scan)"
        ),
    )
    usage_cmd.add_argument(
        "--requirements", default=None,
        help="requirements.txt path backing the report's dependency evidence (required for replay)",
    )
    usage_cmd.add_argument(
        "--times", type=int, default=2,
        help="number of independent replay passes to compare for byte-identical output (replay only, default: 2)",
    )
    usage_cmd.add_argument(
        "--out", default=None,
        help="output path for the assembled report.json (required for assemble)",
    )
    usage_cmd.add_argument("--json", action="store_true", dest="as_json")

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
        help=(
            "global discovery via GitHub Code Search; coverage is bounded, "
            "not total: output reports pages fetched, matches returned, and "
            "an incomplete flag with the bound that fired (e.g. page cap, "
            "server-side truncation, or a result budget)"
        ),
    )
    scope_group.add_argument(
        "--corpus",
        action="store_true",
        default=False,
        dest="corpus_search",
        help=(
            "search every eligible materialized shelf in the corpus (offline, "
            "commit- and blob-pinned); a shelf that is unindexed (with "
            "--require-index), drift-parity, registry-derived, on an "
            "unsupported host, or fails load-time verification is excluded "
            "and named in the output, and corpus_status is never reported "
            "complete when any shelf was excluded"
        ),
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
    if getattr(args, "corpus_search", False):
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
    return "one of --repo, --package, --global, or --corpus is required"


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
    tree_source: object,
    ast_python: bool = False,
    corpus_root: str | os.PathLike[str] | None = None,
) -> object:
    from .adapters.registry import build_adapters
    from .engine import ScopedSearcher
    from .tree import TreeSource

    return ScopedSearcher(
        tree_source=cast(TreeSource, tree_source),
        adapters=build_adapters(ast_python=ast_python),
        corpus_root=corpus_root,
    )


def _bench_progress_reporter(total: int, *, err: TextIO) -> Callable[[object], None]:
    """Build a stderr progress callback reporting task N/total and elapsed time.

    The pinned search-v1 benchmark walks ~30 tasks across full repository
    trees (redis, cpython, TypeScript, ...) with no other user-visible
    output in between; a bare "task X starting" line gives no sense of how
    much work remains, which reads as a hang. This adds a running count and
    an elapsed-time stamp, still one line per task, still stderr-only so
    ``--json`` stdout stays pure.
    """
    start = time.monotonic()
    state = {"index": 0}

    def _report(task: object) -> None:
        state["index"] += 1
        elapsed = time.monotonic() - start
        minutes, seconds = divmod(int(elapsed), 60)
        print(
            f"leitir: benchmark task {state['index']}/{total} "
            f"{getattr(task, 'task_id', 'unknown')} starting "
            f"(elapsed {minutes}m{seconds:02d}s)",
            file=err,
        )

    return _report


def _build_default_benchmark_runner(
    searcher: object, *, progress: Callable[[object], None] | None = None,
) -> object:
    from .bench import BenchmarkRunner

    return BenchmarkRunner(cast(_Searcher, searcher), progress=progress)


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


_GITIGNORE_LINE = ".leitir-refs/"
_GITIGNORE_COVERAGE = frozenset(
    {".leitir-refs/", ".leitir-refs", "/.leitir-refs/", "/.leitir-refs", ".leitir-refs/**"}
)
# Commands whose ``--local`` corpus access is strictly read-only: they never
# create or write under ``./.leitir-refs``, so they must not modify the
# user's ``.gitignore`` either (production-readiness audit 2026-08-23, P3:
# read-only operations should not touch user files).
_READ_ONLY_LOCAL_COMMANDS = frozenset(
    {"bts-compute", "bts-run", "export", "list", "sbom", "search"}
)


def _gitignore_covered(cwd: Path) -> bool:
    gitignore = cwd / ".gitignore"
    try:
        existing = gitignore.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    rules = {
        item.strip()
        for item in existing.splitlines()
        if item.strip() and not item.lstrip().startswith("#")
    }
    return bool(rules & _GITIGNORE_COVERAGE)


def _ensure_local_gitignore(cwd: Path) -> str:
    gitignore = cwd / ".gitignore"
    line = _GITIGNORE_LINE
    if _gitignore_covered(cwd):
        return f"{gitignore} already covers {line}"
    try:
        existing = gitignore.read_text(encoding="utf-8")
    except FileNotFoundError:
        gitignore.write_text(line + "\n", encoding="utf-8")
        return f"created {gitignore} with {line}"
    separator = "" if not existing or existing.endswith("\n") else "\n"
    with gitignore.open("a", encoding="utf-8") as handle:
        handle.write(separator + line + "\n")
    return f"appended {line} to {gitignore}"


def _report_local_gitignore(cwd: Path) -> str:
    """Describe ``.gitignore`` coverage without modifying anything."""

    gitignore = cwd / ".gitignore"
    if _gitignore_covered(cwd):
        return f"{gitignore} already covers {_GITIGNORE_LINE}"
    return (
        f"note: {gitignore} does not cover {_GITIGNORE_LINE} "
        "(read-only command; not modified)"
    )


def _corpus_root(args: argparse.Namespace, err: TextIO) -> Path:
    from .corpus import resolve_root

    if getattr(args, "local", False):
        cwd = Path.cwd()
        if args.command in _READ_ONLY_LOCAL_COMMANDS:
            print(f"leitir: {_report_local_gitignore(cwd)}", file=err)
        else:
            print(f"leitir: {_ensure_local_gitignore(cwd)}", file=err)
        return (cwd / ".leitir-refs").absolute()
    return resolve_root(getattr(args, "root", None))


_LOCAL_FIRST_ECOSYSTEMS = frozenset({"pypi", "npm", "crates"})


def _announce_degraded_resolution(
    parsed: CorpusSpec, resolved: object, announce: TextIO | None
) -> None:
    """Announce a registry-only (degraded) resolution (ADR-0023).

    Shared by the live path and the cached-shelf path (issue #245) so
    both surfaces disclose the missing repository tag binding.
    """
    degraded = getattr(resolved, "degraded_provenance", None)
    if degraded is not None and announce is not None:
        package = cast(Any, resolved)
        print(
            f"leitir: warning: {parsed.raw} resolved registry-only "
            f"({degraded}); materialization uses the checksum-verified "
            f"{package.ref.ecosystem.value} artifact, but the immutable "
            "repository tag binding is unavailable — the shelf identity is "
            "registry-derived, not a git commit",
            file=announce,
        )


def _resolve_from_cached_shelf(
    parsed: CorpusSpec, root: Path, announce: TextIO | None
) -> tuple[ResolvedPackage, str | None, str | None, str | None] | None:
    """Resolve an exact ecosystem pin from a verified cached shelf (issue #245).

    Local-first: when the corpus already holds a shelf bound to exactly
    this name+version and it passes full load-time verification
    (``read_valid_manifest`` re-verifies the anchored per-file digests),
    reconstruct the resolution from the cached manifest instead of
    contacting the registry. Falls back to live resolution (returning
    ``None``) on any miss, ambiguity that cannot verify, or an
    unsupported shelf shape — never silently serving an unverifiable
    shelf. Floating/``latest`` specs never enter this path.
    """

    from .corpus import load_sources
    from .materialize import read_valid_manifest

    # issue #268: deliberately non-strict -- this is a best-effort local-
    # cache shortcut with an explicit, safe fallback. A corrupt catalog
    # yields zero candidates, which falls through to ordinary live
    # resolution below exactly as a genuine cache miss would; it never
    # reports a cache hit it doesn't have.
    candidates = [
        entry
        for entry in load_sources(root)
        if entry.get("name") == parsed.name and entry.get("host") == "github.com"
    ]
    matches: list[tuple[bool, dict[str, object], dict[str, object]]] = []
    for entry in sorted(
        candidates,
        key=lambda item: (
            str(item.get("owner")),
            str(item.get("repo")),
            str(item.get("commit_sha")),
        ),
    ):
        relative = Path(str(entry["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            # Same confinement rule as every other index consumer
            # (corpus.enumerate_shelved_sources): an index entry that
            # escapes the corpus root is never read (issue #245 review).
            continue
        manifest = read_valid_manifest(
            root / relative,
            str(entry["owner"]),
            str(entry["repo"]),
            str(entry["commit_sha"]),
            host="github.com",
        )
        if manifest is None:
            continue
        if manifest.get("ecosystem") != parsed.ecosystem:
            continue
        if manifest.get("version") != parsed.version:
            continue
        if manifest.get("source") not in {"registry-artifact", "git-commit"}:
            continue
        # Identity binding: the manifest — written at materialization
        # from the verified resolution — must itself confirm the
        # requested name (and ecosystem). The sources.json ``name`` is
        # unanchored, so binding only to it would let a one-field index
        # edit serve any shelved package as this pin (issue #245 review,
        # P1). A ``name`` field, where recorded, must agree too.
        if not _manifest_spec_binds_identity(manifest.get("spec"), parsed):
            continue
        name_value = manifest.get("name")
        if isinstance(name_value, str) and name_value != parsed.name:
            continue
        matches.append(
            (isinstance(manifest.get("degraded_provenance"), str), entry, manifest)
        )
    # Prefer full-provenance shelves: the ADR-0023 degraded owner is
    # literally ``registry``, which sorts before most real owners, so
    # pure lexicography would let a degraded shelf shadow a coexisting
    # full-provenance shelf for the same pin (issue #245 review).
    matches.sort(
        key=lambda item: (
            item[0],
            str(item[1].get("owner")),
            str(item[1].get("repo")),
            str(item[1].get("commit_sha")),
        )
    )
    for _degraded, entry, manifest in matches:
        try:
            resolved, tag = _reconstruct_cached_resolution(parsed, entry, manifest)
        except ValueError:
            # A tree-valid manifest whose recorded fields cannot
            # reconstruct a valid ResolvedPackage (unsupported shape:
            # non-HTTPS registry URL, non-HTTP docs URLs, unsafe
            # subpath, tag/degraded invariants, unrecognized checksum
            # format, malformed digest) is skipped — never served, and
            # never allowed to break live fallback (issue #245 review).
            continue
        _announce_degraded_resolution(parsed, resolved, announce)
        if announce is not None:
            scope = resolved.scope
            print(
                f"leitir: pin {parsed.raw} -> cached shelf "
                f"{scope.slug}@{scope.commit_sha} "
                "(resolved offline from the corpus index)",
                file=announce,
            )
        return resolved, tag, "cached-shelf", "corpus-index"
    return None


def _manifest_spec_binds_identity(spec_value: object, parsed: CorpusSpec) -> bool:
    """Whether the manifest's recorded ``spec`` binds the requested identity.

    The ``spec`` string is written at materialization time from the
    verified resolution (for example ``pypi:flask@3.0.3``), so requiring
    it to agree with the requested name/ecosystem closes the
    index-substitution hole: editing only the unanchored ``sources.json``
    ``name`` can no longer relabel a shelved package (issue #245 review).
    A spec that does not parse, or disagrees, rejects the candidate.
    """
    if not isinstance(spec_value, str) or not spec_value:
        return False
    try:
        shelved = parse_corpus_spec(spec_value)
    except SpecParseError:
        return False
    if shelved.name != parsed.name:
        return False
    if shelved.ecosystem is not None and shelved.ecosystem != parsed.ecosystem:
        return False
    return True


def _cached_artifact_info(
    kind: str, url: str, checksum: str
) -> ArtifactInfoLike:
    """Reconstruct an artifact descriptor from the anchored checksum.

    Mirrors the live registry conventions in ``parity`` exactly: PyPI
    and crates publish ``sha256:<hex>`` (digest lowercased hex); npm
    publishes ``sha512-<base64>`` whose digest is the base64-decoded
    bytes as hex — never the raw base64 token (issue #245 review). An
    empty or malformed digest raises ``ValueError`` so the candidate is
    skipped (fail-closed) rather than served.
    """
    import base64
    import binascii

    from .parity import ArtifactInfo

    if checksum.startswith("sha256:"):
        token = checksum[len("sha256:"):]
        if len(token) != 64:
            raise ValueError("sha256 checksum must carry a 64-hex digest")
        try:
            int(token, 16)
        except ValueError as exc:
            raise ValueError("sha256 digest must be hexadecimal") from exc
        return ArtifactInfo(kind, url, "sha256", token.lower(), checksum)
    if checksum.startswith("sha512-"):
        token = checksum[len("sha512-"):]
        try:
            raw = base64.b64decode(token, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("sha512 digest must be valid base64") from exc
        if len(raw) != 64:
            raise ValueError("sha512 digest must decode to 64 bytes")
        return ArtifactInfo(kind, url, "sha512", raw.hex(), checksum)
    raise ValueError(f"unrecognized checksum format: {checksum[:12]}")


def _reconstruct_cached_resolution(
    parsed: CorpusSpec,
    entry: dict[str, object],
    manifest: dict[str, object],
) -> tuple[ResolvedPackage, str | None]:
    """Rebuild the ``ResolvedPackage`` a shelf was materialized under.

    Raises ``ValueError`` for any manifest shape that cannot produce a
    valid package (caller skips the candidate and falls back to live
    resolution — the shelf is never served and the error never escapes
    as a hard failure).
    """
    from .resolver import PackageRef, ResolvedPackage

    scope = RepoScope(
        f"{entry['owner']}/{entry['repo']}", str(entry["commit_sha"])
    )
    registry_url = manifest.get("registry_url")
    if not isinstance(registry_url, str) or not registry_url:
        raise ValueError("cached manifest lacks a registry URL")
    tag_value = manifest.get("tag")
    tag = tag_value if isinstance(tag_value, str) and tag_value else None
    artifact = None
    if manifest.get("source") == "registry-artifact":
        kind = manifest.get("artifact_kind")
        checksum = manifest.get("artifact_checksum")
        if not isinstance(kind, str) or not isinstance(checksum, str):
            raise ValueError("registry-artifact manifest lacks artifact metadata")
        artifact = _cached_artifact_info(kind, registry_url, checksum)
    docs = manifest.get("docs_urls")
    docs_urls = (
        tuple(item for item in docs if isinstance(item, str))
        if isinstance(docs, list)
        else ()
    )
    subpath = manifest.get("subpath")
    published_at = manifest.get("published_at")
    degraded = manifest.get("degraded_provenance")
    resolved = ResolvedPackage(
        PackageRef(
            _ecosystem_enum(cast(str, parsed.ecosystem)),
            parsed.name,
            cast(str, parsed.version),
        ),
        scope,
        tag,
        registry_url,
        subpath=subpath if isinstance(subpath, str) else None,
        docs_urls=docs_urls,
        artifact=artifact,
        published_at=published_at if isinstance(published_at, str) else None,
        degraded_provenance=degraded if isinstance(degraded, str) else None,
    )
    return resolved, tag


def _ecosystem_enum(name: str) -> Ecosystem:
    from .resolver import Ecosystem

    return Ecosystem(name)


class _CachedFirstResolverFacade:
    """Serve the CLI's just-computed resolutions to diff_packages (#245).

    ``diff_packages`` re-resolves each spec internally for identity
    metadata even though the CLI has already resolved and materialized
    both sides. During a registry outage that internal re-resolution
    would fail for exact pins whose verified shelves are already on
    disk. This facade answers ``resolve`` from the resolutions captured
    during the CLI's materialization loop (identical binding — it also
    removes mid-run resolution drift) and delegates everything else to
    the live resolver.
    """

    def __init__(self, inner: object, pinned: dict[tuple[str, str, str], object]) -> None:
        self._inner = inner
        self._pinned = pinned

    def resolve(self, ref: object) -> object:
        ecosystem = getattr(getattr(ref, "ecosystem", None), "value", None)
        key = (ecosystem, getattr(ref, "name", None), getattr(ref, "version", None))
        if key in self._pinned:
            return cast(Any, self._pinned[key])
        return cast(Any, self._inner).resolve(ref)

    def latest_version(self, ecosystem: object, name: str) -> str:
        return cast(Any, self._inner).latest_version(ecosystem, name)

    def resolve_tag_to_sha(self, slug: str, tag: str, host: str | None = None) -> str:
        if host is None:
            return cast(Any, self._inner).resolve_tag_to_sha(slug, tag)
        return cast(Any, self._inner).resolve_tag_to_sha(slug, tag, host=host)

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


class _LocalFirstLockResolver:
    """Answer ``lock_project`` pins from verified cached shelves (ADR-0024).

    ``leitir lock`` resolves exact lockfile pins; every edge carries a
    concrete version, so each pin is local-first eligible exactly like
    the spec commands (issue #245): when the corpus already holds the
    verified shelf for the pin, resolution is reconstructed from the
    cached manifest instead of contacting the registry, keeping an
    entire project lock usable during a registry outage. Any miss,
    ambiguity, or unverifiable shelf falls back to the live resolver —
    the lock never serves a shelf the cached path would reject.
    """

    def __init__(self, inner: object, root: Path, announce: TextIO | None) -> None:
        self._inner = inner
        self._root = root
        self._announce = announce

    def resolve(self, ref: object) -> object:
        ecosystem = getattr(getattr(ref, "ecosystem", None), "value", None)
        name = getattr(ref, "name", None)
        version = getattr(ref, "version", None)
        if (
            isinstance(ecosystem, str)
            and ecosystem in _LOCAL_FIRST_ECOSYSTEMS
            and isinstance(name, str)
            and isinstance(version, str)
        ):
            parsed = CorpusSpec(
                raw=f"{ecosystem}:{name}@{version}",
                ecosystem=ecosystem,
                name=name,
                version=version,
            )
            cached = _resolve_from_cached_shelf(parsed, self._root, self._announce)
            if cached is not None:
                return cached[0]
        return cast(Any, self._inner).resolve(ref)

    def resolve_tag_to_sha(self, slug: str, tag: str, host: str | None = None) -> str:
        if host is None:
            return cast(Any, self._inner).resolve_tag_to_sha(slug, tag)
        return cast(Any, self._inner).resolve_tag_to_sha(slug, tag, host=host)

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


def _resolve_corpus_spec(
    parsed: CorpusSpec,
    resolver: object,
    heads: object,
    cwd: Path,
    announce: TextIO | None = None,
    root: Path | None = None,
) -> tuple[RepoScope | ResolvedPackage, str | None, str | None, str | None]:
    """Resolve a parsed corpus spec, pinning donors to immutable tags by default.

    Head-kind GitHub specs (no explicit ref) resolve through the transport's
    tag-aware default-pin path when available: the latest stable release tag
    plus its dereferenced commit SHA, announced as immutable. Repositories
    with no stable tag inside the bounded tag crawl fall back to a
    default-branch HEAD pin labeled non-immutable; a tag is never invented
    (issue #189 C-1/C-2). Explicit
    branch specs keep ``resolve_head_sha`` semantics and are announced
    non-immutable with the resolution date (C-3). Transports without the
    tag-aware path (embedding seams, fakes) keep the legacy resolution.

    ``announce`` is deliberately positional so test seams that replace this
    function with ``lambda *_args: ...`` keep working.
    """
    from .resolver import resolve_corpus_spec

    # Issue #245: exact ecosystem pins resolve local-first when the
    # corpus already holds the verified shelf, so cached pins stay
    # usable during a registry outage. Floating/latest specs keep the
    # live path.
    if (
        root is not None
        and parsed.ecosystem in _LOCAL_FIRST_ECOSYSTEMS
        and parsed.version is not None
    ):
        cached = _resolve_from_cached_shelf(parsed, root, announce)
        if cached is not None:
            return cached
    if (
        parsed.ecosystem is None
        and parsed.ref_kind == "head"
        and parsed.host in (None, "github.com")
    ):
        pin_resolver = getattr(heads, "resolve_default_pin", None)
        if callable(pin_resolver):
            pin = pin_resolver(parsed.name)
            if announce is not None:
                print(f"leitir: pin {parsed.raw} -> {pin.describe()}", file=announce)
            return (
                RepoScope(parsed.name, pin.commit_sha),
                pin.ref_name if pin.ref_kind == "tag" else None,
                None,
                None,
            )
    resolved, tag, version_source, detection_source = resolve_corpus_spec(
        parsed,
        cast("_CorpusResolver", resolver),
        cast("_HeadResolver", heads),
        cwd,
    )
    _announce_degraded_resolution(parsed, resolved, announce)
    if announce is not None and parsed.ecosystem is None and parsed.ref_kind == "branch":
        scope = cast(RepoScope, getattr(resolved, "scope", resolved))
        from .materialize import _utc_now

        print(
            f"leitir: pin {parsed.raw} -> branch {parsed.ref} "
            f"commit {scope.commit_sha} "
            f"(non-immutable: branch head; resolved {_utc_now()})",
            file=announce,
        )
    return resolved, tag, version_source, detection_source


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


def root_for_bts(args: argparse.Namespace) -> Path:
    """Resolve the corpus root for the BTS commands (no gitignore side talk)."""

    from .corpus import resolve_root

    if getattr(args, "local", False):
        return (Path.cwd() / ".leitir-refs").absolute()
    return resolve_root(getattr(args, "root", None))


def _require_bts_shelf_authenticated(
    root: Path,
    owner: str,
    repo: str,
    commit_sha: str,
    args: argparse.Namespace,
    *,
    err: TextIO,
) -> None:
    """Fail closed unless the BTS donor shelf carries a valid signature."""

    from .materialize import read_valid_manifest, target_path

    target = target_path(root, owner, repo, commit_sha)
    manifest = read_valid_manifest(target, owner, repo, commit_sha)
    if manifest is None:
        raise ValueError(
            f"materialized source failed load-time verification: {target}"
        )
    _require_authenticated_manifest(
        manifest,
        target,
        trusted_keys=getattr(args, "trusted_keys", None),
        err=err,
    )


def _require_all_shelves_authenticated(
    root: Path, args: argparse.Namespace, *, err: TextIO
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
        manifest = read_valid_manifest(
            target,
            entry["owner"],
            entry["repo"],
            entry["commit_sha"],
            host=entry["host"],
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


def _require_authenticated_manifest(
    manifest: Mapping[str, object],
    shelf: Path,
    *,
    trusted_keys: str | None,
    err: TextIO | None,
) -> None:
    """Fail closed unless ``shelf`` carries a valid publisher signature.

    Shared enforcement for every read-side command's
    ``--require-manifest-auth`` (audit 2026-08-23 P2): before any signed-
    shelves-only policy output is produced, the shelf's manifest must verify
    against the configured trusted keys.
    """

    from .manifest_auth import load_trusted_keys, require_manifest_auth

    require_manifest_auth(
        manifest,
        shelf,
        trusted_keys=load_trusted_keys(trusted_keys, shelf_context=shelf),
    )


def _corpus_list(
    root: Path,
    *,
    as_json: bool,
    out: TextIO,
    err: TextIO | None = None,
    require_auth: bool = False,
    trusted_keys: str | None = None,
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
        manifest = read_valid_manifest(
            root / entry["path"],
            entry["owner"],
            entry["repo"],
            entry["commit_sha"],
            host=entry["host"],
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
    root: Path, *, dry_run: bool, recompute_git_parity: bool, out: TextIO
) -> int:
    """Backfill integrity anchors; parity recomputation can downgrade exact to drift."""
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
) -> int:
    from .corpus import INDEX_NAME, materialize_source, remove_source
    from .docpointers import POINTERS_NAME

    try:
        require_manifest_authentication = False
        if getattr(args, "require_manifest_auth", False):
            require_manifest_authentication = True
        root = _corpus_root(args, err)
        if args.command == "list":
            _corpus_list(
                root,
                as_json=args.as_json,
                out=out,
                err=err,
                require_auth=require_manifest_authentication,
                trusted_keys=getattr(args, "trusted_keys", None),
            )
            return int(ExitCode.SUCCESS)
        if args.command == "upgrade-cache":
            return _upgrade_cache(
                root,
                dry_run=args.dry_run,
                recompute_git_parity=args.recompute_git_parity,
                out=out,
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
                _require_all_shelves_authenticated(root, args, err=err)
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
                _require_all_shelves_authenticated(root, args, err=err)
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
            pinned_resolutions: dict[tuple[str, str, str], object] = {}
            for raw in (args.spec_a, args.spec_b):
                parsed = parse_corpus_spec(raw)
                resolved, tag, version_source, _detection = _resolve_corpus_spec(
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
                )
            if args.as_json:
                print(report.to_json(), file=out)
            else:
                _write_diff_human(report, out)
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
                resolved, _, _, _ = _resolve_corpus_spec(
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
                _require_all_shelves_authenticated(root, args, err=err)
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
                        brief_document = build_brief_info(raw, corpus_root=root)
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
                    document = build_info(raw, corpus_root=root)
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


def _run_ask_command(
    args: argparse.Namespace,
    *,
    resolver_factory: Callable[[str | None], object],
    code_search_factory: Callable[[str | None], object],
    tree_source_factory: Callable[[str | None], object],
    searcher_factory: Callable[..., object],
    out: TextIO,
    err: TextIO,
) -> int:
    """Answer a task-shaped query for one package pinned by its lockfile.

    Delegates every materialization, provenance, verified-signature,
    ranked-example, and citation computation to ``leitir info``'s existing
    machinery (via :func:`_run_corpus_command`, which calls
    :func:`leitir.info.build_brief_info`) -- none of it is recomputed here
    (issue #266 A3). This function only (1) resolves the version strictly
    from the caller's own project lockfile, never a registry "latest"
    lookup and never ambient filesystem discovery, and (2) compiles the
    free-text task into deterministic search predicates
    (:func:`leitir.ask.compile_task_predicates`) and runs them against the
    exact shelf ``info`` just materialized.
    """
    import io

    from .ask import compile_task_predicates, rerun_search_command
    from .lockfiles import detect_installed_version_with_source

    pin_input = Path(args.pin).expanduser().absolute()
    pin_dir = pin_input.parent if pin_input.is_file() else pin_input
    if not pin_dir.is_dir():
        print(
            f"leitir: error: --pin directory not found: {redact(str(pin_dir))}",
            file=err,
        )
        return int(ExitCode.MALFORMED_USAGE)

    detected = detect_installed_version_with_source(args.ecosystem, args.package, pin_dir)
    if detected is None:
        print(
            "leitir: error: could not resolve an exact version of "
            f"{args.package!r} ({args.ecosystem}) from a lockfile under "
            f"{redact(str(pin_dir))}; ask requires the project's own lockfile "
            "to pin the version and never falls back to the registry "
            "'latest' version or to ambient filesystem discovery",
            file=err,
        )
        return int(ExitCode.CORPUS_FAILURE)

    prefix = {"npm": "npm", "pypi": "pypi", "crates": "crates", "go": "go"}[
        args.ecosystem
    ]
    spec_str = f"{prefix}:{args.package}@{detected.version}"

    info_args = argparse.Namespace(
        command="info",
        spec=spec_str,
        as_json=True,
        brief=True,
        root=args.root,
        local=args.local,
        cwd=None,
        no_verify=args.no_verify,
        require_manifest_auth=args.require_manifest_auth,
        trusted_keys=args.trusted_keys,
    )
    info_out = io.StringIO()
    info_result = _run_corpus_command(
        info_args,
        resolver_factory=resolver_factory,
        code_search_factory=code_search_factory,
        out=info_out,
        err=err,
    )
    if info_result != int(ExitCode.SUCCESS):
        return info_result

    brief_document = json.loads(info_out.getvalue())
    provenance = cast(dict[str, Any], brief_document["provenance"])

    predicates = compile_task_predicates(args.task)
    compiled = bool(predicates)

    matches_payload: list[dict[str, Any]] | None = None
    coverage_payload: dict[str, Any] | None = None
    search_error: str | None = None
    if compiled:
        owner = provenance.get("owner")
        repo = provenance.get("repo")
        commit_sha = provenance.get("commit_sha")
        try:
            scope = RepoScope(
                slug=f"{owner}/{repo}", commit_sha=cast(str, commit_sha)
            )
            spec = SearchSpec(
                mode=SearchMode.SCOPED_EXHAUSTIVE,
                must=predicates,
                scopes=(scope,),
            )
            token = _github_token()
            tree_source = tree_source_factory(token)
            corpus_root = _corpus_root(args, err)
            searcher = cast(
                _Searcher, searcher_factory(tree_source, corpus_root=corpus_root)
            )
            report = searcher.search(spec)
        except (SearchSpecError, ValueError, VerificationError) as exc:
            search_error = redact(str(exc))
        else:
            matches_payload = [match.to_dict() for match in report.matches]
            coverage_payload = report.coverage.to_dict()

    rerun_command = (
        rerun_search_command(
            package=args.package,
            version=detected.version,
            ecosystem=args.ecosystem,
            predicates=predicates,
        )
        if compiled
        else None
    )
    query_compilation: dict[str, Any] = {
        "compiled": compiled,
        "reason": (
            None
            if compiled
            else "no quoted literal, call, or identifier-shaped token found in "
            "the task description"
        ),
        "predicates": canonical_predicates(predicates),
        "rerun_command": rerun_command,
    }
    if search_error is not None:
        query_compilation["search_error"] = search_error

    document: dict[str, Any] = {
        "schema_version": 1,
        "task": args.task,
        "package": {
            "ecosystem": args.ecosystem,
            "name": args.package,
            "version": detected.version,
            "version_source": "lockfile",
            "lockfile": detected.source,
            "spec": spec_str,
        },
        "provenance": provenance,
        "citation": brief_document["citation"],
        "signatures": cast(dict[str, Any], brief_document["api"])["top_symbols"],
        "examples": cast(dict[str, Any], brief_document["examples"])["top"],
        "trust": brief_document["trust"],
        "query_compilation": query_compilation,
        "matches": matches_payload,
        "coverage": coverage_payload,
    }

    if args.as_json:
        print(json.dumps(document, indent=2, sort_keys=True), file=out)
    else:
        print(args.task, file=out)
        print(f"package: {spec_str} (from {detected.source})", file=out)
        print(document["citation"], file=out)
        for symbol in document["signatures"]:
            print(
                f"  {symbol['kind']} {symbol['qualified_name']}"
                f"{symbol['signature'] or ''}",
                file=out,
            )
        if compiled:
            printed = ", ".join(
                f"{item['kind']}:{item['value']}"
                for item in query_compilation["predicates"]
            )
            print(f"compiled query: {printed}", file=out)
            print(f"rerun: {rerun_command}", file=out)
            if search_error is not None:
                print(f"search error: {search_error}", file=out)
            elif matches_payload:
                print(f"matches: {len(matches_payload)}", file=out)
                for match in matches_payload[:5]:
                    source = cast(dict[str, Any], match["source"])
                    print(f"  {source['permalink']}", file=out)
            else:
                print("matches: 0", file=out)
        else:
            print(f"query not compiled: {query_compilation['reason']}", file=out)
        print(f"trust: {document['trust']}/100", file=out)

    if search_error is not None:
        return int(ExitCode.CORPUS_FAILURE)
    return int(ExitCode.SUCCESS)


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


def _corpus_routings(root: Path) -> dict[tuple[str, str], dict[str, str]]:
    """Routing guidance for every materialized corpus source (issue #190).

    Keyed by ``(owner/repo, commit_sha)`` — the identity a search match
    carries — so the search rendering can attach corpus-derived license
    routing instead of the fail-closed undetermined default.

    issue #268: deliberately non-strict. A corrupt catalog yields an empty
    mapping, and every lookup miss already falls back to the fail-closed
    ``license-undetermined`` routing described above -- there is no
    "complete corpus" claim made here for corruption to falsify.
    """

    from .corpus import load_sources
    from .info import source_routing
    from .materialize import read_valid_manifest

    routings: dict[tuple[str, str], dict[str, str]] = {}
    for entry in load_sources(root):
        manifest = read_valid_manifest(
            root / entry["path"],
            entry["owner"],
            entry["repo"],
            entry["commit_sha"],
            host=entry["host"],
        )
        if manifest is None:
            continue
        routings[
            (f"{entry['owner']}/{entry['repo']}", str(entry["commit_sha"]))
        ] = source_routing(root / entry["path"], manifest.get("license_identifier"))
    return routings


def _write_summary(
    report: SearchReport,
    *,
    file: TextIO,
    routings: dict[tuple[str, str], dict[str, str]] | None = None,
    bounds: CoverageBounds | None = None,
) -> None:
    from .license_policy import undetermined_routing

    cov = report.coverage
    if bounds is not None:
        # Global discovery (issue #191): a lower-bound coverage statement —
        # pages fetched / matches returned / incomplete flag — instead of the
        # raw indeterminate status.  Never a total-coverage claim.
        line = (
            f"coverage=bounded-discovery "
            f"pages={bounds.pages_fetched} "
            f"matches={bounds.matches_returned} "
            f"incomplete={str(bounds.incomplete).lower()}"
        )
        if bounds.incomplete:
            provenance = ",".join(bounds.bounds) or "unspecified"
            line += f" bound={provenance}"
            print(line, file=file)
            print(
                "note: results may be incomplete — the coverage above is a "
                f"lower bound (bound that fired: {provenance}), not a total",
                file=file,
            )
        else:
            print(line, file=file)
    else:
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
        # Search-time license detection does not run (no extra network calls),
        # so routing is corpus-derived when known and fail-closed undetermined
        # otherwise (issue #190: every surfaced source carries the field).
        routing = (routings or {}).get((src.slug, src.commit_sha)) or undetermined_routing().as_field()
        print(
            f"  {src.path}:{src.start_line}-{src.end_line} "
            f"score={match.score:.1f} [{kinds}] "
            f"{src.slug}@{src.commit_sha[:12]} "
            f"routing={routing['verdict']}/{routing['reason']}",
            file=file,
        )
    if len(report.matches) > 10:
        print(f"  ... and {len(report.matches) - 10} more", file=file)


def _write_corpus_summary(report: CorpusSearchReport, *, file: TextIO) -> None:
    """Honest human-readable summary for ``leitir search --corpus``.

    Always names excluded shelves (issue #266): a shelf that is unindexed
    (under ``--require-index``), drift-parity, registry-derived, on an
    unsupported host, or fails load-time verification is printed by identity
    and reason, never folded silently into the numeric coverage line.
    """
    cov = report.coverage
    print(
        f"corpus_status={report.corpus_status.value} "
        f"coverage={cov.status.value} "
        f"shelves_declared_total={report.shelves_declared_total} "
        f"shelves_searched={len(report.shelves_searched)} "
        f"shelves_excluded={len(report.shelves_excluded)} "
        f"eligible={cov.files_eligible} "
        f"indexed={cov.files_indexed} "
        f"excluded={cov.files_excluded} "
        f"matches={len(report.matches)}",
        file=file,
    )
    for exclusion in report.shelves_excluded:
        print(
            f"  excluded {exclusion.host}:{exclusion.owner}/{exclusion.repo}"
            f"@{exclusion.commit_sha[:12]} reason={exclusion.reason}",
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


def _report_json_with_coverage_bounds(
    report: SearchReport, bounds: CoverageBounds | None
) -> str:
    """Add global discovery bounds without changing the closed report model."""
    if bounds is None:
        return report.to_json()

    from .discovery_search import CoverageBounds as RuntimeCoverageBounds

    if not isinstance(bounds, RuntimeCoverageBounds):
        raise ValueError("global search returned malformed coverage bounds")
    payload = json.loads(report.to_json())
    if not isinstance(payload, dict) or not isinstance(payload.get("coverage"), dict):
        raise ValueError("search report has malformed coverage")
    payload["coverage"].update(bounds.to_dict())
    return json.dumps(payload, indent=2, sort_keys=False)


def _write_cli_payload(payload: dict[str, object], *, as_json: bool, out: TextIO) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True), file=out)
        return
    for key in sorted(payload):
        value = payload[key]
        if isinstance(value, (dict, list, tuple)):
            rendered = json.dumps(value, sort_keys=True)
        else:
            rendered = str(value)
        print(f"{key}={rendered}", file=out)


def _write_bts_error(exc: Exception, *, as_json: bool, err: TextIO) -> None:
    if as_json:
        from .bts_errors import BTSError
        from .usage import UsageError

        if isinstance(exc, BTSError):
            print(f"leitir: error: {exc.to_json().strip()}", file=err)
            return
        if isinstance(exc, UsageError):
            print(f"leitir: error: {json.dumps(exc.to_json(), sort_keys=True)}", file=err)
            return
    print(f"leitir: error: {redact(str(exc))}", file=err)


# Conventional shell exit code for a process terminated by SIGINT (128 + 2).
# Not part of ExitCode: that enum enumerates *command outcomes* the corpus
# logic can decide on (success/failure/malformed/etc.), whereas an interrupt
# is delivered by the OS mid-operation and never reaches command logic at
# all. Reusing 130 keeps `leitir` consistent with how every POSIX shell
# already reports Ctrl+C for any other program.
_SIGINT_EXIT_CODE = 130


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
    """Parse one command and wire resolver -> engine -> report.

    This is a thin wrapper around :func:`_main_impl` whose sole job is to
    convert a ``KeyboardInterrupt`` raised anywhere during command dispatch
    (network I/O, materialization, searching, ...) into a clean, single-line
    stderr message and a conventional exit code instead of letting a raw
    traceback reach the user. It intentionally does not install a custom
    signal handler and does not suppress the interrupt: a second Ctrl+C
    during unwinding still raises normally, and this handler only fires
    once the first KeyboardInterrupt has already unwound the stack.
    """
    err = stderr or sys.stderr
    try:
        return _main_impl(
            argv,
            tree_source_factory=tree_source_factory,
            resolver_factory=resolver_factory,
            searcher_factory=searcher_factory,
            code_search_factory=code_search_factory,
            global_searcher_factory=global_searcher_factory,
            benchmark_runner_factory=benchmark_runner_factory,
            stdout=stdout,
            stderr=stderr,
            _exit_windows_doctor_success=_exit_windows_doctor_success,
        )
    except KeyboardInterrupt:
        try:
            print("leitir: interrupted", file=err)
        except OSError as exc:
            if not _is_broken_pipe_error(exc):
                raise
        return _SIGINT_EXIT_CODE


def _main_impl(
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
                error = sys.exception()
                if isinstance(error, KeyboardInterrupt):
                    # Honor the same clean-interrupt contract as main():
                    # a short message on stderr and the conventional SIGINT
                    # exit code, never a raw traceback. This still needs
                    # os._exit (see below) because os.name == "nt" here and
                    # a normal `raise`/return would unwind back through
                    # Py_RunMain, which can stomp the exit status.
                    try:
                        print("leitir: interrupted", file=err)
                    except OSError as exc:
                        if not _is_broken_pipe_error(exc):
                            raise
                    os._exit(_SIGINT_EXIT_CODE)
                # Py_RunMain changes the status to 120 when Py_FinalizeEx
                # cannot flush Windows stdout.  Exit with doctor's actual
                # result (or infrastructure failure if it raised) first.
                try:
                    if error is not None:
                        sys.excepthook(type(error), error, error.__traceback__)
                finally:
                    os._exit(result)

    if args.command == "bench":
        token = _github_token()
        if token is None:
            print(
                "leitir: warning: anonymous search benchmarks consume significant GitHub API budget; set GH_TOKEN to raise limits",
                file=err,
            )
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
                if benchmark_runner_factory is _build_default_benchmark_runner:
                    total_tasks = len(cast(Sequence[object], getattr(manifest, "tasks", ())))
                    runner = cast(
                        _BenchmarkRunner,
                        _build_default_benchmark_runner(
                            searcher,
                            progress=_bench_progress_reporter(total_tasks, err=err),
                        ),
                    )
                else:
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
        "bts-compute",
        "bts-funnel",
        "bts-run",
        "analysis-architecture",
        "analysis-lineage",
        "exit-gate-validate",
        "exit-gate-run",
        "occupied-validate",
        "usage",
    }:
        try:
            if args.command in {"bts-compute", "bts-run"} and getattr(
                args, "require_manifest_auth", False
            ):
                owner, repo, commit_sha = args.spec
                _require_bts_shelf_authenticated(root_for_bts(args), owner, repo, commit_sha, args, err=err)
            if args.command == "bts-compute":
                from .bts import BTSStatus
                from .bts_cli import SeedSelector, list_bts_seeds, run_bts_compute, write_artifacts

                owner, repo, commit_sha = args.spec
                if args.list_seeds:
                    if args.seed_module is not None or args.seed_name is not None or args.out is not None:
                        raise ValueError("--list-seeds cannot be combined with --seed-module, --seed-name, or --out")
                    seeds = list_bts_seeds(
                        _corpus_root(args, err), owner, repo, commit_sha,
                        language=args.language, lock_path=Path(args.lock).expanduser().absolute(),
                    )
                    _write_cli_payload({"schema_version": "leitir-bts-seed-list-v1", "seeds": [{"module": seed.module, "qualified_name": seed.qualified_name, "kind": seed.kind.value, "origin": seed.origin.value} for seed in seeds]}, as_json=True, out=out)
                    return successful()
                if args.seed_module is None or args.seed_name is None or args.out is None:
                    raise ValueError("bts-compute requires --seed-module, --seed-name, and --out unless --list-seeds is used")
                artifacts = run_bts_compute(
                    _corpus_root(args, err),
                    owner,
                    repo,
                    commit_sha,
                    language=args.language,
                    lock_path=Path(args.lock).expanduser().absolute(),
                    policy_path=None if args.policy is None else Path(args.policy).expanduser().absolute(),
                    seed=SeedSelector(args.seed_module, args.seed_name),
                )
                output_directory = Path(args.out).expanduser().absolute()
                write_artifacts(artifacts, output_directory)
                if args.as_json:
                    _write_cli_payload(artifacts.summary, as_json=True, out=out)
                else:
                    _write_cli_payload(artifacts.summary, as_json=False, out=err)
                    print(
                        f"leitir: wrote BTS artifacts to {output_directory}", file=err
                    )
                if artifacts.result.status is BTSStatus.REJECT and not args.allow_reject:
                    return int(ExitCode.CORPUS_FAILURE)
            elif args.command == "bts-funnel":
                from .funnel_cli import run_funnel

                payload = run_funnel(
                    Path(args.spec), Path(args.recipient_manifest), Path(args.stages)
                )
                _write_cli_payload(payload, as_json=args.as_json, out=out)
            elif args.command == "bts-run":
                from .bts_cli import (
                    SeedSelector,
                    resolve_containment_substrate,
                    write_containment_environment_receipt,
                )
                from .pipeline_cli import run_pipeline

                packet_inputs = None
                if args.emit_packets is not None:
                    from .safeio import read_regular_file
                    from .transplant import _inputs_from_value, _strict_json

                    packet_path = Path(args.emit_packets)
                    # The packet parser verifies its embedded digest anchor.
                    packet_bytes = read_regular_file(packet_path, maximum_bytes=1 << 20, no_follow=False)
                    packet_inputs = _inputs_from_value(_strict_json(packet_bytes))
                owner, repo, commit_sha = args.spec
                # Any of the five containment-substrate flags may be omitted;
                # each unset field resolves independently from the committed,
                # self-verified descriptor (ADR-0009 Amendment 1). An explicit
                # flag always wins for that field. This is a convenience over
                # the runtime containment verification in exec_sandbox, never
                # a substitute for it: the resolved values flow unchanged into
                # the same measured checks an explicit flag goes through today.
                resolved_substrate = resolve_containment_substrate(
                    nsjail_sha256=args.nsjail_sha256,
                    nsjail_version=args.nsjail_version,
                    nsjail_build_identity=args.nsjail_build_identity,
                    config_schema_digest=args.config_schema_digest,
                    rootfs_source=args.rootfs_source,
                    rootfs_digest=args.rootfs_digest,
                    descriptor_path=None if args.containment_environment is None else Path(args.containment_environment),
                )
                out_dir = Path(args.out)
                out_dir.mkdir(parents=True, exist_ok=True)
                # Written before the run so the audit trail of what was
                # resolved and from where survives even a rejected run.
                write_containment_environment_receipt(out_dir, resolved_substrate)
                pipeline_result = run_pipeline(
                    _corpus_root(args, err), owner, repo, commit_sha,
                    seed=SeedSelector(args.seed_module, args.seed_name),
                    contract_tests_path=Path(args.contract_spec),
                    out_dir=out_dir,
                    recipient_package=args.recipient_package,
                    nsjail_sha256=resolved_substrate.nsjail_sha256.value,
                    nsjail_version=resolved_substrate.nsjail_version.value,
                    nsjail_build_identity=resolved_substrate.nsjail_build_identity.value,
                    config_schema_digest=resolved_substrate.config_schema_digest.value,
                    rootfs_source=Path(resolved_substrate.rootfs_source.value),
                    rootfs_digest=resolved_substrate.rootfs_digest.value,
                    policy_path=None if args.policy is None else Path(args.policy),
                    emit_packets=packet_inputs,
                )
                payload = {
                    "schema_version": "leitir-pipeline-cli-v1",
                    "verdict": pipeline_result.verdict.status.value,
                    "bts_digest": pipeline_result.verdict.bts_digest,
                    "relocation_digest": pipeline_result.verdict.relocation_digest,
                    "rerun_report_digest": pipeline_result.verdict.rerun_report_digest,
                    "probe_report_digest": pipeline_result.verdict.probe_report_digest,
                    "containment_environment_resolution": resolved_substrate.receipt(),
                }
                _write_cli_payload(payload, as_json=args.as_json, out=out)
            elif args.command == "analysis-architecture":
                from .analysis_cli import run_architecture_assessment

                payload = run_architecture_assessment(
                    Path(args.graph),
                    subject=args.subject,
                    catalog_path=Path(args.catalog) if args.catalog is not None else None,
                    declared_concurrency=args.declared_concurrency,
                )
                _write_cli_payload(payload, as_json=args.as_json, out=out)
            elif args.command == "analysis-lineage":
                from .analysis_cli import validate_lineage_manifest

                payload = validate_lineage_manifest(Path(args.manifest))
                _write_cli_payload(payload, as_json=args.as_json, out=out)
            elif args.command == "exit-gate-validate":
                from .exit_corpus import (
                    cross_check_against_gate,
                    validate_corpus_manifest,
                )

                corpus_path = Path(args.corpus)
                payload = {
                    "cross_check_against_gate": cross_check_against_gate(corpus_path),
                    "validation": validate_corpus_manifest(corpus_path),
                }
                _write_cli_payload(payload, as_json=args.as_json, out=out)
            elif args.command == "exit-gate-run":
                from .pipeline_cli import exit_gate_run

                payload = exit_gate_run(
                    Path(args.corpus), Path(args.corpus_root if args.donors_dir is None else args.donors_dir),
                    corpus_root=Path(args.corpus_root),
                    out_dir=None if args.out is None else Path(args.out),
                    nsjail_version=args.nsjail_version,
                    nsjail_build_identity=args.nsjail_build_identity,
                    config_schema_digest=args.config_schema_digest,
                    rootfs_source=Path(args.rootfs_source),
                    substrate_nsjail_sha256=args.substrate_nsjail_sha,
                    substrate_rootfs_digest=args.substrate_rootfs_digest,
                    trusted_keys_path=None if args.trusted_keys is None else Path(args.trusted_keys),
                    ratification_sidecar=None if args.ratification_sidecar is None else Path(args.ratification_sidecar),
                )
                _write_cli_payload(payload, as_json=args.as_json, out=out)
            elif args.command == "usage":
                from .usage.cli_support import (
                    assemble_payload,
                    load_assemble_plan,
                    load_report,
                    replay_payload,
                    verify_payload,
                )

                if args.action == "replay" and (args.corpus_root is None or args.requirements is None):
                    print(
                        "leitir: error: usage replay requires --corpus-root and --requirements",
                        file=err,
                    )
                    return int(ExitCode.MALFORMED_USAGE)
                if args.action == "assemble" and args.out is None:
                    print("leitir: error: usage assemble requires --out", file=err)
                    return int(ExitCode.MALFORMED_USAGE)
                if args.times < 1:
                    print("leitir: error: --times must be >= 1", file=err)
                    return int(ExitCode.MALFORMED_USAGE)

                if args.action == "assemble":
                    plan = load_assemble_plan(Path(args.report))
                    consumer_root = None if args.corpus_root is None else Path(args.corpus_root)
                    payload = assemble_payload(plan, consumer_root=consumer_root, out_path=Path(args.out))
                    print(
                        f"leitir: usage assemble ok report_digest={payload['report_digest']}",
                        file=err,
                    )
                else:
                    usage_report = load_report(Path(args.report))
                    if args.action == "verify":
                        payload = verify_payload(usage_report)
                    else:
                        payload = replay_payload(
                            usage_report,
                            corpus_root=Path(args.corpus_root),
                            dependency_path=Path(args.requirements),
                            times=args.times,
                        )
                    print(
                        f"leitir: usage {args.action} ok report_digest={usage_report.report_digest}",
                        file=err,
                    )
                _write_cli_payload(payload, as_json=args.as_json, out=out)
            else:
                from .pipeline_cli import occupied_validate
                from .safeio import read_regular_file

                # Occupied artifacts are validated against their digest anchor.
                artifact = read_regular_file(Path(args.artifact), maximum_bytes=1 << 20, no_follow=False)
                payload = occupied_validate(artifact)
                _write_cli_payload(payload, as_json=args.as_json, out=out)
        except Exception as exc:
            _write_bts_error(exc, as_json=args.as_json, err=err)
            return int(ExitCode.CORPUS_FAILURE)
        return successful()

    if args.command == "check":
        from .check import (
            CheckIndexError,
            UnsupportedLanguageError,
            discover_python_files,
            guess_import_root,
            run_check,
        )
        from .corpus import materialize_source
        from .materialize import MaterializationError, _target_lock, read_valid_manifest

        consumer_path = Path(args.path).expanduser().absolute()
        try:
            # Gate on language before any network/materialization work: a
            # non-Python path must reject fast and offline (issue #266 B3).
            discover_python_files(consumer_path)

            root = _corpus_root(args, err)
            token = _github_token()
            resolver = resolver_factory(token)
            heads = code_search_factory(token)
            cwd = Path(args.cwd or Path.cwd()).expanduser().absolute()
            parsed = parse_corpus_spec(args.against)
            resolved, tag, version_source, _detection = _resolve_corpus_spec(
                parsed, resolver, heads, cwd, err, root
            )
            scope = cast(RepoScope, getattr(resolved, "scope", resolved))
            materialize_host = (
                parsed.host or "github.com"
                if parsed.ecosystem is None
                else getattr(resolved, "host", "github.com")
            )
            fetch_options: _FetchOptions = {}
            if os.environ.get("LEITIR_CODELOAD_BASE_URL"):
                fetch_options["base_url"] = os.environ["LEITIR_CODELOAD_BASE_URL"]
            if os.environ.get("LEITIR_GITHUB_API_BASE_URL"):
                fetch_options["tree_base_url"] = os.environ["LEITIR_GITHUB_API_BASE_URL"]
            fetch_options["verify"] = not args.no_verify

            def _announce_fetch() -> None:
                print(f"leitir: materializing {args.against}", file=err)

            target = materialize_source(
                args.against,
                resolved,
                root=root,
                name=parsed.name,
                tag=tag,
                version_source=version_source,
                host=materialize_host,
                repository_resolver=(
                    getattr(resolver, "_repository_resolvers", {}).get(materialize_host)
                    if materialize_host != "github.com"
                    else None
                ),
                on_fetch=_announce_fetch,
                **fetch_options,
            )
            owner, repo = scope.slug.rsplit("/", 1)
            if materialize_host == "git.sr.ht" and not owner.startswith("~"):
                owner = f"~{owner}"
            with _target_lock(root, target, scope.commit_sha):
                manifest = read_valid_manifest(
                    target, owner, repo, scope.commit_sha, host=materialize_host
                )
                if manifest is None:
                    raise VerificationError(
                        f"materialized source failed load-time verification: {target}"
                    )
                recorded_subpath = manifest.get("subpath")
                scan_path = (
                    target / recorded_subpath
                    if isinstance(recorded_subpath, str)
                    else target
                )
                check_report = run_check(
                    consumer_path=consumer_path,
                    against=args.against,
                    package_name=parsed.name,
                    materialized_root=scan_path,
                )
        except (UnsupportedLanguageError, FileNotFoundError, SpecParseError) as exc:
            print(f"leitir: error: {redact(str(exc))}", file=err)
            return int(ExitCode.MALFORMED_USAGE)
        except (CheckIndexError, VerificationError, MaterializationError) as exc:
            print(f"leitir: error: {redact(str(exc))}", file=err)
            return int(ExitCode.CORPUS_FAILURE)
        except Exception as exc:
            print(f"leitir: error: {redact(str(exc))}", file=err)
            return int(ExitCode.CORPUS_FAILURE)

        _write_cli_payload(check_report.to_dict(), as_json=args.as_json, out=out)
        print(
            f"leitir: check {args.path} against {args.against}: "
            f"ok={check_report.sites_ok} violations={check_report.sites_violation} "
            f"unresolved={check_report.sites_unresolved} examined={check_report.sites_examined}",
            file=err,
        )
        if check_report.sites_examined == 0:
            # P1 fix (defect 2): zero examined sites means nothing was
            # verified -- it must never read as a clean pass. This most
            # commonly happens when guess_import_root's normalized-name
            # guess is simply wrong for a renamed distribution (pillow ->
            # PIL, beautifulsoup4 -> bs4, PyYAML -> yaml, python-dateutil ->
            # dateutil, scikit-learn -> sklearn): the resolver then finds no
            # usage of the guessed import root anywhere in the input, so
            # there is nothing to examine at all. Reuses ExitCode.
            # NOTHING_INDEXED -- the same "completed cleanly, but verified
            # nothing" tier `index` already established -- rather than
            # inventing a new code for the same shape of outcome.
            print(
                f"leitir: check found no usage of {args.against} (looked for "
                f"import root {guess_import_root(parsed.name)!r}) anywhere in "
                f"{args.path} -- NOTHING was examined or verified; this is "
                "exit code 4 (NOTHING_INDEXED), not a passing check",
                file=err,
            )
            return int(ExitCode.NOTHING_INDEXED)
        if not check_report.passed:
            return int(ExitCode.CORPUS_FAILURE)
        return successful()

    if args.command == "ask":
        result = _run_ask_command(
            args,
            resolver_factory=resolver_factory,
            code_search_factory=code_search_factory,
            tree_source_factory=tree_source_factory,
            searcher_factory=searcher_factory,
            out=out,
            err=err,
        )
        if result == int(ExitCode.SUCCESS):
            return successful()
        return result

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
    corpus_root: Path | None = None

    coverage_bounds: CoverageBounds | None = None
    corpus_report: CorpusSearchReport | None = None
    report: SearchReport | None = None
    try:
        if args.corpus_search:
            from .adapters.registry import build_adapters
            from .engine import ScopedSearcher
            from .index.query import CorpusSearcher, IndexedSearcher

            corpus_root = _corpus_root(args, err)
            tree_source = tree_source_factory(token)
            scoped = cast(
                ScopedSearcher,
                searcher_factory(tree_source, ast_python=args.ast, corpus_root=corpus_root),
            )
            indexed: IndexedSearcher | None = None
            if args.use_index or args.require_index:
                adapters = build_adapters(ast_python=args.ast)
                indexed = IndexedSearcher(
                    corpus_root, scoped, adapters, require_index=args.require_index
                )
            corpus_searcher = CorpusSearcher(
                corpus_root,
                scoped,
                indexed,
                use_index=args.use_index or args.require_index,
                require_index=args.require_index,
            )
            corpus_report = corpus_searcher.search(
                must=must,
                should=tuple(args.should),
                must_not=tuple(args.must_not),
                whole_file_must=args.whole_file,
            )
        elif args.global_search:
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
            # Honest coverage bounds from the global searcher (issue #191).
            # ``getattr`` keeps injected fake searchers (no bounds) on the
            # legacy summary line.
            coverage_bounds = cast(
                "CoverageBounds | None", getattr(searcher, "last_coverage_bounds", None)
            )
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
            corpus_root = (
                _corpus_root(args, err) if args.root is not None or args.local else None
            )
            searcher = cast(
                _Searcher,
                (
                    searcher_factory(
                        tree_source, ast_python=True, corpus_root=corpus_root
                    )
                    if args.ast
                    else searcher_factory(tree_source, corpus_root=corpus_root)
                )
                if corpus_root is not None
                else (
                    searcher_factory(tree_source, ast_python=True)
                    if args.ast
                    else searcher_factory(tree_source)
                ),
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
    except VerificationError as exc:
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.CORPUS_FAILURE)
    except Exception as exc:
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.INFRASTRUCTURE_FAILURE)

    if corpus_report is not None:
        print(corpus_report.to_json(), file=out)
        _write_corpus_summary(corpus_report, file=err)
        return successful()
    assert report is not None

    corpus_routings = _corpus_routings(corpus_root) if corpus_root is not None else None
    try:
        machine_report = _report_json_with_coverage_bounds(report, coverage_bounds)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"leitir: error: {redact(str(exc))}", file=err)
        return int(ExitCode.INFRASTRUCTURE_FAILURE)
    print(machine_report, file=out)
    _write_summary(
        report,
        file=err,
        routings=corpus_routings,
        bounds=coverage_bounds,
    )
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
