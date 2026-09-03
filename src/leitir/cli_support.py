"""Shared infrastructure for the ``leitir`` CLI dispatch (issue #271).

Extracted verbatim from ``src/leitir/cli.py``: default factories, corpus-root
and credential resolution, the cached-shelf-first spec resolution cluster,
and small stdout/stderr helpers used across more than one verb module. This
module owns no argparse parser construction and no per-verb dispatch of its
own -- see ``leitir.cli_corpus``, ``leitir.cli_bts``, ``leitir.cli_ask``,
``leitir.cli_search``, and ``leitir.cli_diagnostics`` for those, and
``leitir.cli`` for the thin registry/dispatch that ties them together.

Purely structural move: no behavior, flag, or output change from the
pre-#271 ``leitir.cli`` implementation of these functions.
"""

from __future__ import annotations

import argparse
import errno
import importlib.metadata
import json
import logging
import os
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, TextIO, TypedDict, cast

from .credentials import github_token_from_env
from .search import RepoScope, SearchReport, SearchSpec
from .spec import (
    SUPPORTED_SPEC_FORMS,
    CorpusSpec,
    SpecParseError,
    parse_corpus_spec,
)

if TYPE_CHECKING:
    from .diff import DiffReport, ImpactReport  # noqa: F401
    from .parity import ArtifactInfo as ArtifactInfoLike
    from .resolver import Ecosystem, ResolvedPackage, _CorpusResolver, _HeadResolver
    from .warm import WarmSession

logger = logging.getLogger("leitir.cli")

_SIGINT_EXIT_CODE = 130

_UPGRADE_CACHE_DESCRIPTION = (
    "Compute and persist load-time tree digests for legacy verified shelves. "
    "NOTE: the digest is computed from the bytes currently on disk. Run this "
    "only on a corpus whose existing contents you already trust (e.g., "
    "immediately after materialization, before any external process could "
    "modify the cache). To re-materialize a suspicious shelf instead, remove "
    "it first with `leitir remove <spec>` and then run `leitir get <spec>`."
)


def mark_successful() -> int:
    """Emit the deferred update notice (if any) and return ``ExitCode.SUCCESS``.

    Extracted from the ``successful()`` closure every verb dispatch branch in
    the pre-#271 ``_main_impl`` called on its happy path; each verb module
    calls this in place of that closure.
    """
    from ._update_check import maybe_emit_update_notice

    maybe_emit_update_notice()
    return int(ExitCode.SUCCESS)

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


def _configure_logging_from_env(
    args: argparse.Namespace, stderr: TextIO = sys.stderr
) -> Callable[[], None]:
    """Route this invocation's log records to its own ``stderr`` stream.

    Records are captured per call without cross-talk even when several
    invocations run concurrently in one process (``leitir.api.call_json``
    from multiple threads, issue #281): the namespace logger carries a single
    thread-routed handler whose per-thread ``(stream, level)`` routes send
    each record to the stream bound by the thread that logged it. The
    namespace logger's level is the minimum across every live invocation's
    requested level, so one call requesting DEBUG never starves another
    call's requested verbosity; each thread's own route level still gates
    what that thread actually emits. (The level deliberately never ratchets
    back up: route gating after the redaction filter keeps emitted output
    identical, and `Logger.isEnabledFor` caching makes re-raising per call
    pure overhead.)

    Returns the invocation's logging teardown: call it when the invocation
    finishes to restore the calling thread's previous binding (nested
    in-process calls restore the outer call's route; a top-level call
    unbinds, returning the thread to the no-CLI-invocation baseline).
    """
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
    from .logging import configure_logging, get_or_install_routed_handler

    namespace_logger = logging.getLogger("leitir")
    handler = get_or_install_routed_handler(namespace_logger)
    handler.setFormatter(
        logging.Formatter("leitir %(levelname)s %(name)s: %(message)s")
    )
    previous_route = handler.bind_thread(stderr, level)

    def _restore_logging_route() -> None:
        handler.restore_thread(previous_route)

    configure_logging(
        min((*handler.registered_levels(), namespace_logger.getEffectiveLevel())),
        handler=handler,
    )
    if invalid_level:
        logger.warning("ignoring unknown LEITIR_LOG_LEVEL=%r", level_value)
    return _restore_logging_route


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
    *,
    session: WarmSession | None = None,
) -> object:
    from .adapters.registry import build_adapters
    from .engine import ScopedSearcher
    from .tree import TreeSource

    return ScopedSearcher(
        tree_source=cast(TreeSource, tree_source),
        adapters=build_adapters(ast_python=ast_python),
        corpus_root=corpus_root,
        session=session,
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
    explicit_root = getattr(args, "root", None)
    root = resolve_root(explicit_root)
    # L9 (dogfood #266): the fully-defaulted root (no --root, no
    # LEITIR_HOME) is ``~/.leitir`` and is created with no indication,
    # so a user following the quickstart verbatim writes into their home
    # before learning about --root/--local/LEITIR_HOME. Note it once, the
    # first time the default root does not yet exist -- an existing root
    # (this call or a later one, after some command has created it) never
    # repeats the note.
    if (
        explicit_root is None
        and os.environ.get("LEITIR_HOME") is None
        and not root.exists()
    ):
        print(
            f"leitir: note: using default corpus root {root} "
            "(created on first write); to use a different location, pass "
            "--root PATH, --local, or set LEITIR_HOME",
            file=err,
        )
    return root


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
    from .resolver import ResolutionError, resolve_corpus_spec

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
    try:
        resolved, tag, version_source, detection_source = resolve_corpus_spec(
            parsed,
            cast("_CorpusResolver", resolver),
            cast("_HeadResolver", heads),
            cwd,
        )
    except ResolutionError as exc:
        # A bare token with no ecosystem prefix and no owner/repo shape
        # (``leitir get not-a-spec``) falls back to being treated as an
        # npm package name (see ``spec.parse_corpus_spec``'s final
        # ``_split_package(raw, "npm", raw)`` branch) -- this fallback is
        # intentional and documented (ADR-0005 D5: bare-name npm lookup),
        # so it must not be rejected up front. But when that guess turns
        # out wrong, a bare registry lookup failure ("npm registry lookup
        # failed for not-a-spec: HTTP 404") reads as a network problem
        # rather than a likely typo'd spec. Name the guess and list the
        # supported forms, without changing the error type or exit code
        # (dogfood #266 F1/L1).
        if type(exc) is ResolutionError and parsed.ecosystem == "npm" and ":" not in parsed.raw:
            raise ResolutionError(
                f"{exc} ({parsed.raw!r} has no ecosystem prefix or owner/repo shape, "
                f"so it was looked up as a bare npm package name; if that is not what "
                f"you intended, supported spec forms are: {SUPPORTED_SPEC_FORMS})"
            ) from exc
        raise
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
