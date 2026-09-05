"""The ``search`` verb: parser construction and dispatch (issue #271).

Moved here verbatim from ``src/leitir/cli.py``. Purely structural: no
behavior, flag, or output change.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, TextIO, cast

from .cli_support import ExitCode, _corpus_root, _github_token, _Searcher, _validate_scope_args, mark_successful
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
)

if TYPE_CHECKING:
    from .discovery_search import CoverageBounds
    from .warm import WarmSession

def register_search(commands: argparse._SubParsersAction) -> None:
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
            "\n"
            "output streams:\n"
            "  Unlike every other verb, `search` always writes its full machine-readable\n"
            "  report to stdout and the human summary to stderr -- this is not conditional\n"
            "  on any flag. `--json` is accepted for shape-compatibility with other verbs\n"
            "  but is a no-op: output is identical with or without it.\n"
        ),
    )
    search.add_argument(
        "--json",
        action="store_true",
        dest="search_json_noop",
        help=(
            "accepted for flag-shape compatibility with other verbs; has no effect. "
            "search always writes its machine-readable report to stdout and the human "
            "summary to stderr, regardless of this flag"
        ),
    )


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

def _parse_predicate(raw: str) -> Predicate:
    try:
        if raw.startswith("{"):
            data = json.loads(raw)
            if not isinstance(data, dict) or set(data) not in ({"kind", "value"}, {"kind", "value", "language"}):
                raise ValueError("predicate JSON requires kind, value and optional language")
            if not isinstance(data.get("kind"), str) or not isinstance(data.get("value"), str):
                raise ValueError("predicate kind and value must be strings")
            if "language" in data and not isinstance(data["language"], str):
                raise ValueError("predicate language must be a string")
            return Predicate(PredicateKind(data["kind"]), data["value"], data.get("language"))
        kind_str, separator, value = raw.partition(":")
        if not separator:
            raise ValueError("predicate must be kind:value or a JSON object")
        language = None
        prefix, separator, suffix = value.rpartition(":")
        from .adapters.languages import canonicalize_language
        if separator and canonicalize_language(suffix) in {"python", "rust", "go", "javascript", "typescript", "java", "c", "cpp"}:
            value, language = prefix, suffix
        return Predicate(PredicateKind(kind_str), value, language)
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError(f"invalid predicate {raw!r}: {exc}") from exc


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


def _corpus_routings(
    root: Path, *, session: WarmSession | None = None
) -> dict[tuple[str, str], dict[str, str]]:
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
            session=session,
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
def run(
    args: argparse.Namespace,
    *,
    tree_source_factory: Callable[[str | None], object],
    resolver_factory: Callable[[str | None], object],
    searcher_factory: Callable[..., object],
    code_search_factory: Callable[[str | None], object],
    global_searcher_factory: Callable[..., object],
    out: TextIO,
    err: TextIO,
    session: WarmSession | None = None,
) -> int:
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
                (
                    searcher_factory(
                        tree_source,
                        ast_python=args.ast,
                        corpus_root=corpus_root,
                        session=session,
                    )
                    if session is not None
                    else searcher_factory(
                        tree_source, ast_python=args.ast, corpus_root=corpus_root
                    )
                ),
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
                session=session,
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
                    (
                        searcher_factory(
                            tree_source,
                            ast_python=True,
                            corpus_root=corpus_root,
                            session=session,
                        )
                        if session is not None
                        else searcher_factory(
                            tree_source, ast_python=True, corpus_root=corpus_root
                        )
                    )
                    if args.ast
                    else (
                        searcher_factory(
                            tree_source, corpus_root=corpus_root, session=session
                        )
                        if session is not None
                        else searcher_factory(tree_source, corpus_root=corpus_root)
                    )
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
        return mark_successful()
    assert report is not None

    corpus_routings = (
        _corpus_routings(corpus_root, session=session)
        if corpus_root is not None
        else None
    )
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
    return mark_successful()
