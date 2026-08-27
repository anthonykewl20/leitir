"""The ``ask`` verb: parser construction and dispatch (issue #271).

Moved here verbatim from ``src/leitir/cli.py``. Purely structural: no
behavior, flag, or output change.
"""

from __future__ import annotations

import argparse
import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO, cast

from .cli_corpus import _run_corpus_command
from .cli_support import ExitCode, _corpus_root, _github_token, _Searcher, mark_successful
from .logging import redact
from .materialize import VerificationError
from .search import RepoScope, SearchMode, SearchSpec, SearchSpecError, canonical_predicates


def register_ask(commands: argparse._SubParsersAction) -> None:
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
def run(args: argparse.Namespace, *, resolver_factory: Callable[[str | None], object], code_search_factory: Callable[[str | None], object], tree_source_factory: Callable[[str | None], object], searcher_factory: Callable[..., object], out: TextIO, err: TextIO) -> int:
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
        return mark_successful()
    return result
