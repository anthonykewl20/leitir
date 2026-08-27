"""The doctor/bench/check verb group: parsers and dispatch (issue #271).

Three small, independent verbs grouped in one module because none of them
shares a dispatcher with the others in the pre-#271 ``leitir.cli``
implementation (unlike the corpus or BTS families). Moved here verbatim.
Purely structural: no behavior, flag, or output change.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO, cast

from .cli_support import (
    _SIGINT_EXIT_CODE,
    ExitCode,
    _bench_progress_reporter,
    _BenchmarkRun,
    _BenchmarkRunner,
    _build_default_benchmark_runner,
    _corpus_root,
    _FetchOptions,
    _github_token,
    _is_broken_pipe_error,
    _load_benchmark_manifest,
    _protect_stdout_shutdown,
    _write_cli_payload,
    mark_successful,
)
from .logging import redact
from .materialize import VerificationError
from .search import RepoScope
from .spec import SpecParseError, parse_corpus_spec


def register_doctor(commands: argparse._SubParsersAction) -> None:
    doctor = commands.add_parser(
        "doctor", help="diagnose the leitir environment and cache integrity"
    )
    doctor.add_argument("--json", action="store_true", dest="as_json")
    doctor.add_argument("--quiet", action="store_true")
    doctor.add_argument("--no-network", action="store_true")

def register_bench(commands: argparse._SubParsersAction) -> None:
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

def register_check(commands: argparse._SubParsersAction) -> None:
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


def run_doctor_cmd(args: argparse.Namespace, *, out: TextIO, err: TextIO, stdout: TextIO | None, _exit_windows_doctor_success: bool) -> int:
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
                result = mark_successful()
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

def run_bench_cmd(args: argparse.Namespace, *, out: TextIO, err: TextIO, tree_source_factory: Callable[[str | None], object], resolver_factory: Callable[[str | None], object], searcher_factory: Callable[..., object], code_search_factory: Callable[[str | None], object], benchmark_runner_factory: Callable[[object], object]) -> int:
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
    return mark_successful()

def run_check_cmd(args: argparse.Namespace, *, out: TextIO, err: TextIO, resolver_factory: Callable[[str | None], object], code_search_factory: Callable[[str | None], object]) -> int:
    # Looked up dynamically through the ``leitir.cli`` module object so a
    # ``monkeypatch.setattr("leitir.cli._resolve_corpus_spec", ...)`` seam
    # keeps working after this function moved out of cli.py (issue #271).
    from . import cli as _cli_mod
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
        resolved, tag, version_source, _detection = _cli_mod._resolve_corpus_spec(
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
    return mark_successful()

