"""Command-line boundary for search and local source materialization.

For offline integration tests, the corpus wiring honors
``LEITIR_CODELOAD_BASE_URL``, ``LEITIR_GITHUB_API_BASE_URL``,
``LEITIR_NPM_BASE_URL``, ``LEITIR_PYPI_BASE_URL``, ``LEITIR_CRATES_BASE_URL``, and
``LEITIR_GO_PROXY_BASE_URL``. Production defaults remain the official HTTPS
services.

Issue #271: this module used to carry every verb's parser construction and
dispatch logic inline in one large ``main()``/``_main_impl()`` with deep
internal state (ExitStack-like resource wiring, corpus-root resolution,
credential wiring). It is now a thin registry (``build_parser()`` composes
each verb group's own ``register_*`` function, called in the exact original
``add_parser`` order so ``--help`` output is unchanged) plus dispatch
(``_main_impl()`` routes ``args.command`` to the owning verb module's
``run()``/``run_*_cmd()`` function). The per-verb parser construction and
handler logic itself lives in ``leitir.cli_support`` (shared infrastructure:
factories, corpus-root and credential resolution, the cached-shelf-first
spec-resolution cluster) and one module per verb group:
``leitir.cli_diagnostics`` (doctor, bench, check), ``leitir.cli_corpus``
(get/fetch, list, upgrade-cache, trust, remove, clean, lock, sbom, api,
examples, info, diff, export, import, gc, index), ``leitir.cli_ask`` (ask),
``leitir.cli_bts`` (bts-compute, bts-port-contract, bts-run, bts-funnel, analysis-architecture,
analysis-lineage, exit-gate-validate, exit-gate-run, occupied-validate,
usage), and ``leitir.cli_search`` (search).

Purely structural move (issue #271): no behavior, flag, exit-tier, or output
change from the pre-#271 implementation. The private names below that are
no longer defined in this module (e.g. ``_corpus_list``, ``_resolve_corpus_spec``,
``_github_token``, ...) are re-exported from their new home so
``leitir.cli.<name>`` and ``monkeypatch.setattr("leitir.cli.<name>", ...)``
keep working exactly as before for existing tests.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import sys
from collections.abc import Callable, Sequence
from typing import TextIO, cast

from . import cli_ask, cli_bts, cli_corpus, cli_diagnostics, cli_search
from .cli_corpus import _corpus_list, _gc_abandoned_staging, _require_all_shelves_authenticated
from .cli_search import _corpus_routings, _write_summary
from .cli_support import (
    _SIGINT_EXIT_CODE,
    ExitCode,
    _build_default_benchmark_runner,
    _build_default_code_search,
    _build_default_global_searcher,
    _build_default_resolver,
    _build_default_searcher,
    _build_default_tree_source,
    _CachedFirstResolverFacade,
    _configure_logging_from_env,
    _corpus_root,
    _ensure_local_gitignore,
    _github_token,
    _is_broken_pipe_error,
    _LocalFirstLockResolver,
    _resolve_corpus_spec,
    _resolve_from_cached_shelf,
    _write_cli_payload,
    logger,
    mark_successful,
)
from .spec import parse_corpus_spec

__all__ = [
    "ExitCode",
    "build_parser",
    "main",
]

# Re-exported for backward compatibility: pre-#271 tests import these
# private helpers directly from ``leitir.cli`` (e.g.
# ``from leitir.cli import _corpus_list``) or monkeypatch them as
# ``leitir.cli.<name>`` (e.g. ``leitir.cli._resolve_corpus_spec``,
# ``leitir.cli.logger.warning``); listing them here keeps ruff from
# flagging the imports above as unused without changing what any of them
# do. Not part of the intentional public API surface -- new code should
# import these from the module that actually owns them
# (``leitir.cli_support``, ``leitir.cli_corpus``, ...).
_REEXPORTED_FOR_TEST_COMPATIBILITY = (
    importlib.metadata,
    _build_default_benchmark_runner,
    _build_default_code_search,
    _build_default_global_searcher,
    _build_default_resolver,
    _build_default_searcher,
    _build_default_tree_source,
    _CachedFirstResolverFacade,
    _configure_logging_from_env,
    _corpus_list,
    _require_all_shelves_authenticated,
    _corpus_root,
    _corpus_routings,
    _ensure_local_gitignore,
    _gc_abandoned_staging,
    _github_token,
    _LocalFirstLockResolver,
    _resolve_corpus_spec,
    _resolve_from_cached_shelf,
    _write_cli_payload,
    _write_summary,
    logger,
    mark_successful,
    parse_corpus_spec,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level ``leitir`` argument parser.

    Each verb group's own ``register_*`` function is called in exactly the
    order the pre-#271 ``leitir.cli`` implementation called
    ``commands.add_parser()`` for that verb, so ``--help`` output (both the
    top-level subcommand listing and every individual verb's own help) is
    byte-identical to before this refactor: argparse's subcommand listing
    reflects ``add_parser()`` call order, which this sequence reproduces
    exactly, while each verb's own argument order (unaffected by any other
    verb's parser construction) is preserved by each ``register_*`` function
    internally.
    """
    from .cli_support import _installed_version

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

    cli_diagnostics.register_doctor(commands)
    cli_search.register_search(commands)
    cli_corpus.register_index(commands)
    cli_diagnostics.register_bench(commands)
    cli_corpus.register_get_fetch(commands)
    cli_corpus.register_list(commands)
    cli_corpus.register_upgrade(commands)
    cli_corpus.register_trust(commands)
    cli_corpus.register_remove(commands)
    cli_corpus.register_clean(commands)
    cli_corpus.register_lock(commands)
    cli_corpus.register_sbom(commands)
    cli_corpus.register_api(commands)
    cli_corpus.register_examples(commands)
    cli_corpus.register_info(commands)
    cli_ask.register_ask(commands)
    cli_corpus.register_diff(commands)
    cli_diagnostics.register_check(commands)
    cli_corpus.register_export_import(commands)
    cli_corpus.register_gc(commands)
    cli_bts.register_bts_compute(commands)
    cli_bts.register_bts_port_contract(commands)
    cli_bts.register_architecture(commands)
    cli_bts.register_lineage(commands)
    cli_bts.register_exit_gate_validate(commands)
    cli_bts.register_funnel(commands)
    cli_bts.register_bts_run(commands)
    cli_bts.register_exit_gate_run(commands)
    cli_bts.register_occupied_validate(commands)
    cli_bts.register_usage(commands)

    return parser


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

    from ._update_check import maybe_start_update_check

    maybe_start_update_check(
        json_mode=bool(getattr(args, "as_json", False)),
        quiet=bool(getattr(args, "quiet", False)),
    )

    if args.command == "doctor":
        return cli_diagnostics.run_doctor_cmd(
            args,
            out=out,
            err=err,
            stdout=stdout,
            _exit_windows_doctor_success=_exit_windows_doctor_success,
        )

    if args.command == "bench":
        return cli_diagnostics.run_bench_cmd(
            args,
            out=out,
            err=err,
            tree_source_factory=tree_source_factory,
            resolver_factory=resolver_factory,
            searcher_factory=searcher_factory,
            code_search_factory=code_search_factory,
            benchmark_runner_factory=benchmark_runner_factory,
        )

    if args.command in {
        "bts-compute",
        "bts-port-contract",
        "bts-funnel",
        "bts-run",
        "analysis-architecture",
        "analysis-lineage",
        "exit-gate-validate",
        "exit-gate-run",
        "occupied-validate",
        "usage",
    }:
        return cli_bts.run(args, out=out, err=err)

    if args.command == "check":
        return cli_diagnostics.run_check_cmd(
            args,
            out=out,
            err=err,
            resolver_factory=resolver_factory,
            code_search_factory=code_search_factory,
        )

    if args.command == "ask":
        return cli_ask.run(
            args,
            resolver_factory=resolver_factory,
            code_search_factory=code_search_factory,
            tree_source_factory=tree_source_factory,
            searcher_factory=searcher_factory,
            out=out,
            err=err,
        )

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
        return cli_corpus.run(
            args,
            resolver_factory=resolver_factory,
            code_search_factory=code_search_factory,
            out=out,
            err=err,
        )

    # Only "search" remains once every other verb has returned above,
    # exactly as in the pre-#271 implementation.
    return cli_search.run(
        args,
        tree_source_factory=tree_source_factory,
        resolver_factory=resolver_factory,
        searcher_factory=searcher_factory,
        code_search_factory=code_search_factory,
        global_searcher_factory=global_searcher_factory,
        out=out,
        err=err,
    )


def _process_main() -> int:
    """Run the CLI with process-only shutdown handling enabled."""
    return main(_exit_windows_doctor_success=True)


if __name__ == "__main__":
    raise SystemExit(_process_main())
