"""In-process Python API for the ``leitir`` CLI (issue #271).

Issue #271 split ``leitir.cli``'s parser construction and dispatch out of one
large ``main()``/``_main_impl()`` with deep internal state (ExitStack-like
resource wiring, corpus-root resolution, credential wiring) into per-verb
module functions -- ``leitir.cli_corpus.run()``, ``leitir.cli_ask.run()``,
``leitir.cli_search.run()``, and friends -- called from a thin
``leitir.cli._main_impl`` dispatcher. This module is the first concrete
consumer of that split, and it is deliberately a small first step, not a
typed handler API: :func:`call_json` calls :func:`leitir.cli.main` with an
argv list exactly as the command line would, captures stdout/stderr into
in-memory buffers instead of piping them across a process boundary, and
parses the resulting JSON text back into a dict. It removes the OS
process-spawn cost (fork/exec, fresh interpreter start, argv/stdout transfer
through OS pipes) of ``leitir.mcp.bridge``'s current
``subprocess.run([sys.executable, "-m", "leitir.cli", ...])`` path. It does
**not** remove the per-call work every verb still repeats from scratch on
every invocation -- corpus-root resolution, manifest re-verification,
resolver/searcher construction via the default factories -- because each
call to :func:`call_json` still runs a full, independent ``main()`` parse +
dispatch with no state retained between calls. No verb yet exposes a typed
handler that returns a result object directly; every result still round-trips
through ``print(json.dumps(...))`` and back through ``json.loads()``, exactly
as it does across the subprocess boundary today.

Concretely, for a caller weighing this against ``leitir.mcp.bridge`` or a
future warm-mode entry point (issue #272 / ADR-0035):

- **Stdout/stderr capture**: ``call_json`` passes fresh ``io.StringIO()``
  buffers as ``main()``'s ``stdout``/``stderr`` parameters; verb handlers
  print to those, not to the real ``sys.stdout``/``sys.stderr``, so this part
  is safe to call from multiple threads without cross-talk. **One exception**:
  argparse's own parser-level errors (an unrecognized flag, ``--help``,
  ``--version``) call ``ArgumentParser.error()``/``print_help()``, which
  write to the *real* process ``sys.stderr``/``sys.stdout`` by default --
  ``build_parser()`` does not redirect them. For that argv-parse-error class
  specifically, the process exit code (2, i.e. ``ExitCode.MALFORMED_USAGE``)
  is still correctly reported through ``LeitirCallError.exit_code``, but
  ``LeitirCallError``'s message/``stderr`` attribute will be **empty**
  (measured: ``call_json(["search", "--bad-flag"])`` raises
  ``LeitirCallError(exit_code=2, stderr="")`` while argparse's real usage
  text lands on the process's actual stderr). Every error *inside* a verb's
  own dispatch code -- the overwhelming majority of failures, since argparse
  usage errors are rare in a programmatic caller -- prints through the
  captured buffer normally and appears in the message as expected (measured:
  ``call_json(["search"])`` -> ``LeitirCallError(exit_code=2, stderr="leitir:
  error: one of --repo, --package, --global, or --corpus is required")``).
- **Reentrancy/thread safety**: sequential calls (including recursive ones)
  are safe, and so are concurrent calls from separate threads (issue #281).
  Each call's stdout/stderr capture is call-local, and ``_configure_logging_from_env``
  routes ``logging`` records through a single, process-wide *thread-routed*
  handler on the shared ``"leitir"`` logger: every invocation binds its own
  ``(stream, level)`` route for its calling thread, so a warning logged
  during one call's window is written to that call's captured ``err`` buffer
  and never to another call's. The namespace logger's level is the minimum
  across all live invocations so no call's requested verbosity is starved;
  each thread's route level still gates what that thread emits. Records
  logged from threads with no bound route (no in-flight CLI invocation) are
  dropped -- the same silence a fresh process exhibits before any CLI call
  configures a handler.
- **``SystemExit``**: does not escape ``call_json``. ``leitir.cli._main_impl``
  already wraps ``parser.parse_args(argv)`` in
  ``except SystemExit as exc: return int(exc.code)``, so the only place
  argparse's own ``SystemExit`` (raised by ``--help``, ``--version``, or a
  parse error) could occur is already converted to a plain integer before
  ``call_json`` ever sees it; a non-zero exit tier surfaces to the caller as
  a raised ``LeitirCallError`` (never a bare exit code, and never an
  uncaught ``SystemExit``).

``call_json`` therefore satisfies the issue's literal acceptance bar --
"at least one verb demonstrably callable in-process, returning a structured
result without a subprocess" -- but it is **not** the typed, warm-state-aware
entry point issue #272's ADR-0035 (warm mode) is blocked on. That would need
handler functions that accept a pre-built, reusable resolver/tree-source/
corpus-root context across calls instead of rebuilding it via the default
factories every time, and that return a typed result object rather than a
JSON string to re-parse. This refactor makes that follow-up addressable (each
verb group now has one clean function to give a second, typed entry point to)
but does not itself deliver it.
"""

from __future__ import annotations

import io
import json
from typing import Any

from .cli import main


class LeitirCallError(ValueError):
    """Raised when an in-process ``leitir`` CLI invocation fails.

    Carries the same shape of information ``leitir.mcp.bridge.LeitirCLIError``
    carries for the subprocess path: the argv, the exit code, and the
    stderr-derived message.
    """

    def __init__(self, *, argv: list[str], exit_code: int, stderr: str) -> None:
        self.argv = argv
        self.exit_code = exit_code
        self.stderr = stderr
        super().__init__(
            f"leitir {' '.join(argv)} failed (exit {exit_code}): {stderr.strip()}"
        )


def call_json(argv: list[str]) -> dict[str, Any]:
    """Run one ``leitir`` CLI invocation in-process and return its parsed JSON.

    Calls :func:`leitir.cli.main` directly in the current interpreter,
    capturing stdout/stderr into fresh, call-local ``io.StringIO()`` buffers
    instead of spawning ``python -m leitir.cli`` -- no subprocess, no cold
    interpreter start, no OS pipe to move argv/stdout across a process
    boundary. It does **not** remove the per-call resolution/verification
    work every verb still repeats from scratch (see the module docstring);
    only the process-spawn cost is removed. Raises :class:`LeitirCallError`
    if the command exits non-zero or its stdout is not a JSON object, so a
    caller never silently receives an empty or partial result; no
    ``SystemExit`` escapes this function (see the module docstring for why).

    **Safe for sequential in-process use (including recursive calls) and for
    concurrent calls from separate threads** (issue #281). Every call's
    stdout/stderr capture is call-local and does not cross-talk:
    ``_configure_logging_from_env`` (invoked at the top of every ``main()``
    call) binds each invocation's warning route per *thread* on a single,
    process-wide thread-routed handler, so a warning logged during one call's
    window lands in that call's captured buffer and never in another call's.
    This is the property issue #272's warm mode (ADR-0035) needs to serve
    concurrent in-process calls against one warm process.

    This performs no argument validation of its own: ``argv`` is forwarded
    verbatim to :func:`leitir.cli.main`, exactly as ``leitir.mcp.bridge``
    forwards its own constructed argv to the ``python -m leitir.cli``
    subprocess -- the CLI's own parser and dispatch remain the single
    source of truth for what is valid.
    """
    out = io.StringIO()
    err = io.StringIO()
    exit_code = main(list(argv), stdout=out, stderr=err)
    if exit_code != 0:
        raise LeitirCallError(argv=list(argv), exit_code=exit_code, stderr=err.getvalue())
    try:
        document = json.loads(out.getvalue())
    except json.JSONDecodeError as exc:
        raise LeitirCallError(
            argv=list(argv),
            exit_code=exit_code,
            stderr=f"exited 0 but stdout was not valid JSON: {exc}",
        ) from exc
    if not isinstance(document, dict):
        raise LeitirCallError(
            argv=list(argv),
            exit_code=exit_code,
            stderr="leitir CLI JSON output was not an object",
        )
    return document


__all__ = ["LeitirCallError", "call_json"]
