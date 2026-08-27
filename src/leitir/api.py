"""In-process Python API for the ``leitir`` CLI (issue #271).

Issue #271 split ``leitir.cli``'s parser construction and dispatch out of one
large ``main()``/``_main_impl()`` with deep internal state (ExitStack-like
resource wiring, corpus-root resolution, credential wiring) into per-verb
module functions -- ``leitir.cli_corpus.run()``, ``leitir.cli_ask.run()``,
``leitir.cli_search.run()``, and friends -- called from a thin
``leitir.cli._main_impl`` dispatcher. This module is the first concrete
consumer of that split: a small, stable, in-process call surface that
returns the CLI's own structured JSON without spawning a subprocess.

``leitir.mcp.bridge`` still shells out to ``python -m leitir.cli <cmd>
--json`` today (a correctness-by-construction choice made when there was no
clean Python entry point -- see issue #271's motivation) rather than calling
this module; :func:`call_json` is what a future revision of the bridge could
call directly to remove that subprocess boundary, once its own review cycle
signs off on the change (out of scope for this purely structural refactor).
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
    capturing stdout/stderr in memory instead of spawning
    ``python -m leitir.cli`` -- no subprocess, no cold interpreter start, no
    shelf re-verification across a process boundary. Raises
    :class:`LeitirCallError` if the command exits non-zero or its stdout is
    not a JSON object, so a caller never silently receives an empty or
    partial result.

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
