"""Stdlib-only bridge from MCP tool calls to the ``leitir`` CLI.

This module deliberately does **not** import the ``mcp`` SDK (or anything else
outside the Python standard library): it is imported and exercised by
``tests/test_mcp_server.py`` even when the ``mcp`` optional extra is not
installed. The actual MCP protocol wiring (which does need the SDK) lives in
``leitir.mcp.server``.

Every tool call here shells out to ``python -m leitir.cli <command> ... --json``
(or, for ``search``, which has no ``--json`` flag and always emits JSON on
stdout, just ``python -m leitir.cli search ...``) and returns the parsed JSON
document byte-for-byte as the CLI produced it. No resolution, search, or
verification logic is reimplemented here -- this module only builds argv lists
and parses the CLI's own JSON output.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

__all__ = [
    "LeitirCLIError",
    "api",
    "diff",
    "examples",
    "info",
    "run_leitir_json",
    "search",
]

# The directory containing the ``leitir`` package (i.e. ``src/``), so the
# subprocess can find ``leitir.cli`` even if the caller's environment does not
# already have it on PYTHONPATH.
_SRC_ROOT = Path(__file__).resolve().parents[2]

# Wall-clock budget for a single CLI invocation. Materialization work (network
# fetch, verification) can be slow; this is generous but not unbounded so a
# hung subprocess cannot wedge an MCP session forever.
_TIMEOUT_S = 600.0


class LeitirCLIError(Exception):
    """A ``leitir`` CLI invocation failed or produced unparseable output.

    Carries the process exit code and the best available human message so
    callers (the MCP tool wrappers in ``leitir.mcp.server``) can surface a
    structured error instead of silently returning nothing.
    """

    def __init__(self, *, argv: list[str], exit_code: int, message: str, stderr: str) -> None:
        self.argv = argv
        self.exit_code = exit_code
        self.message = message
        self.stderr = stderr
        super().__init__(f"leitir {' '.join(argv)} failed (exit {exit_code}): {message}")

    def to_dict(self) -> dict[str, Any]:
        """Structured payload for an MCP error response."""
        return {
            "argv": self.argv,
            "exit_code": self.exit_code,
            "message": self.message,
        }


def _stderr_message(stderr: str) -> str:
    """Extract the ``leitir: error: ...`` line from stderr, else its tail.

    The CLI prints ``leitir: error: <text-or-json>`` on failure (see
    ``src/leitir/cli.py``); this pulls just that line so the MCP error message
    is not buried in warning noise.
    """
    lines = [line for line in stderr.splitlines() if line.strip()]
    for line in lines:
        if line.startswith("leitir: error:"):
            return line[len("leitir: error:") :].strip()
    return lines[-1] if lines else "no diagnostic output"


def run_leitir_json(argv: list[str]) -> dict[str, Any]:
    """Run ``python -m leitir.cli <argv>`` and return its parsed JSON stdout.

    Raises ``LeitirCLIError`` (never returns a silent empty result) if the
    process exits non-zero or its stdout is not valid JSON.
    """
    # Imported lazily (not at module scope) so that a bare `import
    # leitir.mcp.bridge` performs no subprocess-capable import -- see
    # tests/test_import_purity.py's FORBIDDEN_MODULES gate, which this
    # module must stay off of rather than be allowlisted for.
    import subprocess

    cmd = [sys.executable, "-m", "leitir.cli", *argv]
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    src = str(_SRC_ROOT)
    parts = [src] + ([existing] if existing else [])
    env["PYTHONPATH"] = os.pathsep.join(parts)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raw_stderr = exc.stderr
        timeout_stderr: str = (
            raw_stderr.decode("utf-8", errors="replace") if isinstance(raw_stderr, bytes) else (raw_stderr or "")
        )
        raise LeitirCLIError(
            argv=argv,
            exit_code=124,
            message=f"leitir CLI exceeded the {_TIMEOUT_S:.0f}s timeout",
            stderr=timeout_stderr,
        ) from exc

    if proc.returncode != 0:
        raise LeitirCLIError(
            argv=argv,
            exit_code=proc.returncode,
            message=_stderr_message(proc.stderr),
            stderr=proc.stderr,
        )
    try:
        document = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise LeitirCLIError(
            argv=argv,
            exit_code=proc.returncode,
            message=f"leitir CLI exited 0 but stdout was not valid JSON: {exc}",
            stderr=proc.stderr,
        ) from exc
    if not isinstance(document, dict):
        raise LeitirCLIError(
            argv=argv,
            exit_code=proc.returncode,
            message="leitir CLI JSON output was not an object",
            stderr=proc.stderr,
        )
    return document


def _root_args(*, root: str | None, local: bool) -> list[str]:
    if local:
        return ["--local"]
    if root is not None:
        return ["--root", root]
    return []


def info(
    spec: str,
    *,
    root: str | None = None,
    local: bool = False,
    cwd: str | None = None,
    no_verify: bool = False,
) -> dict[str, Any]:
    """One-shot context for a dependency: provenance, API, examples, trust, parity."""
    argv = ["info", spec, "--json", *_root_args(root=root, local=local)]
    if cwd is not None:
        argv += ["--cwd", cwd]
    if no_verify:
        argv.append("--no-verify")
    return run_leitir_json(argv)


def api(
    spec: str,
    *,
    root: str | None = None,
    local: bool = False,
) -> dict[str, Any]:
    """Extracted, cached symbol index for a materialized source."""
    argv = ["api", spec, "--json", *_root_args(root=root, local=local)]
    return run_leitir_json(argv)


def examples(
    spec: str,
    *,
    root: str | None = None,
    local: bool = False,
) -> dict[str, Any]:
    """Ranked real-usage snippets for a materialized source."""
    argv = ["examples", spec, "--json", *_root_args(root=root, local=local)]
    return run_leitir_json(argv)


def diff(
    spec_a: str,
    spec_b: str,
    *,
    root: str | None = None,
    local: bool = False,
    cwd: str | None = None,
) -> dict[str, Any]:
    """Diff between two resolved source versions."""
    argv = ["diff", spec_a, spec_b, "--json", *_root_args(root=root, local=local)]
    if cwd is not None:
        argv += ["--cwd", cwd]
    return run_leitir_json(argv)


def search(
    *,
    must: list[str],
    should: list[str] | None = None,
    must_not: list[str] | None = None,
    repo: str | None = None,
    commit: str | None = None,
    package: str | None = None,
    version: str | None = None,
    ecosystem: str | None = None,
    corpus: bool = False,
    whole_file: bool = False,
    ast: bool = False,
    use_index: bool = False,
    require_index: bool = False,
    root: str | None = None,
    local: bool = False,
) -> dict[str, Any]:
    """Search a pinned code corpus, scoped by ``--repo``, ``--package``, or ``--corpus``.

    ``must``/``should``/``must_not`` are raw ``kind:value[:language]`` predicate
    strings, forwarded verbatim to the CLI's own predicate parser -- this
    function performs no predicate parsing or validation itself. Scope
    (repo+commit, package+version+ecosystem, or corpus) is likewise forwarded
    as-is; the CLI enforces which combinations are valid.
    """
    argv = ["search"]
    for value in must:
        argv += ["--must", value]
    for value in should or []:
        argv += ["--should", value]
    for value in must_not or []:
        argv += ["--must-not", value]
    if corpus:
        argv.append("--corpus")
    else:
        if repo is not None:
            argv += ["--repo", repo]
            if commit is not None:
                argv += ["--commit", commit]
        elif package is not None:
            argv += ["--package", package]
            if version is not None:
                argv += ["--version", version]
            if ecosystem is not None:
                argv += ["--ecosystem", ecosystem]
    if whole_file:
        argv.append("--whole-file")
    if ast:
        argv.append("--ast")
    if use_index:
        argv.append("--index")
    if require_index:
        argv.append("--require-index")
    argv += _root_args(root=root, local=local)
    # ``search`` has no ``--json`` flag: it always prints its machine-readable
    # report to stdout and a human summary to stderr (see build_parser() /
    # main() in src/leitir/cli.py), so run_leitir_json needs no extra flag here.
    return run_leitir_json(argv)
