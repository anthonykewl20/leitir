"""The actual MCP protocol server: five tools, each a thin wrapper over
``leitir.mcp.bridge``.

Building or running the server requires the ``mcp`` optional extra
(``pip install 'leitir[mcp]'``); this module imports the ``mcp`` SDK lazily,
inside :func:`build_server`, and converts a missing extra into an actionable
:class:`leitir.mcp.MissingExtraError` instead of a raw ``ModuleNotFoundError``
traceback. A bare ``import leitir.mcp.server`` therefore succeeds even without
the extra installed (see tests/test_import_purity.py's module-scope-import
purity gate); only *calling* :func:`build_server` or :func:`main` needs it.

Tool descriptions are intentionally short: MCP tool schemas sit in an agent's
context for the whole session, and judgment about *when* to reach for leitir
belongs in ``skills/leitir/SKILL.md``, not duplicated here.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .._version import installed_version
from . import MissingExtraError, bridge

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer  # type: ignore[import-not-found]

__all__ = ["build_server", "main"]

_EXTRA_HINT = (
    "leitir's MCP server requires the 'mcp' optional extra, which is not "
    "installed. Install it with:\n\n"
    "    pip install 'leitir[mcp]'\n"
    "    # or, for a hash-locked install:\n"
    "    pip install --require-hashes --only-binary :all: -r requirements-mcp.lock\n"
)


def _raise_tool_error(exc: bridge.LeitirCLIError, tool_error_cls: type[Exception]) -> None:
    """Convert a CLI failure into a structured, anticipated MCP tool error.

    ``ToolError``'s message reaches the calling model as tool content (see
    ``mcp.server.mcpserver.exceptions.ToolError``), so it carries the exit
    code and the CLI's own diagnostic rather than surfacing as a silent empty
    result or an unstructured crash.
    """
    raise tool_error_cls(json.dumps(exc.to_dict(), sort_keys=True)) from exc


def build_server() -> MCPServer:
    """Construct the leitir MCPServer with its five tools registered."""
    try:
        from mcp.server.mcpserver import MCPServer as _MCPServer
        from mcp.server.mcpserver.exceptions import ToolError  # type: ignore[import-not-found]
    except ImportError as exc:
        raise MissingExtraError(_EXTRA_HINT) from exc

    def tool_error(exc: bridge.LeitirCLIError) -> None:
        _raise_tool_error(exc, ToolError)

    server = _MCPServer(
        name="leitir",
        version=installed_version(),
        instructions=(
            "Deterministic, provenance-tracked code search over pinned source "
            "corpora. See the leitir skill for when to use each tool."
        ),
    )

    @server.tool(description="One-shot context for a dependency: provenance, API, examples, trust, parity.")
    def info(
        spec: str,
        root: str | None = None,
        local: bool = False,
        cwd: str | None = None,
        no_verify: bool = False,
    ) -> dict[str, Any]:
        try:
            return bridge.info(spec, root=root, local=local, cwd=cwd, no_verify=no_verify)
        except bridge.LeitirCLIError as exc:
            tool_error(exc)
            raise  # pragma: no cover - tool_error always raises

    @server.tool(description="Search a pinned code corpus, scoped by --repo, --package, or --corpus.")
    def search(
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
        try:
            return bridge.search(
                must=must,
                should=should,
                must_not=must_not,
                repo=repo,
                commit=commit,
                package=package,
                version=version,
                ecosystem=ecosystem,
                corpus=corpus,
                whole_file=whole_file,
                ast=ast,
                use_index=use_index,
                require_index=require_index,
                root=root,
                local=local,
            )
        except bridge.LeitirCLIError as exc:
            tool_error(exc)
            raise  # pragma: no cover

    @server.tool(description="Ranked real-usage snippets for a materialized source.")
    def examples(
        spec: str,
        root: str | None = None,
        local: bool = False,
    ) -> dict[str, Any]:
        try:
            return bridge.examples(spec, root=root, local=local)
        except bridge.LeitirCLIError as exc:
            tool_error(exc)
            raise  # pragma: no cover

    @server.tool(description="Extracted, cached symbol index for a materialized source.")
    def api(
        spec: str,
        root: str | None = None,
        local: bool = False,
    ) -> dict[str, Any]:
        try:
            return bridge.api(spec, root=root, local=local)
        except bridge.LeitirCLIError as exc:
            tool_error(exc)
            raise  # pragma: no cover

    @server.tool(description="Diff between two resolved source versions.")
    def diff(
        spec_a: str,
        spec_b: str,
        root: str | None = None,
        local: bool = False,
        cwd: str | None = None,
    ) -> dict[str, Any]:
        try:
            return bridge.diff(spec_a, spec_b, root=root, local=local, cwd=cwd)
        except bridge.LeitirCLIError as exc:
            tool_error(exc)
            raise  # pragma: no cover

    return server


def main() -> int:
    """Entry point for ``python -m leitir.mcp`` (stdio transport)."""
    build_server().run(transport="stdio")
    return 0
