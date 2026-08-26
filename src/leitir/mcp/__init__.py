"""Model Context Protocol server for leitir (optional extra).

This package exposes leitir's five shipped, JSON-capable verbs (``info``,
``search``, ``examples``, ``api``, ``diff``) as MCP tools, so any MCP-capable
agent runtime -- not just Claude Code's skill surface -- can call leitir
directly. It ships as the ``mcp`` optional extra to keep the stdlib-only
runtime (``dependencies = []`` in ``pyproject.toml``) unaffected:

    pip install 'leitir[mcp]'

``leitir.mcp.bridge`` (subprocess-to-CLI plumbing, no third-party imports) is
always importable, extra or not -- it is what ``tests/test_mcp_server.py``
exercises without the extra installed. ``leitir.mcp.server`` (this package's
actual MCP protocol wiring) is likewise always importable at module scope; it
defers its ``mcp`` SDK import into :func:`build_server`, so a bare
``import leitir.mcp`` never requires the extra either. Only *calling*
:func:`build_server` or :func:`main` needs the extra, and does so with
:class:`MissingExtraError` in place of a raw ``ModuleNotFoundError``
traceback.
"""

from __future__ import annotations

from .bridge import LeitirCLIError, run_leitir_json

__all__ = ["LeitirCLIError", "MissingExtraError", "build_server", "main", "run_leitir_json"]


class MissingExtraError(ImportError):
    """Raised in place of a raw ``ModuleNotFoundError`` for the ``mcp`` extra."""


from .server import build_server, main
