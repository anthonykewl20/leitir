"""``python -m leitir.mcp`` -- run the leitir MCP server over stdio.

Requires the ``mcp`` optional extra; see ``leitir/mcp/__init__.py``.
"""

from __future__ import annotations

from . import main

if __name__ == "__main__":
    raise SystemExit(main())
