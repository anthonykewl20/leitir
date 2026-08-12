"""C tier-2 regex adapter."""

from __future__ import annotations

import re

from leitir.adapters._tier2._base import _CALL, RegexInventory, Tier2RegexAdapter

_C_DEFINITIONS = (
    re.compile(r"^\s*(?:[A-Za-z_]\w*[\s*]+)+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{"),
    re.compile(r"^\s*(?:typedef\s+)?(?:struct|union|enum)\s+([A-Za-z_]\w*)\b"),
    re.compile(r"^\s*typedef\b.*\b([A-Za-z_]\w*)\s*;\s*$"),
)
_C_IMPORTS = (re.compile(r"^\s*#\s*include\b"),)

C = RegexInventory("c", (".c", ".h"), _C_DEFINITIONS, (_CALL,), _C_IMPORTS)


class CAdapter(Tier2RegexAdapter):
    def __init__(self) -> None:
        super().__init__(C)
