"""TypeScript tier-2 regex adapter."""

from __future__ import annotations

from leitir.adapters._tier2._base import _CALL, RegexInventory, Tier2RegexAdapter
from leitir.adapters._tier2.javascript import _JS_DEFINITIONS, _JS_IMPORTS

TYPESCRIPT = RegexInventory("typescript", (".ts", ".tsx"), _JS_DEFINITIONS, (_CALL,), _JS_IMPORTS)


class TypeScriptAdapter(Tier2RegexAdapter):
    def __init__(self) -> None:
        super().__init__(TYPESCRIPT)
