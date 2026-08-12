"""JavaScript tier-2 regex adapter."""

from __future__ import annotations

import re

from leitir.adapters._tier2._base import _CALL, RegexInventory, Tier2RegexAdapter
from leitir.adapters._tier2_patterns import EXPORT_CLASS, EXPORT_FUNCTION, EXPORT_VALUE

_JS_DEFINITIONS = (
    EXPORT_FUNCTION,
    EXPORT_CLASS,
    EXPORT_VALUE,
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\b"),
    re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)\b"),
    re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?="),
    re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=.*=>"),
    re.compile(
        r"^\s*(?:(?:public|protected|private|static|abstract|override|readonly|async|get|set)\s+)*"
        r"([A-Za-z_$][\w$]*|constructor)\s*\([^\r\n{};]*\)"
        r"(?:\s*:\s*[^={;]+)?\s*\{"
    ),
)
_JS_IMPORTS = (
    re.compile(r"^\s*import\b(?:.*\bfrom\b)?"),
    re.compile(r"\brequire\s*\("),
)

JAVASCRIPT = RegexInventory("javascript", (".js", ".mjs", ".cjs"), _JS_DEFINITIONS, (_CALL,), _JS_IMPORTS)


class JavaScriptAdapter(Tier2RegexAdapter):
    def __init__(self) -> None:
        super().__init__(JAVASCRIPT)
