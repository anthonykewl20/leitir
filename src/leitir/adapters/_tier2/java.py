"""Java tier-2 regex adapter."""

from __future__ import annotations

import re

from leitir.adapters._tier2._base import _CALL, RegexInventory, Tier2RegexAdapter

_JAVA_DEFINITIONS = (
    re.compile(r"^\s*(?:(?:public|protected|private|abstract|final|static|sealed|non-sealed)\s+)*(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)\b"),
    re.compile(r"^\s*(?:(?:public|protected|private|abstract|final|static|synchronized|native|default)\s+)*(?:<[^>]+>\s+)?[A-Za-z_$][\w$<>,.?\[\]]*\s+([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:throws\b[^\{]+)?\{"),
)
_JAVA_IMPORTS = (re.compile(r"^\s*import\s+(?:static\s+)?"),)

JAVA = RegexInventory("java", (".java",), _JAVA_DEFINITIONS, (_CALL,), _JAVA_IMPORTS)


class JavaAdapter(Tier2RegexAdapter):
    def __init__(self) -> None:
        super().__init__(JAVA)
