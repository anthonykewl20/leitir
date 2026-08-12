"""C++ tier-2 regex adapter."""

from __future__ import annotations

from leitir.adapters._tier2._base import _CALL, RegexInventory, Tier2RegexAdapter
from leitir.adapters._tier2.c import _C_DEFINITIONS, _C_IMPORTS

CPP = RegexInventory("cpp", (".cpp", ".cc", ".cxx", ".hpp", ".hh"), _C_DEFINITIONS, (_CALL,), _C_IMPORTS)


class CppAdapter(Tier2RegexAdapter):
    def __init__(self) -> None:
        super().__init__(CPP)
