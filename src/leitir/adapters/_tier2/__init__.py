"""Tier-2 regex adapters informed by nvim-treesitter node inventories.

The inventories are hand-adapted approximations, not copied query files, based
on https://github.com/nvim-treesitter/nvim-treesitter at revision
c9f9ed6c1892f629ea399f4ee7905f2686fa13f2 (Apache-2.0). There is no
tree-sitter runtime dependency.
"""

from __future__ import annotations

from leitir.adapters._tier2._base import RegexInventory, Tier2RegexAdapter
from leitir.adapters._tier2.c import C, CAdapter
from leitir.adapters._tier2.cpp import CPP, CppAdapter
from leitir.adapters._tier2.java import JAVA, JavaAdapter
from leitir.adapters._tier2.javascript import JAVASCRIPT, JavaScriptAdapter
from leitir.adapters._tier2.typescript import TYPESCRIPT, TypeScriptAdapter

RegexInventory.__module__ = __name__
Tier2RegexAdapter.__module__ = __name__
JavaScriptAdapter.__module__ = __name__
TypeScriptAdapter.__module__ = __name__
JavaAdapter.__module__ = __name__
CAdapter.__module__ = __name__
CppAdapter.__module__ = __name__

__all__ = [
    "CPP",
    "JAVA",
    "JAVASCRIPT",
    "TYPESCRIPT",
    "C",
    "CAdapter",
    "CppAdapter",
    "JavaAdapter",
    "JavaScriptAdapter",
    "RegexInventory",
    "Tier2RegexAdapter",
    "TypeScriptAdapter",
]
