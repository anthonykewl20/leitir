"""Deterministic, integrity-checked local trigram search index."""

from __future__ import annotations

from leitir.index.builder import ShelfRef, build_shelf_index
from leitir.index.query import IndexedSearcher

__all__ = ["IndexedSearcher", "ShelfRef", "build_shelf_index"]
