"""Canonical language-name handling shared by API extraction and search routing."""

from __future__ import annotations

_ALIASES: dict[str, str] = {
    "py": "python",
    "pypi": "python",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
}


def canonicalize_language(language: str) -> str:
    normalized = language.casefold()
    return _ALIASES.get(normalized, normalized)
