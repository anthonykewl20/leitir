"""Deterministic, ordered construction of language adapter tuples."""

from __future__ import annotations

from collections.abc import Callable

from leitir.adapters import GoAdapter, LanguageAdapter, PythonAdapter, RustAdapter
from leitir.adapters._tier2 import (
    CAdapter,
    CppAdapter,
    JavaAdapter,
    JavaScriptAdapter,
    TypeScriptAdapter,
)
from leitir.adapters.languages import canonicalize_language
from leitir.adapters.python_ast import PythonAstAdapter

_ORDERED_FACTORIES: tuple[tuple[str, Callable[[], LanguageAdapter]], ...] = (
    ("python", PythonAdapter),
    ("rust", RustAdapter),
    ("go", GoAdapter),
    ("javascript", JavaScriptAdapter),
    ("typescript", TypeScriptAdapter),
    ("java", JavaAdapter),
    ("c", CAdapter),
    ("cpp", CppAdapter),
)

_DEFAULT_LANGUAGES: tuple[str, ...] = (
    "python",
    "rust",
    "go",
    "javascript",
    "typescript",
    "java",
    "c",
    "cpp",
)


_TRUSTED_ADAPTER_LANGUAGES: dict[type[object], str] = {
    type(factory()): canonicalize_language(name)
    for name, factory in _ORDERED_FACTORIES
}
_TRUSTED_ADAPTER_LANGUAGES[type(PythonAstAdapter(PythonAdapter()))] = canonicalize_language(
    "python"
)


def trusted_adapter_language(adapter: LanguageAdapter) -> str | None:
    """Return the registry-bound language for an exact registered adapter type."""
    return _TRUSTED_ADAPTER_LANGUAGES.get(type(adapter))


def build_adapters(
    languages: tuple[str, ...] = _DEFAULT_LANGUAGES,
    ast_python: bool = False,
) -> tuple[LanguageAdapter, ...]:
    if len(set(languages)) != len(languages):
        raise ValueError("adapter languages must be unique")
    supported = frozenset(name for name, _factory in _ORDERED_FACTORIES)
    unknown = sorted(set(languages) - supported)
    if unknown:
        raise ValueError(f"unsupported adapter languages: {', '.join(unknown)}")
    selected = frozenset(languages)
    adapters: list[LanguageAdapter] = []
    for name, factory in _ORDERED_FACTORIES:
        if name not in selected:
            continue
        if name == "python" and ast_python:
            adapters.append(PythonAstAdapter(PythonAdapter()))
        else:
            adapters.append(factory())
    return tuple(adapters)
