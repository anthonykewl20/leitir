"""Deterministic, ordered construction of language adapter tuples."""

from __future__ import annotations

from collections.abc import Callable

from leitir.adapters import GoAdapter, LanguageAdapter, PythonAdapter, RustAdapter

_ORDERED_FACTORIES: tuple[tuple[str, Callable[[], LanguageAdapter]], ...] = (
    ("python", PythonAdapter),
    ("rust", RustAdapter),
    ("go", GoAdapter),
)

_DEFAULT_LANGUAGES: tuple[str, ...] = ("python", "rust", "go")


def build_adapters(
    languages: tuple[str, ...] = _DEFAULT_LANGUAGES,
    ast_python: bool = False,
) -> tuple[LanguageAdapter, ...]:
    if ast_python:
        raise ValueError("ast_python requires the S5 AST adapter")
    if len(set(languages)) != len(languages):
        raise ValueError("adapter languages must be unique")
    supported = frozenset(name for name, _factory in _ORDERED_FACTORIES)
    unknown = sorted(set(languages) - supported)
    if unknown:
        raise ValueError(f"unsupported adapter languages: {', '.join(unknown)}")
    selected = frozenset(languages)
    return tuple(
        factory() for name, factory in _ORDERED_FACTORIES if name in selected
    )
