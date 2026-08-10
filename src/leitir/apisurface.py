"""Deterministic public API extraction for materialized source trees.

Extractors are registered by language with :func:`register_extractor`.  A
parser-backed JavaScript or TypeScript plugin can replace the built-in
heuristic by registering a callable accepting ``(target_path, language)`` and
returning the same ``ApiIndex`` dictionary contract.
"""

from __future__ import annotations

import ast
import logging
import re
import tokenize
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias, cast

ApiIndex: TypeAlias = dict[str, object]
Extractor: TypeAlias = Callable[[Path, str], ApiIndex]
logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SignatureChange:
    qualified_name: str
    before: str
    after: str

    def as_dict(self) -> dict[str, str]:
        return {
            "qualified_name": self.qualified_name,
            "before": self.before,
            "after": self.after,
        }


@dataclass(frozen=True, slots=True)
class ApiDiff:
    added: tuple[dict[str, object], ...]
    removed: tuple[dict[str, object], ...]
    changed: tuple[SignatureChange, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "added": [dict(symbol) for symbol in self.added],
            "removed": [dict(symbol) for symbol in self.removed],
            "changed": [change.as_dict() for change in self.changed],
        }

_PYTHON_EXTENSIONS = {".py"}
_JAVASCRIPT_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs"}
_TYPESCRIPT_EXTENSIONS = {".ts", ".tsx", ".mts", ".cts"}
_EXPORT_FUNCTION = re.compile(
    r"^\s*export\s+(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*(\([^\r\n{};]*\)(?:\s*:\s*[^={;]+)?)"
)
_EXPORT_CLASS = re.compile(
    r"^\s*export\s+(?:default\s+)?class\s+([A-Za-z_$][\w$]*)(?:\s+extends\s+([^\r\n{]+))?\s*\{?"
)
_EXPORT_VALUE = re.compile(
    r"^\s*export\s+(?:declare\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*([^=;]+))?\s*=\s*(.*)$"
)
_ARROW = re.compile(
    r"^(?:async\s+)?(\([^\r\n{};]*\)|[A-Za-z_$][\w$]*)(?:\s*:\s*[^=]+)?\s*=>"
)
_FUNCTION_VALUE = re.compile(r"^(?:async\s+)?function(?:\s+[A-Za-z_$][\w$]*)?\s*(\([^\r\n{};]*\))")
_CLASS_METHOD = re.compile(
    r"^\s*(?:(?:public|protected|private|static|abstract|override|readonly|async|get|set)\s+)*"
    r"([A-Za-z_$][\w$]*|constructor)\s*(\([^\r\n{};]*\)(?:\s*:\s*[^={;]+)?)\s*(?:\{|;)?\s*$"
)


def _empty_index() -> ApiIndex:
    return {"schema_version": 1, "methods": [], "modules": [], "symbols": []}


def _module_name(relative: Path) -> str:
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "__init__"


def _unparse(node: ast.AST | None) -> str | None:
    return ast.unparse(node) if node is not None else None


def _argument(argument: ast.arg, default: ast.expr | None = None) -> str:
    rendered = argument.arg
    annotation = _unparse(argument.annotation)
    if annotation is not None:
        rendered += f": {annotation}"
    if default is not None:
        rendered += f" = {ast.unparse(default)}"
    return rendered


def _python_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    arguments = node.args
    positional = list(arguments.posonlyargs) + list(arguments.args)
    defaults: list[ast.expr | None] = [None] * (len(positional) - len(arguments.defaults)) + list(arguments.defaults)
    parts = [_argument(argument, default) for argument, default in zip(positional, defaults, strict=False)]
    if arguments.posonlyargs:
        parts.insert(len(arguments.posonlyargs), "/")
    if arguments.vararg is not None:
        parts.append("*" + _argument(arguments.vararg))
    elif arguments.kwonlyargs:
        parts.append("*")
    for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=False):
        parts.append(_argument(argument, default))
    if arguments.kwarg is not None:
        parts.append("**" + _argument(arguments.kwarg))
    signature = f"({', '.join(parts)})"
    returns = _unparse(node.returns)
    return signature + (f" -> {returns}" if returns is not None else "")


def _symbol(
    *,
    kind: str,
    name: str,
    qualified_name: str,
    module: str,
    path: str,
    line: int,
    signature: str | None,
    docstring: str | None,
    method: str,
) -> dict[str, object]:
    return {
        "kind": kind,
        "name": name,
        "qualified_name": qualified_name,
        "module": module,
        "path": path,
        "line": line,
        "signature": signature,
        "docstring": docstring,
        "method": method,
    }


def _python_extractor(target_path: Path, language: str) -> ApiIndex:
    modules: list[dict[str, object]] = []
    symbols: list[dict[str, object]] = []
    try:
        files = sorted(
            (path for path in target_path.rglob("*") if path.is_file() and path.suffix.casefold() in _PYTHON_EXTENSIONS),
            key=lambda path: path.relative_to(target_path).as_posix(),
        )
    except OSError:
        files = []
    for path in files:
        relative = path.relative_to(target_path).as_posix()
        try:
            with tokenize.open(path) as source_file:
                tree = ast.parse(source_file.read(), filename=relative)
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
            continue
        module = _module_name(Path(relative))
        modules.append(
            {
                "name": module,
                "path": relative,
                "docstring": ast.get_docstring(tree),
                "method": "ast",
            }
        )
        for node in tree.body:
            first_symbol = len(symbols)
            try:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
                    symbols.append(
                        _symbol(
                            kind="function",
                            name=node.name,
                            qualified_name=f"{module}.{node.name}",
                            module=module,
                            path=relative,
                            line=node.lineno,
                            signature=_python_signature(node),
                            docstring=ast.get_docstring(node),
                            method="ast",
                        )
                    )
                elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
                    bases = [ast.unparse(base) for base in node.bases]
                    bases.extend(f"{keyword.arg}={ast.unparse(keyword.value)}" for keyword in node.keywords if keyword.arg)
                    class_name = f"{module}.{node.name}"
                    symbols.append(
                        _symbol(
                            kind="class",
                            name=node.name,
                            qualified_name=class_name,
                            module=module,
                            path=relative,
                            line=node.lineno,
                            signature=f"({', '.join(bases)})",
                            docstring=ast.get_docstring(node),
                            method="ast",
                        )
                    )
                    for child in node.body:
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and not child.name.startswith("_"):
                            symbols.append(
                                _symbol(
                                    kind="method",
                                    name=child.name,
                                    qualified_name=f"{class_name}.{child.name}",
                                    module=module,
                                    path=relative,
                                    line=child.lineno,
                                    signature=_python_signature(child),
                                    docstring=ast.get_docstring(child),
                                    method="ast",
                                )
                            )
            except RecursionError:
                del symbols[first_symbol:]
    return _finish(modules, symbols)


def _javascript_module(relative: str) -> str:
    path = Path(relative)
    return "/".join(path.with_suffix("").parts)


def _javascript_extractor(target_path: Path, language: str) -> ApiIndex:
    modules: list[dict[str, object]] = []
    symbols: list[dict[str, object]] = []
    extensions = _TYPESCRIPT_EXTENSIONS if language == "typescript" else _JAVASCRIPT_EXTENSIONS
    try:
        files = sorted(
            (path for path in target_path.rglob("*") if path.is_file() and path.suffix.casefold() in extensions),
            key=lambda path: path.relative_to(target_path).as_posix(),
        )
    except OSError:
        files = []
    for path in files:
        relative = path.relative_to(target_path).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            continue
        module = _javascript_module(relative)
        modules.append({"name": module, "path": relative, "docstring": None, "method": "heuristic"})
        class_name: str | None = None
        class_depth = 0
        for number, line in enumerate(lines, 1):
            stripped = line.strip()
            function_match = _EXPORT_FUNCTION.match(line)
            class_match = _EXPORT_CLASS.match(line)
            value_match = _EXPORT_VALUE.match(line)
            if function_match:
                name, signature = function_match.groups()
                symbols.append(_symbol(kind="function", name=name, qualified_name=f"{module}.{name}", module=module, path=relative, line=number, signature=signature.strip(), docstring=None, method="heuristic"))
            elif class_match:
                name, extends = class_match.groups()
                class_depth = line.count("{") - line.count("}")
                class_name = name if class_depth > 0 else None
                signature = f"({extends.strip()})" if extends else "()"
                symbols.append(_symbol(kind="class", name=name, qualified_name=f"{module}.{name}", module=module, path=relative, line=number, signature=signature, docstring=None, method="heuristic"))
            elif value_match:
                name, annotation, value = value_match.groups()
                arrow = _ARROW.match(value.strip())
                function_value = _FUNCTION_VALUE.match(value.strip())
                if arrow:
                    raw = arrow.group(1)
                    signature = raw if raw.startswith("(") else f"({raw})"
                    kind = "function"
                elif function_value:
                    signature = function_value.group(1)
                    kind = "function"
                else:
                    signature = f": {annotation.strip()}" if annotation else None
                    kind = "constant"
                symbols.append(_symbol(kind=kind, name=name, qualified_name=f"{module}.{name}", module=module, path=relative, line=number, signature=signature, docstring=None, method="heuristic"))
            elif class_name is not None and class_depth == 1 and stripped and not stripped.startswith(("//", "/*", "*", "@")):
                method_match = _CLASS_METHOD.match(line)
                if method_match:
                    name, signature = method_match.groups()
                    symbols.append(_symbol(kind="method", name=name, qualified_name=f"{module}.{class_name}.{name}", module=module, path=relative, line=number, signature=signature.strip(), docstring=None, method="heuristic"))
            if class_name is not None and not class_match:
                class_depth += line.count("{") - line.count("}")
                if class_depth <= 0:
                    class_name = None
                    class_depth = 0
    return _finish(modules, symbols)


def _finish(modules: list[dict[str, object]], symbols: list[dict[str, object]]) -> ApiIndex:
    modules.sort(key=lambda item: (str(item["path"]), str(item["name"])))
    symbols.sort(
        key=lambda item: (
            str(item["qualified_name"]),
            str(item["kind"]),
            int(cast(str | bytes | bytearray | int, item["line"])),
        )
    )
    methods = sorted({str(item["method"]) for item in modules + symbols})
    return {"schema_version": 1, "methods": methods, "modules": modules, "symbols": symbols}


_EXTRACTORS: dict[str, Extractor] = {
    "python": _python_extractor,
    "javascript": _javascript_extractor,
    "typescript": _javascript_extractor,
}


def _language(language: str) -> str:
    from leitir.adapters.languages import canonicalize_language

    return canonicalize_language(language)


def register_extractor(language: str, extractor: Extractor) -> Extractor | None:
    """Register an extractor and return the previously registered callable."""
    if not callable(extractor):
        raise TypeError("extractor must be callable")
    key = _language(language)
    previous = _EXTRACTORS.get(key)
    _EXTRACTORS[key] = extractor
    return previous


def extract_api_surface(target_path: str | Path, language_hint: str | None = None) -> ApiIndex:
    """Extract a stable API index from one source tree without network access."""
    target = Path(target_path)
    logger.debug("extracting API surface path=%s language_hint=%s", target, language_hint)
    if not target.is_dir():
        return _empty_index()
    if language_hint is not None:
        language = _language(language_hint)
        languages: tuple[str, ...] = ("javascript", "typescript") if language == "npm" else (language,)
    else:
        languages = ("python", "javascript", "typescript")
    indexes = []
    for language in languages:
        extractor = _EXTRACTORS.get(language)
        if extractor is not None:
            indexes.append(extractor(target, language))
    modules = [module for index in indexes for module in _records(index, "modules")]
    symbols = [symbol for index in indexes for symbol in _records(index, "symbols")]
    result = _finish(modules, symbols)
    logger.debug("API surface modules=%d symbols=%d", len(modules), len(symbols))
    return result


def _records(index: ApiIndex, field: str) -> list[dict[str, object]]:
    value = index.get(field)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"API extractor returned invalid {field}")
    return [dict(item) for item in value]


def diff_api_indexes(index_a: ApiIndex, index_b: ApiIndex) -> ApiDiff:
    """Return deterministic public-symbol additions, removals, and signature changes."""
    symbols_a = _records(index_a, "symbols")
    symbols_b = _records(index_b, "symbols")

    def grouped(symbols: list[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
        result: dict[str, list[dict[str, object]]] = {}
        for symbol in symbols:
            name = symbol.get("qualified_name")
            if not isinstance(name, str) or not name:
                raise ValueError("API symbol has invalid qualified_name")
            result.setdefault(name, []).append(symbol)
        return result

    by_name_a = grouped(symbols_a)
    by_name_b = grouped(symbols_b)
    added = tuple(by_name_b[name][0] for name in sorted(by_name_b.keys() - by_name_a.keys()))
    removed = tuple(by_name_a[name][0] for name in sorted(by_name_a.keys() - by_name_b.keys()))
    changed: list[SignatureChange] = []
    for name in sorted(by_name_a.keys() & by_name_b.keys()):
        old_records = by_name_a[name]
        new_records = by_name_b[name]
        if len(old_records) != 1 or len(new_records) != 1:
            continue
        before = old_records[0].get("signature")
        after = new_records[0].get("signature")
        if isinstance(before, str) and isinstance(after, str) and before != after:
            changed.append(SignatureChange(name, before, after))
    return ApiDiff(added=added, removed=removed, changed=tuple(changed))


__all__ = [
    "ApiDiff",
    "ApiIndex",
    "Extractor",
    "SignatureChange",
    "diff_api_indexes",
    "extract_api_surface",
    "register_extractor",
]
