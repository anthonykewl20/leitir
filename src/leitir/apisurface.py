"""Deterministic public API extraction for materialized source trees.

Extractors are registered by language with :func:`register_extractor`.  A
parser-backed JavaScript or TypeScript plugin can replace the built-in
heuristic by registering a callable accepting ``(target_path, language)`` and
returning the same ``ApiIndex`` dictionary contract.

Go's exported types and interfaces resolve to the fixed four-kind schema's
``class`` kind, while exported ``const`` and ``var`` declarations resolve to
``constant``.  Go alone excludes ``vendor`` and ``testdata`` trees because
those names are its standard third-party and test-data layout; Python,
JavaScript, and TypeScript keep their existing path semantics.
"""

from __future__ import annotations

import ast
import logging
import re
import tokenize
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias, cast

from leitir._python_ast import parse_python, python_signature
from leitir.adapters._tier2_patterns import (
    ARROW,
    CLASS_METHOD,
    EXPORT_CLASS,
    EXPORT_FUNCTION,
    EXPORT_VALUE,
    FUNCTION_VALUE,
)

ApiIndex: TypeAlias = dict[str, object]
Extractor: TypeAlias = Callable[[Path, str], ApiIndex]
logger = logging.getLogger(__name__)

# Schema version embedded in every emitted API index. Bump when the shape of
# the "methods"/"modules"/"symbols" payload changes incompatibly.
API_SCHEMA_VERSION = 1


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
_GO_EXTENSIONS = {".go"}
_GO_IDENTIFIER = r"(?P<name>[^\W\d]\w*)"
_GO_FUNCTION = re.compile(
    rf"^\s*func\s+(?:\(\s*(?P<receiver>[^)]*)\)\s+)?{_GO_IDENTIFIER}"
)
_GO_TYPE = re.compile(rf"^\s*type\s+{_GO_IDENTIFIER}\b")
_GO_VALUE = re.compile(rf"^\s*(?:const|var)\s+{_GO_IDENTIFIER}\b")
_GO_GROUP_VALUE = re.compile(rf"^\s*{_GO_IDENTIFIER}\b")
_GO_INTERFACE_METHOD = re.compile(rf"^\s*{_GO_IDENTIFIER}\s*\(")


def _empty_index() -> ApiIndex:
    return {"schema_version": API_SCHEMA_VERSION, "methods": [], "modules": [], "symbols": []}


def _module_name(relative: Path) -> str:
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "__init__"


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
                tree = parse_python(source_file.read(), filename=relative)
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
                            signature=python_signature(node),
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
                                    signature=python_signature(child),
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
            function_match = EXPORT_FUNCTION.match(line)
            class_match = EXPORT_CLASS.match(line)
            value_match = EXPORT_VALUE.match(line)
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
                arrow = ARROW.match(value.strip())
                function_value = FUNCTION_VALUE.match(value.strip())
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
                method_match = CLASS_METHOD.match(line)
                if method_match:
                    name, signature = method_match.groups()
                    symbols.append(_symbol(kind="method", name=name, qualified_name=f"{module}.{class_name}.{name}", module=module, path=relative, line=number, signature=signature.strip(), docstring=None, method="heuristic"))
            if class_name is not None and not class_match:
                class_depth += line.count("{") - line.count("}")
                if class_depth <= 0:
                    class_name = None
                    class_depth = 0
    return _finish(modules, symbols)


def _go_code_lines(source: str) -> list[str]:
    output: list[str] = []
    state = "code"
    escaped = False
    index = 0
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if character == "/" and following == "/":
                output.extend((" ", " "))
                state = "line_comment"
                index += 2
                continue
            if character == "/" and following == "*":
                output.extend((" ", " "))
                state = "block_comment"
                index += 2
                continue
            if character == '"':
                output.append(" ")
                state = "quoted"
            elif character == "'":
                output.append(" ")
                state = "rune"
            elif character == "`":
                output.append(" ")
                state = "raw"
            else:
                output.append(character)
        elif state == "line_comment":
            output.append("\n" if character == "\n" else " ")
            if character == "\n":
                state = "code"
        elif state == "block_comment":
            if character == "*" and following == "/":
                output.extend((" ", " "))
                state = "code"
                index += 2
                continue
            output.append("\n" if character == "\n" else " ")
        elif state == "raw":
            output.append("\n" if character == "\n" else " ")
            if character == "`":
                state = "code"
        else:
            output.append("\n" if character == "\n" else " ")
            if character == "\\" and not escaped:
                escaped = True
            elif character in {'"', "'"} and not escaped:
                state = "code"
            else:
                escaped = False
        index += 1
    return "".join(output).splitlines()


def _go_exported(name: str) -> bool:
    return bool(name) and unicodedata.category(name[0]) == "Lu"


def _go_compact(value: str) -> str:
    return (
        " ".join(value.split())
        .replace("( ", "(")
        .replace(" )", ")")
        .replace("[ ", "[")
        .replace(" ]", "]")
    )


def _go_signature(
    lines: list[str], start: int, offset: int, *, stop_at_line_end: bool = False
) -> str | None:
    fragments: list[str] = []
    parentheses = 0
    brackets = 0
    for line_number in range(start, len(lines)):
        fragment = lines[line_number][offset:] if line_number == start else lines[line_number]
        for position, character in enumerate(fragment):
            if character == "(":
                parentheses += 1
            elif character == ")":
                parentheses -= 1
            elif character == "[":
                brackets += 1
            elif character == "]":
                brackets -= 1
            elif character == "{" and parentheses == 0 and brackets == 0:
                fragments.append(fragment[:position])
                value = _go_compact(" ".join(fragments))
                return value or None
        fragments.append(fragment)
        if stop_at_line_end and parentheses == 0 and brackets == 0:
            value = _go_compact(" ".join(fragments))
            return value or None
    value = _go_compact(" ".join(fragments))
    return value or None


def _go_receiver_type(receiver: str) -> str:
    value = receiver.split()[-1] if receiver.split() else ""
    value = value.lstrip("*")
    return value.split("[", 1)[0].rsplit(".", 1)[-1]


def _go_type_signature(line: str, offset: int) -> str | None:
    value = line[offset:].split("{", 1)[0].strip()
    compact = _go_compact(value)
    return compact or None


def _go_extractor(target_path: Path, language: str) -> ApiIndex:
    modules: list[dict[str, object]] = []
    symbols: list[dict[str, object]] = []
    try:
        files = sorted(
            (
                path
                for path in target_path.rglob("*")
                if path.is_file()
                and path.suffix.casefold() in _GO_EXTENSIONS
                and not any(part in {"vendor", "testdata"} for part in path.relative_to(target_path).parts)
            ),
            key=lambda path: path.relative_to(target_path).as_posix(),
        )
    except OSError:
        files = []
    for path in files:
        relative = path.relative_to(target_path).as_posix()
        try:
            lines = _go_code_lines(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            continue
        module = _javascript_module(relative)
        modules.append({"name": module, "path": relative, "docstring": None, "method": "heuristic"})
        brace_depth = 0
        group: str | None = None
        interface_name: str | None = None
        interface_depth = 0
        for number, line in enumerate(lines, 1):
            stripped = line.strip()
            delta = line.count("{") - line.count("}")
            if interface_name is not None and brace_depth == interface_depth:
                method_match = _GO_INTERFACE_METHOD.match(line)
                if method_match and _go_exported(method_match["name"]):
                    name = method_match["name"]
                    symbols.append(
                        _symbol(
                            kind="method",
                            name=name,
                            qualified_name=f"{module}.{interface_name}.{name}",
                            module=module,
                            path=relative,
                            line=number,
                            signature=_go_signature(
                                lines,
                                number - 1,
                                method_match.end() - 1,
                                stop_at_line_end=True,
                            ),
                            docstring=None,
                            method="heuristic",
                        )
                    )
            elif group is not None:
                if brace_depth == 0 and stripped == ")":
                    group = None
                elif brace_depth == 0 and group in {"const", "var"}:
                    value_match = _GO_GROUP_VALUE.match(line)
                    if value_match and _go_exported(value_match["name"]):
                        name = value_match["name"]
                        symbols.append(
                            _symbol(
                                kind="constant",
                                name=name,
                                qualified_name=f"{module}.{name}",
                                module=module,
                                path=relative,
                                line=number,
                                signature=_go_type_signature(line, value_match.end()),
                                docstring=None,
                                method="heuristic",
                            )
                        )
                elif brace_depth == 0 and group == "type":
                    type_match = _GO_GROUP_VALUE.match(line)
                    if type_match and _go_exported(type_match["name"]):
                        name = type_match["name"]
                        symbols.append(
                            _symbol(
                                kind="class",
                                name=name,
                                qualified_name=f"{module}.{name}",
                                module=module,
                                path=relative,
                                line=number,
                                signature=_go_type_signature(line, type_match.end()),
                                docstring=None,
                                method="heuristic",
                            )
                        )
                        type_tail = line[type_match.end():]
                        if re.match(r"\s*(?:\[[^]]*\]\s*)?interface\b", type_tail) and delta > 0:
                            interface_name = name
                            interface_depth = brace_depth + delta
            elif brace_depth == 0:
                group_match = re.match(r"^(const|type|var)\s*\(\s*$", stripped)
                if group_match:
                    group = group_match[1]
                else:
                    function_match = _GO_FUNCTION.match(line)
                    type_match = _GO_TYPE.match(line)
                    value_match = _GO_VALUE.match(line)
                    if function_match and _go_exported(function_match["name"]):
                        name = function_match["name"]
                        receiver = function_match["receiver"]
                        receiver_type = _go_receiver_type(receiver) if receiver else ""
                        kind = "method" if receiver_type else "function"
                        qualified_name = (
                            f"{module}.{receiver_type}.{name}"
                            if receiver_type
                            else f"{module}.{name}"
                        )
                        symbols.append(
                            _symbol(
                                kind=kind,
                                name=name,
                                qualified_name=qualified_name,
                                module=module,
                                path=relative,
                                line=number,
                                signature=_go_signature(lines, number - 1, function_match.end()),
                                docstring=None,
                                method="heuristic",
                            )
                        )
                    elif type_match and _go_exported(type_match["name"]):
                        name = type_match["name"]
                        symbols.append(
                            _symbol(
                                kind="class",
                                name=name,
                                qualified_name=f"{module}.{name}",
                                module=module,
                                path=relative,
                                line=number,
                                signature=_go_type_signature(line, type_match.end()),
                                docstring=None,
                                method="heuristic",
                            )
                        )
                        type_tail = line[type_match.end():]
                        if re.match(r"\s*(?:\[[^]]*\]\s*)?interface\b", type_tail) and delta > 0:
                            interface_name = name
                            interface_depth = brace_depth + delta
                    elif value_match and _go_exported(value_match["name"]):
                        name = value_match["name"]
                        symbols.append(
                            _symbol(
                                kind="constant",
                                name=name,
                                qualified_name=f"{module}.{name}",
                                module=module,
                                path=relative,
                                line=number,
                                signature=_go_type_signature(line, value_match.end()),
                                docstring=None,
                                method="heuristic",
                            )
                        )
            brace_depth += delta
            if interface_name is not None and brace_depth < interface_depth:
                interface_name = None
                interface_depth = 0
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
    return {"schema_version": API_SCHEMA_VERSION, "methods": methods, "modules": modules, "symbols": symbols}


_EXTRACTORS: dict[str, Extractor] = {
    "go": _go_extractor,
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
        languages = ("go", "python", "javascript", "typescript")
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
    "API_SCHEMA_VERSION",
    "ApiDiff",
    "ApiIndex",
    "Extractor",
    "SignatureChange",
    "diff_api_indexes",
    "extract_api_surface",
    "register_extractor",
]
