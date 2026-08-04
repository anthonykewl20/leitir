"""Deterministic usage-example extraction from materialized source trees."""

from __future__ import annotations

from pathlib import Path
import re
from typing import TypeAlias

ExamplesIndex: TypeAlias = dict[str, object]

DEFAULT_LIMIT = 10
_SOURCE_DIRS = {"docs", "examples", "tests"}
_MARKDOWN_EXTENSIONS = {".md", ".markdown", ".mdx"}
_CODE_LANGUAGES = {
    ".bash": "bash",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".css": "css",
    ".go": "go",
    ".h": "c",
    ".hpp": "cpp",
    ".html": "html",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "jsx",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".mjs": "javascript",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".sh": "shell",
    ".sql": "sql",
    ".swift": "swift",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".vue": "vue",
    ".zsh": "shell",
}
_FENCE_OPEN = re.compile(r"^\s*```\s*([^\s`]*)?.*$")
_FENCE_CLOSE = re.compile(r"^\s*```\s*$")


def _candidate(relative: Path) -> bool:
    return bool(relative.parts) and (
        relative.parts[0].casefold() in _SOURCE_DIRS
        or (len(relative.parts) == 1 and relative.name.casefold().startswith("readme"))
    )


def _files(target: Path) -> list[Path]:
    try:
        return sorted(
            (
                path
                for path in target.rglob("*")
                if path.is_file() and not path.is_symlink() and _candidate(path.relative_to(target))
            ),
            key=lambda path: path.relative_to(target).as_posix(),
        )
    except OSError:
        return []


def _fenced_snippets(text: str, path: str) -> list[dict[str, object]]:
    snippets: list[dict[str, object]] = []
    lines = text.splitlines()
    start: int | None = None
    language = ""
    content: list[str] = []
    for number, line in enumerate(lines, 1):
        if start is None:
            match = _FENCE_OPEN.match(line)
            if match is not None:
                start = number + 1
                language = (match.group(1) or "").casefold()
                content = []
        elif _FENCE_CLOSE.match(line):
            code = "\n".join(content)
            if code.strip():
                snippets.append(
                    {"path": path, "line": start, "language": language, "code": code}
                )
            start = None
            language = ""
            content = []
        else:
            content.append(line)
    return snippets


def extract_snippets(target_path: str | Path) -> list[dict[str, object]]:
    """Extract fenced Markdown and whole code-file snippets with provenance."""
    target = Path(target_path)
    if not target.is_dir():
        return []
    snippets: list[dict[str, object]] = []
    for path in _files(target):
        relative = path.relative_to(target).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        extension = path.suffix.casefold()
        if extension in _MARKDOWN_EXTENSIONS or path.name.casefold().startswith("readme"):
            snippets.extend(_fenced_snippets(text, relative))
        elif extension in _CODE_LANGUAGES and text.strip():
            snippets.append(
                {
                    "path": relative,
                    "line": 1,
                    "language": _CODE_LANGUAGES[extension],
                    "code": text,
                }
            )
    return snippets


def public_symbol_names(api_index: dict[str, object]) -> tuple[str, ...]:
    """Return stable public symbol names and qualified names from an API index."""
    records = api_index.get("symbols")
    if not isinstance(records, list):
        return ()
    names: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        for field in ("name", "qualified_name"):
            value = record.get(field)
            if isinstance(value, str) and value:
                names.add(value)
    return tuple(sorted(names))


def match_symbols(code: str, symbols: tuple[str, ...] | list[str] | set[str]) -> list[str]:
    """Return symbols referenced at conservative identifier boundaries."""
    matched = []
    for symbol in sorted(set(symbols)):
        pattern = rf"(?<![\w$]){re.escape(symbol)}(?![\w$])"
        if re.search(pattern, code):
            matched.append(symbol)
    return matched


def extract_examples(
    target_path: str | Path,
    api_index: dict[str, object],
    *,
    limit: int = DEFAULT_LIMIT,
) -> ExamplesIndex:
    """Extract and rank a bounded examples index without network access."""
    symbols = public_symbol_names(api_index)
    ranked: list[dict[str, object]] = []
    for snippet in extract_snippets(target_path):
        matched = match_symbols(str(snippet["code"]), symbols)
        if matched:
            ranked.append(dict(snippet, symbols=matched))
    ranked.sort(
        key=lambda item: (
            -len(item["symbols"]),
            str(item["path"]),
            int(item["line"]),
            -len(str(item["code"])),
        )
    )
    return {
        "schema_version": 1,
        "symbols_source": "api_index",
        "snippets": ranked[: max(0, limit)],
    }


__all__ = [
    "DEFAULT_LIMIT",
    "ExamplesIndex",
    "extract_examples",
    "extract_snippets",
    "match_symbols",
    "public_symbol_names",
]
