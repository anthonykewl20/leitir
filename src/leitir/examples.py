"""Deterministic usage-example extraction from materialized source trees."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import TypeAlias, cast

from .bts_errors import BTSError, BTSRejectReason

ExamplesIndex: TypeAlias = dict[str, object]
logger = logging.getLogger(__name__)

DEFAULT_LIMIT = 10
EXAMPLES_SCHEMA_VERSION = 2
CLASSIFICATION_METHOD = "heuristic-v1"
CLASSIFICATION_DETAIL_CODE = "example_classification_invalid_v1"
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

# Conventional Markdown fence tags that denote Python source but are not the
# bare ``python`` spelling: interactive-shell transcripts (``pycon``,
# ``ipython``, ``doctest``), the historically common short form (``py``),
# and explicit version-qualified tags seen in older docs (``python2``,
# ``python3``). Normalized to the canonical extension-derived spelling so a
# README's real usage transcript classifies the same way a ``.py`` file
# would, instead of falling through to ``unknown`` because the raw tag never
# matches ``_SUPPORTED_LANGUAGES``.
_LANGUAGE_ALIASES = {
    "py": "python",
    "python2": "python",
    "python3": "python",
    "pycon": "python",
    "ipython": "python",
    "doctest": "python",
    # Terminal/shell transcript tags commonly seen in READMEs for install
    # instructions (``choco``/``winget`` in _PACKAGE_MANAGER_INSTALL exist
    # specifically for the powershell/cmd case). These carry the same
    # command syntax as bash/sh for the purposes of classification, so
    # normalize them to the canonical "shell" spelling rather than leaving
    # them unsupported and always UNKNOWN regardless of content.
    "zsh": "shell",
    "console": "shell",
    "cmd": "shell",
    "powershell": "shell",
}


def _normalize_language(language: str) -> str:
    return _LANGUAGE_ALIASES.get(language, language)


# Fence languages whose content is a shell/terminal command line, used to
# recognize package-manager install commands (see _is_install_only_snippet).
# zsh/console/cmd/powershell fence tags normalize to "shell" via
# _LANGUAGE_ALIASES before classification, so they reach this set already
# canonicalized; listed here as just the three post-normalization spellings
# that can actually appear by the time _is_install_only_snippet runs.
_SHELL_LIKE_LANGUAGES = frozenset({"bash", "sh", "shell"})
_PACKAGE_MANAGER_INSTALL = re.compile(
    r"^(?:\$\s*)?(?:sudo\s+)?"
    r"(?:pip3?|pipx|conda|uv|poetry|npm|yarn|pnpm|cargo|gem|go|apt(?:-get)?|brew|choco|winget)\s+"
    r"(?:install|add|get)\b",
    re.IGNORECASE,
)


def _is_install_only_snippet(language: str, code: str) -> bool:
    """Return whether a shell-like snippet is nothing but package-manager installs.

    A ``pip install thing`` block is genuinely useful documentation, but it
    is not a *usage* example -- ranking it as ``minimal_usage`` inverts the
    signal a human relies on to find real API calls. Conservative by design:
    only shell-family languages are considered, and every non-comment,
    non-blank line must match a known install-command shape; anything with
    additional commands (piping, running the tool, etc.) is left alone.
    """
    if language not in _SHELL_LIKE_LANGUAGES:
        return False
    lines = [stripped for line in code.splitlines() if (stripped := line.strip()) and not stripped.startswith("#")]
    if not lines:
        return False
    return all(_PACKAGE_MANAGER_INSTALL.match(line) is not None for line in lines)


class ExampleClass(str, Enum):  # noqa: UP042 - ADR-0010 requires str, Enum
    """Closed, maintainer-pinned semantic example labels in canonical order."""

    MINIMAL_USAGE = "minimal_usage"
    PRODUCTION_USAGE = "production_usage"
    ERROR_HANDLING = "error_handling"
    CONFIGURATION = "configuration"
    INTEGRATION_TEST = "integration_test"
    UNIT_TEST = "unit_test"
    DEPRECATED_EXAMPLE = "deprecated_example"
    BENCHMARK = "benchmark"
    INTERNAL_ONLY_USAGE = "internal_only_usage"
    UNKNOWN = "unknown"


_LABEL_ORDER = {label: index for index, label in enumerate(ExampleClass)}
_SUPPORTED_LANGUAGES = frozenset(_CODE_LANGUAGES.values()) | frozenset(
    {"js", "py", "rb", "rs", "sh", "ts"}
)
_TEST_SEGMENTS = frozenset({"test", "tests"})
_INTEGRATION_SEGMENTS = frozenset({"e2e", "integration", "integration_test", "integration_tests"})
_BENCHMARK_SEGMENTS = frozenset({"bench", "benches", "benchmark", "benchmarks"})
_INTERNAL_SEGMENTS = frozenset({"internal", "private"})
_PRODUCTION_SEGMENTS = frozenset({"prod", "production"})
_DEPRECATED_MARKERS = frozenset({"deprecated", "deprecation"})
_BENCHMARK_MARKERS = frozenset({"bench", "benchmark", "criterion"})
_ERROR_MARKERS = frozenset({"catch", "except", "rescue", "try"})
_CONFIGURATION_MARKERS = frozenset(
    {"config", "configuration", "configure", "env", "environment", "option", "options", "settings"}
)
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _classification_error(message: str) -> BTSError:
    return BTSError(
        BTSRejectReason.REJECT_HARD_GATE_FAILED,
        message,
        detail_code=CLASSIFICATION_DETAIL_CODE,
    )


@dataclass(frozen=True, slots=True, order=True)
class ExampleRuleEvidence:
    """One classifier rule result bound to its complete source-record identity."""

    label: ExampleClass
    rule_id: str
    rule_version: str
    path: str
    line: int
    language: str
    symbols: tuple[str, ...]
    code_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.label, ExampleClass):
            raise _classification_error("example evidence has an unrecognized label")
        if not isinstance(self.rule_id, str) or not self.rule_id or not isinstance(self.rule_version, str) or not self.rule_version:
            raise _classification_error("example evidence rule identity is missing")
        source_path = PurePosixPath(self.path) if isinstance(self.path, str) else None
        if (
            source_path is None
            or not self.path
            or source_path.is_absolute()
            or ".." in source_path.parts
            or source_path.as_posix() != self.path
            or not isinstance(self.line, int)
            or isinstance(self.line, bool)
            or self.line < 1
        ):
            raise _classification_error("example evidence source location is invalid")
        if not isinstance(self.language, str):
            raise _classification_error("example evidence language is invalid")
        if (
            not isinstance(self.symbols, tuple)
            or not all(isinstance(symbol, str) and symbol for symbol in self.symbols)
            or self.symbols != tuple(sorted(set(self.symbols)))
        ):
            raise _classification_error("example evidence symbols are not sorted and unique")
        if not isinstance(self.code_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.code_sha256):
            raise _classification_error("example evidence code digest is invalid")

    def as_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-compatible evidence record."""
        return {
            "label": self.label.value,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "path": self.path,
            "line": self.line,
            "language": self.language,
            "symbols": list(self.symbols),
            "code_sha256": self.code_sha256,
        }


@dataclass(frozen=True, slots=True)
class ExampleClassification:
    """Canonical multi-label semantic classification for one example record."""

    labels: tuple[ExampleClass, ...]
    method: str
    confidence_bps: int | None
    evidence: tuple[ExampleRuleEvidence, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.labels, tuple) or not self.labels:
            raise _classification_error("example classification labels must be a non-empty tuple")
        if not all(isinstance(label, ExampleClass) for label in self.labels):
            raise _classification_error("example classification contains an unrecognized label")
        canonical = tuple(sorted(set(self.labels), key=_LABEL_ORDER.__getitem__))
        if self.labels != canonical:
            raise _classification_error("example classification labels must be sorted and unique")
        if ExampleClass.UNKNOWN in self.labels and self.labels != (ExampleClass.UNKNOWN,):
            raise _classification_error("unknown example classification must be exclusive")
        if self.method != CLASSIFICATION_METHOD:
            raise _classification_error("example classification method is unsupported")
        if self.labels == (ExampleClass.UNKNOWN,):
            if self.confidence_bps is not None:
                raise _classification_error("unknown example classification cannot have confidence")
        elif (
            not isinstance(self.confidence_bps, int)
            or isinstance(self.confidence_bps, bool)
            or not 0 <= self.confidence_bps <= 10_000
        ):
            raise _classification_error("concrete example classification confidence is invalid")
        if not isinstance(self.evidence, tuple) or not all(
            isinstance(item, ExampleRuleEvidence) for item in self.evidence
        ):
            raise _classification_error("example classification evidence is invalid")
        evidence_labels = tuple(item.label for item in self.evidence)
        if evidence_labels != self.labels:
            raise _classification_error("each example label must have exactly one ordered evidence record")
        source_keys = {
            (item.path, item.line, item.language, item.symbols, item.code_sha256)
            for item in self.evidence
        }
        if len(source_keys) != 1:
            raise _classification_error("example classification evidence cites different source records")

    def as_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-compatible classification record."""
        return {
            "labels": [label.value for label in self.labels],
            "method": self.method,
            "confidence_bps": self.confidence_bps,
            "evidence": [item.as_dict() for item in self.evidence],
        }


def _source_fields(record: Mapping[str, object]) -> tuple[str, int, str, str, tuple[str, ...]]:
    path = record.get("path")
    line = record.get("line")
    language = record.get("language")
    code = record.get("code")
    raw_symbols = record.get("symbols")
    if (
        not isinstance(path, str)
        or not path
        or PurePosixPath(path).is_absolute()
        or ".." in PurePosixPath(path).parts
        or PurePosixPath(path).as_posix() != path
        or not isinstance(line, int)
        or isinstance(line, bool)
        or line < 1
        or not isinstance(language, str)
        or not isinstance(code, str)
        or not code.strip()
        or not isinstance(raw_symbols, (list, tuple))
        or not raw_symbols
        or not all(isinstance(symbol, str) and symbol for symbol in raw_symbols)
    ):
        raise _classification_error("example source record is malformed")
    symbols = tuple(sorted(set(cast(list[str] | tuple[str, ...], raw_symbols))))
    return path, line, _normalize_language(language.casefold()), code, symbols


def _path_words(path: str) -> tuple[set[str], str]:
    parts = PurePosixPath(path).parts
    segments = {part.casefold() for part in parts[:-1]}
    filename = parts[-1].casefold()
    stem_words = set(re.findall(r"[a-z0-9]+", Path(filename).stem))
    return segments | stem_words, filename


def classify_example(record: Mapping[str, object]) -> ExampleClassification:
    """Classify one extracted example using only pinned exact V1 rules.

    Unsupported languages and records without a conclusive pinned rule remain
    visible as ``UNKNOWN``. Malformed records reject with ADR-0010's registered
    classification reason/detail pair.
    """

    if not isinstance(record, Mapping):
        raise _classification_error("example source record must be a mapping")
    path, line, language, code, symbols = _source_fields(record)
    digest = sha256(code.encode("utf-8")).hexdigest()

    rules: dict[ExampleClass, tuple[str, int]] = {}
    path_words, filename = _path_words(path)
    code_tokens = {token.casefold() for token in _TOKEN.findall(code)}

    if language not in _SUPPORTED_LANGUAGES:
        rules[ExampleClass.UNKNOWN] = ("unsupported_language", 0)
    else:
        is_test = bool(path_words & _TEST_SEGMENTS) or filename.startswith("test_") or filename.endswith("_test.py")
        is_integration = bool(path_words & _INTEGRATION_SEGMENTS)
        if is_test:
            if is_integration:
                rules[ExampleClass.INTEGRATION_TEST] = ("integration_test_path", 9500)
            else:
                rules[ExampleClass.UNIT_TEST] = ("unit_test_path", 9500)
        elif path_words & _PRODUCTION_SEGMENTS:
            rules[ExampleClass.PRODUCTION_USAGE] = ("production_path", 9500)
        elif (
            "docs" in path_words or "examples" in path_words or filename.startswith("readme")
        ) and not _is_install_only_snippet(language, code):
            rules[ExampleClass.MINIMAL_USAGE] = ("usage_example_path", 9000)

        if code_tokens & _ERROR_MARKERS:
            rules[ExampleClass.ERROR_HANDLING] = ("error_marker", 8500)
        if code_tokens & _CONFIGURATION_MARKERS:
            rules[ExampleClass.CONFIGURATION] = ("configuration_marker", 8500)
        if path_words & _BENCHMARK_SEGMENTS or code_tokens & _BENCHMARK_MARKERS:
            rules[ExampleClass.BENCHMARK] = ("benchmark_marker", 9000)
        if path_words & _INTERNAL_SEGMENTS or any(symbol.rsplit(".", 1)[-1].startswith("_") for symbol in symbols):
            rules[ExampleClass.INTERNAL_ONLY_USAGE] = ("internal_marker", 9000)
        if "deprecated" in path_words or code_tokens & _DEPRECATED_MARKERS:
            rules[ExampleClass.DEPRECATED_EXAMPLE] = ("deprecation_marker", 9000)
        if not rules:
            rules[ExampleClass.UNKNOWN] = ("no_conclusive_rule", 0)

    labels = tuple(sorted(rules, key=_LABEL_ORDER.__getitem__))
    evidence = tuple(
        ExampleRuleEvidence(
            label=label,
            rule_id=rules[label][0],
            rule_version="1",
            path=path,
            line=line,
            language=language,
            symbols=symbols,
            code_sha256=digest,
        )
        for label in labels
    )
    confidence = None if labels == (ExampleClass.UNKNOWN,) else min(rules[label][1] for label in labels)
    return ExampleClassification(labels, CLASSIFICATION_METHOD, confidence, evidence)


def classify_examples(records: list[Mapping[str, object]] | tuple[Mapping[str, object], ...]) -> tuple[ExampleClassification, ...]:
    """Classify existing example records in their supplied deterministic order."""

    if not isinstance(records, (list, tuple)):
        raise _classification_error("example records must be a list or tuple")
    return tuple(classify_example(record) for record in records)


def valid_serialized_classification(record: Mapping[str, object]) -> bool:
    """Return whether a serialized classification exactly matches pinned rules."""

    classification = record.get("classification")
    if not isinstance(classification, dict):
        return False
    try:
        expected = classify_example(record).as_dict()
    except BTSError:
        return False
    return classification == expected


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
                language = _normalize_language((match.group(1) or "").casefold())
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
    logger.debug("extracting examples path=%s public_symbols=%d limit=%d", target_path, len(symbols), limit)
    ranked: list[dict[str, object]] = []
    for snippet in extract_snippets(target_path):
        matched = match_symbols(str(snippet["code"]), symbols)
        if matched:
            record = dict(snippet, symbols=matched)
            ranked.append(dict(record, classification=classify_example(record).as_dict()))
    def _sort_key(item: dict[str, object]) -> tuple[int, int, str, int, int]:
        classification = cast(dict[str, object], item["classification"])
        labels = cast(list[str], classification["labels"])
        is_unknown_only = labels == [ExampleClass.UNKNOWN.value]
        return (
            1 if is_unknown_only else 0,
            -len(cast(list[str], item["symbols"])),
            str(item["path"]),
            int(cast(str | bytes | bytearray | int, item["line"])),
            -len(str(item["code"])),
        )

    ranked.sort(key=_sort_key)
    logger.debug("examples matched=%d returned=%d", len(ranked), min(len(ranked), max(0, limit)))
    return {
        "schema_version": EXAMPLES_SCHEMA_VERSION,
        "symbols_source": "api_index",
        "snippets": ranked[: max(0, limit)],
    }


__all__ = [
    "CLASSIFICATION_METHOD",
    "DEFAULT_LIMIT",
    "EXAMPLES_SCHEMA_VERSION",
    "ExampleClass",
    "ExampleClassification",
    "ExampleRuleEvidence",
    "ExamplesIndex",
    "classify_example",
    "classify_examples",
    "extract_examples",
    "extract_snippets",
    "match_symbols",
    "public_symbol_names",
    "valid_serialized_classification",
]
