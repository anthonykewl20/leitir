"""Stdlib mutation engine: plant one semantic fault at a time and ask the tests whether they notice.

Mutants are spliced into the *original* source text at the exact node span
(never a whole-file ``ast.unparse``), so the diff is one line and tracebacks
keep their line numbers.  Every mutant is compiled before it is trusted.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

NO_MUTATE = "pragma: no mutate"

# Modules whose fail-closed behaviour is the product's core promise; survivors
# here are weighted heavier than survivors elsewhere.
INTEGRITY_MODULES = frozenset(
    {
        "leitir.materialize",
        "leitir.treehash",
        "leitir.safeio",
        "leitir.manifest_auth",
        "leitir.snapshot",
        "leitir.resolver",
        "leitir.parity",
        "leitir.sumdb",
        "leitir.streaming",
        "leitir.trust",
        "leitir.spec",
        "leitir.lockfiles",
        "leitir.corpus",
        "leitir.exit_corpus",
        "leitir.exec_sandbox",
        "leitir.license_policy",
        "leitir.transplant",
        "leitir.credentials",
        "leitir._regex_budget",
        "leitir.tree",
    }
)

_CMP_SWAP: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
}
_ARITH_SWAP: dict[type[ast.operator], type[ast.operator]] = {
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
    ast.Mult: ast.FloorDiv,
    ast.FloorDiv: ast.Mult,
}


@dataclass(frozen=True)
class Mutant:
    path: str  # repo-relative posix path
    module: str  # dotted module name
    operator: str
    lineno: int
    end_lineno: int
    col: int
    end_col: int
    original: str
    mutated: str

    @property
    def id(self) -> str:
        material = json.dumps(
            [self.path, self.operator, self.lineno, self.col, self.original, self.mutated],
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def describe(self) -> str:
        return f"{self.path}:{self.lineno} {self.operator}: `{self.original}` -> `{self.mutated}`"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "module": self.module,
            "operator": self.operator,
            "lineno": self.lineno,
            "col": self.col,
            "original": self.original,
            "mutated": self.mutated,
        }


# --------------------------------------------------------------------------
# enumeration
# --------------------------------------------------------------------------


def _line_offsets(source: str) -> list[int]:
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    return offsets


def _span(source: str, offsets: list[int], node: ast.AST) -> tuple[int, int] | None:
    lineno = getattr(node, "lineno", None)
    end_lineno = getattr(node, "end_lineno", None)
    col = getattr(node, "col_offset", None)
    end_col = getattr(node, "end_col_offset", None)
    if not all(isinstance(item, int) for item in (lineno, end_lineno, col, end_col)):
        return None
    assert isinstance(lineno, int) and isinstance(end_lineno, int) and isinstance(col, int) and isinstance(end_col, int)

    # col offsets are in UTF-8 bytes; convert per line.
    def to_char(line_no: int, byte_col: int) -> int:
        line_start = offsets[line_no - 1]
        line_text = source[line_start : offsets[line_no]]
        return line_start + len(line_text.encode("utf-8")[:byte_col].decode("utf-8", errors="replace"))

    return (to_char(lineno, col), to_char(end_lineno, end_col))


class _Collector(ast.NodeVisitor):
    """Collect candidate (node, operator, replacement_text) triples."""

    def __init__(self, source: str, skip_lines: set[int]) -> None:
        self.source = source
        self.skip_lines = skip_lines
        self.candidates: list[tuple[ast.AST, str, str]] = []
        self._in_annotation = 0

    # -- helpers ------------------------------------------------------------

    def _skip(self, node: ast.AST) -> bool:
        lineno = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", None)
        if not isinstance(lineno, int):
            return True
        last = end if isinstance(end, int) else lineno
        return any(line in self.skip_lines for line in range(lineno, last + 1)) or self._in_annotation > 0

    def _add(self, node: ast.AST, operator: str, replacement: str) -> None:
        if not self._skip(node):
            self.candidates.append((node, operator, replacement))

    # -- annotations / docstrings are never mutated --------------------------

    def _visit_annotated_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Decorators (dataclass flags, lru_cache sizes) are configuration, not behaviour.
        self._in_annotation += 1
        self.visit(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        self._in_annotation -= 1
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        body = node.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body = body[1:]
        for statement in body:
            self.visit(statement)

    visit_FunctionDef = _visit_annotated_function
    visit_AsyncFunctionDef = _visit_annotated_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        body = node.body
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body = body[1:]
        for statement in body:
            self.visit(statement)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = node.targets
        if any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
            return
        self.visit(node.value)

    def visit_If(self, node: ast.If) -> None:
        test = node.test
        # ``if TYPE_CHECKING:`` blocks are import-only.
        if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
            for statement in node.orelse:
                self.visit(statement)
            return
        if not isinstance(test, (ast.Compare, ast.BoolOp, ast.UnaryOp, ast.Constant)):
            self._add(test, "if-negate", f"not ({ast.unparse(test)})")
        self.generic_visit(node)

    # -- expression operators -----------------------------------------------

    def visit_Compare(self, node: ast.Compare) -> None:
        if len(node.ops) == 1:
            op = node.ops[0]
            swapped = _CMP_SWAP.get(type(op))
            if swapped is not None:
                new = ast.Compare(left=node.left, ops=[swapped()], comparators=node.comparators)
                self._add(node, "cmp-swap", ast.unparse(new))
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        swapped = ast.Or() if isinstance(node.op, ast.And) else ast.And()
        new = ast.BoolOp(op=swapped, values=node.values)
        self._add(node, "boolop-swap", ast.unparse(new))
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, ast.Not):
            self._add(node, "not-drop", ast.unparse(node.operand))
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        swapped = _ARITH_SWAP.get(type(node.op))
        # Skip string-literal concatenation; mutating message text is noise.
        literal_str = any(
            (isinstance(side, ast.Constant) and isinstance(side.value, str)) or isinstance(side, ast.JoinedStr)
            for side in (node.left, node.right)
        )
        if swapped is not None and not literal_str:
            new = ast.BinOp(left=node.left, op=swapped(), right=node.right)
            self._add(node, "arith-swap", ast.unparse(new))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if value is True:
            self._add(node, "bool-flip", "False")
        elif value is False:
            self._add(node, "bool-flip", "True")
        elif isinstance(value, int) and not isinstance(value, bool):
            self._add(node, "int-shift", repr(value + 1))

    # -- statement operators ------------------------------------------------

    def visit_Raise(self, node: ast.Raise) -> None:
        if node.exc is not None:
            self._add(node, "raise-drop", "pass")
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        value = node.value
        if value is not None and not (isinstance(value, ast.Constant) and value.value is None):
            self._add(node, "return-none", "return None")
        self.generic_visit(node)

    def visit_Break(self, node: ast.Break) -> None:
        self._add(node, "break-continue", "continue")

    def visit_Continue(self, node: ast.Continue) -> None:
        self._add(node, "break-continue", "break")


def _module_name(repo_root: Path, path: Path) -> str:
    relative = path.resolve().relative_to((repo_root / "src").resolve())
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def enumerate_mutants(repo_root: Path, path: Path) -> list[Mutant]:
    """Return every compilable mutant for one source file, in source order."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    skip_lines = {index + 1 for index, line in enumerate(source.splitlines()) if NO_MUTATE in line}
    collector = _Collector(source, skip_lines)
    collector.visit(tree)
    offsets = _line_offsets(source)
    relative = path.resolve().relative_to(repo_root.resolve()).as_posix()
    module = _module_name(repo_root, path)
    mutants: list[Mutant] = []
    seen: set[str] = set()
    for node, operator, replacement in collector.candidates:
        span = _span(source, offsets, node)
        if span is None:
            continue
        start, end = span
        lineno = int(getattr(node, "lineno"))  # noqa: B009 - validated by _span
        end_lineno = int(getattr(node, "end_lineno", lineno) or lineno)
        col = int(getattr(node, "col_offset"))  # noqa: B009
        end_col = int(getattr(node, "end_col_offset", col) or col)
        original = source[start:end]
        if "\n" in original and operator not in {"raise-drop", "return-none", "if-negate", "cmp-swap", "boolop-swap"}:
            continue
        mutated_source = source[:start] + replacement + source[end:]
        try:
            compile(mutated_source, str(path), "exec")
        except SyntaxError:
            continue
        mutant = Mutant(
            path=relative,
            module=module,
            operator=operator,
            lineno=lineno,
            end_lineno=end_lineno,
            col=col,
            end_col=end_col,
            original=original,
            mutated=replacement,
        )
        if mutant.id in seen:
            continue
        seen.add(mutant.id)
        mutants.append(mutant)
    return mutants


def apply_mutant(source: str, mutant: Mutant) -> str:
    offsets = _line_offsets(source)
    start = offsets[mutant.lineno - 1] + _byte_to_char(source, offsets, mutant.lineno, mutant.col)
    end = offsets[mutant.end_lineno - 1] + _byte_to_char(source, offsets, mutant.end_lineno, mutant.end_col)
    if source[start:end] != mutant.original:
        raise ValueError(f"source drifted; cannot apply mutant {mutant.id}")
    return source[:start] + mutant.mutated + source[end:]


def _byte_to_char(source: str, offsets: list[int], line_no: int, byte_col: int) -> int:
    line_text = source[offsets[line_no - 1] : offsets[line_no]]
    return len(line_text.encode("utf-8")[:byte_col].decode("utf-8", errors="replace"))


# --------------------------------------------------------------------------
# test selection
# --------------------------------------------------------------------------

_IMPORT_PATTERNS = (
    re.compile(r"^\s*from\s+leitir(?:\.[\w.]+)?\s+import\s+([\w\s,()]+)", re.MULTILINE),
    re.compile(r"^\s*import\s+leitir(?:\.[\w.]+)?", re.MULTILINE),
)


@dataclass
class TestSelector:
    """Map a mutant to the tests most likely to notice it.

    Precise mode uses coverage *contexts* (line -> test ids) produced by the
    coverage probe.  Fallback mode uses static import references in test
    files, which is coarser but never empty for a module that any test imports.
    """

    repo_root: Path
    contexts: dict[str, dict[int, tuple[str, ...]]] = field(default_factory=dict)
    static_map: dict[str, tuple[str, ...]] = field(default_factory=dict)
    max_tests: int = 60

    @classmethod
    def build(cls, repo_root: Path, contexts_path: Path | None) -> TestSelector:
        selector = cls(repo_root=repo_root)
        if contexts_path is not None and contexts_path.exists():
            selector.contexts = load_coverage_contexts(contexts_path)
        selector.static_map = build_static_map(repo_root)
        return selector

    @property
    def precise(self) -> bool:
        return bool(self.contexts)

    def select(self, mutant: Mutant) -> tuple[tuple[str, ...], str]:
        """Return ``(test_node_ids, mode)`` where mode is ``contexts``, ``static``, or ``none``."""
        if self.contexts:
            lines = self.contexts.get(mutant.path, {})
            tests: set[str] = set()
            for line in range(mutant.lineno, mutant.end_lineno + 1):
                tests.update(lines.get(line, ()))
            if tests:
                return (_cap(sorted(tests), self.max_tests), "contexts")
            return ((), "none")
        files = self.static_map.get(mutant.module, ())
        return (files, "static" if files else "none")


def _cap(tests: list[str], limit: int) -> tuple[str, ...]:
    """Keep a deterministic, evenly spaced subset so one hot line does not select the whole suite."""
    if len(tests) <= limit:
        return tuple(tests)
    step = len(tests) / limit
    return tuple(tests[int(index * step)] for index in range(limit))


def load_coverage_contexts(path: Path) -> dict[str, dict[int, tuple[str, ...]]]:
    """Parse ``coverage json --show-contexts`` output into ``{file: {line: (test ids...)}}``."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, dict[int, tuple[str, ...]]] = {}
    for file_name, entry in raw.get("files", {}).items():
        contexts = entry.get("contexts")
        if not isinstance(contexts, dict):
            continue
        normalized = file_name.replace(os.sep, "/")
        normalized = normalized.removeprefix("./")
        per_line: dict[int, tuple[str, ...]] = {}
        for line_text, names in contexts.items():
            tests = sorted({name.split("|", 1)[0] for name in names if name and name.split("|", 1)[0]})
            if tests:
                per_line[int(line_text)] = tuple(tests)
        result[normalized] = per_line
    return result


def build_static_map(repo_root: Path) -> dict[str, tuple[str, ...]]:
    tests_dir = repo_root / "tests"
    mapping: dict[str, set[str]] = {}
    for test_file in sorted(tests_dir.glob("test_*.py")):
        text = test_file.read_text(encoding="utf-8", errors="replace")
        relative = test_file.relative_to(repo_root).as_posix()
        for module in _referenced_modules(text):
            mapping.setdefault(module, set()).add(relative)
    return {module: tuple(sorted(files)) for module, files in mapping.items()}


def _referenced_modules(text: str) -> Iterator[str]:
    for match in re.finditer(r"^\s*from\s+(leitir(?:\.[\w.]+)?)\s+import\s+(.+)$", text, re.MULTILINE):
        base, names = match.group(1), match.group(2)
        yield base
        if base == "leitir" or (base.count(".") == 1 and base != "leitir"):
            for name in re.split(r"[\s,()]+", names):
                if name and name.islower():
                    yield f"{base}.{name}"
    for match in re.finditer(r"^\s*import\s+(leitir(?:\.[\w.]+)?)", text, re.MULTILINE):
        yield match.group(1)
    for match in re.finditer(r"leitir\.((?:\w+\.)*\w+)", text):
        parts = match.group(1).split(".")
        for depth in range(1, len(parts) + 1):
            yield "leitir." + ".".join(parts[:depth])


# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------

KILLED = "killed"
SURVIVED = "survived"
TIMEOUT = "timeout"
ERROR = "error"
UNCOVERED = "uncovered"


@dataclass(frozen=True)
class MutantOutcome:
    mutant: Mutant
    outcome: str
    duration: float
    tests: tuple[str, ...]
    selection_mode: str
    exit_code: int | None = None
    tail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.mutant.to_dict(),
            "outcome": self.outcome,
            "duration": round(self.duration, 3),
            "tests": list(self.tests),
            "selection_mode": self.selection_mode,
            "exit_code": self.exit_code,
        }


def _clean_env(repo_root: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("LEITIR_ENABLE_")}
    env["PYTHONPATH"] = str(repo_root / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["LEITIR_CALIBRATION_MUTANT"] = "1"
    return env


def _purge_pyc(path: Path) -> None:
    cache = path.parent / "__pycache__"
    if cache.is_dir():
        for pyc in cache.glob(f"{path.stem}.*.pyc"):
            try:
                pyc.unlink()
            except OSError:
                pass


def run_pytest(repo_root: Path, tests: Sequence[str], *, timeout: float) -> tuple[int | None, float, str]:
    command = [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "--no-header", *tests]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            env=_clean_env(repo_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else ""
        return (None, time.monotonic() - started, output[-2000:])
    output = completed.stdout.decode("utf-8", errors="replace")
    return (completed.returncode, time.monotonic() - started, output[-2000:])


def run_mutant(
    repo_root: Path, mutant: Mutant, tests: Sequence[str], selection_mode: str, *, timeout: float
) -> MutantOutcome:
    path = repo_root / mutant.path
    original_bytes = path.read_bytes()
    source = original_bytes.decode("utf-8")
    mutated = apply_mutant(source, mutant)
    _purge_pyc(path)
    try:
        path.write_bytes(mutated.encode("utf-8"))
        exit_code, duration, tail = run_pytest(repo_root, tests, timeout=timeout)
    finally:
        path.write_bytes(original_bytes)
        _purge_pyc(path)
        if path.read_bytes() != original_bytes:  # pragma: no cover - defensive
            raise RuntimeError(f"failed to restore {path}")
    if exit_code is None:
        outcome = TIMEOUT
    elif exit_code == 0:
        outcome = SURVIVED
    elif exit_code in (1, 2):
        outcome = KILLED
    else:
        outcome = ERROR
    return MutantOutcome(mutant, outcome, duration, tuple(tests), selection_mode, exit_code, tail)


def target_files(repo_root: Path, modules: Iterable[str] | None = None) -> list[Path]:
    src = repo_root / "src" / "leitir"
    files = sorted(
        path
        for path in src.rglob("*.py")
        if "__pycache__" not in path.parts and path.name != "__init__.py"
    )
    if modules:
        wanted = set(modules)
        files = [path for path in files if _module_name(repo_root, path) in wanted or _module_name(repo_root, path).split(".")[1] in wanted]
    return files


def severity_for(mutant: Mutant) -> str:
    integrity = mutant.module in INTEGRITY_MODULES or mutant.module.rsplit(".", 1)[0] in INTEGRITY_MODULES
    if mutant.operator == "raise-drop":
        return "high" if integrity else "medium"
    if integrity:
        return "medium"
    return "low"
