"""Deterministic, non-executing relocation of a complete BTS and its tests.

The objects in this module are the E1 boundary from ADR-0009.  Relocation is
deliberately an in-memory operation; :meth:`Relocation.publish` is the optional
atomic filesystem projection of the already-authorized bytes.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from itertools import pairwise
from pathlib import Path, PurePosixPath, PureWindowsPath

from leitir.bts import BTS, BTSResult, BTSStatus, MemberEvidence, _digest
from leitir.bts_errors import BTSError, BTSRejectReason

RELOCATION_SCHEMA_VERSION = "leitir-bts-relocation-v1"
RELOCATION_LAYOUT = "staging-v1"
REWRITE_ALGORITHM = "leitir-ast-import-rewrite-v1"
SCAFFOLD_ALGORITHM = "leitir-empty-project-scaffold-v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MODULE_PART = re.compile(r"[A-Za-z_]\w*\Z", re.ASCII)

# Checked-in policy data, not host import discovery.  Prefix reservations cover
# bootstrap/test/scaffold namespaces; roots cover Python 3.11's stdlib surface.
_STDLIB_ROOTS = frozenset(
    """__future__ _abc _ast _asyncio _bisect _blake2 _bz2 _codecs _collections
    _contextvars _csv _datetime _decimal _functools _hashlib _heapq _imp _io
    _json _locale _lzma _md5 _operator _pickle _posixsubprocess _random _sha1
    _sha256 _sha3 _sha512 _signal _socket _sqlite3 _ssl _stat _string _struct
    _thread _tokenize _tracemalloc _typing _uuid _warnings _weakref _zoneinfo
    abc aifc argparse array ast asynchat asyncio asyncore base64 bdb binascii
    bisect builtins bz2 calendar cgi cgitb chunk cmath cmd code codecs codeop
    collections colorsys compileall concurrent configparser contextlib
    contextvars copy copyreg cProfile crypt csv ctypes curses dataclasses
    datetime dbm decimal difflib dis doctest email encodings ensurepip enum
    errno faulthandler fcntl filecmp fileinput fnmatch fractions ftplib functools
    gc genericpath getopt getpass gettext glob graphlib grp gzip hashlib heapq
    hmac html http idlelib imaplib imghdr imp importlib inspect io ipaddress
    itertools json keyword lib2to3 linecache locale logging lzma mailbox mailcap
    marshal math mimetypes mmap modulefinder multiprocessing netrc nis nntplib
    ntpath nturl2path numbers opcode operator optparse os pathlib pdb pickle
    pickletools pipes pkgutil platform plistlib poplib posix posixpath pprint
    profile pstats pty pwd py_compile pyclbr pydoc queue quopri random re
    readline reprlib resource rlcompleter runpy sched secrets select selectors
    shelve shlex shutil signal site smtpd smtplib sndhdr socket socketserver
    sqlite3 sre_compile sre_constants sre_parse ssl stat statistics string
    stringprep struct subprocess sunau symtable sys sysconfig tabnanny tarfile
    telnetlib tempfile termios textwrap threading time timeit tkinter token
    tokenize tomllib trace traceback tracemalloc tty turtle turtledemo types
    typing unicodedata unittest urllib uu uuid venv warnings wave weakref
    webbrowser wsgiref xdrlib xml xmlrpc zipapp zipfile zipimport zlib zoneinfo""".split()
)
_RESERVED_PREFIXES = ("_pytest", "importlib", "leitir", "pytest", "test", "tests", "harness", "probes")
_PRELOADED = frozenset({"builtins", "sys", "_frozen_importlib", "_frozen_importlib_external", "importlib._bootstrap", "importlib._bootstrap_external"})
_BUILTIN_NAMES = frozenset(vars(builtins))


def _reject(reason: BTSRejectReason, message: str, detail: str) -> BTSError:
    return BTSError(reason, message, detail_code=detail)


def _module(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or any(_MODULE_PART.fullmatch(part) is None for part in value.split(".")):
        raise ValueError(f"{field} must be a dotted Python module name")
    return value


def _path(value: object, field: str = "path") -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or PureWindowsPath(value).drive
        or "\\" in value
        or "\x00" in value
        or ".." in candidate.parts
        or candidate.as_posix() != value
        or value == "."
        or unicodedata.normalize("NFC", value) != value
    ):
        raise ValueError(f"{field} must be a normalized relative POSIX path")
    return value


def _sha(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


@dataclass(frozen=True, slots=True, order=True)
class ModuleMapping:
    donor: str
    recipient: str

    def __post_init__(self) -> None:
        _module(self.donor, "donor")
        _module(self.recipient, "recipient")


@dataclass(frozen=True, slots=True)
class ReservedModuleManifest:
    """Pinned names unavailable to relocated production modules (V5)."""

    modules: tuple[str, ...] = tuple(sorted(_STDLIB_ROOTS))
    prefixes: tuple[str, ...] = _RESERVED_PREFIXES
    preloaded: tuple[str, ...] = tuple(sorted(_PRELOADED))

    def __post_init__(self) -> None:
        for values, name in ((self.modules, "modules"), (self.prefixes, "prefixes"), (self.preloaded, "preloaded")):
            if not isinstance(values, tuple):
                raise ValueError(f"reserved {name} must be a tuple")
            checked = tuple(sorted(_module(item, name) for item in values))
            if len(set(checked)) != len(checked):
                raise ValueError(f"duplicate reserved {name}")
            object.__setattr__(self, name, checked)

    @property
    def digest(self) -> str:
        return _sha(_canonical({"modules": self.modules, "prefixes": self.prefixes, "preloaded": self.preloaded}))

    def reserves(self, module: str) -> bool:
        return (
            module in self.preloaded
            or module.split(".", 1)[0] in self.modules
            or any(module == prefix or module.startswith(prefix + ".") for prefix in self.prefixes)
        )


DEFAULT_RESERVED_MODULES = ReservedModuleManifest()


@dataclass(frozen=True, slots=True)
class ModuleMap:
    """A deterministic, one-to-one donor-to-recipient module mapping."""

    entries: tuple[ModuleMapping, ...]
    reserved: ReservedModuleManifest = DEFAULT_RESERVED_MODULES

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple) or not all(isinstance(item, ModuleMapping) for item in self.entries):
            raise ValueError("entries must be a tuple of ModuleMapping values")
        if not isinstance(self.reserved, ReservedModuleManifest):
            raise ValueError("reserved must be a ReservedModuleManifest")
        ordered = tuple(sorted(self.entries))
        if not ordered:
            raise ValueError("ModuleMap must not be empty")
        donors = {item.donor for item in ordered}
        recipients = {item.recipient for item in ordered}
        if len(donors) != len(ordered) or len(recipients) != len(ordered):
            raise _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "ModuleMap is not one-to-one", "relocate_module_map_duplicate_v1")
        for entry in ordered:
            if self.reserved.reserves(entry.recipient):
                raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "recipient module is reserved", "relocate_reserved_module_collision_v1")
        # Nested donor mappings must preserve the same package relationship.
        for parent in ordered:
            for child in ordered:
                suffix = child.donor.removeprefix(parent.donor + ".")
                if suffix != child.donor and child.recipient != f"{parent.recipient}.{suffix}":
                    raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "ambiguous nested ModuleMap", "relocate_ambiguous_module_map_v1")
        object.__setattr__(self, "entries", ordered)

    @classmethod
    def from_pairs(cls, *pairs: tuple[str, str], reserved: ReservedModuleManifest = DEFAULT_RESERVED_MODULES) -> ModuleMap:
        return cls(tuple(ModuleMapping(*pair) for pair in pairs), reserved)

    @property
    def digest(self) -> str:
        return _sha(_canonical({"entries": [(item.donor, item.recipient) for item in self.entries], "reserved": self.reserved.digest}))

    def exact(self, donor: str) -> str | None:
        return next((item.recipient for item in self.entries if item.donor == donor), None)

    def rewrite(self, module: str) -> str | None:
        matches = [item for item in self.entries if module == item.donor or module.startswith(item.donor + ".")]
        if not matches:
            return None
        longest = max(matches, key=lambda item: (len(item.donor), item.donor))
        return longest.recipient + module[len(longest.donor):]

    @property
    def donor_roots(self) -> frozenset[str]:
        return frozenset(item.donor.split(".", 1)[0] for item in self.entries)


class BindingScope(str, Enum):  # noqa: UP042 - canonical contract pins str, Enum
    MODULE = "module"
    BINDING = "binding"


@dataclass(frozen=True, slots=True, order=True)
class RecipientBinding:
    module: str
    name: str
    scope: BindingScope = BindingScope.BINDING

    def __post_init__(self) -> None:
        _module(self.module, "module")
        if _MODULE_PART.fullmatch(self.name) is None:
            raise ValueError("binding name must be a Python identifier")
        if not isinstance(self.scope, BindingScope):
            raise ValueError("scope must be BindingScope")


@dataclass(frozen=True, slots=True)
class RecipientBindingManifest:
    bindings: tuple[RecipientBinding, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.bindings, tuple) or not all(isinstance(item, RecipientBinding) for item in self.bindings):
            raise ValueError("bindings must be a tuple of RecipientBinding values")
        ordered = tuple(sorted(self.bindings))
        if len(set(ordered)) != len(ordered):
            raise ValueError("duplicate recipient binding")
        object.__setattr__(self, "bindings", ordered)

    @property
    def digest(self) -> str:
        return _sha(_canonical([(item.module, item.name, item.scope.value) for item in self.bindings]))


EMPTY_RECIPIENT_BINDINGS = RecipientBindingManifest()


@dataclass(frozen=True, slots=True, order=True)
class SourceFile:
    path: str
    content: bytes

    def __post_init__(self) -> None:
        _path(self.path)
        if not isinstance(self.content, bytes):
            raise ValueError("source content must be bytes")


@dataclass(frozen=True, slots=True, order=True)
class ContractTest:
    path: str
    content: bytes
    module: str

    def __post_init__(self) -> None:
        _path(self.path)
        if not self.path.endswith(".py") or not isinstance(self.content, bytes):
            raise ValueError("contract test must be a Python file with byte content")
        _module(self.module, "module")


class FileRole(str, Enum):  # noqa: UP042 - canonical contract pins str, Enum
    MANIFEST = "manifest"
    SOURCE = "source"
    TEST_ORIGINAL = "test_original"
    TEST_REWRITTEN = "test_rewritten"
    PROBE = "probe"
    HARNESS = "harness"


@dataclass(frozen=True, slots=True, order=True)
class RelocatedFile:
    path: str
    role: FileRole
    content: bytes
    mode: int = 0o444

    def __post_init__(self) -> None:
        _path(self.path)
        if not isinstance(self.role, FileRole) or not isinstance(self.content, bytes):
            raise ValueError("invalid relocated file")
        if self.mode != 0o444:
            raise ValueError("authorizing relocation bytes must be read-only")

    @property
    def sha256(self) -> str:
        return _sha(self.content)


@dataclass(frozen=True, slots=True, order=True)
class MountAuthorization:
    logical_path: str
    read_only: bool
    donor_present: bool


@dataclass(frozen=True, slots=True)
class Relocation:
    schema_version: str
    bts_digest: str
    module_map: ModuleMap
    files: tuple[RelocatedFile, ...]
    baseline_mounts: tuple[MountAuthorization, ...]
    rerun_mounts: tuple[MountAuthorization, ...]
    relocation_digest: str

    def to_bytes(self) -> bytes:
        """Render the complete tree deterministically, including file bytes."""
        return _canonical(
            {
                "baseline_mounts": [(item.logical_path, item.read_only, item.donor_present) for item in self.baseline_mounts],
                "bts_digest": self.bts_digest,
                "files": [
                    {"content_hex": item.content.hex(), "mode": item.mode, "path": item.path, "role": item.role.value, "sha256": item.sha256}
                    for item in self.files
                ],
                "module_map_digest": self.module_map.digest,
                "relocation_digest": self.relocation_digest,
                "rerun_mounts": [(item.logical_path, item.read_only, item.donor_present) for item in self.rerun_mounts],
                "schema_version": self.schema_version,
            }
        )

    def publish(self, target: Path) -> None:
        """Atomically project this relocation into an absent or empty recipient."""
        if not isinstance(target, Path):
            raise TypeError("target must be pathlib.Path")
        target = target.absolute()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "recipient is not empty", "relocate_recipient_not_empty_v1")
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.relocate-", dir=target.parent))
        try:
            for item in self.files:
                output = staging.joinpath(*item.path.split("/"))
                output.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(item.content)
                    handle.flush()
                    os.fsync(handle.fileno())
                output.chmod(item.mode)
            for directory, directories, _ in os.walk(staging, topdown=False):
                for name in directories:
                    os.chmod(Path(directory, name), stat.S_IRUSR | stat.S_IXUSR)
            if target.exists():
                target.rmdir()
            os.replace(staging, target)
            if os.name == "posix":
                directory_fd = os.open(target.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise


def _offsets(data: bytes) -> list[int]:
    result = [0]
    for line in data.splitlines(keepends=True):
        result.append(result[-1] + len(line))
    return result


def _span(data: bytes, member: MemberEvidence) -> bytes:
    source = member.source
    starts = _offsets(data)
    if source.start_line >= len(starts) or source.end_line >= len(starts):
        raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "member span lies outside source bytes", "relocate_member_span_v1")
    start = starts[source.start_line - 1] + source.start_col
    end = starts[source.end_line - 1] + source.end_col
    if start > end or end > len(data):
        raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "member byte coordinates are invalid", "relocate_member_span_v1")
    return data[start:end]


def _member_range(data: bytes, member: MemberEvidence) -> tuple[int, int]:
    starts = _offsets(data)
    source = member.source
    if source.start_line >= len(starts) or source.end_line >= len(starts):
        raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "member span lies outside source bytes", "relocate_member_span_v1")
    return starts[source.start_line - 1] + source.start_col, starts[source.end_line - 1] + source.end_col


def _reject_required_expansion() -> BTSError:
    return _reject(
        BTSRejectReason.REJECT_UNDER_COLLECTION,
        "emission requires a wider authorized source span",
        "relocate_required_span_expansion_v1",
    )


def _check_enclosing_spans(data: bytes, members: tuple[MemberEvidence, ...]) -> None:
    """Reject omitted decorators/future flags rather than silently widening."""
    try:
        tree = ast.parse(data.decode("utf-8", errors="strict"), type_comments=True, feature_version=(3, 11))
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise _reject_required_expansion() from exc
    starts = _offsets(data)
    authorized = tuple(_member_range(data, member) for member in members)
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            start, end = _node_range(node, starts)
            if not any(left <= start and end <= right for left, right in authorized):
                raise _reject_required_expansion()
    definitions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    for member in members:
        source = member.source
        matching = [
            node
            for node in definitions
            if node.lineno == source.start_line and node.col_offset == source.start_col
        ]
        if matching and matching[0].decorator_list:
            decorator_start = min(_node_range(decorator, starts)[0] for decorator in matching[0].decorator_list)
            member_start, _ = _member_range(data, member)
            if decorator_start < member_start:
                raise _reject_required_expansion()


def _node_range(node: ast.AST, starts: list[int]) -> tuple[int, int]:
    line = getattr(node, "lineno", None)
    col = getattr(node, "col_offset", None)
    end_line = getattr(node, "end_lineno", None)
    end_col = getattr(node, "end_col_offset", None)
    if not all(isinstance(value, int) for value in (line, col, end_line, end_col)):
        raise ValueError("AST node has no complete source range")
    assert isinstance(line, int) and isinstance(col, int) and isinstance(end_line, int) and isinstance(end_col, int)
    return starts[line - 1] + col, starts[end_line - 1] + end_col


def _absolute_relative(module_context: str, level: int, imported: str | None) -> str:
    package = module_context.rpartition(".")[0]
    parts = package.split(".") if package else []
    if level > len(parts):
        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "relative import crosses package root", "relocate_relative_import_boundary_v1")
    base = parts[: len(parts) - level + 1]
    if imported:
        base.extend(imported.split("."))
    if not base:
        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "relative import has no absolute module", "relocate_relative_import_boundary_v1")
    return ".".join(base)


def _import_binding(alias: ast.alias, *, from_import: bool, rewritten_name: str) -> str:
    if alias.asname:
        return alias.asname
    if from_import:
        return alias.name
    return rewritten_name.split(".", 1)[0]


def _allowed_unchanged_import(module: str, module_map: ModuleMap, external: frozenset[str]) -> bool:
    root = module.split(".", 1)[0]
    return (
        root in _STDLIB_ROOTS
        or any(module == name or module.startswith(name + ".") for name in external)
        or any(module == item.recipient or module.startswith(item.recipient + ".") for item in module_map.entries)
    )


def _bound_names(node: ast.AST) -> tuple[str, ...]:
    """Return the names a top-level statement publishes, in source order."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return (node.name,)
    if isinstance(node, ast.Import):
        return tuple(_import_binding(alias, from_import=False, rewritten_name=alias.name) for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        return tuple(_import_binding(alias, from_import=True, rewritten_name=alias.name) for alias in node.names if alias.name != "*")

    names: list[str] = []

    def collect(target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                collect(item)

    if isinstance(node, ast.Assign):
        for target in node.targets:
            collect(target)
    elif isinstance(node, ast.AnnAssign):
        collect(node.target)
    elif isinstance(node, ast.AugAssign):
        collect(node.target)
    return tuple(names)


def _scope_locals(node: ast.AST) -> frozenset[str]:
    """Collect lexical locals without descending into child lexical scopes."""
    names: set[str] = set()
    globals_: set[str] = set()

    class Collector(ast.NodeVisitor):
        def visit_Global(self, value: ast.Global) -> None:
            globals_.update(value.names)

        def visit_FunctionDef(self, value: ast.FunctionDef) -> None:
            if value is not node:
                names.add(value.name)
                return
            self.generic_visit(value)

        def visit_AsyncFunctionDef(self, value: ast.AsyncFunctionDef) -> None:
            if value is not node:
                names.add(value.name)
                return
            self.generic_visit(value)

        def visit_ClassDef(self, value: ast.ClassDef) -> None:
            if value is not node:
                names.add(value.name)
                return
            self.generic_visit(value)

        def visit_Lambda(self, value: ast.Lambda) -> None:
            if value is not node:
                return
            self.generic_visit(value)

        def visit_Name(self, value: ast.Name) -> None:
            if isinstance(value.ctx, (ast.Store, ast.Del)):
                names.add(value.id)

        def visit_arg(self, value: ast.arg) -> None:
            names.add(value.arg)

        def visit_Import(self, value: ast.Import) -> None:
            names.update(_import_binding(alias, from_import=False, rewritten_name=alias.name) for alias in value.names)

        def visit_ImportFrom(self, value: ast.ImportFrom) -> None:
            names.update(_import_binding(alias, from_import=True, rewritten_name=alias.name) for alias in value.names if alias.name != "*")

    Collector().visit(node)
    return frozenset(names - globals_)


def _free_names(tree: ast.AST) -> frozenset[str]:
    """Find names that will be resolved from a relocated module's globals."""
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    scopes = {
        node: _scope_locals(node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef))
    }
    globals_by_scope = {
        node: frozenset(name for statement in ast.walk(node) if isinstance(statement, ast.Global) for name in statement.names)
        for node in scopes
    }
    free: set[str] = set()
    for name in ast.walk(tree):
        if not isinstance(name, ast.Name) or not isinstance(name.ctx, ast.Load):
            continue
        current = parents.get(name)
        resolved = False
        inside_function = False
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                inside_function = True
                if name.id in globals_by_scope[current]:
                    break
                if name.id in scopes[current]:
                    resolved = True
                    break
            elif isinstance(current, ast.ClassDef):
                # Class suites resolve their own assignments; methods do not.
                if not inside_function and name.id in scopes[current]:
                    resolved = True
                    break
            current = parents.get(current)
        if not resolved:
            free.add(name.id)
    return frozenset(free)


def _test_facing_names(tests: tuple[ContractTest, ...], module: str, aliases: Mapping[str, str]) -> frozenset[str]:
    """Return explicit attributes/imports that contract tests require from a module."""
    requested: set[str] = set()
    imported: dict[str, tuple[str, tuple[str, ...]]] = {}
    for test in tests:
        try:
            tree = ast.parse(test.content.decode("utf-8", "strict"), feature_version=(3, 11))
        except (UnicodeError, SyntaxError, ValueError) as exc:
            raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "contract test cannot be analyzed for relocation closure", "relocate_test_closure_parse_v1") from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported_module = aliases.get(node.module, node.module)
                if imported_module == module:
                    requested.update(alias.name for alias in node.names if alias.name != "*")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imported_module = aliases.get(alias.name, alias.name)
                    bound = alias.asname or alias.name.split(".", 1)[0]
                    suffix = () if alias.asname else tuple(alias.name.split(".")[1:])
                    imported[bound] = (imported_module, suffix)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            attributes: list[str] = []
            current: ast.AST = node
            while isinstance(current, ast.Attribute):
                attributes.append(current.attr)
                current = current.value
            if not isinstance(current, ast.Name) or current.id not in imported:
                continue
            imported_module, suffix = imported[current.id]
            parts = tuple(reversed(attributes))
            if imported_module == module and parts[: len(suffix)] == suffix and len(parts) > len(suffix):
                requested.add(parts[len(suffix)])
    return frozenset(requested)


def _authorize_preamble_imports(data: bytes, module_context: str, module_map: ModuleMap, external: frozenset[str]) -> None:
    """Preamble imports need explicit policy authority; stdlib is not implicit."""
    try:
        tree = ast.parse(data.decode("utf-8", "strict"), feature_version=(3, 11))
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "preamble source cannot be parsed", "relocate_preamble_parse_v1") from exc
    for node in tree.body:
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        modules = (
            tuple(alias.name for alias in node.names)
            if isinstance(node, ast.Import)
            else (_absolute_relative(module_context, node.level, node.module) if node.level else (node.module or ""),)
        )
        for imported in modules:
            rewritten = module_map.rewrite(imported)
            donor_rooted = imported.split(".", 1)[0] in module_map.donor_roots
            authorized = any(imported == item or imported.startswith(item + ".") for item in external)
            if rewritten is None and (donor_rooted or not authorized):
                raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "preamble import is not policy-authorized", "relocate_preamble_unauthorized_import_v1")


def build_preamble_closure(
    source_data: bytes,
    module: str,
    members: tuple[MemberEvidence, ...],
    tests: tuple[ContractTest, ...],
    module_map: ModuleMap,
    external: frozenset[str],
    test_import_aliases: Mapping[str, str],
) -> tuple[bytes, ...]:
    """Build a deterministic, fail-closed top-level dependency preamble.

    Only AST top-level bindings from the member's own authorized donor file can
    be added.  Imports are retained only when their relocation mapping or the
    exact policy's external set authorizes them.
    """
    try:
        tree = ast.parse(source_data.decode("utf-8", "strict"), feature_version=(3, 11))
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "source cannot be analyzed for relocation closure", "relocate_preamble_parse_v1") from exc
    starts = _offsets(source_data)
    ranges = tuple(_member_range(source_data, member) for member in members)
    nodes = tuple(tree.body)
    node_ranges = tuple(_node_range(node, starts) for node in nodes)
    selected = {
        index
        for index, (start, end) in enumerate(node_ranges)
        if any(left <= start and end <= right for left, right in ranges)
    }
    emitted = b"\n\n".join(_span(source_data, member) for member in members)
    try:
        emitted_tree = ast.parse(emitted.decode("utf-8", "strict"), feature_version=(3, 11))
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "member requires an enclosing source span", "relocate_required_span_expansion_v1") from exc
    bindings: dict[str, int] = {}
    for index, node in enumerate(nodes):
        for name in _bound_names(node):
            bindings[name] = index
    needed = set(_free_names(emitted_tree)) | set(_test_facing_names(tests, module, test_import_aliases))
    while True:
        emitted_names = {name for index in selected for name in _bound_names(nodes[index])}
        unresolved = sorted(name for name in needed - emitted_names if name not in _BUILTIN_NAMES)
        additions: list[int] = []
        for name in unresolved:
            closure_index = bindings.get(name)
            if closure_index is None:
                raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "preamble has an unresolvable free name", "relocate_preamble_unresolved_name_v1")
            additions.append(closure_index)
        additions = sorted(set(additions) - selected)
        if not additions:
            break
        selected.update(additions)
        closure_tree = ast.Module(body=[nodes[index] for index in sorted(selected)], type_ignores=[])
        needed.update(_free_names(closure_tree))
    preamble: list[bytes] = []
    for index in sorted(selected):
        if any(left <= node_ranges[index][0] and node_ranges[index][1] <= right for left, right in ranges):
            continue
        start, end = node_ranges[index]
        data = source_data[start:end]
        _authorize_preamble_imports(data, module, module_map, external)
        preamble.append(_rewrite_python(data, module, module_map, external, "preamble"))
    return tuple(preamble)


def _rewrite_python(data: bytes, module_context: str, module_map: ModuleMap, external: frozenset[str], role: str, import_aliases: Mapping[str, str] | None = None) -> bytes:
    try:
        text = data.decode("utf-8", errors="strict")
        tree = ast.parse(text, type_comments=True, feature_version=(3, 11))
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "emission requires a wider authorized source span", "relocate_required_span_expansion_v1") from exc
    parents: dict[ast.AST, ast.AST] = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    starts = _offsets(data)
    replacements: list[tuple[int, int, bytes]] = []
    reference_rewrites: dict[str, str] = {}
    bindings: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            dynamic = isinstance(node.func, ast.Name) and node.func.id == "__import__"
            dynamic = dynamic or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
            )
            if dynamic:
                raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "dynamic imports cannot be proved or rewritten", "relocate_dynamic_import_v1")
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if parents.get(node) is not tree:
            raise _reject(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "conditional, fallback, or local import is unsupported", "relocate_conditional_import_v1")
        if isinstance(node, ast.Import):
            for alias in node.names:
                mapped = ({} if import_aliases is None else import_aliases).get(alias.name, alias.name)
                rewritten = module_map.rewrite(mapped)
                donor_rooted = mapped.split(".", 1)[0] in module_map.donor_roots
                if rewritten is None:
                    if donor_rooted:
                        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "donor import has no unambiguous mapping", "relocate_unresolved_import_v1")
                    if not _allowed_unchanged_import(mapped, module_map, external):
                        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "import is neither stdlib nor declared external", "relocate_undeclared_external_import_v1")
                    rewritten = mapped
                else:
                    alias_start, _ = _node_range(alias, starts)
                    replacements.append((alias_start, alias_start + len(alias.name.encode()), rewritten.encode()))
                    if alias.asname is None:
                        reference_rewrites[alias.name] = rewritten
                binding = _import_binding(alias, from_import=False, rewritten_name=rewritten)
                if binding in bindings:
                    raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "import bindings collide in recipient scope", "relocate_binding_collision_v1")
                bindings.add(binding)
        else:
            if any(alias.name == "*" for alias in node.names):
                raise _reject(BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT, "star imports cannot be rewritten", "relocate_star_import_v1")
            absolute = _absolute_relative(module_context, node.level, node.module) if node.level else (node.module or "")
            mapped = ({} if import_aliases is None else import_aliases).get(absolute, absolute)
            rewritten = module_map.rewrite(mapped)
            donor_rooted = mapped.split(".", 1)[0] in module_map.donor_roots
            if rewritten is None and donor_rooted and not _allowed_unchanged_import(mapped, module_map, external):
                raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "donor import has no unambiguous mapping", "relocate_unresolved_import_v1")
            if rewritten is None and not _allowed_unchanged_import(mapped, module_map, external):
                raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "import is neither stdlib nor declared external", "relocate_undeclared_external_import_v1")
            if rewritten is not None:
                start, end = _node_range(node, starts)
                header = data[start:end]
                keyword = re.search(rb"\bimport\b", header)
                if keyword is None:
                    raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "cannot locate import header", "relocate_import_span_v1")
                import_at = keyword.start()
                from_at = header.find(b"from")
                module_start = from_at + len(b"from")
                while module_start < import_at and header[module_start:module_start + 1] in b" \t":
                    module_start += 1
                module_end = import_at
                while module_end > module_start and header[module_end - 1:module_end] in b" \t":
                    module_end -= 1
                replacements.append((start + module_start, start + module_end, rewritten.encode()))
            for alias in node.names:
                binding = _import_binding(alias, from_import=True, rewritten_name=rewritten or absolute)
                if binding in bindings:
                    raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "import bindings collide in recipient scope", "relocate_binding_collision_v1")
                bindings.add(binding)

    # For unaliased ``import a.b``, Python references use the imported path.
    # Rewrite the longest Attribute/Name expressions, excluding import syntax.
    import_nodes = tuple(node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)))
    occupied = [(start, end) for node in import_nodes for start, end in [_node_range(node, starts)]]
    candidates: list[tuple[int, int, bytes]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        start, end = _node_range(node, starts)
        if any(left <= start and end <= right for left, right in occupied):
            continue
        expression = ast.get_source_segment(text, node)
        if expression is None:
            continue
        for donor, recipient in sorted(reference_rewrites.items(), key=lambda item: (-len(item[0]), item[0])):
            if expression == donor or expression.startswith(donor + "."):
                candidates.append((start, end, (recipient + expression[len(donor):]).encode()))
                break
    for candidate in sorted(candidates, key=lambda item: (item[0], -item[1])):
        if not any(left <= candidate[0] and candidate[1] <= right for left, right, _ in replacements):
            replacements.append(candidate)

    ordered = sorted(replacements, key=lambda item: (item[0], -item[1]))
    nonoverlap: list[tuple[int, int, bytes]] = []
    for item in ordered:
        if nonoverlap and item[0] < nonoverlap[-1][1]:
            continue
        nonoverlap.append(item)
    output = data
    for start, end, replacement in reversed(nonoverlap):
        output = output[:start] + replacement + output[end:]
    try:
        checked = ast.parse(output.decode("utf-8", errors="strict"), type_comments=True, feature_version=(3, 11))
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "rewritten source is not valid Python", "relocate_invalid_rewrite_v1") from exc
    for node in ast.walk(checked):
        if isinstance(node, ast.Import) and any(alias.name.split(".", 1)[0] in module_map.donor_roots for alias in node.names):
            raise _reject(BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED, f"{role} retains a donor import", "relocate_donor_import_remains_v1")
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".", 1)[0] in module_map.donor_roots:
            raise _reject(BTSRejectReason.REJECT_DONOR_IMPORT_OBSERVED, f"{role} retains a donor import", "relocate_donor_import_remains_v1")
    return output


def _module_path(module: str) -> str:
    return f"{RELOCATION_LAYOUT}/src/{module.replace('.', '/')}.py"


def _validate_bts(value: BTS | BTSResult) -> BTS:
    if isinstance(value, BTSResult):
        if value.status is not BTSStatus.COMPLETE or value.report.status is not BTSStatus.COMPLETE or value.bts is None:
            raise _reject(BTSRejectReason.REJECT_HARD_GATE_FAILED, "only a COMPLETE BTS may be relocated", "relocate_non_complete_bts_v1")
        bts = value.bts
        value.report.from_json(value.report.to_bytes())
        primary = _digest(
            (value.report, bts),
            omit=frozenset({"analysis_digest", "bts_digest", "member_equivalence_digest"}),
        )
    elif isinstance(value, BTS):
        bts = value
        primary = bts.bts_digest
    else:
        raise TypeError("relocate_tests requires a BTS or BTSResult")
    if bts.schema_version != "leitir-bts-v1" or _DIGEST.fullmatch(bts.bts_digest) is None or _DIGEST.fullmatch(bts.member_equivalence_digest) is None:
        raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "BTS identity is malformed", "relocate_bts_identity_v1")
    equivalence = _digest(bts, omit=frozenset({"bts_digest", "member_equivalence_digest"}))
    if bts.member_equivalence_digest != equivalence or bts.bts_digest != primary:
        raise _reject(
            BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
            "BTS identity does not match its canonical records",
            "relocate_bts_identity_v1",
        )
    if not bts.members:
        raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "BTS has no relocatable members", "relocate_empty_bts_v1")
    return bts


def _inventory(files: Iterable[RelocatedFile]) -> list[dict[str, object]]:
    return [
        {"mode": item.mode, "path": item.path, "role": item.role.value, "sha256": item.sha256, "size": len(item.content)}
        for item in sorted(files)
    ]


def relocate_tests(
    bts: BTS | BTSResult,
    /,
    *,
    module_map: ModuleMap,
    source_files: tuple[SourceFile, ...],
    tests: tuple[ContractTest, ...],
    sibling_sources: tuple[tuple[str, SourceFile], ...] = (),
    declared_external_modules: tuple[str, ...] = (),
    recipient_bindings: RecipientBindingManifest = EMPTY_RECIPIENT_BINDINGS,
    test_import_aliases: tuple[tuple[str, str], ...] = (),
) -> Relocation:
    """Produce the canonical empty-recipient tree; never import or execute it."""
    artifact = _validate_bts(bts)
    if not isinstance(module_map, ModuleMap) or not isinstance(recipient_bindings, RecipientBindingManifest):
        raise TypeError("invalid relocation policy input")
    if not isinstance(source_files, tuple) or not all(isinstance(item, SourceFile) for item in source_files):
        raise TypeError("source_files must be a tuple of SourceFile values")
    if not isinstance(tests, tuple) or not all(isinstance(item, ContractTest) for item in tests):
        raise TypeError("tests must be a tuple of ContractTest values")
    if not isinstance(sibling_sources, tuple) or not all(
        isinstance(module, str) and isinstance(source, SourceFile) for module, source in sibling_sources
    ):
        raise TypeError("sibling_sources must be module/SourceFile pairs")
    external = frozenset(_module(item, "declared external module") for item in declared_external_modules)
    if len(external) != len(declared_external_modules):
        raise ValueError("duplicate declared external module")
    if test_import_aliases != tuple(sorted(set(test_import_aliases))) or not all(
        isinstance(alias, str) and isinstance(module, str) for alias, module in test_import_aliases
    ):
        raise ValueError("test import aliases must be sorted unique text pairs")
    import_aliases = dict(test_import_aliases)
    donor_modules = sorted({member.node.module for member in artifact.members})
    missing = [module for module in donor_modules if module_map.exact(module) is None]
    if missing:
        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "ModuleMap is not total for BTS members", "relocate_module_map_not_total_v1")
    sibling_modules = tuple(module for module, _ in sibling_sources)
    if sibling_modules != tuple(sorted(set(sibling_modules))) or set(sibling_modules) & set(donor_modules):
        raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "sibling source authorization is not a disjoint sorted closure", "relocate_sibling_source_policy_v1")
    for module, source in sibling_sources:
        _module(module, "sibling source module")
        if module_map.exact(module) is None or source.path != module.replace(".", "/") + ".py":
            raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "sibling source has no exact safe module mapping", "relocate_sibling_source_policy_v1")

    by_path: dict[str, bytes] = {}
    folded: dict[str, str] = {}
    for item in sorted(source_files):
        alias = item.path.casefold()
        if item.path in by_path or (alias in folded and folded[alias] != item.path):
            raise _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "source path aliases another input", "relocate_source_path_collision_v1")
        by_path[item.path] = item.content
        folded[alias] = item.path

    members_by_path: dict[str, list[MemberEvidence]] = {}
    for member in artifact.members:
        members_by_path.setdefault(member.source.path, []).append(member)
    for source_path in sorted(members_by_path):
        source_data = by_path.get(source_path)
        if source_data is None:
            raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "BTS source bytes are missing", "relocate_source_missing_v1")
        _check_enclosing_spans(source_data, tuple(members_by_path[source_path]))

    chunks: dict[str, list[tuple[tuple[object, ...], bytes]]] = {}
    definitions: dict[str, set[str]] = {}
    members_by_module: dict[str, list[MemberEvidence]] = {}
    for member in artifact.members:
        source_data = by_path.get(member.source.path)
        if source_data is None:
            raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "BTS source bytes are missing", "relocate_source_missing_v1")
        chunk = _span(source_data, member)
        if _sha(chunk) != member.source_bytes_sha256:
            raise _reject(BTSRejectReason.REJECT_PROVENANCE_MISMATCH, "BTS member bytes do not match their digest", "relocate_member_digest_v1")
        target_module = module_map.exact(member.node.module)
        assert target_module is not None
        rewritten = _rewrite_python(chunk, member.node.module, module_map, external, "source")
        try:
            parsed = ast.parse(rewritten.decode("utf-8"), feature_version=(3, 11))
        except (UnicodeError, SyntaxError, ValueError) as exc:  # defensive; rewrite already parsed
            raise _reject(BTSRejectReason.REJECT_UNDER_COLLECTION, "member requires an enclosing source span", "relocate_required_span_expansion_v1") from exc
        for node in parsed.body:
            names: tuple[str, ...] = ()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names = (node.name,)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = tuple(target.id for target in targets if isinstance(target, ast.Name))
            for name in names:
                if name in definitions.setdefault(target_module, set()):
                    raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "top-level BTS definitions collide", "relocate_binding_collision_v1")
                definitions[target_module].add(name)
        key = (member.source.path, member.source.start_line, member.source.start_col, member.source.end_line, member.source.end_col, member.node.qualified_name)
        chunks.setdefault(target_module, []).append((key, rewritten))
        members_by_module.setdefault(member.node.module, []).append(member)
    for module in sorted(members_by_module):
        module_members = tuple(sorted(members_by_module[module], key=lambda item: (
            item.source.path,
            item.source.start_line,
            item.source.start_col,
            item.source.end_line,
            item.source.end_col,
            item.node.qualified_name,
        )))
        source_data = by_path[module_members[0].source.path]
        preamble = build_preamble_closure(
            source_data,
            module,
            module_members,
            tests,
            module_map,
            external,
            import_aliases,
        )
        if preamble:
            target_module = module_map.exact(module)
            assert target_module is not None
            chunks.setdefault(target_module, []).append(((module_members[0].source.path, -1, 0, 0, 0, "preamble"), b"\n\n".join(preamble)))
    for module, source in sibling_sources:
        target_module = module_map.exact(module)
        assert target_module is not None
        rewritten = _rewrite_python(source.content, module, module_map, external, "source")
        chunks.setdefault(target_module, []).append(((source.path, 0, 0, 0, 0, module), rewritten))

    occupied = {(item.module, item.name) for item in recipient_bindings.bindings}
    for module in donor_modules:
        target = module_map.exact(module)
        assert target is not None
        if any(binding_module == target for binding_module, _ in occupied):
            for name in definitions.get(target, set()):
                if (target, name) in occupied:
                    raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "BTS definition collides with recipient binding", "relocate_binding_collision_v1")
    for recipient_binding in recipient_bindings.bindings:
        if recipient_binding.scope is BindingScope.MODULE and any(
            recipient_binding.module == entry.recipient
            or recipient_binding.module.startswith(entry.recipient + ".")
            or entry.recipient.startswith(recipient_binding.module + ".")
            for entry in module_map.entries
        ):
            raise _reject(BTSRejectReason.REJECT_UNRESOLVED_EDGE, "recipient module path collides", "relocate_module_collision_v1")

    files: list[RelocatedFile] = [
        RelocatedFile(f"{RELOCATION_LAYOUT}/probes/.empty", FileRole.PROBE, b"")
    ]
    for module in sorted(chunks):
        content = b"\n\n".join(chunk for _, chunk in sorted(chunks[module]))
        if not content.endswith(b"\n"):
            content += b"\n"
        files.append(RelocatedFile(_module_path(module), FileRole.SOURCE, content))
        parts = module.split(".")[:-1]
        for length in range(1, len(parts) + 1):
            init_path = f"{RELOCATION_LAYOUT}/src/{'/'.join(parts[:length])}/__init__.py"
            if not any(item.path == init_path for item in files):
                files.append(RelocatedFile(init_path, FileRole.SOURCE, b""))

    seen_tests: set[str] = set()
    for test in sorted(tests):
        if test.path in seen_tests:
            raise _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "duplicate contract test path", "relocate_test_path_collision_v1")
        seen_tests.add(test.path)
        rewritten = _rewrite_python(test.content, test.module, module_map, external, "test", import_aliases)
        files.append(RelocatedFile(f"{RELOCATION_LAYOUT}/tests/original/{test.path}", FileRole.TEST_ORIGINAL, test.content))
        files.append(RelocatedFile(f"{RELOCATION_LAYOUT}/tests/rewritten/{test.path}", FileRole.TEST_REWRITTEN, rewritten))

    input_manifest = _canonical(
        {
            "bts_digest": artifact.bts_digest,
            "declared_external_modules": sorted(external),
            "sibling_sources": [{"module": module, "path": source.path, "sha256": _sha(source.content)} for module, source in sibling_sources],
            "layout": RELOCATION_LAYOUT,
            "member_equivalence_digest": artifact.member_equivalence_digest,
            "module_map_digest": module_map.digest,
            "test_import_aliases": list(test_import_aliases),
            "recipient_binding_manifest_digest": recipient_bindings.digest,
            "reserved_module_manifest_digest": module_map.reserved.digest,
            "schema_version": RELOCATION_SCHEMA_VERSION,
        }
    )
    source_manifest = _canonical({"files": _inventory(item for item in files if item.role is FileRole.SOURCE), "schema_version": RELOCATION_SCHEMA_VERSION})
    test_manifest = _canonical({"files": _inventory(item for item in files if item.role in {FileRole.TEST_ORIGINAL, FileRole.TEST_REWRITTEN}), "schema_version": RELOCATION_SCHEMA_VERSION})
    empty_manifest = _canonical({"files": [], "schema_version": RELOCATION_SCHEMA_VERSION})
    files.extend(
        [
            RelocatedFile(f"{RELOCATION_LAYOUT}/manifests/input.json", FileRole.MANIFEST, input_manifest),
            RelocatedFile(f"{RELOCATION_LAYOUT}/manifests/source.json", FileRole.MANIFEST, source_manifest),
            RelocatedFile(f"{RELOCATION_LAYOUT}/manifests/test.json", FileRole.MANIFEST, test_manifest),
            RelocatedFile(f"{RELOCATION_LAYOUT}/manifests/probe.json", FileRole.MANIFEST, empty_manifest),
            RelocatedFile(f"{RELOCATION_LAYOUT}/manifests/runner.json", FileRole.MANIFEST, empty_manifest),
        ]
    )
    relocation_manifest = _canonical(
        {
            "authorizing_bytes_read_only": True,
            "donor_baseline": "read_only",
            "donor_rerun": "absent",
            "files": _inventory(files),
            "rewrite_algorithm": REWRITE_ALGORITHM,
            "scaffold_algorithm": SCAFFOLD_ALGORITHM,
            "schema_version": RELOCATION_SCHEMA_VERSION,
        }
    )
    files.append(RelocatedFile(f"{RELOCATION_LAYOUT}/manifests/relocation.json", FileRole.MANIFEST, relocation_manifest))
    ordered_files = tuple(sorted(files))
    paths = [item.path for item in ordered_files]
    if len(paths) != len(set(paths)) or len({path.casefold() for path in paths}) != len(paths):
        raise _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "relocation output paths collide", "relocate_output_path_collision_v1")
    for left, right in pairwise(paths):
        if right.startswith(left + "/"):
            raise _reject(BTSRejectReason.REJECT_DUPLICATE_RESULT, "relocation has a file/directory prefix collision", "relocate_output_prefix_collision_v1")

    baseline = tuple(sorted((MountAuthorization("donor", True, True), MountAuthorization(f"{RELOCATION_LAYOUT}/tests/original", True, False))))
    rerun_prefixes = (
        f"{RELOCATION_LAYOUT}/harness/",
        f"{RELOCATION_LAYOUT}/manifests/",
        f"{RELOCATION_LAYOUT}/probes/",
        f"{RELOCATION_LAYOUT}/src/",
        f"{RELOCATION_LAYOUT}/tests/rewritten/",
    )
    # File-granular authorizations make the S2 mount digest bind one exact E1
    # file rather than ambiguously authorizing a directory tree.
    rerun = tuple(
        MountAuthorization(item.path, True, False)
        for item in ordered_files
        if item.path.startswith(rerun_prefixes)
    )
    tree_identity = _canonical(
        {
            "baseline_mounts": [(item.logical_path, item.read_only, item.donor_present) for item in baseline],
            "bts_digest": artifact.bts_digest,
            "files": _inventory(ordered_files),
            "module_map_digest": module_map.digest,
            "rerun_mounts": [(item.logical_path, item.read_only, item.donor_present) for item in rerun],
            "schema_version": RELOCATION_SCHEMA_VERSION,
        }
    )
    return Relocation(RELOCATION_SCHEMA_VERSION, artifact.bts_digest, module_map, ordered_files, baseline, rerun, _sha(tree_identity))


__all__ = [
    "DEFAULT_RESERVED_MODULES",
    "EMPTY_RECIPIENT_BINDINGS",
    "RELOCATION_LAYOUT",
    "RELOCATION_SCHEMA_VERSION",
    "BindingScope",
    "ContractTest",
    "FileRole",
    "ModuleMap",
    "ModuleMapping",
    "MountAuthorization",
    "RecipientBinding",
    "RecipientBindingManifest",
    "RelocatedFile",
    "Relocation",
    "ReservedModuleManifest",
    "SourceFile",
    "relocate_tests",
]
