"""Conservative, dependency-free project lockfile version detection."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath

from leitir.bts_errors import BTSError, BTSRejectReason


@dataclass(frozen=True, slots=True)
class DetectedVersion:
    """An exact installed version and the project file that supplied it."""

    version: str
    source: str


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    """One exact, actionable dependency discovered in a project file."""

    name: str
    version: str
    resolved_sha: str | None
    spec: str

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "resolved_sha": self.resolved_sha,
            "spec": self.spec,
        }


@dataclass(frozen=True, slots=True)
class DependencyClosure:
    """The dependency universe supplied by one ecosystem's project files."""

    ecosystem: str
    graph: str
    source: str
    deps: tuple[DependencyEdge, ...]


class ManifestDiagnosticKind(StrEnum):
    """Closed outcomes which cannot be hidden by manifest-backed parsing."""

    ABSENT = "absent"
    MALFORMED = "malformed"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class VerifiedManifestBytes:
    """Bytes and content identity already authorized by a recipient manifest."""

    path: str
    role: str
    byte_length: int
    sha256: str
    content: bytes


@dataclass(frozen=True, slots=True)
class DependencyManifestPolicy:
    """The exact supported dependency sources expected by a profile."""

    required_sources: tuple[str, ...]
    optional_sources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, order=True)
class ManifestDependencyDiagnostic:
    """A source or record that was not successfully parsed."""

    path: str
    kind: ManifestDiagnosticKind
    record: str
    detail_code: str


@dataclass(frozen=True, slots=True)
class ManifestDependencySource:
    """One manifest source's dependency result and parser provenance."""

    path: str
    source_digest: str
    ecosystem: str
    parser_id: str
    parser_version: str
    graph: str
    deps: tuple[DependencyEdge, ...]
    attempted_records: int
    parsed_records: int
    diagnostics: tuple[ManifestDependencyDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class ManifestDependencyResult:
    """Deterministically ordered results for all policy-declared sources."""

    sources: tuple[ManifestDependencySource, ...]
    diagnostics: tuple[ManifestDependencyDiagnostic, ...]


_NPM_VERSION = re.compile(
    r"^[0-9]+(?:\.[0-9]+){1,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_NPM_PACKAGE = re.compile(
    r"^(?:[A-Za-z0-9_.~-][A-Za-z0-9_.~-]*|@[A-Za-z0-9_.~-]+/[A-Za-z0-9_.~-]+)$"
)
_PYTHON_PIN = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*==\s*"
    r"([^\s;#]+)(?:\s*;[^#]*)?(?:\s+#.*)?\s*$"
)
_PYTHON_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")
_GO_VERSION = re.compile(
    r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_COMMIT_SHA = re.compile(r"(?i)(?:^|[#@])([0-9a-f]{40})(?:$|[^0-9a-f])")
_GO_PSEUDO_VERSION = re.compile(
    r"^v\d+\.\d+\.\d+.*(?:-|\.)\d{14}-([0-9a-f]{12})(?:\+incompatible)?$"
)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def _read_json(path: Path) -> object | None:
    text = _read_text(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return None


def _exact_npm(value: object) -> str | None:
    return value if isinstance(value, str) and _NPM_VERSION.fullmatch(value) else None


def _npm_node_modules(root: Path, name: str) -> str | None:
    payload = _read_json(root / "node_modules" / Path(name) / "package.json")
    return _exact_npm(payload.get("version")) if isinstance(payload, dict) else None


def _npm_package_lock(root: Path, name: str) -> str | None:
    payload = _read_json(root / "package-lock.json")
    if not isinstance(payload, dict):
        return None
    packages = payload.get("packages")
    if isinstance(packages, dict):
        package = packages.get(f"node_modules/{name}")
        if isinstance(package, dict):
            version = _exact_npm(package.get("version"))
            if version is not None:
                return version
    dependencies = payload.get("dependencies")
    if isinstance(dependencies, dict):
        package = dependencies.get(name)
        if isinstance(package, dict):
            return _exact_npm(package.get("version"))
    return None


def _split_npm_key(value: str) -> tuple[str, str] | None:
    value = value.removeprefix("/")
    separator = value.rfind("@")
    if separator <= 0:
        return None
    return value[:separator], value[separator + 1 :].split("(", 1)[0]


def _npm_pnpm(root: Path, name: str) -> str | None:
    text = _read_text(root / "pnpm-lock.yaml")
    if text is None:
        return None
    version_match = re.search(r"(?m)^lockfileVersion:\s*['\"]?([^'\"\s]+)", text)
    if version_match is None or version_match.group(1).split(".", 1)[0] not in {"6", "9"}:
        return None

    section_indent: int | None = None
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent == 0:
            section_indent = 0 if stripped in {"packages:", "snapshots:"} else None
            continue
        if section_indent is None or indent <= section_indent:
            continue
        # Package/snapshot keys are direct children. Nested dependency keys are
        # deliberately ignored rather than guessed at.
        if indent != section_indent + 2 or ":" not in stripped:
            continue
        key = stripped.split(":", 1)[0].strip().strip("'\"")
        parsed = _split_npm_key(key)
        if parsed is not None and parsed[0] == name:
            version = _exact_npm(parsed[1])
            if version is not None:
                return version
    return None


def _yarn_header_names(header: str) -> list[str]:
    body = header[:-1].strip().strip("'\"")
    names: list[str] = []
    for spec in body.split(", "):
        parsed = _split_npm_key(spec.strip().strip("'\""))
        if parsed is not None:
            names.append(parsed[0])
    return names


def _npm_yarn(root: Path, name: str) -> str | None:
    text = _read_text(root / "yarn.lock")
    if text is None:
        return None
    matched = False
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if line and not line[0].isspace() and not line.lstrip().startswith("#"):
            matched = line.endswith(":") and not line.startswith("__metadata:") and name in _yarn_header_names(line)
            continue
        if not matched:
            continue
        version_match = re.match(r"^\s+version(?:\s+|:\s*)([^\s#]+)", line)
        if version_match:
            version = _exact_npm(version_match.group(1).strip("'\"").split("(", 1)[0])
            if version is not None:
                return version
    return None


def _npm_package_json(root: Path, name: str) -> str | None:
    payload = _read_json(root / "package.json")
    if not isinstance(payload, dict):
        return None
    for field in ("dependencies", "devDependencies"):
        dependencies = payload.get(field)
        if isinstance(dependencies, dict):
            version = _exact_npm(dependencies.get(name))
            if version is not None:
                return version
    return None


def _normalize_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _python_pin(value: str, name: str) -> str | None:
    match = _PYTHON_PIN.fullmatch(value)
    if match is None or _normalize_python_name(match.group(1)) != _normalize_python_name(name):
        return None
    version = match.group(2)
    if not _PYTHON_VERSION.fullmatch(version):
        return None
    return version


def _pypi_requirements(root: Path, name: str) -> str | None:
    text = _read_text(root / "requirements.txt")
    if text is None:
        return None
    for line in text.splitlines():
        pin = _python_pin(line, name)
        if pin is not None:
            return pin
    return None


def _pypi_pyproject(root: Path, name: str) -> str | None:
    text = _read_text(root / "pyproject.toml")
    if text is None:
        return None
    try:
        payload = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, TypeError):
        return None
    project = payload.get("project")
    dependencies = project.get("dependencies") if isinstance(project, dict) else None
    if not isinstance(dependencies, list):
        return None
    for dependency in dependencies:
        if isinstance(dependency, str):
            pin = _python_pin(dependency, name)
            if pin is not None:
                return pin
    return None


def _cargo(root: Path, name: str) -> str | None:
    text = _read_text(root / "Cargo.lock")
    if text is None:
        return None
    try:
        payload = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, TypeError):
        return None
    packages = payload.get("package")
    if not isinstance(packages, list):
        return None
    for package in packages:
        if isinstance(package, dict) and package.get("name") == name:
            version = package.get("version")
            if isinstance(version, str) and version and not any(ch.isspace() for ch in version):
                return version
    return None


def _go(root: Path, name: str) -> str | None:
    text = _read_text(root / "go.mod")
    if text is None:
        return None
    return next((edge.version for edge in _go_requirements(text) if edge.name == name), None)


def _identity(package: dict[object, object]) -> str | None:
    for field in ("gitHead", "checksum", "integrity"):
        value = package.get(field)
        if isinstance(value, str) and value.strip():
            return value
    resolved = package.get("resolved")
    if isinstance(resolved, str):
        match = _COMMIT_SHA.search(resolved)
        if match is not None:
            return match.group(1).lower()
    source = package.get("source")
    if isinstance(source, str):
        match = _COMMIT_SHA.search(source)
        if match is not None:
            return match.group(1).lower()
    return None


def _edge(ecosystem: str, name: object, version: object, identity: str | None = None) -> DependencyEdge | None:
    if not isinstance(name, str) or not name or any(char.isspace() for char in name):
        return None
    if not isinstance(version, str) or not version or any(char.isspace() for char in version):
        return None
    return DependencyEdge(name, version, identity, f"{ecosystem}:{name}@{version}")


def _ordered(edges: list[DependencyEdge]) -> tuple[DependencyEdge, ...]:
    unique: dict[tuple[str, str, str], DependencyEdge] = {}
    for edge in edges:
        key = (edge.name, edge.version, edge.spec)
        existing = unique.get(key)
        if existing is None or (edge.resolved_sha or "") > (existing.resolved_sha or ""):
            unique[key] = edge
    return tuple(unique[key] for key in sorted(unique))


def _npm_name_from_path(path: str) -> str | None:
    marker = "node_modules/"
    if marker not in path:
        return None
    remainder = path.rsplit(marker, 1)[1]
    if remainder.startswith("@"):
        parts = remainder.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return remainder.split("/", 1)[0]


def _npm_dependency_tree(
    dependencies: object,
    edges: list[DependencyEdge],
    diagnostics: list[tuple[str, ManifestDiagnosticKind]] | None = None,
    record_prefix: str = "dependencies",
) -> tuple[int, int]:
    if not isinstance(dependencies, dict):
        if dependencies is not None and diagnostics is not None:
            diagnostics.append((record_prefix, ManifestDiagnosticKind.MALFORMED))
            return (1, 0)
        return (0, 0)
    attempted = 0
    parsed = 0
    for name, package in dependencies.items():
        attempted += 1
        record = f"{record_prefix}.{name}"
        if not isinstance(package, dict):
            if diagnostics is not None:
                diagnostics.append((record, ManifestDiagnosticKind.MALFORMED))
            continue
        edge = _edge("npm", name, package.get("version"), _identity(package))
        if edge is not None:
            edges.append(edge)
            parsed += 1
        elif diagnostics is not None:
            diagnostics.append((record, ManifestDiagnosticKind.MALFORMED))
        nested_attempted, nested_parsed = _npm_dependency_tree(
            package.get("dependencies"), edges, diagnostics, f"{record}.dependencies"
        )
        attempted += nested_attempted
        parsed += nested_parsed
    return attempted, parsed


def _npm_closure_from_payload(
    payload: object,
    *,
    source: str,
    diagnostics: list[tuple[str, ManifestDiagnosticKind]] | None = None,
) -> tuple[DependencyClosure | None, int, int]:
    if not isinstance(payload, dict) or payload.get("lockfileVersion") not in (2, 3):
        return None, 0, 0
    edges: list[DependencyEdge] = []
    attempted = 0
    parsed = 0
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for path, package in packages.items():
            # The empty package path is project metadata, not a dependency record.
            if path == "":
                continue
            attempted += 1
            record = f"packages.{path}"
            if not isinstance(path, str) or not isinstance(package, dict):
                if diagnostics is not None:
                    diagnostics.append((record, ManifestDiagnosticKind.MALFORMED))
                continue
            name = _npm_name_from_path(path)
            edge = _edge("npm", name, package.get("version"), _identity(package))
            if edge is None:
                if diagnostics is not None:
                    diagnostics.append((record, ManifestDiagnosticKind.UNSUPPORTED if name is None else ManifestDiagnosticKind.MALFORMED))
                continue
            edges.append(edge)
            parsed += 1
    elif packages is not None:
        attempted += 1
        if diagnostics is not None:
            diagnostics.append(("packages", ManifestDiagnosticKind.MALFORMED))
    nested_attempted, nested_parsed = _npm_dependency_tree(payload.get("dependencies"), edges, diagnostics)
    attempted += nested_attempted
    parsed += nested_parsed
    return DependencyClosure("npm", "complete", source, _ordered(edges)), attempted, parsed


def _npm_closure(root: Path) -> DependencyClosure | None:
    payload = _read_json(root / "package-lock.json")
    closure, _, _ = _npm_closure_from_payload(payload, source="package-lock.json")
    return closure


def _cargo_closure_from_payload(
    payload: object,
    *,
    source: str,
    diagnostics: list[tuple[str, ManifestDiagnosticKind]] | None = None,
) -> tuple[DependencyClosure | None, int, int]:
    if not isinstance(payload, dict):
        return None, 0, 0
    packages = payload.get("package")
    if not isinstance(packages, list):
        return None, 0, 0
    edges: list[DependencyEdge] = []
    attempted = 0
    parsed = 0
    for index, package in enumerate(packages):
        attempted += 1
        record = f"package[{index}]"
        if not isinstance(package, dict):
            if diagnostics is not None:
                diagnostics.append((record, ManifestDiagnosticKind.MALFORMED))
            continue
        name = package.get("name")
        version = package.get("version")
        # A source-less package is a local workspace member.  Validate its
        # identity, but do not report it as an external dependency.
        if package.get("source") is None:
            if _edge("crates", name, version) is None:
                if diagnostics is not None:
                    diagnostics.append((record, ManifestDiagnosticKind.MALFORMED))
            else:
                parsed += 1
            continue
        edge = _edge("crates", name, version, _identity(package))
        if edge is None:
            if diagnostics is not None:
                diagnostics.append((record, ManifestDiagnosticKind.MALFORMED))
            continue
        edges.append(edge)
        parsed += 1
    return DependencyClosure("crates", "complete", source, _ordered(edges)), attempted, parsed


def _cargo_closure(root: Path) -> DependencyClosure | None:
    text = _read_text(root / "Cargo.lock")
    if text is None:
        return None
    try:
        payload = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, TypeError):
        return None
    closure, _, _ = _cargo_closure_from_payload(payload, source="Cargo.lock")
    return closure


def _go_mod_tokens(line: str) -> list[str]:
    """Tokenize one go.mod line; comments do not split quoted strings.

    Double-quoted tokens follow strconv.Unquote's Go escape vocabulary.
    Backticks and single quotes are reserved by modfile.parseString.
    """
    tokens: list[str] = []
    position = 0
    while position < len(line):
        if line[position].isspace():
            position += 1
            continue
        if line.startswith("//", position):
            break
        if line[position] in "()":
            tokens.append(line[position])
            position += 1
            continue
        if line[position] == '"':
            position += 1
            value: list[str] = []
            while position < len(line) and line[position] != '"':
                character = line[position]
                position += 1
                if character == "\\":
                    if position >= len(line):
                        raise ValueError("unterminated Go string")
                    escape = line[position]
                    position += 1
                    simple = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"'}
                    if escape in simple:
                        character = simple[escape]
                    else:
                        if escape in "xXuU" and escape != "X":
                            width = {"x": 2, "u": 4, "U": 8}[escape]
                            digits = line[position:position + width]
                            position += width
                            valid = re.fullmatch(r"[0-9a-fA-F]+", digits)
                            radix = 16
                        elif escape in "01234567":
                            width = 3
                            digits = escape + line[position:position + 2]
                            position += 2
                            valid = re.fullmatch(r"[0-7]+", digits)
                            radix = 8
                        else:
                            raise ValueError("invalid Go escape")
                        if len(digits) != width or valid is None:
                            raise ValueError("invalid Go escape digits")
                        code = int(digits, radix)
                        if (radix == 8 and code > 255) or code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
                            raise ValueError("invalid Go escape value")
                        character = chr(code)
                value.append(character)
            if position >= len(line):
                raise ValueError("unterminated Go string")
            position += 1
            tokens.append("".join(value))
        else:
            start = position
            while position < len(line) and not line[position].isspace() and line[position] not in "()" and not line.startswith("//", position):
                if line[position] in "\"'`" or line.startswith("/*", position):
                    raise ValueError("invalid Go token")
                position += 1
            tokens.append(line[start:position])
    return tokens


def _go_requirements(
    text: str, diagnostics: list[tuple[str, ManifestDiagnosticKind]] | None = None
) -> list[DependencyEdge]:
    edges: list[DependencyEdge] = []
    in_require = False
    for line_number, raw in enumerate(text.splitlines(), 1):
        try:
            tokens = _go_mod_tokens(raw)
        except ValueError:
            if diagnostics is not None:
                diagnostics.append((f"line:{line_number}", ManifestDiagnosticKind.MALFORMED))
            continue
        if not tokens:
            continue
        if tokens == ["require", "("]:
            in_require = True
            continue
        if in_require and tokens == [")"]:
            in_require = False
            continue
        if tokens[0] == "require":
            candidate = tokens[1:]
        elif in_require:
            candidate = tokens
        else:
            continue
        if len(candidate) != 2 or _GO_VERSION.fullmatch(candidate[1]) is None:
            if diagnostics is not None:
                diagnostics.append((f"line:{line_number}", ManifestDiagnosticKind.MALFORMED))
            continue
        match = _GO_PSEUDO_VERSION.fullmatch(candidate[1])
        edge = _edge("go", candidate[0], candidate[1], match.group(1) if match else None)
        if edge is not None:
            edges.append(edge)
        elif diagnostics is not None:
            diagnostics.append((f"line:{line_number}", ManifestDiagnosticKind.MALFORMED))
    if in_require and diagnostics is not None:
        diagnostics.append(("require-block", ManifestDiagnosticKind.MALFORMED))
    return edges


def _go_closure(root: Path) -> DependencyClosure | None:
    text = _read_text(root / "go.mod")
    if text is None:
        return None
    return DependencyClosure("go", "direct-only", "go.mod", _ordered(_go_requirements(text)))


def _python_edges(
    text: str, diagnostics: list[tuple[str, ManifestDiagnosticKind]] | None = None
) -> list[DependencyEdge]:
    edges: list[DependencyEdge] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _PYTHON_PIN.fullmatch(line)
        if match is None or _PYTHON_VERSION.fullmatch(match.group(2)) is None:
            if diagnostics is not None:
                diagnostics.append((f"line:{line_number}", ManifestDiagnosticKind.UNSUPPORTED))
            continue
        edge = _edge("pypi", _normalize_python_name(match.group(1)), match.group(2))
        if edge is not None:
            edges.append(edge)
        elif diagnostics is not None:
            diagnostics.append((f"line:{line_number}", ManifestDiagnosticKind.MALFORMED))
    return edges


def _python_closure(root: Path) -> DependencyClosure | None:
    edges: list[DependencyEdge] = []
    sources: list[str] = []
    requirements = _read_text(root / "requirements.txt")
    if requirements is not None:
        sources.append("requirements.txt")
        edges.extend(_python_edges(requirements))
    text = _read_text(root / "pyproject.toml")
    if text is not None:
        sources.append("pyproject.toml")
        try:
            payload = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, TypeError):
            payload = {}
        project = payload.get("project") if isinstance(payload, dict) else None
        dependencies = project.get("dependencies") if isinstance(project, dict) else None
        if isinstance(dependencies, list):
            edges.extend(_python_edges("\n".join(item for item in dependencies if isinstance(item, str))))
    if not sources:
        return None
    return DependencyClosure("pypi", "direct-only", "+".join(sources), _ordered(edges))


def dependency_closures(directory: str | Path) -> tuple[DependencyClosure, ...]:
    """Compute every supported lockfile closure without performing network I/O."""

    root = Path(directory)
    closures = tuple(
        closure
        for closure in (
            _npm_closure(root),
            _cargo_closure(root),
            _go_closure(root),
            _python_closure(root),
        )
        if closure is not None
    )
    return tuple(sorted(closures, key=lambda closure: closure.ecosystem))


_MANIFEST_SOURCE_NAMES: dict[str, tuple[str, str, str, str]] = {
    "Cargo.lock": ("crates", "leitir-cargo-lock", "1", "complete"),
    "go.mod": ("go", "leitir-go-mod", "2", "direct-only"),
    "package-lock.json": ("npm", "leitir-package-lock", "1", "complete"),
    "pyproject.toml": ("pypi", "leitir-pyproject", "1", "direct_only"),
    "requirements.txt": ("pypi", "leitir-requirements", "1", "direct_only"),
}


def _manifest_source_metadata(path: str) -> tuple[str, str, str, str] | None:
    return _MANIFEST_SOURCE_NAMES.get(PurePosixPath(path).name)


def _valid_manifest_path(path: str) -> bool:
    candidate = PurePosixPath(path)
    return (
        bool(path)
        and "\\" not in path
        and not candidate.is_absolute()
        and not PureWindowsPath(path).drive
        and candidate.as_posix() == path
        and all(part not in {"", ".", ".."} for part in candidate.parts)
    )


def _manifest_diagnostic(
    path: str,
    kind: ManifestDiagnosticKind,
    record: str,
    *,
    source_failure: bool = False,
) -> ManifestDependencyDiagnostic:
    if kind is ManifestDiagnosticKind.ABSENT:
        detail = "recipient_manifest_source_absent_v1"
    elif source_failure:
        detail = "dependency_source_parse_failed_v1"
    elif kind is ManifestDiagnosticKind.MALFORMED:
        detail = "dependency_record_malformed_v1"
    elif kind is ManifestDiagnosticKind.SKIPPED:
        detail = "dependency_record_omitted_v1"
    else:
        detail = "dependency_record_unsupported_v1"
    return ManifestDependencyDiagnostic(path, kind, record, detail)


def _decode_manifest_source(file: VerifiedManifestBytes) -> str | None:
    try:
        return file.content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _manifest_python_pyproject(
    text: str, diagnostics: list[tuple[str, ManifestDiagnosticKind]]
) -> tuple[DependencyEdge, ...] | None:
    try:
        payload = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, TypeError):
        return None
    project = payload.get("project")
    if project is None:
        return ()
    if not isinstance(project, dict):
        return None
    dependencies = project.get("dependencies")
    if dependencies is None:
        return ()
    if not isinstance(dependencies, list):
        return None
    edges: list[DependencyEdge] = []
    for index, dependency in enumerate(dependencies):
        record = f"project.dependencies[{index}]"
        if not isinstance(dependency, str):
            diagnostics.append((record, ManifestDiagnosticKind.MALFORMED))
            continue
        local: list[tuple[str, ManifestDiagnosticKind]] = []
        parsed = _python_edges(dependency, local)
        edges.extend(parsed)
        diagnostics.extend((record, kind) for _, kind in local)
    return _ordered(edges)


def _parse_manifest_source(file: VerifiedManifestBytes) -> ManifestDependencySource:
    metadata = _manifest_source_metadata(file.path)
    if metadata is None:  # Checked at the policy boundary; retained for type safety.
        raise ValueError("unsupported dependency manifest source")
    ecosystem, parser_id, parser_version, graph = metadata
    source_name = PurePosixPath(file.path).name
    raw_diagnostics: list[tuple[str, ManifestDiagnosticKind]] = []
    text = _decode_manifest_source(file)
    source_failed = text is None
    deps: tuple[DependencyEdge, ...] = ()
    attempted = 0
    parsed = 0
    if text is not None and source_name == "package-lock.json":
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            payload = None
            source_failed = True
        if not source_failed:
            closure, attempted, parsed = _npm_closure_from_payload(
                payload, source=file.path, diagnostics=raw_diagnostics
            )
            source_failed = closure is None
            if closure is not None:
                deps = closure.deps
    elif text is not None and source_name == "Cargo.lock":
        try:
            payload = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, TypeError):
            payload = None
            source_failed = True
        if not source_failed:
            closure, attempted, parsed = _cargo_closure_from_payload(
                payload, source=file.path, diagnostics=raw_diagnostics
            )
            source_failed = closure is None
            if closure is not None:
                deps = closure.deps
    elif text is not None and source_name == "go.mod":
        edges = _go_requirements(text, raw_diagnostics)
        deps = _ordered(edges)
        attempted = len(edges) + len(raw_diagnostics)
        parsed = len(edges)
    elif text is not None and source_name == "requirements.txt":
        edges = _python_edges(text, raw_diagnostics)
        deps = _ordered(edges)
        attempted = len(edges) + len(raw_diagnostics)
        parsed = len(edges)
    elif text is not None and source_name == "pyproject.toml":
        parsed_edges = _manifest_python_pyproject(text, raw_diagnostics)
        source_failed = parsed_edges is None
        if parsed_edges is not None:
            deps = parsed_edges
            attempted = len(parsed_edges) + len(raw_diagnostics)
            parsed = len(parsed_edges)

    diagnostics: list[ManifestDependencyDiagnostic]
    if source_failed:
        diagnostics = [
            _manifest_diagnostic(
                file.path,
                ManifestDiagnosticKind.MALFORMED,
                "<source>",
                source_failure=True,
            )
        ]
        attempted = 0
        parsed = 0
        deps = ()
    else:
        diagnostics = [
            _manifest_diagnostic(file.path, kind, record)
            for record, kind in raw_diagnostics
        ]
    return ManifestDependencySource(
        path=file.path,
        source_digest=file.sha256,
        ecosystem=ecosystem,
        parser_id=parser_id,
        parser_version=parser_version,
        graph=graph,
        deps=deps,
        attempted_records=attempted,
        parsed_records=parsed,
        diagnostics=tuple(sorted(diagnostics)),
    )


def dependency_closures_from_manifest(
    files: tuple[VerifiedManifestBytes, ...],
    policy: DependencyManifestPolicy,
) -> ManifestDependencyResult:
    """Parse only content-bound bytes, retaining every non-parsed record.

    Unlike :func:`dependency_closures`, this function never opens a path.  It is
    therefore suitable for authorizing recipient profiles.
    """

    if not isinstance(files, tuple) or not isinstance(policy, DependencyManifestPolicy):
        raise TypeError("files and policy must use manifest-bound types")
    declared = policy.required_sources + policy.optional_sources
    if (
        len(set(declared)) != len(declared)
        or any(_manifest_source_metadata(path) is None or not _valid_manifest_path(path) for path in declared)
    ):
        raise ValueError("dependency manifest policy has invalid or duplicate sources")
    by_path: dict[str, VerifiedManifestBytes] = {}
    for file in files:
        if not isinstance(file, VerifiedManifestBytes) or not _valid_manifest_path(file.path):
            raise ValueError("invalid verified manifest bytes")
        if file.path in by_path:
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                "recipient manifest contains duplicate paths",
                detail_code="recipient_manifest_bytes_mismatch_v1",
            )
        expected_digest = f"sha256:{hashlib.sha256(file.content).hexdigest()}"
        if type(file.byte_length) is not int or file.byte_length != len(file.content) or file.sha256 != expected_digest:
            raise BTSError(
                BTSRejectReason.REJECT_PROVENANCE_MISMATCH,
                f"recipient manifest bytes do not match {file.path}",
                detail_code="recipient_manifest_bytes_mismatch_v1",
            )
        by_path[file.path] = file

    sources: list[ManifestDependencySource] = []
    diagnostics: list[ManifestDependencyDiagnostic] = []
    declared_set = frozenset(declared)
    for path in sorted(by_path):
        if _manifest_source_metadata(path) is not None and path not in declared_set:
            diagnostics.append(
                _manifest_diagnostic(path, ManifestDiagnosticKind.SKIPPED, "<source>")
            )
    for path in sorted(declared):
        current_file = by_path.get(path)
        if current_file is None:
            diagnostics.append(_manifest_diagnostic(path, ManifestDiagnosticKind.ABSENT, "<source>"))
            continue
        source = _parse_manifest_source(current_file)
        sources.append(source)
        diagnostics.extend(source.diagnostics)
    return ManifestDependencyResult(
        sources=tuple(sorted(sources, key=lambda item: item.path)),
        diagnostics=tuple(sorted(diagnostics)),
    )


def detect_installed_version_with_source(
    ecosystem: str, package_name: str, directory: str | Path
) -> DetectedVersion | None:
    """Return an exact project-selected version and its source, or ``None``."""

    root = Path(directory)
    readers: tuple[tuple[str, Callable[[Path, str], str | None]], ...]
    if ecosystem == "npm":
        if not _NPM_PACKAGE.fullmatch(package_name):
            return None
        readers = (
            ("node_modules", _npm_node_modules),
            ("package-lock.json", _npm_package_lock),
            ("pnpm-lock.yaml", _npm_pnpm),
            ("yarn.lock", _npm_yarn),
            ("package.json", _npm_package_json),
        )
    elif ecosystem == "pypi":
        readers = (("requirements.txt", _pypi_requirements), ("pyproject.toml", _pypi_pyproject))
    elif ecosystem == "crates":
        readers = (("Cargo.lock", _cargo),)
    elif ecosystem == "go":
        readers = (("go.mod", _go),)
    else:
        return None
    for source, reader in readers:
        version = reader(root, package_name)
        if version is not None:
            return DetectedVersion(version, source)
    return None


def detect_installed_version(
    ecosystem: str, package_name: str, directory: str | Path
) -> str | None:
    """Return the exact installed version selected by project files."""

    detected = detect_installed_version_with_source(ecosystem, package_name, directory)
    return detected.version if detected is not None else None


__all__ = [
    "DependencyClosure",
    "DependencyEdge",
    "DependencyManifestPolicy",
    "DetectedVersion",
    "ManifestDependencyDiagnostic",
    "ManifestDependencyResult",
    "ManifestDependencySource",
    "ManifestDiagnosticKind",
    "VerifiedManifestBytes",
    "dependency_closures",
    "dependency_closures_from_manifest",
    "detect_installed_version",
    "detect_installed_version_with_source",
]
