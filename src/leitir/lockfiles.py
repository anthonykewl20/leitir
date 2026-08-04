"""Conservative, dependency-free project lockfile version detection."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import tomllib


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
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            candidate = line[len("require ") :].split()
        elif in_require:
            candidate = line.split()
        else:
            continue
        if len(candidate) == 2 and candidate[0] == name and _GO_VERSION.fullmatch(candidate[1]):
            return candidate[1]
    return None


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


def _npm_dependency_tree(dependencies: object, edges: list[DependencyEdge]) -> None:
    if not isinstance(dependencies, dict):
        return
    for name, package in dependencies.items():
        if not isinstance(package, dict):
            continue
        edge = _edge("npm", name, package.get("version"), _identity(package))
        if edge is not None:
            edges.append(edge)
        _npm_dependency_tree(package.get("dependencies"), edges)


def _npm_closure(root: Path) -> DependencyClosure | None:
    payload = _read_json(root / "package-lock.json")
    if not isinstance(payload, dict) or payload.get("lockfileVersion") not in (2, 3):
        return None
    edges: list[DependencyEdge] = []
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for path, package in packages.items():
            if not isinstance(path, str) or not isinstance(package, dict):
                continue
            name = _npm_name_from_path(path)
            edge = _edge("npm", name, package.get("version"), _identity(package))
            if edge is not None:
                edges.append(edge)
    _npm_dependency_tree(payload.get("dependencies"), edges)
    return DependencyClosure("npm", "complete", "package-lock.json", _ordered(edges))


def _cargo_closure(root: Path) -> DependencyClosure | None:
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
    edges: list[DependencyEdge] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if package.get("source") is None:
            continue
        edge = _edge("crates", name, package.get("version"), _identity(package))
        if edge is not None:
            edges.append(edge)
    return DependencyClosure("crates", "complete", "Cargo.lock", _ordered(edges))


def _go_requirements(text: str) -> list[DependencyEdge]:
    edges: list[DependencyEdge] = []
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require "):
            candidate = line[len("require ") :].split()
        elif in_require:
            candidate = line.split()
        else:
            continue
        if len(candidate) != 2 or _GO_VERSION.fullmatch(candidate[1]) is None:
            continue
        match = _GO_PSEUDO_VERSION.fullmatch(candidate[1])
        edge = _edge("go", candidate[0], candidate[1], match.group(1) if match else None)
        if edge is not None:
            edges.append(edge)
    return edges


def _go_closure(root: Path) -> DependencyClosure | None:
    text = _read_text(root / "go.mod")
    if text is None:
        return None
    return DependencyClosure("go", "complete", "go.mod", _ordered(_go_requirements(text)))


def _python_edges(text: str) -> list[DependencyEdge]:
    edges: list[DependencyEdge] = []
    for line in text.splitlines():
        match = _PYTHON_PIN.fullmatch(line)
        if match is None or _PYTHON_VERSION.fullmatch(match.group(2)) is None:
            continue
        edge = _edge("pypi", _normalize_python_name(match.group(1)), match.group(2))
        if edge is not None:
            edges.append(edge)
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


def detect_installed_version_with_source(
    ecosystem: str, package_name: str, directory: str | Path
) -> DetectedVersion | None:
    """Return an exact project-selected version and its source, or ``None``."""

    root = Path(directory)
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
    "DetectedVersion",
    "dependency_closures",
    "detect_installed_version",
    "detect_installed_version_with_source",
]
