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


__all__ = ["DetectedVersion", "detect_installed_version", "detect_installed_version_with_source"]
