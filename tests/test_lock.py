"""Dependency metadata and lock tests.

Covers two requirements:

* **dependency substitution** — the package's abstract dependency declarations in
  ``pyproject.toml`` are substituted with concrete pinned versions by the lock.
* **fully pinned lock metadata** — every non-comment line in ``requirements.txt``
  is an exact ``name==version`` pin.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = REPO_ROOT / "requirements.txt"
PYPROJECT = REPO_ROOT / "pyproject.toml"

PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9._+!-]+)$"
)


def _normalize(name: str) -> str:
    """PEP 503 normalization for comparing distribution names."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _read_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN_RE.match(line)
        assert match is not None, f"line is not an exact pin: {line!r}"
        pins[_normalize(match.group("name"))] = match.group("version")
    return pins


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


class TestFullyPinnedLock:
    def test_every_line_is_exact_pin(self):
        pins = _read_pins()
        # A non-empty, fully pinned closure resolved from a clean environment.
        assert pins, "requirements.txt has no pins"

    def test_test_dependency_present(self):
        pins = _read_pins()
        assert _normalize("pytest") in pins, "missing test dependency: pytest"

    def test_retired_runtime_dependencies_are_absent(self):
        pins = _read_pins()
        for name in ["trafilatura", "docker", "pyyaml"]:
            assert _normalize(name) not in pins, f"retired dependency remains: {name}"

    def test_build_tooling_present(self):
        pins = _read_pins()
        for name in ["build", "setuptools", "wheel", "pyproject-hooks"]:
            assert _normalize(name) in pins, f"missing build tooling: {name}"

    def test_transitive_closure_present(self):
        pins = _read_pins()
        # Representative transitive packages required by pytest and build.
        for name in ["pluggy", "packaging"]:
            assert _normalize(name) in pins, f"missing transitive: {name}"

    def test_no_unpinned_or_url_requirements(self):
        for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            assert "==" in line, f"unpinned requirement: {line!r}"
            assert not line.startswith(("-", "git+", "http")), (
                f"non-pin requirement form: {line!r}"
            )


class TestDependencySubstitution:
    def test_pyproject_dependencies_are_abstract(self):
        """Abstract declarations carry no exact pin, so the lock can substitute."""
        deps = _pyproject()["project"]["dependencies"]
        for dep in deps:
            assert "==" not in dep, f"dependency is pre-pinned: {dep!r}"

    def test_lock_substitutes_concrete_version_for_each_declared_dep(self):
        deps = _pyproject()["project"]["dependencies"]
        pins = _read_pins()
        for dep in deps:
            declared = _normalize(re.split(r"[<>=!~;\[]", dep, maxsplit=1)[0])
            assert declared in pins, (
                f"declared dependency {declared!r} has no pinned substitute in the lock"
            )

    def test_build_system_requires_have_pinned_substitutes(self):
        requires = _pyproject()["build-system"]["requires"]
        pins = _read_pins()
        for req in requires:
            name = _normalize(re.split(r"[<>=!~;\[]", req, maxsplit=1)[0])
            assert name in pins, (
                f"build-system requirement {name!r} not pinned in the lock"
            )

    def test_exact_pinned_versions_are_concrete(self):
        pins = _read_pins()
        # Every version must be a concrete release identifier (no wildcards).
        for name, version in pins.items():
            assert version, f"{name} has empty version"
            assert "*" not in version, f"{name} has wildcard version {version!r}"
