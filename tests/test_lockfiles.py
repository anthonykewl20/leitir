"""Fixture-style coverage for conservative project version detection."""

from __future__ import annotations

import json

import pytest

from leitir.lockfiles import detect_installed_version, detect_installed_version_with_source


def _write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_npm_node_modules_has_highest_priority(tmp_path):
    _write(tmp_path, "node_modules/zod/package.json", '{"version":"3.24.0"}')
    _write(tmp_path, "package-lock.json", '{"packages":{"node_modules/zod":{"version":"3.23.0"}}}')
    found = detect_installed_version_with_source("npm", "zod", tmp_path)
    assert found is not None
    assert (found.version, found.source) == ("3.24.0", "node_modules")


@pytest.mark.parametrize("lockfile_version", [1, 2, 3])
def test_package_lock_versions_and_scoped_names(tmp_path, lockfile_version):
    if lockfile_version == 1:
        body = {"lockfileVersion": 1, "dependencies": {"@scope/pkg": {"version": "1.2.3"}}}
    else:
        body = {
            "lockfileVersion": lockfile_version,
            "packages": {"node_modules/@scope/pkg": {"version": "1.2.3"}},
        }
    _write(tmp_path, "package-lock.json", json.dumps(body))
    assert detect_installed_version("npm", "@scope/pkg", tmp_path) == "1.2.3"


@pytest.mark.parametrize(
    "content,name,version",
    [
        ("lockfileVersion: '6.0'\npackages:\n  /zod@3.22.0:\n    resolution: {}\n", "zod", "3.22.0"),
        (
            "lockfileVersion: '9.0'\npackages:\n  '@scope/pkg@1.2.3':\n    resolution: {}\n",
            "@scope/pkg",
            "1.2.3",
        ),
    ],
)
def test_pnpm_v6_and_v9_package_key_styles(tmp_path, content, name, version):
    _write(tmp_path, "pnpm-lock.yaml", content)
    assert detect_installed_version("npm", name, tmp_path) == version


def test_yarn_v1_and_berry(tmp_path):
    _write(
        tmp_path,
        "yarn.lock",
        '"@scope/pkg@^1.0.0":\n  version "1.4.0"\n\n"zod@npm:^3":\n  version: 3.22.0\n',
    )
    assert detect_installed_version("npm", "@scope/pkg", tmp_path) == "1.4.0"
    assert detect_installed_version("npm", "zod", tmp_path) == "3.22.0"


def test_package_json_accepts_exact_dependencies_only(tmp_path):
    _write(
        tmp_path,
        "package.json",
        json.dumps({"dependencies": {"zod": "^3.22.0"}, "devDependencies": {"typescript": "5.4.5"}}),
    )
    assert detect_installed_version("npm", "zod", tmp_path) is None
    assert detect_installed_version("npm", "typescript", tmp_path) == "5.4.5"


def test_requirements_exact_pin_and_pep503_name_normalization(tmp_path):
    _write(tmp_path, "requirements.txt", "Other>=1.0\nMy_Package==2.31.0 # pinned\nrequests~=2.0\n")
    assert detect_installed_version("pypi", "my.package", tmp_path) == "2.31.0"
    assert detect_installed_version("pypi", "other", tmp_path) is None
    assert detect_installed_version("pypi", "requests", tmp_path) is None


def test_requirements_wildcard_is_not_an_exact_pin(tmp_path):
    _write(tmp_path, "requirements.txt", "demo==1.2.*\n")
    assert detect_installed_version("pypi", "demo", tmp_path) is None


def test_pyproject_project_dependencies_only(tmp_path):
    _write(
        tmp_path,
        "pyproject.toml",
        '[project]\nrequires-python = ">=3.11"\ndependencies = ["Requests == 2.32.0", "range>=1"]\n',
    )
    assert detect_installed_version("pypi", "requests", tmp_path) == "2.32.0"
    assert detect_installed_version("pypi", "range", tmp_path) is None
    assert detect_installed_version("pypi", "python", tmp_path) is None


def test_cargo_lock_package_pairs(tmp_path):
    _write(
        tmp_path,
        "Cargo.lock",
        'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.203"\n\n'
        '[[package]]\nname = "other"\nversion = "2.0.0"\n',
    )
    assert detect_installed_version("crates", "serde", tmp_path) == "1.0.203"
    assert detect_installed_version("crates", "missing", tmp_path) is None


def test_go_mod_single_block_and_indirect_requirements(tmp_path):
    _write(
        tmp_path,
        "go.mod",
        "module example.com/app\nrequire example.com/one v1.2.3\nrequire (\n"
        "  example.com/two v2.3.4 // indirect\n)\n",
    )
    assert detect_installed_version("go", "example.com/one", tmp_path) == "v1.2.3"
    assert detect_installed_version("go", "example.com/two", tmp_path) == "v2.3.4"


@pytest.mark.parametrize("ecosystem", ["npm", "pypi", "crates", "go", "unknown"])
def test_missing_files_return_none(tmp_path, ecosystem):
    assert detect_installed_version(ecosystem, "demo", tmp_path) is None


def test_npm_package_name_cannot_escape_node_modules(tmp_path):
    _write(tmp_path, "package.json", '{"version":"1.2.3"}')
    assert detect_installed_version("npm", "../../..", tmp_path) is None


@pytest.mark.parametrize(
    "ecosystem,filename,content",
    [
        ("npm", "package-lock.json", "{"),
        ("npm", "pnpm-lock.yaml", "lockfileVersion: nope\npackages:\n  zod@3.0.0:\n"),
        ("npm", "yarn.lock", '"zod@^3":\n  version "^3.0.0"\n'),
        ("pypi", "pyproject.toml", "[project\n"),
        ("crates", "Cargo.lock", "[[package]\n"),
        ("go", "go.mod", "require example.com/demo ^1.2.3\n"),
    ],
)
def test_malformed_or_non_exact_content_never_raises(tmp_path, ecosystem, filename, content):
    _write(tmp_path, filename, content)
    assert detect_installed_version(ecosystem, "zod" if ecosystem == "npm" else "example.com/demo", tmp_path) is None


def test_malformed_higher_priority_file_falls_through(tmp_path):
    _write(tmp_path, "package-lock.json", "not json")
    _write(tmp_path, "package.json", '{"dependencies":{"zod":"3.22.0"}}')
    assert detect_installed_version("npm", "zod", tmp_path) == "3.22.0"
