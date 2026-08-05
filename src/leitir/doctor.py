"""Environment and integrity diagnostics for :command:`leitir doctor`."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import logging
import os
import platform as platform_module
import re
import stat
import sys
import tempfile
import traceback
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, Literal, TextIO

from .corpus import resolve_root
from .materialize import MANIFEST_NAME, read_valid_manifest
from .treehash import (
    TREE_HASH_ALGORITHM,
    TreeHashMismatchError,
    compute_materialized_tree_hash,
    verify_materialized_tree_hash,
)

Status = Literal["pass", "warn", "error", "skip"]


@dataclass(frozen=True)
class Check:
    """The stable result shape shared by human and JSON output."""

    name: str
    status: Status
    summary: str
    detail: str | None = None
    json_data: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "summary": self.summary,
            "detail": self.detail,
            "data": self.json_data,
        }


_CREDENTIALS = (
    "GITHUB_TOKEN", "GITLAB_TOKEN", "BITBUCKET_TOKEN", "BITBUCKET_USERNAME",
    "CODEBERG_TOKEN", "SRHT_TOKEN", "NPM_TOKEN", "PYPI_TOKEN", "PIP_TOKEN",
    "CARGO_TOKEN",
)
_ENDPOINTS = (
    ("npm", "https://registry.npmjs.org/"),
    ("pypi", "https://pypi.org/pypi/leitir/json"),
    ("crates", "https://crates.io/"),
    ("github", "https://api.github.com/"),
    ("gitlab", "https://gitlab.com/"),
    ("bitbucket", "https://api.bitbucket.org/"),
    ("codeberg", "https://codeberg.org/"),
    ("sourcehut", "https://git.sr.ht/"),
)
_REQUIRED_MANIFEST_FIELDS = (
    "host", "owner", "repo", "commit_sha", "fetch_method", "spec",
    "repo_url", "fetched_at",
)


def check_python_version() -> Check:
    version = ".".join(str(part) for part in sys.version_info[:3])
    status: Status = "pass" if tuple(sys.version_info[:2]) >= (3, 11) else "error"
    return Check("python.version", status, f"Python {version} (>=3.11 required)",
                 json_data={"python": version})


def check_platform() -> Check:
    os_name = platform_module.system() or sys.platform
    architecture = platform_module.machine() or "unknown"
    return Check("platform", "pass", f"{os_name} ({architecture})",
                 json_data={"os": os_name, "architecture": architecture})


def check_install_location() -> Check:
    try:
        location = importlib.metadata.distribution("leitir").locate_file("")
    except importlib.metadata.PackageNotFoundError as exc:
        return Check(
            "install.location",
            "warn",
            "distribution metadata not found (source checkout is still usable)",
            str(exc),
        )
    absolute = Path(str(location)).absolute()
    return Check("install.location", "pass", str(absolute),
                 json_data={"path": str(absolute)})


def check_installed_version() -> Check:
    try:
        version = importlib.metadata.version("leitir")
    except importlib.metadata.PackageNotFoundError as exc:
        return Check("install.version", "error", "leitir distribution version not found", str(exc))
    return Check("install.version", "pass", version, json_data={"version": version})


def check_entry_point_resolves() -> Check:
    try:
        module = importlib.import_module("leitir.cli")
        if not callable(getattr(module, "main", None)):
            raise TypeError("leitir.cli:main is not callable")
    except Exception as exc:  # noqa: BLE001 - diagnostics must contain check failures
        return Check("install.entry_point", "error", "leitir.cli:main does not resolve",
                     "".join(traceback.format_exception(exc)))
    return Check("install.entry_point", "pass", "leitir.cli:main resolves")


def check_internal_imports() -> Check:
    package_dir = Path(__file__).parent
    modules = sorted(
        path.stem for path in package_dir.glob("*.py")
        if not path.stem.startswith("_")
    )
    failures: list[str] = []
    for name in modules:
        try:
            importlib.import_module(f"leitir.{name}")
        except Exception as exc:  # noqa: BLE001 - one broken module must not stop the scan
            failures.append(f"leitir.{name}:\n{''.join(traceback.format_exception(exc))}")
    if failures:
        return Check("imports", "error", f"{len(failures)} of {len(modules)} modules failed to import",
                     "\n".join(failures), {"modules": modules, "failed": len(failures)})
    return Check("imports", "pass", f"all {len(modules)} leitir modules import cleanly",
                 json_data={"modules": len(modules)})


def check_corpus_root_path(root: Path) -> Check:
    return Check("corpus.root_path", "pass", str(root), json_data={"path": str(root)})


def check_corpus_root_exists(root: Path) -> Check:
    if root.is_dir():
        return Check("corpus.exists", "pass", "directory exists")
    return Check("corpus.exists", "warn", "directory does not exist (normal before first use)")


def check_corpus_root_writable(root: Path) -> Check:
    if not root.is_dir():
        return Check("corpus.writable", "skip", "corpus root does not exist")
    mode = stat.S_IMODE(root.stat().st_mode)
    if mode & 0o222 == 0:
        return Check("corpus.writable", "error", "corpus root has no write permission bits")
    try:
        fd, name = tempfile.mkstemp(prefix=".leitir-doctor-write-", dir=root)
        os.close(fd)
        Path(name).unlink()
    except OSError as exc:
        return Check("corpus.writable", "error", "cannot write to corpus root", str(exc))
    return Check("corpus.writable", "pass", "yes")


def check_corpus_root_symlinks_supported(root: Path) -> Check:
    if not root.is_dir():
        return Check("corpus.symlinks", "skip", "corpus root does not exist")
    try:
        with tempfile.TemporaryDirectory(prefix=".leitir-doctor-link-", dir=root) as directory:
            base = Path(directory)
            target = base / "target"
            link = base / "link"
            target.write_bytes(b"x")
            link.symlink_to(target.name)
            if link.read_bytes() != b"x":
                raise OSError("created symlink did not resolve to its target")
    except OSError as exc:
        return Check("corpus.symlinks", "warn", f"symlink creation failed: {exc}")
    return Check("corpus.symlinks", "pass", "supported")


def check_corpus_root_atomic_replace(root: Path) -> Check:
    if not root.is_dir():
        return Check("corpus.atomic_replace", "skip", "corpus root does not exist")
    try:
        with tempfile.TemporaryDirectory(prefix=".leitir-doctor-replace-", dir=root) as directory:
            base = Path(directory)
            source, destination = base / "source", base / "destination"
            source.write_bytes(b"new")
            destination.write_bytes(b"old")
            os.replace(source, destination)
            if destination.read_bytes() != b"new":
                raise OSError("replacement content did not match")
    except OSError as exc:
        return Check("corpus.atomic_replace", "error", "atomic replacement failed", str(exc))
    return Check("corpus.atomic_replace", "pass", "supported")


def _load_manifest(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def check_cache_state(root: Path) -> tuple[list[Check], list[tuple[Path, dict[str, Any]]]]:
    manifests = sorted(root.rglob(MANIFEST_NAME)) if root.is_dir() else []
    loaded = [(path, payload) for path in manifests if (payload := _load_manifest(path)) is not None]
    verified = [(path, payload) for path, payload in loaded if payload.get("verified") is True]
    digest_count = sum("materialized_tree_hash" in payload for _path, payload in loaded)
    missing = [path for path, payload in verified if "materialized_tree_hash" not in payload]
    corrupted: list[Path] = []
    for path in manifests:
        payload = _load_manifest(path)
        if payload is None:
            corrupted.append(path)
            continue
        owner = payload.get("owner")
        repo = payload.get("repo")
        commit_sha = payload.get("commit_sha")
        host = payload.get("host", "github.com")
        if (
            not isinstance(owner, str)
            or not isinstance(repo, str)
            or not isinstance(commit_sha, str)
            or not isinstance(host, str)
        ):
            corrupted.append(path)
            continue
        manifest_logger = logging.getLogger("leitir.materialize")
        old_disabled = manifest_logger.disabled
        try:
            manifest_logger.disabled = True
            valid = read_valid_manifest(
                path.parent, owner, repo, commit_sha, host=host
            )
        finally:
            manifest_logger.disabled = old_disabled
        if valid is None and path not in missing:
            corrupted.append(path)
    shelf = Check("cache.shelves", "pass",
                  f"{len(manifests)} total, {len(verified)} verified, {digest_count} with digest",
                  json_data={"total": len(manifests), "verified": len(verified),
                             "digest_present": digest_count})
    digest_status: Status = "warn" if missing else "pass"
    digest = Check("cache.digest_missing", digest_status,
                   f"{len(missing)} verified shelves lack a digest" +
                   (" (run 'leitir upgrade-cache')" if missing else ""),
                   json_data={"count": len(missing), "paths": [str(path) for path in missing]})
    corrupted_status: Status = "warn" if corrupted else "pass"
    corrupt = Check("cache.corrupted", corrupted_status,
                    f"{len(corrupted)} shelves failed manifest validation",
                    "\n".join(str(path) for path in corrupted) or None,
                    {"count": len(corrupted), "paths": [str(path) for path in corrupted]})
    return [shelf, digest, corrupt], loaded


def check_credentials() -> Check:
    present = [name for name in _CREDENTIALS if name in os.environ]
    malformed = [name for name in present if any(char.isspace() or ord(char) < 32
                                                  for char in os.environ[name])]
    if malformed:
        return Check("creds", "warn", f"{len(malformed)} credential variables contain whitespace/control characters",
                     ", ".join(malformed), {"present": present, "malformed": malformed})
    if present:
        return Check("creds", "pass", f"{len(present)} credential variables present (values hidden)",
                     json_data={"present": present, "malformed": []})
    return Check("creds", "pass", "no host tokens in environment (anonymous by default)",
                 json_data={"present": [], "malformed": []})


def _user_agent(version: str | None) -> str:
    return f"leitir/{version or 'unknown'} doctor"


def check_network_endpoint(name: str, url: str, version: str | None) -> Check:
    request = urllib.request.Request(url, headers={"User-Agent": _user_agent(version)})
    try:
        with urllib.request.urlopen(request, timeout=1.0) as response:
            code = response.getcode()
    except urllib.error.HTTPError as exc:
        category = "4xx" if 400 <= exc.code < 500 else "5xx" if exc.code >= 500 else "HTTP error"
        return Check(f"network.{name}", "warn", f"{url} returned {category} ({exc.code})",
                     json_data={"url": url, "http_status": exc.code})
    except TimeoutError as exc:
        return Check(f"network.{name}", "warn", f"{url} timed out", str(exc), {"url": url})
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            return Check(f"network.{name}", "warn", f"{url} timed out", str(exc), {"url": url})
        return Check(f"network.{name}", "warn", f"{url} network error", str(exc), {"url": url})
    except Exception as exc:  # noqa: BLE001 - network diagnostics are warning-only
        return Check(f"network.{name}", "warn", f"{url} network error", str(exc), {"url": url})
    if 200 <= code < 400:
        return Check(f"network.{name}", "pass", f"{url} reachable",
                     json_data={"url": url, "http_status": code})
    return Check(f"network.{name}", "warn", f"{url} returned HTTP {code}",
                 json_data={"url": url, "http_status": code})


def check_manifest_schema(manifests: list[tuple[Path, dict[str, Any]]]) -> Check:
    if not manifests:
        return Check("manifest.schema", "skip", "no shelves to inspect")
    path, payload = max(manifests, key=lambda item: str(item[1].get("fetched_at", "")))
    missing = [field for field in _REQUIRED_MANIFEST_FIELDS if field not in payload]
    if missing:
        return Check("manifest.schema", "error", f"most-recent shelf is missing required fields: {', '.join(missing)}",
                     str(path), {"path": str(path), "missing": missing})
    algorithm = payload.get("materialized_tree_hash_algorithm")
    if algorithm is not None and algorithm != TREE_HASH_ALGORITHM:
        return Check("manifest.schema", "warn", f"most-recent shelf uses unknown tree-hash algorithm: {algorithm}",
                     str(path), {"path": str(path), "algorithm": algorithm})
    return Check("manifest.schema", "pass", "most-recent shelf passes schema check",
                 json_data={"path": str(path), "algorithm": algorithm})


def check_integrity_selftest() -> Check:
    try:
        with tempfile.TemporaryDirectory(prefix="leitir-doctor-selftest-") as directory:
            root = Path(directory)
            (root / "one.txt").write_bytes(b"alpha")
            (root / "two.txt").write_bytes(b"bravo")
            digest, scope = compute_materialized_tree_hash(root)
            (root / "two.txt").write_bytes(b"Bravo")
            try:
                verify_materialized_tree_hash(root, digest, algorithm=TREE_HASH_ALGORITHM, scope=scope)
            except TreeHashMismatchError:
                pass
            else:
                raise AssertionError("byte tamper was not detected")
    except Exception as exc:  # noqa: BLE001 - the self-test reports every regression
        return Check("selftest.integrity", "error", "synthetic integrity roundtrip failed",
                     "".join(traceback.format_exception(exc)))
    return Check("selftest.integrity", "pass", "byte-tamper detected by materialized_tree_hash")


def _version_tuple(value: str) -> tuple[int, ...]:
    match = re.match(r"^(\d+(?:\.\d+)*)", value)
    if match is None:
        raise ValueError(f"unsupported version: {value!r}")
    return tuple(int(part) for part in match.group(1).split("."))


def check_update_availability(installed_version: str | None) -> Check:
    if installed_version is None:
        return Check("update.available", "skip", "installed version is unavailable")
    url = "https://pypi.org/pypi/leitir/json"
    request = urllib.request.Request(url, headers={"User-Agent": _user_agent(installed_version)})
    try:
        with urllib.request.urlopen(request, timeout=1.0) as response:
            payload = json.load(response)
        latest = payload["info"]["version"]
        if not isinstance(latest, str):
            raise TypeError("PyPI info.version is not a string")
        newer = _version_tuple(latest) > _version_tuple(installed_version)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return Check("update.available", "skip", "package is not published on PyPI (pre-publication or fork)")
        return Check("update.available", "skip", "could not check PyPI for updates", str(exc))
    except (TimeoutError, OSError, urllib.error.URLError, KeyError,
            TypeError, ValueError, json.JSONDecodeError) as exc:
        return Check("update.available", "skip", "could not check PyPI for updates", str(exc))
    except Exception as exc:  # noqa: BLE001 - update diagnosis must never be an error
        return Check("update.available", "skip", "could not check PyPI for updates", str(exc))
    if newer:
        return Check("update.available", "warn", f"update available: {installed_version} -> {latest}",
                     json_data={"installed": installed_version, "latest": latest})
    return Check("update.available", "pass", f"you are on the latest release ({installed_version})",
                 json_data={"installed": installed_version, "latest": latest})


def _safe(name: str, function: Callable[[], Check]) -> Check:
    try:
        return function()
    except Exception as exc:  # noqa: BLE001 - doctor checks are isolated by contract
        return Check(name, "error", "check raised unexpectedly",
                     "".join(traceback.format_exception(exc)))


def collect_checks(*, no_network: bool = False, root: Path | None = None) -> tuple[list[Check], str | None]:
    """Run every diagnostic independently and return results plus installed version."""
    corpus_root = (root or resolve_root(None)).absolute()
    checks = [
        _safe("python.version", check_python_version),
        _safe("platform", check_platform),
        _safe("install.location", check_install_location),
        _safe("install.version", check_installed_version),
        _safe("install.entry_point", check_entry_point_resolves),
        _safe("imports", check_internal_imports),
        _safe("corpus.root_path", lambda: check_corpus_root_path(corpus_root)),
        _safe("corpus.exists", lambda: check_corpus_root_exists(corpus_root)),
        _safe("corpus.writable", lambda: check_corpus_root_writable(corpus_root)),
        _safe("corpus.symlinks", lambda: check_corpus_root_symlinks_supported(corpus_root)),
        _safe("corpus.atomic_replace", lambda: check_corpus_root_atomic_replace(corpus_root)),
    ]
    try:
        cache_checks, manifests = check_cache_state(corpus_root)
        checks.extend(cache_checks)
    except Exception as exc:  # noqa: BLE001 - retain results from all other categories
        checks.append(Check("cache.shelves", "error", "cache inspection failed",
                            "".join(traceback.format_exception(exc))))
        manifests = []
    checks.append(_safe("creds", check_credentials))
    installed = next((check.json_data["version"] for check in checks
                      if check.name == "install.version" and check.status == "pass"
                      and check.json_data is not None), None)
    if no_network:
        checks.extend(Check(f"network.{name}", "skip", "network checks disabled by --no-network",
                            json_data={"url": url}) for name, url in _ENDPOINTS)
    else:
        checks.extend(_safe(f"network.{name}", partial(
                            check_network_endpoint, name, url, installed))
                      for name, url in _ENDPOINTS)
    checks.append(_safe("manifest.schema", lambda: check_manifest_schema(manifests)))
    checks.append(_safe("selftest.integrity", check_integrity_selftest))
    checks.append(Check("update.available", "skip", "network checks disabled by --no-network")
                  if no_network else _safe("update.available",
                                           lambda: check_update_availability(installed)))
    return checks, installed


def _counts(checks: Sequence[Check]) -> dict[str, int]:
    return {status: sum(check.status == status for check in checks)
            for status in ("pass", "warn", "error", "skip")}


def _exit_code(checks: Sequence[Check]) -> int:
    if any(check.status == "error" for check in checks):
        return 2
    if any(check.status == "warn" for check in checks):
        return 1
    return 0


def _write_human(checks: Sequence[Check], out: TextIO, *, quiet: bool) -> None:
    color = bool(not quiet and getattr(out, "isatty", lambda: False)()
                 and "NO_COLOR" not in os.environ)
    colors = {"pass": "\033[32m", "warn": "\033[33m", "error": "\033[31m", "skip": "\033[90m"}
    if not quiet:
        print("leitir doctor — environment and integrity diagnostic\n", file=out)
    for check in checks:
        if quiet and check.status == "pass":
            continue
        marker = f"[{check.status}]".ljust(8)
        if color:
            marker = f"{colors[check.status]}{marker}\033[0m"
        print(f"{marker} {check.name:<28} {check.summary}", file=out)
        if check.detail and check.status in ("warn", "error"):
            for line in check.detail.rstrip().splitlines():
                print(f"         {line}", file=out)
    if not quiet:
        counts = _counts(checks)
        print(f"\nSummary: {counts['pass']} passed, {counts['warn']} warnings, "
              f"{counts['error']} errors, {counts['skip']} skipped", file=out)


def run_doctor(*, as_json: bool = False, quiet: bool = False, no_network: bool = False,
               stdout: TextIO | None = None, root: Path | None = None) -> int:
    """Run diagnostics, render exactly one selected format, and return 0/1/2."""
    checks, installed = collect_checks(no_network=no_network, root=root)
    out = sys.stdout if stdout is None else stdout
    if as_json:
        generated = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        payload = {"schema": 1, "generated_at": generated, "version": installed,
                   "checks": [check.as_dict() for check in checks], "summary": _counts(checks)}
        print(json.dumps(payload, sort_keys=True), file=out)
    else:
        _write_human(checks, out, quiet=quiet)
    return _exit_code(checks)


__all__ = ["Check", "collect_checks", "run_doctor"]
