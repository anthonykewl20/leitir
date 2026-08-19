"""Import-purity tests.

Importing ``leitir`` and its submodules must perform no network request, Docker
invocation or client creation, subprocess call, credential read, environment
credential read, or filesystem write. These checks run in a fresh child
interpreter so they are not fooled by an already-warm module cache in this test
process.

The module list is enumerated programmatically (issue #206): the
``pkgutil.walk_packages`` walk over the imported ``leitir`` package is
authoritative, and a filesystem walk of ``src/leitir`` ``*.py`` files is
asserted equal to it, so the two counts cannot diverge silently. Every
enumerated submodule is imported in its own isolated child and checked against
``FORBIDDEN_MODULES``; modules that legitimately cannot pass sit on
``ALLOWLIST_IMPURE`` with a one-line reason (platform-scoped exemptions live in
``PLATFORM_ALLOWLIST_IMPURE``). Adding a submodule that pulls a forbidden
module without an allowlist entry fails the gate naming the module.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from string import Template
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
PACKAGE_NAME = "leitir"

# Modules that would only be imported if an external-effect side effect occurred.
#
# Presence in sys.modules is a proxy, and for ``urllib.request`` it is a loose
# one: binding those names performs no I/O, so a module-scope import would not
# by itself breach the stated invariant. The kernel's HTTP clients defer the
# import into the calling methods to keep this list meaningful, which also keeps
# a bare ``import leitir.resolver`` from materialising an HTTP stack.
FORBIDDEN_MODULES = [
    "docker",
    "trafilatura",
    "requests",
    "urllib.request",
    "http.client",
    "subprocess",
]

# Modules exempt from the purity gate. EVERY entry needs a one-line reason
# (asserted by test_allowlist_entries_carry_reasons); an exemption without a
# written reason is prohibited. This allowlist encodes purity POLICY for the
# project and is subject to owner review (issue #206).
#
# Import-time binding of ``urllib.request``/``subprocess`` names performs no
# I/O by itself; these modules bind them at module scope by design. The kernel
# surface (resolver, engine, search, materialize, ...) must stay off this list.
ALLOWLIST_IMPURE: dict[str, str] = {
    "leitir._update_check": (
        "GitHub-releases update checker binds urllib.request/urllib.error at module "
        "scope; the network lookup runs only inside explicitly invoked functions"
    ),
    "leitir.doctor": (
        "diagnostic CLI probes network health; imports urllib.request/urllib.error "
        "(and leitir._update_check) at module scope; operator command, never kernel-imported"
    ),
    "leitir.exec_sandbox": (
        "containment launcher: module-scope subprocess import is the module's purpose "
        "(spawns donor/test processes inside the sandbox)"
    ),
    "leitir.sumdb": (
        "Go checksum-database client: module-scope `from urllib.request import Request` "
        "binding; fetches happen only inside explicitly invoked functions"
    ),
    "leitir.rerun": (
        "imports leitir.exec_sandbox at module scope (drives the containment launcher "
        "for reruns), pulling subprocess transitively"
    ),
    "leitir.bts_pipeline": (
        "imports leitir.rerun (transitively leitir.exec_sandbox/subprocess) at module scope"
    ),
    "leitir.bts_exit_gate": (
        "imports leitir.rerun (transitively leitir.exec_sandbox/subprocess) at module scope"
    ),
    "leitir.bts_bench": (
        "imports leitir.exec_sandbox and leitir.rerun at module scope, pulling subprocess"
    ),
    "leitir.transplant": (
        "imports leitir.bts_pipeline and leitir.rerun (transitively subprocess) at module scope"
    ),
    "leitir.occupied": (
        "imports leitir.rerun (transitively leitir.exec_sandbox/subprocess) at module scope"
    ),
    "leitir.exit_corpus": (
        "imports leitir.bts_exit_gate (transitively leitir.exec_sandbox/subprocess) at module scope"
    ),
    "leitir.pipeline_cli": (
        "pipeline CLI aggregates the exec_sandbox/rerun/transplant stages at module scope"
    ),
}

# Platform-scoped exemptions, keyed by the running interpreter's ``sys.platform``
# value ("linux", "darwin", "win32"). Use these for modules whose import is only
# valid on a specific OS (e.g. a Windows-only module importing ``winreg``): on
# other platforms the isolated import cannot succeed, and the entry here keeps
# the gate deterministic across OSes instead of flaky. Entries carry non-empty
# reasons exactly like ``ALLOWLIST_IMPURE``. Currently empty: the #206 survey at
# 9f24ca97210bbffb4a682f4def85ed84773d09ac found no platform-conditional
# module-scope imports in src/leitir (fcntl/msvcrt imports live inside functions).
PLATFORM_ALLOWLIST_IMPURE: dict[str, dict[str, str]] = {}

# Bounds for the isolated-child fan-out: at most this many child interpreters
# in flight (children are batched through a bounded thread pool to respect the
# suite runtime budget), and each child gets a hard wall-clock timeout.
_MAX_PROBE_WORKERS = 8
_CHILD_TIMEOUT_S = 60.0

# Isolated-child script templates ($-placeholders are substituted with repr()s).
_ENUMERATE_TEMPLATE = Template(
    """import importlib, json, sys
import pkgutil

sys.path.insert(0, $src)
errors = []


def _onerror(name):
    errors.append(name)


pkg = importlib.import_module($package)
modules = [pkg.__name__] + sorted(
    name for _, name, _ in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + ".", onerror=_onerror)
)
print(json.dumps({"modules": modules, "errors": sorted(set(errors))}))
"""
)

_PROBE_TEMPLATE = Template(
    """import importlib, json, sys

sys.path.insert(0, $src)
importlib.import_module($module)
present = sorted(m for m in $forbidden if m in sys.modules)
print(json.dumps({"present": present}))
"""
)

_AGGREGATE_IMPORT_TEMPLATE = Template(
    """import importlib, sys

sys.path.insert(0, $src)
$imports
"""
)


class _PurityResult(NamedTuple):
    """Outcome of importing one submodule in an isolated child."""

    module: str
    present: list[str]  # forbidden modules found in sys.modules (sorted)
    crash: str  # last stderr line (or synthetic message) if the import failed
    leftovers: list[str]  # files the import wrote into the child cwd (sorted)


def _run_isolated(script: str, cwd: Path) -> tuple[int, str, str]:
    env = dict(os.environ)
    # Do not let a parent environment credential leak into the child.
    env.pop("OPENROUTER_API_KEY", None)
    # Interpreter bytecode-cache writes are not a module side effect; keep the
    # child sandboxes free of __pycache__ noise.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(cwd),
            timeout=_CHILD_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"isolated child exceeded the {_CHILD_TIMEOUT_S:.0f}s timeout"
    return proc.returncode, proc.stdout, proc.stderr


def _stderr_tail(err: str, code: int) -> str:
    lines = [ln for ln in err.splitlines() if ln.strip()]
    return lines[-1] if lines else f"exit code {code}"


def _last_json_object(out: str) -> dict[str, object] | None:
    """Parse the last non-empty stdout line as a JSON object, else ``None``.

    An import-time ``print`` in probed code must degrade into a named gate
    failure, never an unhandled ``ValueError`` in the test process.
    """
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if not lines:
        return None
    try:
        payload = json.loads(lines[-1])
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _enumerate_filesystem(src_root: Path, package: str) -> list[str]:
    """Dotted module names for every ``*.py`` file under ``src_root/package``.

    ``__init__.py`` maps to the enclosing package name; everything else maps to
    its dotted module path. Sorted for determinism.
    """
    pkg_dir = src_root / package
    names: set[str] = set()
    for path in pkg_dir.rglob("*.py"):
        rel = path.relative_to(pkg_dir).with_suffix("")
        parts = rel.parts[:-1] if rel.parts[-1] == "__init__" else rel.parts
        names.add(package + ("" if not parts else "." + ".".join(parts)))
    return sorted(names)


def _enumerate(src_root: Path, package: str) -> tuple[list[str], list[str]]:
    """Authoritative pkgutil enumeration of ``package`` plus its filesystem cross-check.

    Returns ``(modules, problems)``: ``modules`` is the sorted pkgutil walk
    (authoritative); ``problems`` is empty when the filesystem walk of
    ``src_root/package/*.py`` matches it exactly and no package import errored
    during the walk.
    """
    script = _ENUMERATE_TEMPLATE.substitute(src=repr(str(src_root)), package=repr(package))
    code, out, err = _run_isolated(script, src_root)
    problems: list[str] = []
    if code != 0:
        return [], [f"pkgutil enumeration of {package!r} failed: {_stderr_tail(err, code)}"]
    payload = _last_json_object(out)
    if payload is None:
        return [], [f"pkgutil enumeration of {package!r} produced unparseable stdout"]
    raw_modules = payload.get("modules")
    raw_errors = payload.get("errors")
    if not isinstance(raw_modules, list):
        return [], [f"pkgutil enumeration of {package!r} produced an unexpected payload"]
    modules = sorted({str(name) for name in raw_modules})
    errors = sorted({str(name) for name in raw_errors}) if isinstance(raw_errors, list) else []
    if errors:
        problems.append(f"pkgutil walk hit import errors in packages: {errors}")
    fs_modules = _enumerate_filesystem(src_root, package)
    only_pkgutil = sorted(set(modules) - set(fs_modules))
    only_fs = sorted(set(fs_modules) - set(modules))
    if only_pkgutil or only_fs or len(modules) != len(fs_modules):
        problems.append(
            f"enumeration divergence: pkgutil walk has {len(modules)} modules, "
            f"filesystem walk has {len(fs_modules)}; pkgutil-only={only_pkgutil}; "
            f"filesystem-only={only_fs}"
        )
    return modules, problems


def _probe_module(src_root: Path, module: str, workroot: Path) -> _PurityResult:
    """Import ``module`` in an isolated child cwd'd to a fresh sandbox dir."""
    workdir = workroot / module
    workdir.mkdir(parents=True, exist_ok=True)
    script = _PROBE_TEMPLATE.substitute(
        src=repr(str(src_root)), module=repr(module), forbidden=repr(FORBIDDEN_MODULES)
    )
    code, out, err = _run_isolated(script, workdir)
    leftovers = sorted(p.name for p in workdir.iterdir())
    if code != 0:
        return _PurityResult(module, [], _stderr_tail(err, code), leftovers)
    payload = _last_json_object(out)
    if payload is None:
        return _PurityResult(module, [], "probe produced unparseable stdout (import-time print?)", leftovers)
    raw_present = payload.get("present")
    if not isinstance(raw_present, list):
        return _PurityResult(module, [], "probe produced an unexpected payload", leftovers)
    return _PurityResult(module, sorted(str(name) for name in raw_present), "", leftovers)


def _probe_all(
    src_root: Path,
    modules: Sequence[str],
    workroot: Path,
    max_workers: int = _MAX_PROBE_WORKERS,
) -> dict[str, _PurityResult]:
    """Probe every module in its own isolated child, bounded to ``max_workers``."""
    workers = max(1, min(max_workers, os.cpu_count() or 1, len(modules)))
    if workers == 1:
        results = [_probe_module(src_root, module, workroot) for module in modules]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda module: _probe_module(src_root, module, workroot), modules))
    return {result.module: result for result in results}


def _allowlist_reason_failures(allowlist: Mapping[str, str]) -> list[str]:
    """Entries without a non-empty reason string (SP-2 meta-assertion helper)."""
    return [
        f"{module}: allowlist entry is missing a non-empty reason string"
        for module in sorted(allowlist)
        if not isinstance(allowlist[module], str) or not allowlist[module].strip()
    ]


def _purity_gate_failures(
    src_root: Path,
    package: str,
    allowlist: Mapping[str, str],
    platform_allowlist: Mapping[str, Mapping[str, str]],
    workroot: Path,
) -> list[str]:
    """Run the enumerated purity gate over an arbitrary tree.

    Returns a sorted-stable list of human-readable failure lines, each naming
    the offending module: unallowlisted impurity, unallowlisted import crash,
    filesystem writes during import, enumeration divergence, or allowlist
    entries that are stale (name an unknown module, or a module that imports
    pure on this platform).
    """
    modules, problems = _enumerate(src_root, package)
    failures = [f"enumeration: {problem}" for problem in problems]
    effective = dict(allowlist)
    effective.update(platform_allowlist.get(sys.platform, {}))
    results = _probe_all(src_root, modules, workroot)
    for module in modules:  # already sorted
        result = results[module]
        if result.leftovers:
            failures.append(f"{module}: import wrote filesystem artifacts: {result.leftovers}")
        if result.crash:
            if module not in effective:
                failures.append(f"{module}: isolated import crashed: {result.crash}")
        elif result.present:
            if module not in effective:
                failures.append(f"{module}: pulled forbidden modules at import: {result.present}")
    for module in sorted(effective):
        if module not in results:
            failures.append(f"{module}: allowlist entry names a module the enumeration did not find")
        else:
            result = results[module]
            if not result.crash and not result.present and not result.leftovers:
                failures.append(f"{module}: stale allowlist entry (module imports pure on this platform)")
    return failures


def test_forbidden_modules_set_is_unchanged() -> None:
    """Tripwire: the forbidden-modules invariant must never be weakened."""
    assert FORBIDDEN_MODULES == [
        "docker",
        "trafilatura",
        "requests",
        "urllib.request",
        "http.client",
        "subprocess",
    ]


def test_enumeration_matches_filesystem() -> None:
    """AC-2: the pkgutil walk (authoritative) equals the on-disk *.py walk."""
    modules, problems = _enumerate(SRC, PACKAGE_NAME)
    assert problems == [], "\n".join(problems)
    fs_modules = _enumerate_filesystem(SRC, PACKAGE_NAME)
    assert modules == fs_modules, (
        f"pkgutil walk ({len(modules)} modules) diverges from filesystem walk "
        f"({len(fs_modules)} modules): pkgutil-only="
        f"{sorted(set(modules) - set(fs_modules))}, filesystem-only="
        f"{sorted(set(fs_modules) - set(modules))}"
    )


def test_allowlist_entries_carry_reasons() -> None:
    """AC-4/C-3: every allowlist entry (all platform branches) has a reason."""
    problems = _allowlist_reason_failures(ALLOWLIST_IMPURE)
    for platform_key in sorted(PLATFORM_ALLOWLIST_IMPURE):
        problems.extend(
            f"[{platform_key}] {problem}"
            for problem in _allowlist_reason_failures(PLATFORM_ALLOWLIST_IMPURE[platform_key])
        )
    assert problems == [], "\n".join(problems)


def test_allowlist_entry_without_reason_is_rejected() -> None:
    """SP-2: the reason meta-assertion rejects empty/blank reasons."""
    assert _allowlist_reason_failures({"leitir.fake": ""}) != []
    assert _allowlist_reason_failures({"leitir.fake": "   "}) != []
    assert _allowlist_reason_failures({"leitir.fake": "documented reason"}) == []


def test_all_submodules_pure_or_allowlisted(tmp_path: Path) -> None:
    """AC-1/C-1/C-4: every enumerated submodule is pure or allowlisted, and the
    allowlist exactly covers the impure set (no silent omission, no stale entry)."""
    failures = _purity_gate_failures(
        SRC, PACKAGE_NAME, ALLOWLIST_IMPURE, PLATFORM_ALLOWLIST_IMPURE, tmp_path
    )
    assert failures == [], "\n".join(failures)


def test_import_writes_no_filesystem_artifact(tmp_path: Path) -> None:
    modules, problems = _enumerate(SRC, PACKAGE_NAME)
    assert problems == [], "\n".join(problems)
    workdir = tmp_path / "sandbox"
    workdir.mkdir()
    imports = "\n".join(f"importlib.import_module({module!r})" for module in modules)
    script = _AGGREGATE_IMPORT_TEMPLATE.substitute(src=repr(str(SRC)), imports=imports)
    code, _out, err = _run_isolated(script, workdir)
    assert code == 0, f"import failed: {err}"
    # Importing every enumerated module must not create any files.
    leftovers = sorted(p.name for p in workdir.iterdir())
    assert leftovers == [], f"import wrote filesystem artifacts: {leftovers}"


def test_new_impure_module_fails_the_gate(tmp_path: Path) -> None:
    """AC-3/SP-1: a new impure submodule without an allowlist decision fails the
    gate by name, while a new pure submodule passes."""
    pkg = tmp_path / "fixture_tree"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "pure_mod.py").write_text("", encoding="utf-8")
    (pkg / "impure_mod.py").write_text(
        "import subprocess  # simulated new impure module\n", encoding="utf-8"
    )
    failures = _purity_gate_failures(tmp_path, "fixture_tree", {}, {}, tmp_path / "work")
    impure_failures = [f for f in failures if f.startswith("fixture_tree.impure_mod:")]
    assert impure_failures != [], f"gate must fail naming fixture_tree.impure_mod; got: {failures}"
    assert "subprocess" in impure_failures[0]
    assert not [f for f in failures if f.startswith("fixture_tree.pure_mod:")], failures


def test_platform_branch_scopes_allowlist_entries(tmp_path: Path) -> None:
    """SP-4/SP-3: a module unimportable on this platform fails the gate with its
    traceback unless exempted under the *running* platform's branch; a branch
    keyed to another platform must not exempt it."""
    pkg = tmp_path / "fixture_tree"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "platform_only.py").write_text(
        "import __leitir_fixture_platform_missing_module__  "
        "# simulates an OS-specific stack absent here\n",
        encoding="utf-8",
    )
    # A branch for a platform we are NOT running on must not exempt the module.
    other_platform = "vms" if sys.platform != "vms" else "unicos"
    failures = _purity_gate_failures(
        tmp_path,
        "fixture_tree",
        {},
        {other_platform: {"fixture_tree.platform_only": "other-OS-only stack"}},
        tmp_path / "work_other",
    )
    crash_failures = [f for f in failures if f.startswith("fixture_tree.platform_only:")]
    assert crash_failures != [], f"gate must fail naming the crashing module; got: {failures}"
    assert "crashed" in crash_failures[0]
    assert "ModuleNotFoundError" in crash_failures[0]
    # The running platform's branch exempts it with a documented reason.
    passing = _purity_gate_failures(
        tmp_path,
        "fixture_tree",
        {},
        {sys.platform: {"fixture_tree.platform_only": "platform-specific import; unavailable on this OS"}},
        tmp_path / "work_here",
    )
    assert not [f for f in passing if f.startswith("fixture_tree.platform_only:")], passing
