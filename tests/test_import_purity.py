"""Import-purity tests.

Importing ``leitir`` and its submodules must perform no network request, Docker
invocation or client creation, subprocess call, credential read, environment
credential read, or filesystem write. These checks run in a fresh child
interpreter so they are not fooled by an already-warm module cache in this test
process.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"

# Modules that would only be imported if an external-effect side effect occurred.
#
# Presence in sys.modules is a proxy, and for ``urllib.request`` it is a loose
# one: binding those names performs no I/O, so a module-scope import would not
# by itself breach the stated invariant. The kernel's HTTP clients defer the
# import into the calling methods to keep this list meaningful, which also keeps
# a bare ``import leitir.resolver`` from materialising an HTTP stack. Narrowing
# the list to what it really proves is a separate, reviewable change.
FORBIDDEN_MODULES = [
    "docker",
    "trafilatura",
    "requests",
    "urllib.request",
    "http.client",
    "subprocess",
]


def _run_isolated(script: str, cwd: Path) -> tuple[int, str, str]:
    env = dict(os.environ)
    # Do not let a parent environment credential leak into the child.
    env.pop("OPENROUTER_API_KEY", None)
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd),
    )
    return proc.returncode, proc.stdout, proc.stderr


def test_import_leitir_does_not_load_external_effect_modules(tmp_path):
    script = textwrap.dedent(
        f"""
        import json, sys
        sys.path.insert(0, {str(SRC)!r})
        import leitir
        import leitir.adapters, leitir.cli, leitir.credentials, leitir.discovery_search
        import leitir.engine, leitir.logging, leitir.parity, leitir.resolver, leitir.search
        import leitir.tree, leitir.lockfiles, leitir.corpus, leitir.materialize, leitir.snapshot, leitir.sbom, leitir.apisurface, leitir.examples, leitir.diff, leitir.trust, leitir.info
        present = [m for m in {FORBIDDEN_MODULES!r} if m in sys.modules]
        print(json.dumps({{"present": present}}))
        """
    )
    code, out, err = _run_isolated(script, tmp_path)
    assert code == 0, f"import failed: {err}"
    payload = json.loads(out)
    assert payload["present"] == [], (
        f"importing leitir pulled in external-effect modules: {payload['present']}"
    )


def test_import_writes_no_filesystem_artifact(tmp_path):
    workdir = tmp_path / "sandbox"
    workdir.mkdir()
    script = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {str(SRC)!r})
        import leitir
        import leitir.adapters, leitir.cli, leitir.credentials, leitir.discovery_search
        import leitir.engine, leitir.logging, leitir.parity, leitir.resolver, leitir.search
        import leitir.tree, leitir.lockfiles, leitir.corpus, leitir.materialize, leitir.snapshot, leitir.sbom, leitir.apisurface, leitir.examples, leitir.diff, leitir.trust, leitir.info
        """
    )
    code, _out, err = _run_isolated(script, workdir)
    assert code == 0, f"import failed: {err}"
    # Importing the kernel must not create any files.
    leftovers = [p.name for p in workdir.iterdir()]
    assert leftovers == [], f"import wrote filesystem artifacts: {leftovers}"
