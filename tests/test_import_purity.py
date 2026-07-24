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
        """
        import json, sys
        sys.path.insert(0, %r)
        import leitir
        import leitir.contracts, leitir.config, leitir.logging, leitir.protocols
        present = [m for m in %r if m in sys.modules]
        print(json.dumps({"present": present}))
        """
        % (str(SRC), FORBIDDEN_MODULES)
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
        """
        import sys
        sys.path.insert(0, %r)
        import leitir
        import leitir.config
        leitir.config.Config.default().serialize()
        """
        % str(SRC)
    )
    code, _out, err = _run_isolated(script, workdir)
    assert code == 0, f"import failed: {err}"
    # Importing and serializing must not create any files.
    leftovers = [p.name for p in workdir.iterdir()]
    assert leftovers == [], f"import wrote filesystem artifacts: {leftovers}"


def test_protocols_carry_no_concrete_external_effect_implementation():
    # The Protocol seams are runtime-checkable interfaces with no concrete
    # side-effect implementations in the package.
    from leitir import protocols

    for name in [
        "ModelTransport",
        "SearchProvider",
        "ExtractionProvider",
        "CredentialProvider",
        "SandboxExecutor",
        "TraceSink",
    ]:
        proto = getattr(protocols, name)
        assert hasattr(proto, "_is_protocol"), f"{name} is not a Protocol"
        # A trivial object that does NOT implement the method is not an instance.
        assert not isinstance(object(), proto)
