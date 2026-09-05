"""Real PyPI source and signed-cache tampering; no fixture transport or source."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
    reason="set LEITIR_ENABLE_LIVE_E2E=1 for real registry/cache integrity probes",
)


@pytest.mark.live
def test_info_does_not_authenticate_fabricated_cached_signatures(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from leitir.manifest_auth import (
        canonical_json,
        derive_projection,
        key_id_for_public_key,
        sign_projection,
    )

    root = tmp_path / "corpus"
    def invoke(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "leitir.cli", *args, "--root", str(root), "--json"],
            capture_output=True, text=True, timeout=180, check=False,
        )

    fetched = invoke("info", "pypi:packaging@24.1")
    assert fetched.returncode == 0, fetched.stderr
    original = json.loads(fetched.stdout)
    entry = json.loads((root / "sources.json").read_text())[0]
    target = root / entry["path"]
    manifest = json.loads((target / "leitir-manifest.json").read_text())
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw()
    trusted = tmp_path / "trusted-keys.json"
    trusted.write_text(json.dumps({"schema_version": 2, "keys": [{
        "key_id": key_id_for_public_key(public),
        "public_key_b64": base64.b64encode(public).decode(),
        "note": "Ephemeral live probe; private key is never persisted",
    }]}))
    signature = target.parent / (target.name + ".leitir-manifest-auth.json")
    signature.write_bytes(canonical_json(sign_projection(derive_projection(manifest), key)))
    args = ("info", "pypi:packaging@24.1", "--require-manifest-auth", "--trusted-keys", str(trusted))
    control = invoke(*args)
    assert control.returncode == 0, control.stderr
    cache = Path(original["paths"]["api_index"])
    payload = json.loads(cache.read_text())
    symbol = next(item for item in payload["symbols"] if item["kind"] == "class")
    symbol.update(name="AAAFabricatedSignature", qualified_name="AAAFabricatedSignature", signature="(invented)")
    cache.write_text(json.dumps(payload))
    result = invoke(*args)
    assert result.returncode == 0, result.stderr
    assert "AAAFabricatedSignature" not in result.stdout
    assert "AAAFabricatedSignature" not in cache.read_text()
    assert json.loads(result.stdout)["provenance"]["verified"] is True
    # Recomputed classification hashes beside an altered cache are not source
    # authority either. Keep the real snippet metadata but forge its content.
    from leitir.examples import classify_example

    examples = Path(original["paths"]["examples_index"])
    sample = json.loads(examples.read_text())
    assert sample["snippets"]
    snippet = sample["snippets"][0]
    snippet["code"] += "\nAAAFabricatedExample()\n"
    snippet["classification"] = classify_example(snippet).as_dict()
    examples.write_text(json.dumps(sample))
    output = invoke(*args)
    assert output.returncode == 0, output.stderr
    assert "AAAFabricatedExample" not in output.stdout
    assert "AAAFabricatedExample" not in examples.read_text()
    # A valid cache still cannot authorize a corrupted donor tree/signature.
    record = json.loads(signature.read_text())
    record["signature"] = base64.b64encode(bytes(64)).decode()
    signature.write_bytes(canonical_json(record))
    rejected = invoke(*args)
    assert rejected.returncode != 0
    assert "AAAFabricatedSignature" not in rejected.stdout
