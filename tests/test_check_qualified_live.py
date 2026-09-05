"""Actual Requests consumers and qualified source evidence through the CLI."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1", reason="actual Requests source requires LEITIR_ENABLE_LIVE_E2E=1")


@pytest.mark.live
def test_requests_qualified_calls_and_public_reexports(tmp_path: Path) -> None:
    root = tmp_path / "corpus"
    cases = [
        ('import requests\nrequests.help.info()\n', False),
        ('import requests.help\nrequests.help.info()\n', True),
        ('import requests.help as helper\nhelper.info()\n', True),
        ('from requests import help\nhelp.info()\n', True),
        ('import requests\nrequests.help.info()\nimport requests.help\n', False),
        ('import requests\ndef other():\n    import requests.help\nrequests.help.info()\n', False),
        ('import requests\nrequests.utils.parse_header_links("")\n', True),
        ('import requests\nrequests.parse_header_links("value")\n', False),
        ('from requests import parse_header_links\nparse_header_links("value")\n', False),
        ('import requests.utils\nrequests.utils.parse_header_links("value")\n', True),
        ('from requests.utils import parse_header_links\nparse_header_links("value")\n', True),
        ('import requests\nrequests.get("https://example.com")\n', True),
        ('from requests import Session\nSession()\n', True),
        ('import requests as lib\nlib.parse_header_links("")\nimport requests.utils as lib\n', False),
        ('import requests.utils as lib\ndef use():\n    import requests as lib\n    return lib.parse_header_links("")\nuse()\n', False),
        ('import requests.Session as S\nS.get(None, "")\n', False),
        ('from requests.Session import get\nget(None, "")\n', False),
        ('def use():\n    import requests.utils as lib\n    return lib.parse_header_links("")\nuse()\n', True),
        ('import requests.utils as lib\nlib.parse_header_links("")\nimport requests.utils as lib\nlib.parse_header_links("")\n', True),
    ]
    for position, (consumer, supported) in enumerate(cases):
        path = tmp_path / f"consumer{position}.py"
        path.write_text(consumer)
        result = subprocess.run([sys.executable, "-m", "leitir.cli", "check", str(path), "--against", "pypi:requests@2.32.3", "--root", str(root), "--json"], capture_output=True, text=True, timeout=180, check=False)
        assert result.returncode in {0, 1}, result.stderr
        report = json.loads(result.stdout)
        assert report["counts"]["sites_examined"] > 0
        if supported:
            assert report["counts"]["sites_ok"] > 0, report
        else:
            assert report["counts"]["sites_ok"] == 0, report
            assert report["counts"]["sites_unresolved"] + report["counts"]["sites_violation"] > 0

    # The qualified checker still relies on the same authenticated shelf gate.
    # Mutate actual downloaded bytes and exercise that gate directly, without
    # allowing the CLI's normal online re-materialization to repair the donor.
    from leitir.materialize import read_valid_manifest

    entry = json.loads((root / "sources.json").read_text())[0]
    target = root / entry["path"]
    assert read_valid_manifest(target, entry["owner"], entry["repo"], entry["commit_sha"], host=entry["host"]) is not None
    source = next(target.rglob("api.py"))
    source.write_bytes(source.read_bytes() + b"\n# altered downloaded source\n")
    assert read_valid_manifest(target, entry["owner"], entry["repo"], entry["commit_sha"], host=entry["host"]) is None
