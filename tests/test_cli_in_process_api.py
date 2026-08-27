"""Issue #271: leitir is callable in-process without shelling out to itself.

``leitir.api.call_json`` is the first concrete consumer of the #271 split:
it calls :func:`leitir.cli.main` directly in the current interpreter and
returns the CLI's own structured JSON, the same contract
``leitir.mcp.bridge.run_leitir_json`` gets today only via a
``subprocess.run([sys.executable, "-m", "leitir.cli", ...])`` call. This
test proves the in-process path actually avoids a subprocess (by making
``subprocess.run`` raise if invoked at all) and still returns the same
structured result a user gets from ``leitir list --json`` on the command
line.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from leitir.api import LeitirCallError, call_json
from leitir.corpus import write_sources
from leitir.materialize import MANIFEST_NAME
from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields

SHA = "c" * 40


def _corpus(root):
    relative = f"repos/github.com/acme/widget/{SHA}"
    target = root / relative
    (target / "tests").mkdir(parents=True)
    manifest = {
        "host": "github.com",
        "owner": "acme",
        "repo": "widget",
        "commit_sha": SHA,
        "fetch_method": "codeload-tarball",
        "spec": f"acme/widget@{SHA}",
        "repo_url": "https://github.com/acme/widget",
        "fetched_at": "2026-08-01T00:00:00Z",
        "verified": False,
        "verified_at": None,
        "parity": "unknown",
        "docs_urls": [],
        "entry_points": [],
    }
    digest, scope = compute_materialized_tree_hash(target)
    manifest.update(manifest_digest_fields(digest, scope=scope))
    (target / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    entry = {
        "name": "widget",
        "host": "github.com",
        "owner": "acme",
        "repo": "widget",
        "commit_sha": SHA,
        "path": relative,
        "fetched_at": manifest["fetched_at"],
    }
    write_sources(root, [entry])
    return target


def test_call_json_returns_structured_result_without_a_subprocess(tmp_path, monkeypatch):
    _corpus(tmp_path)

    def _forbidden_subprocess_run(*_args, **_kwargs):
        raise AssertionError(
            "call_json must not spawn a subprocess -- it should call "
            "leitir.cli.main() directly in this interpreter"
        )

    monkeypatch.setattr(subprocess, "run", _forbidden_subprocess_run)

    spec = f"acme/widget@{SHA}"
    document = call_json(["trust", spec, "--root", str(tmp_path), "--json"])

    assert document["spec"] == spec
    assert document["name"] == "widget"
    assert set(document) == {
        "schema_version",
        "name",
        "path",
        "spec",
        "trust_breakdown",
        "trust_score",
    }


def test_call_json_raises_with_exit_code_and_message_on_failure(tmp_path):
    with pytest.raises(LeitirCallError) as excinfo:
        call_json(["get", "not-a-spec", "--root", str(tmp_path), "--json"])
    assert excinfo.value.exit_code != 0
    assert excinfo.value.argv == ["get", "not-a-spec", "--root", str(tmp_path), "--json"]
