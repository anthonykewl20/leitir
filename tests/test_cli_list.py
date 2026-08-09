from __future__ import annotations

import io
import json

from leitir.cli import ExitCode, main
from leitir.corpus import write_sources
from leitir.materialize import MANIFEST_NAME
from leitir.treehash import compute_materialized_tree_hash, manifest_digest_fields


SHA = "b" * 40


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


def _invoke(argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_trust_writes_manifest_and_json_then_list_surfaces_score(tmp_path):
    target = _corpus(tmp_path)
    spec = f"acme/widget@{SHA}"
    code, out, err = _invoke(["trust", spec, "--root", str(tmp_path), "--json"])
    assert code == ExitCode.SUCCESS
    assert err == ""
    payload = json.loads(out)
    assert payload["spec"] == spec
    assert set(payload) == {"schema_version", "name", "path", "spec", "trust_breakdown", "trust_score"}
    assert payload["schema_version"] == 1
    assert [item["factor"] for item in payload["trust_breakdown"]] == sorted(item["factor"] for item in payload["trust_breakdown"])
    manifest = json.loads((target / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["trust_score"] == payload["trust_score"]
    assert manifest["trust_breakdown"] == payload["trust_breakdown"]

    code, listed, _ = _invoke(["list", "--root", str(tmp_path)])
    assert code == ExitCode.SUCCESS
    assert f"trust={payload['trust_score']}" in listed
    code, listed, _ = _invoke(["list", "--root", str(tmp_path), "--json"])
    assert json.loads(listed)[0]["trust_score"] == payload["trust_score"]


def test_trust_human_prints_score_and_breakdown(tmp_path):
    _corpus(tmp_path)
    code, out, err = _invoke(["trust", f"acme/widget@{SHA}", "--root", str(tmp_path)])
    assert code == ExitCode.SUCCESS
    assert err == ""
    assert "widget trust=" in out
    assert "  verification:" in out
    assert " evidence=" in out
