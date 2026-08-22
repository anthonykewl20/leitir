"""Opt-in live end-to-end coverage for materialized-tree verification."""

from __future__ import annotations

import io
import json
import os

import pytest

from leitir.cli import ExitCode, main
from leitir.corpus import load_sources

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("LEITIR_ENABLE_LIVE_E2E") != "1",
        reason="set LEITIR_ENABLE_LIVE_E2E=1 to run live tree-hash verification",
    )
]

SPEC = "npm:is-number@7.0.0"


def _invoke(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _list_json(root) -> list[dict[str, object]]:
    code, out, _err = _invoke(["list", "--root", str(root), "--json"])
    assert code == ExitCode.SUCCESS
    return json.loads(out)


def test_live_tree_hash_detects_tampering_and_recovers(tmp_path):
    code, _out, err = _invoke(["get", SPEC, "--root", str(tmp_path)])
    assert code == ExitCode.SUCCESS, err
    assert any(item.get("verification") == "verified" for item in _list_json(tmp_path))

    entry = load_sources(tmp_path)[0]
    index = tmp_path / entry["path"] / "index.js"
    data = index.read_bytes()
    assert data
    index.write_bytes(bytes([data[0] ^ 1]) + data[1:])

    assert not any(
        item.get("verification") == "verified" for item in _list_json(tmp_path)
    )

    code, _out, err = _invoke(["get", SPEC, "--root", str(tmp_path)])
    assert code == ExitCode.SUCCESS, err
    assert any(item.get("verification") == "verified" for item in _list_json(tmp_path))
