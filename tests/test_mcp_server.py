"""Tests for the optional MCP server (issue #266 task A4).

``leitir.mcp.bridge`` is stdlib-only and importable without the ``mcp`` extra,
so most of this file runs unconditionally. The one live-protocol test that
needs the real SDK is gated behind ``pytest.importorskip("mcp")``. The
missing-extra test simulates absence of the extra deterministically (via
``sys.modules["mcp"] = None``) so it passes the same way whether or not the
extra happens to be installed in the environment running the suite.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

import pytest

from leitir.mcp import bridge


class _FakeCompletedProcess:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_subprocess(monkeypatch: pytest.MonkeyPatch, result: _FakeCompletedProcess) -> list[list[str]]:
    """Replace subprocess.run inside leitir.mcp.bridge, recording every argv."""
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> _FakeCompletedProcess:
        calls.append(cmd)
        return result

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


# ---------------------------------------------------------------------------
# Each of the five tools returns the CLI's JSON unmodified.
# ---------------------------------------------------------------------------


def test_info_returns_cli_json_unmodified(monkeypatch: pytest.MonkeyPatch) -> None:
    document = {
        "provenance": {"owner": "psf", "repo": "requests", "commit_sha": "abc123"},
        "api": {"symbols": 3, "method": "python", "index_path": "/x", "top_symbols": []},
        "examples": {"count": 1, "index_path": "/y", "top": []},
        "trust": {"score": 42},
        "license": {"identifier": "Apache-2.0", "method": "spdx", "confidence": "high"},
        "routing": {"verdict": "allow", "reason": "permissive"},
        "parity": {"parity": "exact"},
        "paths": {"tree": "/z"},
        "extra_nested": {"a": [1, 2, {"b": "c"}]},
    }
    calls = _patch_subprocess(monkeypatch, _FakeCompletedProcess(0, stdout=json.dumps(document)))
    result = bridge.info("requests", root="/corpus")
    assert result == document
    [argv] = calls
    assert argv[3:6] == ["info", "requests", "--json"]
    assert "--root" in argv and "/corpus" in argv


def test_api_returns_cli_json_unmodified(monkeypatch: pytest.MonkeyPatch) -> None:
    document = {"schema_version": "leitir-api-v1", "symbols": [{"kind": "function", "qualified_name": "f"}]}
    calls = _patch_subprocess(monkeypatch, _FakeCompletedProcess(0, stdout=json.dumps(document)))
    result = bridge.api("owner/repo@sha")
    assert result == document
    [argv] = calls
    assert argv[3:6] == ["api", "owner/repo@sha", "--json"]


def test_examples_returns_cli_json_unmodified(monkeypatch: pytest.MonkeyPatch) -> None:
    document = {"schema_version": "leitir-examples-v1", "count": 2, "top": [{"path": "a.py", "line": 1}]}
    calls = _patch_subprocess(monkeypatch, _FakeCompletedProcess(0, stdout=json.dumps(document)))
    result = bridge.examples("owner/repo@sha", local=True)
    assert result == document
    [argv] = calls
    assert argv[3:6] == ["examples", "owner/repo@sha", "--json"]
    assert "--local" in argv


def test_diff_returns_cli_json_unmodified(monkeypatch: pytest.MonkeyPatch) -> None:
    document = {"schema_version": "leitir-diff-v1", "files": [{"path": "a.py", "status": "modified"}]}
    calls = _patch_subprocess(monkeypatch, _FakeCompletedProcess(0, stdout=json.dumps(document)))
    result = bridge.diff("pkg@1.0.0", "pkg@1.1.0", cwd="/proj")
    assert result == document
    [argv] = calls
    assert argv[3:7] == ["diff", "pkg@1.0.0", "pkg@1.1.0", "--json"]
    assert "--cwd" in argv and "/proj" in argv


def test_search_returns_cli_json_unmodified_and_has_no_json_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    document = {
        "spec_digest": "sha256:deadbeef",
        "coverage": {"status": "complete_for_declared_universe"},
        "matches": [],
        "resolution": {"strategy": "scoped_exhaustive"},
    }
    calls = _patch_subprocess(monkeypatch, _FakeCompletedProcess(0, stdout=json.dumps(document)))
    result = bridge.search(must=["exact_text:foo"], repo="owner/repo", commit="a" * 40)
    assert result == document
    [argv] = calls
    assert argv[3] == "search"
    assert "--json" not in argv  # search has no --json flag: JSON is always its stdout
    assert argv.count("--must") == 1
    assert "exact_text:foo" in argv
    assert "--repo" in argv and "owner/repo" in argv
    assert "--commit" in argv and "a" * 40 in argv


# ---------------------------------------------------------------------------
# corpus search preserves coverage-honesty fields verbatim.
# ---------------------------------------------------------------------------


def test_corpus_search_preserves_coverage_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    document = {
        "spec_digest": "sha256:cafef00d",
        "coverage": {"status": "partial"},
        "matches": [{"path": "lib/x.py", "line": 10}],
        "resolution": {"strategy": "corpus"},
        "shelves_searched": [["github", "owner", "repo", "sha"]],
        "shelves_excluded": [
            {"identity": "npm:left-pad@1.0.0", "reason": "unindexed", "detail": "no trigram index"}
        ],
        "shelves_declared_total": 2,
        "corpus_status": "partial",
    }
    calls = _patch_subprocess(monkeypatch, _FakeCompletedProcess(0, stdout=json.dumps(document)))
    result = bridge.search(must=["exact_text:foo"], corpus=True)
    # The three coverage-honesty fields must survive to the caller untouched:
    # an MCP client that sees matches but not these could wrongly conclude a
    # symbol exists nowhere when shelves were actually excluded.
    assert result["corpus_status"] == "partial"
    assert result["shelves_excluded"] == document["shelves_excluded"]
    assert result["shelves_declared_total"] == 2
    assert result == document  # byte-for-byte, not reshaped/summarized
    [argv] = calls
    assert "--corpus" in argv


# ---------------------------------------------------------------------------
# A failing leitir invocation surfaces a structured error with its exit code.
# ---------------------------------------------------------------------------


def test_cli_failure_raises_structured_error_with_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_subprocess(
        monkeypatch,
        _FakeCompletedProcess(3, stdout="", stderr="leitir: error: package not found on npm\n"),
    )
    with pytest.raises(bridge.LeitirCLIError) as excinfo:
        bridge.info("does-not-exist")
    exc = excinfo.value
    assert exc.exit_code == 3
    assert exc.message == "package not found on npm"
    payload = exc.to_dict()
    assert payload["exit_code"] == 3
    assert payload["message"] == "package not found on npm"
    assert payload["argv"][:2] == ["info", "does-not-exist"]


def test_cli_success_but_invalid_json_still_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_subprocess(monkeypatch, _FakeCompletedProcess(0, stdout="not json", stderr=""))
    with pytest.raises(bridge.LeitirCLIError) as excinfo:
        bridge.api("owner/repo@sha")
    assert "not valid JSON" in excinfo.value.message


def test_cli_timeout_raises_structured_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 1))

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(bridge.LeitirCLIError) as excinfo:
        bridge.examples("owner/repo@sha")
    assert excinfo.value.exit_code == 124


# ---------------------------------------------------------------------------
# Importing/using leitir.mcp without the extra gives an actionable message.
# ---------------------------------------------------------------------------


def test_bare_import_of_leitir_mcp_always_succeeds() -> None:
    # leitir.mcp itself is stdlib-only at the package level; only building or
    # running the actual protocol server needs the mcp SDK (see below).
    import leitir.mcp

    assert leitir.mcp.LeitirCLIError is bridge.LeitirCLIError


def test_missing_extra_gives_actionable_message(monkeypatch: pytest.MonkeyPatch) -> None:
    import leitir.mcp

    # Simulate the mcp extra being absent, deterministically, regardless of
    # whether it is actually installed in the environment running this test:
    # `None` in sys.modules makes any `import mcp` raise ImportError.
    monkeypatch.setitem(sys.modules, "mcp", None)

    with pytest.raises(leitir.mcp.MissingExtraError) as excinfo:
        leitir.mcp.build_server()

    message = str(excinfo.value)
    assert "pip install" in message
    assert "leitir[mcp]" in message
    assert "mcp" in message.lower()


# ---------------------------------------------------------------------------
# Live-protocol test: gated behind the mcp extra actually being installed.
# ---------------------------------------------------------------------------


def test_live_server_registers_exactly_the_five_tools() -> None:
    pytest.importorskip("mcp")
    import asyncio

    from leitir.mcp.server import build_server

    server = build_server()

    async def _list() -> list[str]:
        tools = await server.list_tools()
        return sorted(tool.name for tool in tools)

    names = asyncio.run(_list())
    assert names == ["api", "diff", "examples", "info", "search"]
