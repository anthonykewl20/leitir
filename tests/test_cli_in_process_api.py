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
import logging
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

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


def test_call_json_reports_handler_level_malformed_usage_with_a_message():
    """A rejection raised inside a verb's own dispatch code (not argparse
    itself) prints through the captured stderr buffer, so the caller gets
    a non-empty, actionable message alongside the exit code."""
    with pytest.raises(LeitirCallError) as excinfo:
        call_json(["search"])
    assert excinfo.value.exit_code == 2
    assert "one of --repo, --package, --global, or --corpus is required" in str(excinfo.value)
    assert excinfo.value.stderr.strip() != ""


def test_call_json_argparse_level_error_has_correct_exit_code_but_empty_message(capsys):
    """Documented limitation: argparse's own parser-level errors (an
    unrecognized flag here) write to the real process stderr rather than
    the io.StringIO buffer call_json passes as main()'s stderr, since
    build_parser() does not redirect argparse's own error()/print_help()
    output. The exit code is still correct and no SystemExit escapes;
    only the captured message is empty for this specific error class."""
    with pytest.raises(LeitirCallError) as excinfo:
        call_json(["search", "--this-flag-does-not-exist"])
    assert excinfo.value.exit_code == 2
    assert excinfo.value.stderr == ""
    # The real message did go somewhere: argparse's own usage/error text
    # landed on the actual process stderr, not silently lost.
    captured = capsys.readouterr()
    assert "unrecognized arguments" in captured.err


def test_call_json_captures_warnings_per_call_under_concurrency(tmp_path, monkeypatch):
    """Issue #281: concurrent ``call_json`` calls must each capture their own
    ``logging`` warnings.

    ``_configure_logging_from_env`` once installed a single shared
    ``StreamHandler`` on the process-global ``"leitir"`` logger and swapped it
    per call, so two overlapping in-flight calls raced on that handler: a
    warning logged during one call's window could be routed into another
    call's captured buffer, or vanish from the call that logged it. The fix
    routes records through a thread-routed handler -- each invocation binds
    its own ``(stream, level)`` route for its calling thread -- so this test
    drives genuinely concurrent calls (a barrier aligns their windows) and
    asserts each call's captured stderr contains exactly its own warning and
    error, and no other call's.
    """
    import itertools

    import leitir.corpus as corpus_mod

    _corpus(tmp_path)
    sequence = itertools.count()
    tokens: list[str] = []

    def recording_record_trust(spec, root):
        # Stand-in for the trust verb's work: emit the call's warning through
        # the "leitir" logger, then fail the call so the captured stderr
        # surfaces in LeitirCallError. The real record_trust is deliberately
        # not invoked here -- it rewrites the manifest inside the shelf, and
        # a concurrent reader's load-time tree verification transiently sees
        # the writer's staging temp file (a separate, pre-existing race,
        # unrelated to log routing).
        token = f"sentinel-{next(sequence):04d}"
        logging.getLogger("leitir").warning("attributable warning %s", token)
        tokens.append(token)
        raise RuntimeError(f"stop after warning {token}")

    monkeypatch.setattr(corpus_mod, "record_trust", recording_record_trust)
    argv = ["trust", f"acme/widget@{SHA}", "--root", str(tmp_path), "--json"]

    rounds = 6
    workers = 8
    for _ in range(rounds):
        start = threading.Barrier(workers)
        failures: list[LeitirCallError] = []

        def one_call() -> None:
            start.wait()
            try:
                call_json(argv)
            except LeitirCallError as exc:
                failures.append(exc)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(one_call) for _ in range(workers)]
            for future in futures:
                future.result()

        assert len(failures) == workers
        for exc in failures:
            own = [token for token in tokens if token in exc.stderr]
            assert len(own) == 1, (
                f"call captured {own!r}, expected exactly its own sentinel"
            )
            assert "attributable warning" in exc.stderr
            assert f"leitir: error: stop after warning {own[0]}" in exc.stderr
            others = [token for token in tokens if token != own[0] and token in exc.stderr]
            assert not others, f"call captured another call's warning: {others!r}"


def test_concurrent_calls_with_different_levels_gate_per_route(tmp_path, monkeypatch):
    """A ``--debug`` call and a default-level call running concurrently must
    each get their own requested verbosity: the debug call's DEBUG records
    reach its buffer; the default call's DEBUG records are gated by its own
    route level, never leaking into either buffer."""
    import leitir.corpus as corpus_mod

    _corpus(tmp_path)

    def level_probe_record_trust(spec, root):
        logger = logging.getLogger("leitir")
        logger.debug("debug probe for %s", spec)
        logger.warning("warning probe for %s", spec)
        raise RuntimeError("probe done")

    monkeypatch.setattr(corpus_mod, "record_trust", level_probe_record_trust)
    spec = f"acme/widget@{SHA}"
    debug_argv = ["--debug", "trust", spec, "--root", str(tmp_path), "--json"]
    plain_argv = ["trust", spec, "--root", str(tmp_path), "--json"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        debug_call = pool.submit(call_json, debug_argv)
        plain_call = pool.submit(call_json, plain_argv)
        with pytest.raises(LeitirCallError) as debug_error:
            debug_call.result()
        with pytest.raises(LeitirCallError) as plain_error:
            plain_call.result()

    assert "debug probe" in debug_error.value.stderr
    assert "warning probe" in debug_error.value.stderr
    assert "debug probe" not in plain_error.value.stderr
    assert "warning probe" in plain_error.value.stderr


def test_nested_call_restores_the_outer_call_logging_route(tmp_path, monkeypatch):
    """A nested in-process call must hand the logging route back to the outer
    call when it finishes: the outer call's later warnings return to the
    outer buffer, and the inner call's captured stderr stays its own."""
    import leitir.corpus as corpus_mod

    _corpus(tmp_path)

    def nesting_record_trust(spec, root):
        logger = logging.getLogger("leitir")
        logger.warning("outer before inner")
        with pytest.raises(LeitirCallError) as inner_error:
            call_json(["get", "not-a-spec", "--root", str(root), "--json"])
        assert "not-a-spec" in inner_error.value.stderr
        assert "outer before inner" not in inner_error.value.stderr
        logger.warning("outer after inner")
        raise RuntimeError("outer done")

    monkeypatch.setattr(corpus_mod, "record_trust", nesting_record_trust)

    with pytest.raises(LeitirCallError) as outer_error:
        call_json(["trust", f"acme/widget@{SHA}", "--root", str(tmp_path), "--json"])

    assert "outer before inner" in outer_error.value.stderr
    assert "outer after inner" in outer_error.value.stderr
    assert "not-a-spec" not in outer_error.value.stderr
