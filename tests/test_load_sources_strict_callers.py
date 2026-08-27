"""Regression tests for issue #268.

`leitir.corpus.load_sources` used to silently recover from a corrupt
catalog (`sources.json`) by renaming it to `sources.json.bak` and returning
`[]`, unless a caller opted into `strict=True`. PR #267 adopted
`strict=True` for the corpus-wide search eligibility path only. This file
exercises every other caller this issue's audit determined would produce a
false success or a destructive action on a corrupt catalog, and pins that
each one now fails closed instead: real materialized shelves sit untouched
on disk, the catalog is corrupted, and the command/function must reject
rather than silently proceed as if the corpus were empty.

Since #268 P1 (independent review of PR #276), a non-strict read of a
corrupt catalog no longer renames the file at all -- it is left exactly as
it was, so every subsequent read, in this process or any other, keeps
re-detecting the same corruption honestly. See
`test_three_successive_processes_never_launder_a_corrupt_catalog` for the
regression test that exercises this across genuinely separate processes.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import tarfile
from pathlib import Path

import pytest
from _http_server import json_body, routed_server
from test_snapshot import SHA_A, make_corpus

from leitir.cli import ExitCode, _require_all_shelves_authenticated, main
from leitir.corpus import _upsert, load_sources, remove_source
from leitir.docpointers import POINTERS_NAME
from leitir.doctor import run_doctor
from leitir.materialize import VerificationError
from leitir.snapshot import export_corpus

_PIN_SHA = "d" * 40


def _pypi_tarball(commit_sha: str = _PIN_SHA) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        content = b"pinned\n"
        member = tarfile.TarInfo(f"demo-{commit_sha}/README.md")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return data.getvalue()


def _pypi_routes() -> dict[str, object]:
    return {
        "/pypi/demo/1.2/json": (
            200,
            {},
            json_body(
                {"info": {"project_urls": {"Source": "https://github.com/acme/demo"}}}
            ),
        ),
        "/repos/acme/demo/git/ref/tags/v1.2": (
            200,
            {},
            json_body({"object": {"type": "commit", "sha": _PIN_SHA}}),
        ),
        f"/acme/demo/tar.gz/{_PIN_SHA}": (200, {}, _pypi_tarball()),
    }


def _corrupt_catalog(root) -> None:
    (root / "sources.json").write_bytes(b"{not valid json at all")


def _run(args: list[str]) -> tuple[int, object, str]:
    out = io.StringIO()
    err = io.StringIO()
    code = main(args, stdout=out, stderr=err)
    payload = json.loads(out.getvalue()) if out.getvalue().strip() else {}
    return code, payload, err.getvalue()


def test_upsert_corrupt_catalog_fails_closed_not_silent_data_loss(tmp_path):
    """`_upsert` backs every materialize-write. A corrupt catalog must not be
    silently treated as empty and then overwritten with only the new entry,
    discarding the record of every previously catalogued source.
    """
    entries = make_corpus(tmp_path)
    _corrupt_catalog(tmp_path)

    new_entry = {
        "name": "gamma",
        "host": "github.com",
        "owner": "gamma",
        "repo": "three",
        "commit_sha": "3" * 40,
        "path": f"repos/github.com/gamma/three/{'3' * 40}",
        "fetched_at": "2026-01-02T03:04:05Z",
    }
    with pytest.raises(VerificationError):
        _upsert(tmp_path, new_entry)

    # Neither previously materialized shelf's bytes were touched.
    for entry in entries:
        assert (tmp_path / str(entry["path"]) / "src" / "data.bin").exists()
    # Strict mode raises before any recovery happens: the corrupt file is
    # left exactly as it was (never renamed -- see #268 P1), and --
    # critically -- was never replaced by a fresh sources.json containing
    # only the new entry.
    assert (tmp_path / "sources.json").read_bytes() == b"{not valid json at all"
    assert not (tmp_path / "sources.json.bak").exists()


def test_remove_source_corrupt_catalog_fails_closed_not_silent_pointer_wipe(tmp_path):
    """A corrupt catalog must abort `remove` before any shelf bytes are
    deleted and before POINTERS.md is regenerated as if the corpus held
    nothing -- both would be reported as an unqualified success otherwise.
    """
    make_corpus(tmp_path)
    original_pointers = (tmp_path / POINTERS_NAME).read_bytes()
    alpha_target = tmp_path / "repos" / "github.com" / "alpha" / "one" / SHA_A

    _corrupt_catalog(tmp_path)

    with pytest.raises(VerificationError):
        remove_source(tmp_path, "alpha", "one", SHA_A)

    # The shelf was not deleted: the catalog was validated before any
    # destructive filesystem action was taken.
    assert alpha_target.exists()
    assert (alpha_target / "src" / "data.bin").exists()
    # POINTERS.md was not silently regenerated as an empty-corpus document.
    assert (tmp_path / POINTERS_NAME).read_bytes() == original_pointers


def test_export_corrupt_catalog_fails_closed_not_empty_snapshot(tmp_path):
    """`export` must never produce an immutable, successful-looking snapshot
    that asserts the corpus has zero sources when real shelves sit
    untouched on disk (issue #268's stated worst case: the falsified state
    would then be replayable via `import`).
    """
    make_corpus(tmp_path)
    _corrupt_catalog(tmp_path)

    output = tmp_path / "out" / "corpus.lock"
    with pytest.raises(VerificationError):
        export_corpus(output, root=tmp_path)

    assert not output.exists()


def test_sbom_cli_corrupt_catalog_fails_closed_not_empty_sbom(tmp_path):
    """`sbom` must fail closed rather than emit an SBOM asserting the corpus
    has zero packages.
    """
    make_corpus(tmp_path)
    _corrupt_catalog(tmp_path)

    code, payload, err = _run(["sbom", "--root", str(tmp_path)])

    assert code == ExitCode.CORPUS_FAILURE
    assert payload == {}
    assert "corrupt" in err or "cannot be established" in err


def test_strict_verification_error_names_recovery_path(tmp_path):
    """issue #268 (coordinator review): a fail-closed path with no stated
    recovery is a bricked tool. A user whose catalog is corrupt can no
    longer materialize anything (``_upsert`` is strict), so the error must
    name the corrupt file, the corpus root, and a concrete way out --
    not just "corrupt, cannot be established".
    """
    make_corpus(tmp_path)
    _corrupt_catalog(tmp_path)

    with pytest.raises(VerificationError) as excinfo:
        load_sources(tmp_path, strict=True)
    message = str(excinfo.value)

    # Names the corrupt file and the corpus root.
    assert str(tmp_path / "sources.json") in message
    assert str(tmp_path) in message
    # States a concrete recovery step: restore from backup, or move the
    # corrupt file aside yourself and re-add sources -- never just "it's
    # broken". No automated command is offered to do the move (issue #268
    # P1: that automated move is what laundered corruption into an honest-
    # looking missing file for a later reader) -- it must be an explicit,
    # deliberate user action.
    assert "recovery:" in message
    assert "backup" in message
    assert "mv " in message
    assert "sources.json.bak" in message
    assert "leitir get" in message
    # Reassures the user the materialized shelf bytes were not touched.
    assert "repos" in message


def test_require_all_shelves_authenticated_corrupt_catalog_fails_closed(tmp_path):
    """Under `--require-manifest-auth`, a corrupt catalog must not be read
    back as zero shelves and thus vacuously "every shelf is authenticated".
    """
    make_corpus(tmp_path)
    _corrupt_catalog(tmp_path)

    args = argparse.Namespace(trusted_keys=None)
    err = io.StringIO()
    with pytest.raises(VerificationError):
        _require_all_shelves_authenticated(tmp_path, args, err=err)


def test_doctor_corrupt_catalog_reports_error_not_clean_bill_of_health(tmp_path):
    """`doctor` exists to catch exactly this: a corrupt catalog must surface
    as a failing `cache.registered_shelves` check, not `pass: no registered
    corpus entries`.
    """
    make_corpus(tmp_path)
    _corrupt_catalog(tmp_path)

    out = io.StringIO()
    code = run_doctor(as_json=True, no_network=True, stdout=out, root=tmp_path)

    payload = json.loads(out.getvalue())
    checks = {check["name"]: check for check in payload["checks"]}
    assert checks["cache.registered_shelves"]["status"] == "error"
    assert code != int(ExitCode.SUCCESS)


def test_list_corrupt_catalog_is_still_benign_empty_not_error(tmp_path):
    """`list` is deliberately left non-strict (issue #268 audit): a human
    reading an empty list investigates. It must still succeed, but must
    never be the *only* record -- `load_sources` also raises a
    `RuntimeWarning`. Since #268 P1, the corrupt file is deliberately left
    in place (not renamed to `.bak`) so a later read -- by `list` again, or
    by any other command in a fresh process -- keeps seeing the same
    corruption rather than a laundered, genuinely-missing file.
    """
    make_corpus(tmp_path)
    _corrupt_catalog(tmp_path)

    with pytest.warns(RuntimeWarning, match="corpus catalog corrupt"):
        code, payload, _err = _run(["list", "--root", str(tmp_path), "--json"])

    assert code == ExitCode.SUCCESS
    assert payload == []
    assert not (tmp_path / "sources.json.bak").exists()
    assert (tmp_path / "sources.json").read_bytes() == b"{not valid json at all"


def test_file_not_found_catalog_remains_honest_empty_under_every_strict_caller(tmp_path):
    """A genuinely absent catalog (nothing ever materialized) is never
    corruption -- it must stay the honest empty corpus for every strict
    caller too, per the issue's explicit sad-path requirement.
    """
    assert load_sources(tmp_path, strict=True) == []
    code, payload, _err = _run(["sbom", "--root", str(tmp_path)])
    assert code == ExitCode.SUCCESS
    assert payload["packages"] == []



def test_upsert_protection_survives_laundering_through_the_ordinary_get_cli_path(
    tmp_path, monkeypatch
):
    """Independent review of PR #276 (P1): reproduce the defeat through the
    *ordinary* `get` CLI path, not a synthetic direct call to `_upsert`,
    within a single process.

    `get pypi:<pin>` resolves local-first: `_resolve_from_cached_shelf`
    reads the catalog non-strict *before* `materialize_source` ever reaches
    `_upsert`'s strict read. Under the old contract, that earlier non-strict
    read would rename the corrupt catalog to `sources.json.bak` and return
    no candidates; `_upsert`'s later strict read would then see a plain,
    laundered `FileNotFoundError` and silently rebuild the catalog as if
    the corpus had always been empty. Under the current contract (#268 P1:
    non-strict reads never rename the corrupt file), the earlier non-strict
    read leaves the corrupt file exactly as it was, so `_upsert`'s strict
    read sees the same corruption directly and fails closed -- no memo of
    any kind is needed for this to hold, in this process or any other (see
    `test_three_successive_processes_never_launder_a_corrupt_catalog`
    below for the cross-process case this is really about).
    """
    monkeypatch.setenv("LEITIR_UPDATE_CHECK", "0")
    out, err = io.StringIO(), io.StringIO()

    with routed_server(_pypi_routes()) as server:
        monkeypatch.setenv("LEITIR_PYPI_BASE_URL", server.base_url + "/pypi")
        monkeypatch.setenv("LEITIR_GITHUB_API_BASE_URL", server.base_url)
        monkeypatch.setenv("LEITIR_CODELOAD_BASE_URL", server.base_url)

        # First, a real, honest materialize: a genuine catalogued shelf on
        # disk, exactly as any user's corpus accumulates one.
        code = main(
            ["get", "pypi:demo@1.2", "--root", str(tmp_path), "--no-verify"],
            stdout=out,
            stderr=err,
        )
        assert code == ExitCode.SUCCESS, err.getvalue()
        materialized_path = out.getvalue().strip()
        assert (tmp_path / "repos").exists()
        entries_before = load_sources(tmp_path)
        assert len(entries_before) == 1

        # Corrupt the catalog in place -- garbage bytes, not valid JSON.
        _corrupt_catalog(tmp_path)

        # Re-run the exact same `get`. `_resolve_from_cached_shelf` reads
        # the corrupt catalog first (non-strict, by design) and leaves it
        # untouched; `_upsert`'s strict read then sees the same corruption
        # directly and fails closed, reporting CORPUS_FAILURE.
        out2, err2 = io.StringIO(), io.StringIO()
        code2 = main(
            ["get", "pypi:demo@1.2", "--root", str(tmp_path), "--no-verify"],
            stdout=out2,
            stderr=err2,
        )

    assert code2 == ExitCode.CORPUS_FAILURE, err2.getvalue()
    # The catalog was never silently rewritten as a fresh, one-entry index,
    # and -- since #268 P1 -- was never renamed away either.
    assert (tmp_path / "sources.json").read_bytes() == b"{not valid json at all"
    assert not (tmp_path / "sources.json.bak").exists()
    # The genuinely materialized shelf from the first, honest `get` is
    # untouched on disk -- only the catalog's *record* of it was corrupt.
    assert Path(materialized_path).exists()
    assert (Path(materialized_path) / "leitir-manifest.json").exists()


def test_three_successive_processes_never_launder_a_corrupt_catalog(tmp_path):
    """Independent review of PR #276 (P1, second round): the process-
    lifetime memo this test used to pin (`corpus._observed_corrupt_roots`)
    only protected a single interpreter, but `leitir` is a per-invocation
    CLI: every `leitir` command is its own fresh process. Two `main()`
    calls inside one pytest test function -- as the previous version of
    this test did -- share that one process and its memo, so they can only
    ever exercise the case the reviewer showed was already fixed; they
    cannot detect the defect that survived, because the memo the fix relied
    on doesn't exist yet in a second, genuinely separate process.

    This test drives the real installed `leitir` console-script entry point
    as three genuinely separate `subprocess.run` invocations against the
    same on-disk corpus root, with real materialized shelves and a real
    corrupt catalog -- reproducing exactly the scenario from the review
    comment:

    1. Materialize two real shelves (`alpha/one`, `beta/two`) via ordinary
       `get` calls -- process 1 and process 2.
    2. Corrupt `sources.json` in place.
    3. Process 3 runs `get` for a third, unrelated pinned spec
       (`gamma/three`). Under the old (renaming) contract this is exactly
       the "ordinary retry, or a different pinned spec run afterward"
       scenario the reviewer reproduced: `_resolve_from_cached_shelf`
       (non-strict) would rename the corrupt catalog to `.bak`, and
       `_upsert`'s strict read would then see a laundered
       `FileNotFoundError` and silently rebuild the catalog containing only
       `gamma/three`, discarding the still-on-disk `alpha/one` and
       `beta/two`. Under the current (non-renaming) contract, process 3's
       non-strict read leaves the corrupt file in place, so `_upsert`'s
       strict read sees the same corruption directly and fails closed.

    Asserts the catalog is never silently rebuilt: process 3 must fail, the
    corrupt file must still be exactly the corrupt bytes (no rename, no
    rewrite), and all three real shelves' bytes must remain on disk,
    reachable once the catalog is manually recovered.
    """
    import subprocess
    import sys

    def _get(spec: str, *, root, base_url: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["LEITIR_UPDATE_CHECK"] = "0"
        env["LEITIR_PYPI_BASE_URL"] = base_url + "/pypi"
        env["LEITIR_GITHUB_API_BASE_URL"] = base_url
        env["LEITIR_CODELOAD_BASE_URL"] = base_url
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "leitir.cli",
                "get",
                spec,
                "--root",
                str(root),
                "--no-verify",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _tarball_for(repo: str, sha: str) -> bytes:
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            content = b"pinned\n"
            member = tarfile.TarInfo(f"{repo}-{sha}/README.md")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        return data.getvalue()

    def _routes_for(owner: str, repo: str, pin: str, sha: str) -> dict[str, object]:
        return {
            f"/pypi/{repo}/{pin}/json": (
                200,
                {},
                json_body(
                    {
                        "info": {
                            "project_urls": {
                                "Source": f"https://github.com/{owner}/{repo}"
                            }
                        }
                    }
                ),
            ),
            f"/repos/{owner}/{repo}/git/ref/tags/v{pin}": (
                200,
                {},
                json_body({"object": {"type": "commit", "sha": sha}}),
            ),
            f"/{owner}/{repo}/tar.gz/{sha}": (200, {}, _tarball_for(repo, sha)),
        }

    sha_one = "1" * 40
    sha_two = "2" * 40
    sha_three = "3" * 40
    routes: dict[str, object] = {}
    routes.update(_routes_for("alpha", "one", "1.0", sha_one))
    routes.update(_routes_for("beta", "two", "2.0", sha_two))
    routes.update(_routes_for("gamma", "three", "3.0", sha_three))

    with routed_server(routes) as server:
        # Process 1: materialize alpha/one.
        proc1 = _get("pypi:one@1.0", root=tmp_path, base_url=server.base_url)
        assert proc1.returncode == 0, proc1.stderr

        # Process 2: materialize beta/two.
        proc2 = _get("pypi:two@2.0", root=tmp_path, base_url=server.base_url)
        assert proc2.returncode == 0, proc2.stderr

        entries = load_sources(tmp_path)
        assert {entry["name"] for entry in entries} == {"one", "two"}
        one_target = tmp_path / "repos" / "github.com" / "alpha" / "one" / sha_one
        two_target = tmp_path / "repos" / "github.com" / "beta" / "two" / sha_two
        assert (one_target / "leitir-manifest.json").exists()
        assert (two_target / "leitir-manifest.json").exists()

        # Corrupt the catalog on disk -- simulating a torn write, exactly
        # as issue #268 describes. Nothing about this comes from an
        # in-process memo: it is real, persistent, on-disk state.
        _corrupt_catalog(tmp_path)

        # Process 3: a fresh interpreter, no knowledge of processes 1 or 2,
        # runs an ordinary `get` for a third, unrelated pinned spec -- the
        # realistic next action a user or a retry takes.
        proc3 = _get("pypi:three@3.0", root=tmp_path, base_url=server.base_url)

    assert proc3.returncode != 0, proc3.stdout + proc3.stderr

    # The catalog was never silently rebuilt to contain only gamma/three.
    assert (tmp_path / "sources.json").read_bytes() == b"{not valid json at all"
    assert not (tmp_path / "sources.json.bak").exists()

    # alpha/one and beta/two's shelf bytes are still on disk, untouched --
    # the defect this test targets would have discarded their only record
    # (the catalog entry) while leaving the bytes orphaned.
    assert (one_target / "leitir-manifest.json").exists()
    assert (two_target / "leitir-manifest.json").exists()
    # gamma/three's repo bytes may have been fetched before `_upsert`'s
    # strict read aborted (materialization writes shelf files, then
    # catalogs the entry) -- that ordering is unrelated to this issue. What
    # matters is the catalog itself: gamma/three must never have been
    # *catalogued*, since the corrupt sources.json was never parsed back
    # into a valid entry list this run. Confirmed above: sources.json is
    # still exactly the corrupt bytes, so it names neither gamma/three nor
    # (critically) only gamma/three in place of alpha/one and beta/two.
