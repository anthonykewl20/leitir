"""Regression tests for issue #268.

`leitir.corpus.load_sources` silently recovers from a corrupt catalog
(`sources.json`) by renaming it to `sources.json.bak` and returning `[]`,
unless a caller opts into `strict=True`. PR #267 adopted `strict=True` for
the corpus-wide search eligibility path only. This file exercises every
other caller this issue's audit determined would produce a false success or
a destructive action on a corrupt catalog, and pins that each one now fails
closed instead: real materialized shelves sit untouched on disk, the
catalog is corrupted, and the command/function must reject rather than
silently proceed as if the corpus were empty.
"""

from __future__ import annotations

import argparse
import io
import json
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
    # Strict mode raises before the silent-recovery rename: the corrupt
    # file is left exactly as it was, and -- critically -- was never
    # replaced by a fresh sources.json containing only the new entry.
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
    # States a concrete recovery step: restore from backup, or reset via a
    # non-strict command and re-add sources -- never just "it's broken".
    assert "recovery:" in message
    assert "backup" in message
    assert "sources.json.bak" in message
    assert "leitir list" in message
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
    `RuntimeWarning` and leaves `sources.json.bak` on disk.
    """
    make_corpus(tmp_path)
    _corrupt_catalog(tmp_path)

    with pytest.warns(RuntimeWarning, match="corpus catalog corrupt"):
        code, payload, _err = _run(["list", "--root", str(tmp_path), "--json"])

    assert code == ExitCode.SUCCESS
    assert payload == []
    assert (tmp_path / "sources.json.bak").exists()


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
    *ordinary* `get` CLI path, not a synthetic direct call to `_upsert`.

    `get pypi:<pin>` resolves local-first: `_resolve_from_cached_shelf`
    reads the catalog non-strict *before* `materialize_source` ever reaches
    `_upsert`'s strict read. Before the process-lifetime corruption memo,
    that earlier non-strict read would rename the corrupt catalog to
    `sources.json.bak` and return no candidates; `_upsert`'s later strict
    read would then see a plain, laundered `FileNotFoundError` and silently
    rebuild the catalog as if the corpus had always been empty -- exactly
    the destructive false success this issue targets, reached through the
    primary path the issue is about (any pinned `pypi:`/`npm:`/`crates:`
    spec via `get`/`diff`/`remove`/`check`), not an edge case.
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
        # the corrupt catalog first (non-strict, by design); without the
        # fix, `_upsert`'s strict read would then see a laundered
        # `FileNotFoundError` and rebuild the catalog from scratch,
        # reporting SUCCESS.
        out2, err2 = io.StringIO(), io.StringIO()
        code2 = main(
            ["get", "pypi:demo@1.2", "--root", str(tmp_path), "--no-verify"],
            stdout=out2,
            stderr=err2,
        )

    assert code2 == ExitCode.CORPUS_FAILURE, err2.getvalue()
    # The catalog was never silently rewritten as a fresh, one-entry index.
    assert not (tmp_path / "sources.json").exists()
    assert (tmp_path / "sources.json.bak").exists()
    # The genuinely materialized shelf from the first, honest `get` is
    # untouched on disk -- only the catalog's *record* of it was corrupt.
    assert Path(materialized_path).exists()
    assert (Path(materialized_path) / "leitir-manifest.json").exists()
