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

import pytest
from test_snapshot import SHA_A, make_corpus

from leitir.cli import ExitCode, _require_all_shelves_authenticated, main
from leitir.corpus import _upsert, load_sources, remove_source
from leitir.docpointers import POINTERS_NAME
from leitir.doctor import run_doctor
from leitir.materialize import VerificationError
from leitir.snapshot import export_corpus


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
