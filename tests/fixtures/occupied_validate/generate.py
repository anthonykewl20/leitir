#!/usr/bin/env python3
"""Regenerate the committed occupied-validate example artifact.

The artifact is a pure function of the in-repo test fixtures (same
``_fixture``/``_budget``/``_policy`` inputs the occupied tests use), so the
bytes are deterministic across runs and Python versions.

Usage (from the repository root)::

    PYTHONPATH=src:tests python tests/fixtures/occupied_validate/generate.py

Writes ``example-artifact.json`` next to this script and verifies it passes
``leitir.pipeline_cli.occupied_validate`` before replacing it (atomic write).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parents[2]
for _entry in (_REPO / "src", _REPO):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from tests.test_pipeline_cli_occupied_artifact import _artifact, _bytes  # noqa: E402


def main() -> int:
    from leitir.pipeline_cli import occupied_validate

    target = _HERE / "example-artifact.json"
    payload = _bytes(_artifact())
    summary = occupied_validate(payload)
    if summary.get("status") != "complete":
        raise SystemExit("generated artifact failed validation; refusing to write")
    # _bytes is canonical (sorted keys, compact separators, trailing newline).
    fd, staging = tempfile.mkstemp(dir=_HERE, prefix=".example-artifact-", suffix=".json")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging, target)
    except BaseException:
        try:
            os.unlink(staging)
        except FileNotFoundError:
            pass
        raise
    print(f"wrote {target} ({len(payload)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
