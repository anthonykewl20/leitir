# Issue #341: sampled-scope rejection regression

The reported raise-drop mutant survived before the new test: the static
selection ran 900 passing tests with 63 environment-gated skips. The existing
index eligibility test can reject sampled scope independently of tree-hash
verification, masking the missing rejection.

The regression materializes a real, below-cap shelf, verifies its unchanged
legacy aggregate digest, changes only the manifest scope to `sampled`, and
requires both `VerificationError` from integrity verification and a cache miss
from manifest loading. With mutant `3aef870d4e7fc1f4` applied, it fails with
`DID NOT RAISE`; with the original source restored, it passes. Production code
and behavior are unchanged, so no README or ADR behavior update is needed.

## Calibration evidence

The issue's original ledger entry was extracted unchanged from the
`calibration-run` artifact of [run 34009155781](https://github.com/anthonykewl20/leitir/actions/runs/34009155781)
into a single-finding ledger. The tracked global ledger predates this finding.
This scoped replay does not disposition or retire unrelated findings.

Commands, from the repository root:

```sh
python tools/calibrate.py mutant 3aef870d4e7fc1f4 --path src/leitir/treehash.py
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt --with coverage==7.15.2 --with pytest-cov==7.1.0 python -m pytest -q tests/test_materialize.py::test_legacy_full_tree_rejects_tampered_sampled_scope --cov=leitir.treehash --cov-context=test --cov-report=
uv run --no-project --with coverage==7.15.2 python -m coverage json --show-contexts -o .leitir-calibration/coverage-contexts.json
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python tools/calibrate.py mutant 3aef870d4e7fc1f4 --path src/leitir/treehash.py --run
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python tools/calibrate.py --ledger docs/evidence/issue-341-2026-09-07/ledger.json run --probes mutation --modules treehash --mutants 0
```

`--mutants 0` disables new exploration; the open recorded finding is still
re-tested. The run executed and killed the mutant, with zero control failures,
errors, timeouts, or survivors. `ledger.json` records `fixed` and `mutants.json`
records the killing test. The run SHA is the base commit; the new test was an
uncommitted working-tree addition at measurement time. For another replay,
restore the original open entry from the linked artifact first.
