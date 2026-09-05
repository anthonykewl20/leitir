# Actual process termination and materialization recovery

Executed 2026-09-05 10:31:23–10:31:26 UTC against release source `66b88c24ff97f18669fe1c48e18c74e949cc84e1` (same Git head at start/end).

Source: actual GitHub `pypa/packaging` commit `85442b8032cb7bae72866dfd7782234a98dd2fb7`. Fresh owned corpus only; no shared/user shelf was changed.

Contract read: materialization publishes a verified manifest/tree through atomic rename while holding the target advisory lock (ADR-0006). Unpublished sibling staging is disposable; the next target lock acquisition sweeps abandoned staging.

The probe launched the production CLI `get` with the exact source pin, observed actual extracted files appear in its staging directory, sent SIGSTOP, recorded the filesystem, then sent SIGKILL. No production hooks, synthetic data, fake shelves, transport mocks, or source edits were used.

Observed at 1.489 seconds: four actual source files existed in unpublished staging. Three were completely written and byte-identical to the subsequently verified source. The fourth, `.github/workflows/lint.yml`, was still zero bytes: this run intercepted active extraction before its write completed. There was no manifest, canonical shelf, or sources catalog. The production manifest loader rejected the incomplete staging.

SIGKILL produced exit `-9`. Repeating the same normal CLI command immediately completed successfully, reclaimed abandoned staging and published the exact requested commit with `verified: true`, `parity: exact` and full tree coverage. The final production manifest/tree verification passed. Tree hash: `h1:only4Jqg2nQVRSHqtx3pyJnpIR81v84hZmgXYWQGf3U=`. Recovery took 1.451 seconds; total probe 2.981 seconds.

Evidence: `probe.py` (exact orchestration), `events.json` (commands/PID/timing/signals), `stopped-snapshot.json` (observed filenames/sizes/digests), `result.json`, `final-manifest.json`, and captured CLI stdout/stderr. The missing/partial-file rejection is actual process-crash evidence. It does not claim coverage of power loss, every publication instruction boundary, or non-Linux process semantics.

The accompanying `evidence.tar.gz` preserves every original evidence file, including the exact executed Python scripts. It excludes the downloaded corpus. Extract it into a separate directory to inspect the recorded scripts and original filenames.
