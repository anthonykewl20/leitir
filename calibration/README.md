# calibration/

Tracked outputs of the self-calibration loop (`tools/calibrate.py`, docs/calibration.md, ADR-0037).

- `ledger.json` — every finding ever observed, its status, and the per-run history. Do not hand-edit statuses; use `python tools/calibrate.py disposition`.
- `REPORT.md` — regenerated on every run.
- `perf-baseline.json` — host-fingerprinted timing baseline for the perf probe.

Volatile run artifacts live in `.leitir-calibration/` (ignored).
