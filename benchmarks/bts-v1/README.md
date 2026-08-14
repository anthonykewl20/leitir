# BTS v1 evaluation publication target

This is the publication target for issue #75's Behavioral Transplant Set (BTS)
evaluation evidence. It makes pinned manifests and exported, reproducible run
artifacts reviewable without treating benchmark evidence as a live claim.
Any optional exit-corpus self-hash is content binding only; external
ratification authority is deferred in v1.

## Layout

- `tasks/` contains pinned BTS evaluation manifests and their human-reviewed gold.
- `runs/` is the destination for `tools/export_bts_eval.py`; each exported run is
  stored as `<run-digest>/run.json` and `<run-digest>/METRICS.md`. The harness
  has no separate run ID, so the graded run digest is the immutable run ID.

## Adding a real task

The owner must define a `BTSEvalTask` and `BTSGold` from a real transplant,
including human-verified candidate grades and all applicable expected evidence.
Get independent review of the gold and task provenance, then pin the completed
manifest in `tasks/`. Only then execute the harness and export its canonical
run JSON. Do not use this reference fixture as evidence for a real task.

`reference-synthetic-v1.json` is a deliberately synthetic schema and exporter
fixture, **not** one of the six real BTS tasks. The closed manifest schema has
no metadata extension field, so its synthetic status is encoded in its
benchmark and task IDs and in this documentation.

## Exporting a harness run

From the repository root, export a canonical `BTSEvalRun` JSON emitted by the
harness:

```console
PYTHONPATH=src python tools/export_bts_eval.py path/to/run.json
```

The exporter rejects non-canonical JSON, unknown schema fields, malformed
metrics, a missing timing envelope, and a timing envelope whose run digest is
not bound to the graded canonical run. It writes `run.json` verbatim and a
deterministic `METRICS.md`.
`METRICS.md` intentionally omits a generated-at timestamp so identical input
evidence has identical publication bytes.

## Current state

The deterministic evaluation harness is landed. The six real tasks remain an
owner-external responsibility, and the timing envelope comparison is deferred.
