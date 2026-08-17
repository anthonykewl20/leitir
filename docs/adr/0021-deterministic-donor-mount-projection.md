# ADR-0021: Deterministic donor mount projection for runtime-digest stability

- Status: Accepted
- Deciders: leitir maintainers
- Date: 2026-08-17
- Technical Story: #73 — run-to-run corpus runtime-digest drift blocks ratification

## Context and Problem Statement

The contained Phase-A workflow materializes every exit-corpus donor fresh on
each CI run. Materialization writes `leitir-manifest.json` at the shelf root
with wall-clock `fetched_at`/`verified_at` fields, and preserves source member
modes. The donor-present baseline policy mounted that shelf directly at
`/donor` and bound it with `_verified_directory_tree_digest`, which hashes
every entry — including the root manifest — so the donor mount digest (and
every digest derived from it: baseline mount plan, execution policy, corpus
runtime digest) changed on every run. Load-time shelf verification
(`compute_materialized_tree_hash`) excludes exactly the root-level manifest,
which is why content verification passed while the mounted digest drifted:
issue #73 recorded corpus runtime digests `a504ec92…` vs `a76e3c68…` across two
green runs.

## Decision Drivers

- The corpus runtime digest must be a pure function of pinned inputs (donor
  commit content, corpus, substrate pins, leitir version) before an owner can
  ratify it out of band.
- Content verification must not weaken: the shelf stays Hash1-verified
  upstream and the mount binding must still cover exactly the bytes that
  execute.
- Fail-closed on anything unexpected in the shelf; no silently accepted or
  truncated entries.

## Considered Options

- Drop wall-clock timestamps from materialization manifests.
- Exclude `leitir-manifest.json` universally inside
  `_verified_directory_tree_digest`.
- Add a mount-kind field to the containment policy schema so the verifier
  could skip manifests per mount.
- Stage a manifest-free, mode-canonicalized projection of the verified shelf
  and mount that (chosen).

## Decision Outcome

Chosen option: "a deterministic donor mount projection", because it makes the
mounted bytes a pure function of pinned donor content without touching any
verification authority.

`pipeline_cli._prepare_donor_projection(corpus_root, snapshot)` walks the
verified shelf fail-closed (children sorted by `os.fsencode(name)`, the same
ordering as the execution-time digest), skips exactly the validated root-level
`leitir-manifest.json`, rejects symlinks, special files, noncanonical names,
and oversized files with distinct detail codes, and publishes a copy with
canonical modes (directories `0755`, files `0644` — the contained baseline
executes via `/usr/bin/python3`, so executable bits are unused) into a
content-addressed stage under `.leitir-bts-staging`, guarded by the same flock
and completion-marker discipline as the E1 shared stage. The `/donor` mounts at
all three shelf-mount call sites (`assemble_bts_task_request`, `run_pipeline`,
`exit_gate_run`) bind the projection, and the mount digest is computed by the
unchanged `_verified_directory_tree_digest` — the identical function
execution-time verification recomputes.

Excluding the root manifest from the mount binding does not weaken content
verification. The manifest is deliberately excluded from
`compute_materialized_tree_hash` itself (ADR-0006): the tree digest is stored
inside the manifest, so it cannot cover it without self-reference — that
exclusion is precisely why the manifest's wall-clock fields could drift the
mounted digest while verification stayed green. Nothing Hash1 verified is
unmounted: every entry the tree hash binds is projected byte-exact. The
manifest's integrity-relevant fields are covered separately by the ADR-0018
signed projection (`manifest_auth.py` `_PROJECTION_FIELDS` pins host, owner,
repo, commit_sha, source, and the three tree-hash identity fields, and by
design omits the volatile `fetched_at`/`verified_at`) — and those deliberately
unpinned wall-clock fields are exactly why they must not enter the mount
binding. The projection is also strictly stricter than the old direct mount:
it rejects shelf symlinks and special files that Hash1 tolerated, and binds
byte-exact copies of everything the contained baseline can import or read from
`/donor` at canonical modes, so a changed donor commit still changes the
runtime digest while a re-materialized identical commit no longer does.

### Positive Consequences

- The donor mount digest, baseline mount-plan digest, execution-policy digest,
  and corpus runtime digest are stable across runs for pinned inputs; #73's
  ratification blocker is removed at the source (re-signing remains an owner
  ceremony).
- Re-materialization no longer invalidates cached stages: complete projection
  stages are verified and reused.
- Entry-level `LEITIR_NSJAIL_DEBUG=1` mount-source manifest lines make any
  future drift diagnosable from controller logs alone.

### Negative Consequences

- Baseline evidence recorded before this change embeds the old shelf-bound
  mount digests; task baseline sidecars are unaffected (they pin aggregate
  outcomes, not mount digests), but corpus runtime digests must be re-measured
  once before ratification.
- A donor file larger than the projection's new per-file bound (64 MiB) is now
  rejected fail-closed at projection time. This is a new rejection: the
  load-time tree verifier had no per-file size bound, so such a file
  previously mounted; the bound never truncates.
- Donor shelves containing symlinks or special files were already rejected
  before this change — the old direct-mount digest walk failed on them at
  policy construction. They are now reclassified with a distinct, typed detail
  code at projection time instead of a generic walk failure.

## Pros and Cons of the Options

### Drop wall-clock timestamps from manifests

- Good, because the shelf itself would hash stably.
- Bad, because `fetched_at`/`verified_at` are load-bearing freshness evidence
  consumed by `trust.py`, `doctor.py`, and `info.py`; removing them weakens
  provenance reporting for every shelf, not just the mounted donors.

### Exclude the manifest universally in `_verified_directory_tree_digest`

- Good, because one function change covers all mounts.
- Bad, because the same function binds the rootfs and staged relocation trees;
  a universal exclusion would silently stop binding any root-level
  `leitir-manifest.json` in every mount source — a verification weakening.

### Mount-kind field in the policy schema

- Good, because the verifier could skip the manifest per mount explicitly.
- Bad, because `POLICY_SCHEMA` and its `config_schema_digest` are pinned by
  `benchmarks/exit-corpus/corpus-v1.1.json`; a schema change invalidates the
  corpus pin and forces re-measurement of every substrate identity anyway.

## Links

- [#73 — runtime digest ratification](https://github.com/anthonykewl20/leitir/issues/73)
- [ADR-0006 — Load-time tree verification](0006-load-time-tree-verification.md)
- [ADR-0009 — Transplant validation](0009-transplant-validation.md)
- [ADR-0018 — Manifest authenticity](0018-manifest-authenticity.md)
