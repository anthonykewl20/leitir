# Issue #338 — runtime re-ratification and Phase C for 0.2.000 (2026-09-05)

This directory retains the owner ceremony and the authenticated Phase-C gate
result that close the ratification half of #338. Nothing here was produced
by an unsigned or self-made trust root; the trust root is the unchanged
`benchmarks/exit-corpus/trusted-keys-v1.json`.

## Ceremony

* `ceremony-log.txt` — the exact output of the owner signing session on the
  owner's workstation. It confirms the owner key ID
  `7baec2e9c408e77ad74312c2d9c575a73fae02275a015a4becd8c829814b5505`, prints
  the canonical projection bytes (compact, key-sorted UTF-8 plus one LF),
  writes `benchmarks/exit-corpus/ratification-v1.json` with projection digest
  `fbdbe2d87f385aed91b204959f337f74955d74680e48ee74b7f038942f5e669e`, and
  verifies it through `require_detached_projection_auth` against the trust
  root. No private key material is recorded.
* Rejection probes in the same log, all against the fresh trust root:

  | Probe | Result |
  | --- | --- |
  | tampered signature | `ManifestAuthBadSignatureError` |
  | tampered projection | `ManifestAuthProjectionMismatchError` |
  | stale 2026-08-17 sidecar | `ManifestAuthProjectionMismatchError` |
  | self-made untrusted key | `ManifestAuthUnknownKeyError` |
  | missing sidecar | `ManifestAuthMalformedError` |

* The superseded sidecar is archived as
  `benchmarks/exit-corpus/ratification-v1-superseded-2026-08-17.json`.

## Phase C gate

[Run 33974049348](https://github.com/anthonykewl20/leitir/actions/runs/33974049348)
(`bts-containment.yml`, `workflow_dispatch`, `run_bench=false`, head
`ee2e3ed78c9b228566a3eedd8a274669ab06e83f` on `release/ratify-0.2.000`)
consumed the published `containment-rootfs-v1` asset, verified its tree
digest, materialized the five pinned donors and ran `exit-gate-run` with
`--trusted-keys`. The `bts-exit-gate-evidence` artifact is retained verbatim
under `contained-phase-c/`:

* `summary.json`: `status: complete`, `corpus_manifest_digest
  sha256:901bf7ac3cdfc5e7fcb59a9f6c153d24724c7525d7398174478d3d1322b40f69`,
  `corpus_content_digest a969398a…`, `report_digest sha256:4dadccbe…`.
* `exit-gate-report.json`: `authority_digest_matches: true`; every donor
  (`luhn-checksum`, `backoff-full-jitter`, `url-normalize-fragment`,
  `webcolors-rgb-to-hex`, `haversine-avg-earth-radius`) reports
  `status: complete`, `complete_bts`, `donor_ban_proved`,
  `exact_rerun_parity`, `no_observed_donor_import`, `probes_complete`,
  `zero_failure_baseline`, with recorded counts 2 passed / 0 failed /
  0 skipped equal to the expected counts.
* Per-donor `baseline-recording.json` files hold the contained recordings.

The measured digest equals the digest of the unratified Phase-A runs
33951188380, 33953061013, 33956771092 and 33960563929, so the signature
authorizes exactly the runtime that was observed, and the gate flipped from
`reject` (Phase A) to `complete` (Phase C) with no other change than the
recorded authority.
