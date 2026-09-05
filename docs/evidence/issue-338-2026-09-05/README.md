# Issue #338 — runtime re-ratification, Phase C and publication of 0.2.000 (2026-09-05)

This directory retains the owner ceremony, the authenticated Phase-C gate
result and the publication evidence that close #338. Nothing here was produced
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

## Publication

* Tag `v0.2.000` (annotated) points at merge commit
  `bed62edba760a1378c0b7971ca6c79851885af24` (PR #339 into `main`). The
  canonical Phase-C run on that commit,
  [33975487102](https://github.com/anthonykewl20/leitir/actions/runs/33975487102),
  is `complete` with the same `corpus_manifest_digest` and `report_digest
  sha256:4dadccbe…` as the branch run.
* Release gate: the release workflow
  [33976141410](https://github.com/anthonykewl20/leitir/actions/runs/33976141410)
  selected the successful `push` CI run
  [33975473875](https://github.com/anthonykewl20/leitir/actions/runs/33975473875)
  for that exact SHA (full seven-leg matrix; CodeQL run 33975473857 also
  succeeded), reused its `python-package-distributions` artifact without
  rebuilding, verified tag/file-name/METADATA identities and archive payloads
  with `tools/verify_release.py`, attested build provenance for both files,
  re-checked the recorded digests and published the committed notes
  (`published-assets/release-run.json`, `release.json`).
* Downloaded published assets (`published-assets/SHA256SUMS`):

  | Asset | SHA-256 |
  | --- | --- |
  | `leitir-0.2.0-py3-none-any.whl` | `c575fe3d94ba40d531c8624819961a6d34fac854a60663365c9a6a80517abe47` |
  | `leitir-0.2.0.tar.gz` | `6d496e10f741813ab9141f03b780f2c9fffea9bf6c89a859121baaa962e81055` |

  Both digests equal the digests the release workflow recorded and the
  digests of the CI run's own `python-package-distributions` artifact
  downloaded independently.
* `gh attestation verify --repo anthonykewl20/leitir` succeeds for both files;
  the statement names both subjects with those digests and was produced by
  `refs/tags/v0.2.000` in run 33976141410 (`published-assets/attestations.json`).
* `tools/verify_release.py --tag v0.2.000` accepts the downloaded assets
  (`published-assets/verify-release.json`).
* Isolated install: a fresh Python 3.11 venv with only the published wheel
  reports `leitir 0.2.000` and completes `leitir info npm:zod@3.22.0 --json`
  against live npm (`published-assets/isolated-cli.txt`). With the
  hash-locked `requirements-mcp.lock` added, `python -m leitir.mcp` answers
  `initialize` as `leitir 0.2.000`, lists the five tools and completes a live
  `info` call for `pypi:attrs@23.2.0` (`published-assets/isolated-mcp.txt`).
