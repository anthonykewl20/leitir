# Exit corpus v1

This directory is the substrate-independent content for the issue #73 exit
corpus. It contains pinned donor identities, authored contract tests, recorded
baselines, and a content-bound review record; it does **not** contain vendor
source code or runnable containment configuration.

## Layout

* `corpus-v1.1.json` is the canonical closed-schema runnable manifest accepted by
  `leitir.exit_corpus.validate_corpus_manifest`.
* `policies/<case-id>.json` is the closed per-donor resolution policy. It
  authorizes only review-record external edges (for example `random`) or a
  pinned-exact adapter edge.
* `donors/<case-id>/donor-meta.json` records the donor pin, selected source
  path, seed, permissive license, and SHA-256 of the pinned license file.
* `donors/<case-id>/contract_tests/` contains deterministic, Leitir-authored
  contract tests. These are corpus artifacts, not donor source.
* `review-record-v1.md` documents selection and review evidence. Its byte-level
  SHA-256 is the `review_receipt_digest` in each manifest case.

## Re-materializing and re-recording a baseline

The future CI runner must fetch each repository commit directly, verify that
the detached `HEAD` equals `donor.commit_sha`, verify the named license-file
digest from `donor-meta.json`, and expose the donor at `test_pythonpath` before
running that case's committed contract tests inside the donor-present nsjail
policy. It must never execute donor tests on the host, use a moving branch, or
use a vendored donor copy. The selected paths are `.` for luhn, backoff,
url-normalize, and haversine, and `src` for webcolors. The v1.1 manifest spells these as
per-case `import_roots` and links the matching `policies/<case-id>.json` file;
its `runtime_deps` records the exact plain version
`idna` `3.18` only for url-normalize. It is installed only into the contained
execution image; runtime dependencies are not Leitir runtime dependencies.

To re-record after an authorized corpus change: materialize fresh detached
checkouts, run each case with pytest, record collected/pass/fail/skip counts in
the manifest baseline and this README, recompute the review-record SHA-256,
write that value to every case receipt, canonicalize the manifest, and verify
its `content_digest` under multiple `PYTHONHASHSEED` values. Any changed result
requires a new independent review and out-of-band ratification; it is not a
routine refresh.

Recorded on 2026-08-15 against freshly fetched pins:

| Case | Collected | Pass | Fail | Skip |
| --- | ---: | ---: | ---: | ---: |
| luhn-checksum | 2 | 2 | 0 | 0 |
| backoff-full-jitter | 2 | 2 | 0 | 0 |
| url-normalize-fragment | 2 | 2 | 0 | 0 |
| webcolors-rgb-to-hex | 2 | 2 | 0 | 0 |
| haversine-avg-earth-radius | 2 | 2 | 0 | 0 |

## Ratification and execution boundary

`ratified_manifest_digest` is deliberately `null`. The protocol is:

1. **Phase A:** run `exit-gate-run` unratified. Its report publishes the stable
   runtime `corpus_manifest_digest`; the gate honestly rejects.
2. **Phase B:** an independent out-of-band ratifier signs the canonical
   projection `{corpus_id, corpus_manifest_digest, ratified_runtime_digest}`
   with its Ed25519 key and publishes `ratification-v1.json` outside the donor
   shelf. `ratified_manifest_digest` remains the record-level
   `sha256("ratify:" + content_digest)` content-binding convention.
3. **Phase C:** set `ratified_runtime_digest` to the Phase-A runtime digest and
   rerun with `--trusted-keys` (and, if non-default, `--ratification-sidecar`).
   Missing, tampered, self-made, or untrusted signatures reject; equality alone
   cannot create authority.

The runnable substrate pins become authoritative once CI has measured them.
This bootstrap corpus leaves them null until the first successful measurement;
CI still requires explicit measured values and rejects drift after pinning.

A digest computed by this repository only binds content and cannot ratify it.

This content does not make the exit gate runnable by itself. `exit-gate-run`
requires the honest containment substrate, including `nsjail`, a donor-free
immutable rootfs containing the pinned interpreter/stdlib, `/harness/runner.py`,
and explicit `-S` runtime dependencies; see `leitir.pipeline_cli` for the
runtime boundary. The rootfs digest is a deterministic tree hash of that image,
not of the donor corpus.
