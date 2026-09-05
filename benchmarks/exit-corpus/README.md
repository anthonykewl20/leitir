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

`ratified_manifest_digest` remains `null`; it is a content-binding convention,
not the out-of-band authority. The ratified runtime authority is recorded in
`ratified_runtime_digest`. The protocol is:

1. **Phase A:** run `exit-gate-run` unratified. Its report publishes the stable
   runtime `corpus_manifest_digest`; the gate honestly rejects.
   Authority digests bind verified source content and in-sandbox destinations,
   not runner-local workspace or temporary-directory path spellings.
2. **Phase B:** an independent out-of-band ratifier signs the canonical
   projection `{corpus_id, corpus_manifest_digest, ratified_runtime_digest}`
   with its Ed25519 key and publishes `ratification-v1.json` outside the donor
   shelf. `ratified_manifest_digest` remains the record-level
   `sha256("ratify:" + content_digest)` content-binding convention.
3. **Phase C:** set `ratified_runtime_digest` to the Phase-A runtime digest and
   rerun with `--trusted-keys` (and, if non-default, `--ratification-sidecar`).
   Missing, tampered, self-made, or untrusted signatures reject; equality alone
   cannot create authority.

### 2026-09-05 runtime digest re-ratified for 0.2.000 (ceremony complete)

The 0.2.000 release source changed the contained runtime (the #309 BTS walk
correction and the release fixes), so the runtime digest moved and the
2026-08-17 signature could no longer authorize it. The re-measured digest is
`sha256:901bf7ac3cdfc5e7fcb59a9f6c153d24724c7525d7398174478d3d1322b40f69`.
It was measured identically by four runs. Run
[33951188380](https://github.com/anthonykewl20/leitir/actions/runs/33951188380)
reported it only in its `ManifestAuthProjectionMismatchError` against the
stale sidecar and stopped before the gate. The three unratified Phase-A runs
[33953061013](https://github.com/anthonykewl20/leitir/actions/runs/33953061013),
[33956771092](https://github.com/anthonykewl20/leitir/actions/runs/33956771092)
and [33960563929](https://github.com/anthonykewl20/leitir/actions/runs/33960563929)
(final release source) each completed all five donors at 2/0/0 with exact
rerun parity, donor-ban proof and complete probes.

`corpus-v1.1.json` now records that digest in `ratified_runtime_digest`, and
the detached `ratification-v1.json` binds the canonical projection
`{corpus_id, corpus_manifest_digest, ratified_runtime_digest}` — both digest
fields carry that same measured value — under the unchanged owner ratifier key:

* owner ratifier key ID:
  `7baec2e9c408e77ad74312c2d9c575a73fae02275a015a4becd8c829814b5505`
  (still the single key in `trusted-keys-v1.json`; its private half is held
  out of band by the owner under `~/.leitir/` and is never committed). The
  trust root was not rotated; the ceremony re-signed with the existing key.
* projection digest:
  `fbdbe2d87f385aed91b204959f337f74955d74680e48ee74b7f038942f5e669e`.
* The ceremony was executed by the owner on 2026-09-05 on the owner's
  workstation (`docs/evidence/issue-338-2026-09-05/ceremony-log.txt`). The
  same log records the fail-closed probes run against the fresh trust root:
  tampered signature, tampered projection, the stale 2026-08-17 sidecar, a
  self-made untrusted key and a missing sidecar all reject.
* The superseded 2026-08-17 sidecar is archived as
  `ratification-v1-superseded-2026-08-17.json`. It remains valid evidence of
  that ceremony but no longer matches the active projection, so the active
  gate rejects it (`ManifestAuthProjectionMismatchError`).

`ratified_manifest_digest` remains `null` by convention: it is the record-level
`sha256("ratify:" + content_digest)` content-binding convention, not the
out-of-band authority. The authority is the signed sidecar plus
`ratified_runtime_digest`, exactly as the protocol above defines.

Phase C follows this record: the ratifying change reruns `exit-gate-run` with
`--trusted-keys` on the release source, and its summary must flip from
`reject` to `complete` with `corpus_manifest_digest sha256:901bf7ac…`. The
Phase-C evidence for 0.2.000 is recorded in
`docs/evidence/issue-338-2026-09-05/README.md`.

### Ceremony history

**2026-08-17 — runtime digest ratified (superseded 2026-09-05).**

The ADR-0021-stabilized runtime digest was ratified:
`sha256:72949674c997fe803e58c4060a787c5484785cc96b9bb450c7659aab72658c79`.
`corpus-v1.1.json` recorded it in `ratified_runtime_digest`, and the detached
sidecar (now archived as `ratification-v1-superseded-2026-08-17.json`) bound the canonical projection
`{corpus_id, corpus_manifest_digest, ratified_runtime_digest}` — both digest
fields carry that same measured value — under the owner-controlled long-term
ratifier key rotated in for this ceremony:

* owner ratifier key ID:
  `7baec2e9c408e77ad74312c2d9c575a73fae02275a015a4becd8c829814b5505`
  (the single key in `trusted-keys-v1.json`; its private half is held out of
  band by the owner under `~/.leitir/` and is never committed).

`ratified_manifest_digest` remains `null` by convention: it is the record-level
`sha256("ratify:" + content_digest)` content-binding convention, not the
out-of-band authority. The authority is the signed sidecar plus
`ratified_runtime_digest`, exactly as the protocol above defines.

Phase C follows this record: the ratifying change reruns `exit-gate-run` with
`--trusted-keys`, and its summary must flip from `reject` to `complete` with
`corpus_manifest_digest sha256:72949674…`. That gate completed on branch run
[32018653190](https://github.com/anthonykewl20/leitir/actions/runs/32018653190)
and canonical main run
[32018948262](https://github.com/anthonykewl20/leitir/actions/runs/32018948262),
the closing evidence for #73.

**2026-08-16 — ceremony held pending a stable runtime digest.** The
out-of-band ceremony was performed and retained as audit evidence under the
session-delegated key
`8528aa694a3d94213741a20158a9f7c3fb4a3a13f5f231b009f651053beaf38b`. Its
sidecar is archived as `ratification-v1-held-2026-08-16.json`; it no longer
verifies under the rotated trust root, and its private key was destroyed after
the ceremony, as the archived trust entry's rotation note required.

Ratification was **HELD**: `ratified_runtime_digest` stayed `null` because the
runtime corpus digest drifted run-to-run through staged mount-source tree
digests that embedded the shelf manifest's wall-clock `fetched_at`/`verified_at`
fields. Phase-A [run 31964398451](https://github.com/anthonykewl20/leitir/actions/runs/31964398451)
measured `sha256:a504ec929a59228ab570ac89dd6dbaaf494314f4bd55e508263548101564ce43`,
while same-main diagnostic [run 31966286416](https://github.com/anthonykewl20/leitir/actions/runs/31966286416)
measured `sha256:a76e3c68…`. The baseline mount-plan digest changed
`a8116078…` → `ad54fb29…`, the execution-policy digest changed
`9c3faf85…` → `54bb6aae…`, and the baseline digest changed
`2f889172…` → `b20f5b5e…`. Those pre-fix measurements remain historical
evidence.

**2026-08-17 — ADR-0021 stabilized the runtime digest.** The manifest-free,
mode-canonicalized donor mount projection made the runtime digest a pure
function of pinned inputs. Stability evidence: post-fix runs
[32008683557](https://github.com/anthonykewl20/leitir/actions/runs/32008683557)
and [32009633642](https://github.com/anthonykewl20/leitir/actions/runs/32009633642)
both measured `corpus_manifest_digest
sha256:72949674c997fe803e58c4060a787c5484785cc96b9bb450c7659aab72658c79`
with byte-identical evidence: their `bts-exit-gate-evidence` artifacts match
byte-for-byte (exit-gate report and summary), every donor baseline digest is
equal across the runs, and each run emitted the same 84 canonical
`mount-source manifest` lines (75 unique entries) under
`LEITIR_NSJAIL_DEBUG=1`, so any residual drift remains diagnosable from
controller logs. The 2026-08-17 owner ceremony then rotated the trust root to
the long-term owner key above and signed the measured digest.

The substrate pins are stable and remain pinned:

* `nsjail_sha256`: `sha256:2a740ac196d27176216788f6213d585cd5b5933f83f2c9bff31ce95cd64939d4`
* `nsjail_version`: `nsjail@f78475530b46d0186111a9096b30725f816b55fe`
* `nsjail_build_identity`: `sha256:9fc7783e8fee63cf059bb5e48053f3ac77e80fda34128917bae956bda90c0c4b`
* `config_schema_digest`: `sha256:39803af3291a1f08860ec1ec4b028aba5d000df53d2f0f73781718f75ff16c80`
* `rootfs_digest`: `sha256:ec28886a5e448e9d6b088470c85ee2e0d170e16002bd78ecc835e9d4161155ac`

The first pin raced a GitHub runner-image rollout: Phase A measured
`sha256:e82de50658175072ae7cd26e5741aafd2b28d3c8e3e1abd28ca4f0768489e0a2`,
while a later per-run rebuild measured another tree. It is superseded by the
[published `containment-rootfs-v1` release asset](https://github.com/anthonykewl20/leitir/releases/tag/containment-rootfs-v1).
The asset is a sorted, fixed-metadata tarball; consumers extract it with mode
preservation and recompute this canonical tree digest before any policy is
built. Its recorded tarball SHA-256 is
`sha256:50cd430be18d424453569ed02a0f95b937ca44505762af446a001cdc7f72ddd2`.

The workflow passes the trusted-key file by its absolute workspace path
because the trust-anchor loader rejects relative paths; it is outside the
donor shelf (`$RUNNER_TEMP/leitir-corpus-root`). The delegated session key
was rotated to the owner-controlled long-term key above on 2026-08-17; any
future re-ratification re-signs with that owner key (or a successor recorded
the same way: rotate `trusted-keys-v1.json`, re-sign, and append the ceremony
history here). Future rotations should follow ADR-0022's retire or compromise
ceremony and migrate the file to the v2 schema as part of the rotation.

A digest computed by this repository only binds content and cannot ratify it.

This content does not make the exit gate runnable by itself. `exit-gate-run`
requires the honest containment substrate, including `nsjail`, a donor-free
immutable rootfs containing the pinned interpreter/stdlib, `/harness/runner.py`,
and explicit `-S` runtime dependencies; see `leitir.pipeline_cli` for the
runtime boundary. The rootfs digest is a deterministic tree hash of that image,
not of the donor corpus.
