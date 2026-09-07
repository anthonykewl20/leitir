# Real-world validation audit — issue #343

This work does not replace deterministic unit tests with network-only tests.
It separates their claims, executes real installed-product journeys, and fixes
faults exposed by those journeys. No test count is a proof of universal product
correctness.

## What was wrong with the evidence

- The full offline suite could pass while the live gate remained closed.
- Many tests call Python implementation APIs or use local transport/fixture
  data. These remain regression evidence, not installed-product evidence.
- Four purported live containment tests unconditionally skipped even after
  their environment gates opened. They contained no assertions. Removed those
  placeholders; actual containment evidence comes from the hosted CLI job.
  A new inventory guard failed on all four original bodies before removal.
- The inventory helper accepted collected filenames without checking whether
  collection itself succeeded. It now rejects a failed collection.
- Benchmark pin verification walked thousands of unrelated Git trees in a
  truncated repository. Two exploratory runs were interrupted while blocked
  in network reads. Targeted Git tree-chain verification retains all 32 source
  pin/hash/line assertions and completed in 28.37 seconds. Full-tree fallback
  remains a separate live contract and was not replaced with a partial walk.

`test-audit.json` is a structural inventory, not a semantic judgment of every
patch call. Environment patching and principal-operation replacement require
reading the test to distinguish them. A file whose name contains "live" can
also be an evidence-corruption or orchestration test; it is not automatically
a real-world user journey.

## Defects found using actual upstream data

1. **CommonJS API omission.** The installed command fetched the real
   `npm:is-number@7.0.0` package but reported zero API symbols for its direct
   `module.exports = function(num)` export. The source-backed heuristic now
   reports that function, preserving its line/signature. A deliberately
   fabricated API-cache symbol cannot survive a subsequent `info` call.
2. **Unsupported-host `ask` traceback.** Starting from the unmodified pinned
   `rsc/quote` Go manifest, `lock` fetched its real module dependency. `ask`
   treated its proxy-only shelf as GitHub and leaked an HTTP 404 traceback.
   The installed regression failed before the fix. It now emits structured
   `search_error`, null matches/coverage, and a nonzero exit while retaining
   available source-backed information. Provider tree-read errors use the
   same controlled failure path.
3. **Hosted anonymous-rate-limit failure.** The real contained exit gate
   completed all five donors, but the optional BTS benchmark exhausted the
   anonymous GitHub quota. Authenticated donor acquisition now happens in an
   unprivileged host step; no token is passed into the sudo/contained runner.
   Sidecars are validated before fetching and cached shelves are verified
   again before execution. The failed run remains part of the evidence.

4. **Windows command journal hashes.** Independent artifact verification found
   122 stream hashes in the first Windows artifact did not match saved bytes:
   text-mode file writes introduced CRLF after hashing LF-normalized output.
   The journal now writes explicit UTF-8 bytes and reads each saved stream back
   to verify its recorded digest. The original mismatches remain in the archive.

## Assertion corrections and known boundaries

The initial exploratory journey run also made two incorrect assumptions:
corpus search excludes invalid indexes with explicit `corpus_status=partial`
and exit 0, whereas snapshot-import integrity failures use exit 1. Assertions
now pin these documented contracts, including zero matches and explicit
exclusions/non-success coverage. Neither correction weakened a production
rejection. The initial run's errors are retained rather than relabeled as
successful validation.

Rust crate acquisition works, but the built-in API extractors do not support
Rust. The registry journey validates acquisition and explicitly checks the
unsupported analysis result; it is not counted as successful Rust extraction.
`pypi:packaging@24.2` lacks import-root evidence recognized by `check`; the
command correctly reports `nothing_examined` with exit 4. The Requests journey
instead checks an unmodified real upstream consumer and independently counts
its relevant AST calls. This verifies static symbol existence, not execution
of the consumer's Python code.

The hosted donor corpus exercises selected real source functions under actual
containment. Its contract cases are deliberately authored acceptance criteria;
they do not establish arbitrary downstream compatibility or all donor behavior.

The six-task BTS benchmark completed measurement but reproduced the existing
published unsuccessful integration metrics exactly: integration 0/5, adaptation
integrity 0/9, helper recall 2/11. The sixth task rejects unknown mypy parity.
Its previous README called this a green run; that claim is corrected here.
Substantial real task-integration work is tracked with acceptance criteria in
[#346](https://github.com/anthonykewl20/leitir/issues/346). The anonymous Bitbucket
enumeration check still encounters HTTP 429; authenticated validation is tracked
in [#345](https://github.com/anthonykewl20/leitir/issues/345). Neither is a pass.

## Evidence lanes

- **Installed user journeys:** clean wheel installation, no runtime dependencies,
  console commands outside the checkout, all downloaded Git blobs checked
  against independent GitHub metadata, all emitted Python API definitions
  checked against source AST locations, example text checked against source,
  actual source/index/manifest/API-cache/snapshot tampering and recovery,
  source-line search oracle and three hash seeds, registry acquisition,
  real dependency lock/check/ask, snapshots, SBOMs, diff, cleanup and doctor.
- **Existing live inventory:** actual provider and public/API workflows,
  separately reported from installed-console evidence. Interrupted attempts,
  environment skips and failed runs remain visible.
- **Contained execution:** exact release-pinned nsjail/rootfs and donor pins,
  fresh hosted exit-gate and optional task-corpus reports.
- **Offline regression and CI:** required full suite, ruff, mypy, docs-truth,
  platform/coverage/determinism/auth/package checks; supplementary evidence.

Final result counts, artifact identities, hosted run links, limitations and
reviewed commit are recorded in this PR and the accompanying result manifest.

## Archive handling

`raw-evidence.tar.gz` retains command streams, pytest logs/JUnit, provider metadata
and containment reports, including failed and interrupted attempts. It excludes
installed environments and corpus caches. `artifact-manifest.json` hashes the
archived bytes. One interrupted diagnostic log contained a credential; only that
credential is replaced with `[REDACTED_GITHUB_CREDENTIAL]` before archiving, and
the manifest records the replacement count. All other archived output is retained
as produced. Old Windows command-hash mismatches are explicitly historical failures,
not valid file bindings; the archive manifest binds their actual saved bytes.

## Recorded results and review amendment

The reconciled enabled live inventory contains 96 cases: **95 passed, one
Bitbucket rate-limit skip, zero failures** across the recorded attempts and
retries. `live-inventory-results.json` maps every exact test ID to its outcome
and evidence file. The eight tree/cache/verification cases passed in 1483.74s;
the single full recovery returned 81,368 blobs versus 53,309 initially visible.
The serial suite produced **3744 passed, 166 skipped, 4 warnings in 1045.71s**.
These are measured results at the commits identified in `results.json`.

Both platforms' installed journeys passed at PR merge commit `2e150dc3`, whose
complete tree equals branch commit `4c2c899`: 11 cases, 71 commands each, no
unexpected exits or stream-hash mismatches. The sensitive review then found
that a regex brace could fabricate a nested CommonJS export. The retained
`commonjs-runtime-red.log` compares actual Node output with the actual extractor;
the green log repeats that flow after the conservative slash boundary fix.
The crafted adversarial source is a rejection probe, not an upstream package
or independent evidence of general JS support. The regression failed before
that fix; seven API regression cases passed afterward. Final post-review CI,
installed journey runs and approvals are recorded in PR #344; the earlier
archive remains unchanged as historical evidence, with its commit boundaries
explicitly retained.

Run `python docs/evidence/issue-343-2026-09-07/verify.py` to verify archive/file
bindings and both recorded final-platform command journals. A changed copy of
the actual archive was rejected (`archive-tamper.log`). These hashes bind the
recorded evidence bytes; the reviewed repository commit supplies their anchor.
