# Leitir — Status (2026-08-16)

Leitir is a deterministic code-search kernel with a standalone evidence-bound
scoring engine. The v1 Hy3 synthesis pipeline has been deleted.

## Where things stand

**ADR-001 is complete.** Slices P1–P6 plus the retirement slice P0r are landed.
The kernel accepts a typed `SearchSpec`, returns a provenance-bound
`SearchReport`, resolves packages across PyPI/crates/Go, ranks deterministically,
and ships a pinned 32-task benchmark across eight languages (four tasks each)
behind `leitir bench`. (`src/leitir/bench.py:24-31`,
`src/leitir/benchmarks/search-v1/manifest.json:1`.)

ADR-001's search kernel now includes the search-v2 extensions: a deterministic
eight-language adapter registry and canonical language routing, opt-in Python
AST/`symtable` matching, heuristic Tier-2 adapters, whole-file required
predicates, verified streaming for blobs above 2 MiB, bounded truncated-tree
recovery with partial-result reporting, exposed global budgets, and exact
global `(slug, commit_sha, path, blob_sha)` provenance validation.
(`src/leitir/adapters/registry.py:17-59`,
`src/leitir/adapters/languages.py:5-17`,
`src/leitir/adapters/python_ast.py:186-226`,
`src/leitir/adapters/_tier2/_base.py:27-100`, `src/leitir/streaming.py:37-168`,
`src/leitir/tree.py:136-210`, `src/leitir/cli.py:377-405`,
`src/leitir/discovery_search.py:671-707`.)

Search v2 (v0.1.4) is implementation-complete and was independently
cross-reviewed and hardened post-merge in PRs #109, #112, #113, #114, #115,
#117, #120, #121, and #122. Tracking issues #108, #110, #111, #116, #118,
and #119 are closed.

The Behavioral Transplant Set code landed on `main` via PR #127. ADR-0008
through ADR-0011 are Accepted and Implemented, and issues #55, #60, #61, #62,
#63, #64, and #72 are closed. The v0.1.2 milestone remains open only for epic
#52 and exit gate #73: all five Phase-A donors have repeatedly completed under
containment with 2/0/0 baseline and rerun outcomes. The final honest run
[31967278924](https://github.com/anthonykewl20/leitir/actions/runs/31967278924)
is an overall reject solely because `ratified_runtime_digest` remains null
until a stable runtime digest can be ratified. The six-task #75 benchmark is
published; its one `worker-shutdown-predicate` result remains an honest partial.

### v0.1.3 — composition and multi-language

ADR-0012 through ADR-0017 and ADR-0019 are Accepted and implemented. ADR-0012's
stage-1 policy/registry and stage-2 JavaScript,
TypeScript, Rust, and Go producers live in
`src/leitir/graph/{ts_kernel,javascript,typescript,rust,go}.py`, backed by the
hash-locked optional `tree-sitter` extra and `requirements-tree-sitter.lock`.
The certified tuple is `tree-sitter==0.25.2` with JavaScript 0.25.0, TypeScript
0.23.2, Rust 0.24.2, and Go 0.25.0; it is wheel-only and fails closed on
unsupported platforms, including musllinux-aarch64. Its 66 wheel SHA-256
digests are installed only with `--require-hashes --only-binary :all:`; a
missing extra rejects with `REJECT_UNSUPPORTED_EXTRA`. The 3.12/3.14
tree-sitter CI job runs all four polyglot test files. ADR-0012's tuple ABI,
hash/platform, and measured-limits questions are answered, with the 7,544-file
limits evidence at `docs/evidence/oq3-tree-sitter-limits-2026-08-14.md`.
The producers remain conservative and never guess, with per-language golden,
tamper, determinism, and budget tests.
Composition, architecture, duplicate-abstraction detection, lineage,
integration-cost, occupied-recipient validation, and ADR-0018's optional
detached manifest-authentication layer landed through PRs #132–#139 and the
2026-08-15 integration work. v0.1.3 is complete; #148's evidence-backed CLI
surface is complete and its tracker is closed.

2026-08-16: PRs #163–#179 completed containment, security, benchmark, rootfs,
and ratification follow-up. The release-pinned, published
`containment-rootfs-v1` asset verifies to
`sha256:ec28886a5e448e9d6b088470c85ee2e0d170e16002bd78ecc835e9d4161155ac`.
PR #166 remediated the security P2 findings (evidence redaction, scratch quota,
uid-map fail-closed handling, nsjail golden hash, idna pin, and Go-zip golden
vector) after two independent reviews recorded no P0/P1 findings.

Ratification is held rather than claimed: the Ed25519 ceremony sidecar and
trusted-key record exist, but `ratified_runtime_digest` is null pending an
owner signature. ADR-0021's manifest-free donor mount projection removed the
run-to-run drift of staged mount-source tree digests, so the runtime digest is
now a pure function of pinned inputs; re-measure it, then re-sign. See
[`benchmarks/exit-corpus/README.md`](../benchmarks/exit-corpus/README.md).

2026-08-14: ADR-0017 trust-binding hardening pins occupied-gate authority to policy, requires bound rerun receipts, and requires complete dependency evidence for composition acceptance.

2026-08-14: benchmark-driven hardening made verified local-shelf scoped search
drop from a seven-minute timeout to 1.8s with 0 blob GETs; expanded first-party
Go API extraction from 0 to 93 symbols; refreshed license detection from null to
Apache-2.0; and made `gopkg.in` and `google.golang.org` modules resolve and
verify through authenticated Go module zips.

2026-08-14: #144 is resolved by retaining the full materialized-tree-hash
requirement for trigram-index eligibility. The documented local-shelf exception
continues to serve verified local bytes without weakening index eligibility.
SumDB response reads are bounded to 1 MiB and fail closed with
`SumDBVerificationError`.

**ADR-002 is complete.** Slices S1-S9 are landed. The
scoring engine has typed contracts and a non-compensating gate, canonical
provenance, and collectors for engine correctness, retrieval effectiveness,
code health, test adequacy, supply chain, and controlled performance, plus a
deterministic renderer, release profile, and a published self-assessment
guarded by a regeneration drift check.

ADR-002 is a six-dimension repository self-assessment, not an independent
implementation of runtime corpus trust. The runtime seven-factor model remains
owned by `src/leitir/trust.py` and is guarded by its deterministic weight/factor
contract and weight-swap mutation tests in `tests/test_trust.py`.

**ADR-004 is implemented; slices M1–M7 are complete.** It adds a local
source materialization layer (corpus): SHA-pinned, verified, complete
source trees shelved into a gitignored folder with provenance manifests
and documentation pointers, so AI agents reference proven open-source
code instead of generating from scratch. The design re-implements the
fetch-and-cache model of vercel-labs/opensrc (Apache-2.0; attribution in
the ADR) and extends it with commit-SHA pinning, integrity verification,
multi-ecosystem lockfile version detection, and a normative agent
workflow, an agent skill, and a pinned fetch-correctness benchmark.

**ADR-005 is implemented; slices C1–C10 are complete.** It extends the
corpus from a verified git-tree shelf into a verified, byte-exact,
reproducible, analyzable dependency source: GitLab/Bitbucket host-aware
resolvers and materialization (C1); registry-artifact parity
`exact|drift|unknown` with fail-closed checksum verification (C2);
byte-exact artifact-first resolution with `source` provenance (C3);
transitive dependency closure via `leitir lock` (C4); immutable snapshot
`export`/`import` with fail-closed, verify-all-before-shelve rehydration
(C5); SBOM generation via `leitir sbom` SPDX 2.3 / CycloneDX 1.5 with
deterministic license inference (C6); API surface extraction via
`leitir api` (C7); usage-example extraction via `leitir examples` (C8);
version diffing via `leitir diff` (C9); and deterministic trust scoring
via `leitir trust` surfaced in `leitir list` (C10).

**ADR-006 is implemented.** Load-time tree verification is provided by the new
`src/leitir/treehash.py` module. Verified shelves must carry a
`materialized_tree_hash` and are re-hashed whenever loaded; missing, malformed,
unsupported, or mismatched mandatory fields fail closed. Legacy verified
shelves migrate with `leitir upgrade-cache`, while `update_manifest`
opportunistically backfills a digest after existing provenance checks pass.
Hashing is deterministically bounded at `MAX_FILES=1000` and `MAX_BYTES=64 MiB`,
with partial coverage explicitly recorded as sampled. Follow-ups #18 and #19
are closed; #20 is closed with its performance optimization deferred. The
originating #17 is also closed. Broader audit work is tracked by the
[Production-ready path (v0.x series)](https://github.com/anthonykewl20/leitir/milestone/1).

## Operational readiness

| Gate | State | Evidence / remaining work |
| --- | --- | --- |
| Load test | **MET** | 116 packages, including 29 sampled-boundary cases, completed the required load/search/integrity phases: [`loadtest-100-2026-08.md`](evidence/loadtest-100-2026-08.md). |
| Dogfood | **MET** | Independent evidence is recorded in [`dogfood-2026-08-15.md`](evidence/dogfood-2026-08-15.md). The tracked friction backlog is L1, L3, L4, L7, L8, L9, M3 items 1/2, and M4. |
| Live canary | **GREEN** | `GH_TOKEN`-gated probes are enabled daily; main runs 31934680140 and 31934798266 are green. Three v2 surfaces skip by design because their test files are not landed. |
| Security sign-off | **DONE** | Two independent reviews on post-#163 state recorded no P0/P1; PR #166 remediated all reported P2 findings. |
| Phase-A containment | **5/5 COMPLETE** | Each donor repeatedly completed contained baseline/rerun at 2/0/0. Run 31967278924 is intentionally overall-reject only for pending runtime ratification. |
| Runtime ratification | **PENDING** | Ceremony key/sidecar are committed; ADR-0021 removed the mount-source digest drift. Re-measure the stabilized runtime digest, then re-sign. |
| BTS bench (#75) | **PUBLISHED** | Published run `88330e29…` has five complete tasks with exact baselines/metrics and one honest `worker-shutdown-predicate` partial (`bts_cli_parity_v1`); E5b timing remains deferred offline. |

Milestone state: #42 is **closed** and v0.1.1 milestone closeout is pending;
v0.1.2 remains open for #73 ratification and #52; v0.1.3 and v0.1.4 are
complete, with the v0.1.4 release owner-gated. #75 and #148 are also closed.

Post-ADR-005 hardening + sprint: GitLab nested-subgroup paths; trust
"tests" fairness (`has_tests` from the git tree, neutral for artifact
sources); Bitbucket live tolerance of anonymous rate-limiting; `leitir lock
--best-effort`; `leitir info <spec>` one-shot agent context (provenance +
api + examples + trust + parity) with a versioned `--json` contract across
commands; unified credentials (private Bitbucket archive auth incl.
app-password Basic, optional npm/PyPI/crates registry tokens); Go module
multi-host (`gitlab.com`/`bitbucket.org`/`golang.org/x`); Codeberg and
Sourcehut hosts; and fail-closed cleanup of orphan dirs on failed
materialization. Comprehensive real-world + sad-path testing passed.

Offline suite: **2647 passed, 122 skipped**. The skips are opt-in live tests
behind `LEITIR_ENABLE_LIVE_E2E=1` / `LEITIR_ENABLE_SCORE_LIVE=1` and polyglot
tests that require the optional tree-sitter extra; with that extra installed,
the four polyglot test files run **105 additional tests**.

## What the scorer says about Leitir

The published canonical self-assessment **passes the offline profile**:

```
profile=offline  decision=pass  complete=true
score_bps=unknown  observed_score_bps=8697
lower_bound_bps=7247  upper_bound_bps=8914
release_readiness=not_claimed          exit 0
```

The published artifact has no missing required results and no blockers.
The fixed offline gate deselects the explicitly live-gated Go resolver test;
the live test remains available under `LEITIR_ENABLE_LIVE_E2E=1` but no longer
makes the offline-only collector fail by construction. Advisory OpenSSF and
performance evidence remains unknown, so the exact score remains unknown and
this is not a release-readiness claim.
Its deterministic evidence is tracked under `.leitir-score/evidence`; the
offline pytest JUnit is regenerated for every clean pinned run. The regeneration
gate byte-compares both canonical outputs.

To narrow the remaining score bounds, collect the missing advisory evidence.
Do **not** relax the policy: anti-gaming rule 2 makes policy, qrels, baselines
and exclusions separately reviewable artifacts that are never changed in the
same slice as an implementation.

## History worth knowing

The prior status file (2026-07-25) recorded a **false green**: a run accepted on
Tier-3-only evidence when the manifest required Tier 2. That diagnosis drove
both ADRs, and the resulting invariants are now enforced in code and pinned by
tests:

- a zero-collection test run cannot read as pass, even if the process exit says 0;
- skipped tests are never counted as passing, and an all-skipped run is not green;
- global discovery claiming exhaustiveness is a hard failure;
- an unknown score renders as unknown with bounds, never as zero;
- zero completed mutants never yields a perfect mutation score;
- the OpenSSF aggregate is discarded, because it omits inconclusive checks and
  can therefore rise as evidence goes missing.

The fail-closed grounding gate that the old status file named as the top
priority was never pushed and was lost when the repository was re-cloned on
2026-08-01. It is moot: it guarded the v1 acceptance path, which no longer
exists. Its intent — never accept on unsatisfied evidence — is now carried by
the scoring engine's gate precedence.

## Open work

- **Bitbucket live re-verification** — Bitbucket live tests now skip cleanly
  under anonymous rate-limiting (no `BITBUCKET_TOKEN`) instead of failing the
  gate; the offline fixture suite covers Bitbucket correctness. Fully running
  the Bitbucket live path still requires a token.
- **Custom private registry URLs** — default-registry auth tokens
  (`NPM_TOKEN`/`PYPI_TOKEN`/`CARGO_TOKEN`) are supported; private registry
  endpoints with different URLs (npm Enterprise, Artifactory, private PyPI
  index) are a future follow-up on top of the unified credentials layer.
- **Sourcehut live** — covered offline + a live resolver test; full live
  materialization needs an `SRHT_TOKEN`.
- **Self-scorecard release gate (#41)** — the current worktree reaches an
  offline-only pass with complete required benchmark, coverage, and mutation
  evidence. The public OpenSSF API still returns 404, and release readiness
  additionally requires live OpenSSF evidence and an approved controlled
  performance baseline. The hard release gate is due before v1.0 (the
  10,000-user adoption milestone), not v0.1.1.
- **Metric floors and baselines** — deliberately absent. §7 and §10 require
  these to be adopted in a separate reviewable change once a measured corpus
  exists; no slice may bundle them with an implementation.
- **In-toto signing** — §11 defers it; the unsigned statement is sufficient for
  the first executable score.
- **Import-purity proxy** — the gate forbids `urllib.request` in `sys.modules`,
  which is a loose proxy since binding those names performs no I/O. The HTTP
  clients defer the import to keep the gate honest; narrowing the list to what
  it actually proves is a separate change.

## Issues

[#13](https://github.com/anthonykewl20/leitir/issues/13),
[#15](https://github.com/anthonykewl20/leitir/issues/15) and
[#16](https://github.com/anthonykewl20/leitir/issues/16) predate both ADRs and
are substantially superseded by them; see the comments on each.

## How to run

```bash
# Offline suite
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest

# Live re-verification against GitHub (opt-in)
LEITIR_ENABLE_LIVE_E2E=1 PYTHONPATH=src uv run --no-project \
  --with-requirements requirements.txt python -m pytest tests/test_bench_e2e_live.py

# Score this repository
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python \
  tools/score_engine.py run --profile offline \
  --json-out .leitir-score/assessment.json --html-out .leitir-score/scorecard.html
```

The scorer shells out to pytest, so it must run under an interpreter that can
import it — a bare `python3` silently collects nothing and reports
`COLLECTOR_ARTIFACT_MISSING`.
