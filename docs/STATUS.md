# Leitir — Status (2026-08-04)

Leitir is a deterministic code-search kernel with a standalone evidence-bound
scoring engine. The v1 Hy3 synthesis pipeline has been deleted.

## Where things stand

**ADR-001 is complete.** Slices P1–P6 plus the retirement slice P0r are landed.
The kernel accepts a typed `SearchSpec`, returns a provenance-bound
`SearchReport`, resolves packages across PyPI/crates/Go, ranks deterministically,
and ships a pinned 12-task benchmark behind `leitir bench`.

**ADR-002 is complete.** Slices S1-S9 are landed. The
scoring engine has typed contracts and a non-compensating gate, canonical
provenance, and collectors for engine correctness, retrieval effectiveness,
code health, test adequacy, supply chain, and controlled performance, plus a
deterministic renderer, release profile, and a published self-assessment
guarded by a regeneration drift check.

**ADR-004 is implemented; slices M1–M7 are complete.** It adds a local
source materialization layer (corpus): SHA-pinned, verified, complete
source trees shelved into a gitignored folder with provenance manifests
and documentation pointers, so AI agents reference proven open-source
code instead of generating from scratch. The design re-implements the
fetch-and-cache model of vercel-labs/opensrc (Apache-2.0; attribution in
the ADR) and extends it with commit-SHA pinning, integrity verification,
multi-ecosystem lockfile version detection, and a normative agent
workflow, an agent skill, and a pinned fetch-correctness benchmark.

**ADR-005 is in progress.** Slices C1–C7 are landed: GitLab/Bitbucket
host-aware resolvers and materialization (C1); registry-artifact parity
(C2); byte-exact artifact-first resolution (C3); transitive dependency
closure via `leitir lock` (C4); immutable snapshot export/import (C5);
SBOM generation via `leitir sbom` (C6); and API surface extraction via
`leitir api` with Python `ast` + a JS/TS heuristic and plugin hook (C7).
Slices C8–C10 remain.

Offline suite: **991 passed, 45 skipped**. The 45 skips are opt-in live tests
behind `LEITIR_ENABLE_LIVE_E2E=1` / `LEITIR_ENABLE_SCORE_LIVE=1`.

## What the scorer says about Leitir

Run against this repository, the engine **declines to pass itself**:

```
profile=offline  decision=indeterminate  complete=false
score_bps=unknown  observed_score_bps=10000
lower_bound_bps=476  upper_bound_bps=10000
release_readiness=not_claimed          exit 3
```

This is the correct output, not a defect. Everything measured passed — hence
`observed=10000` — but 29 required results have never been collected on this
repository, so the exact score is unknown and the bounds stay wide. A tool that
reported a confident 10000 here would be reproducing the exact failure this
project started from.

To improve that number, collect the missing evidence. Do **not** relax the
policy: anti-gaming rule 2 makes policy, qrels, baselines and exclusions
separately reviewable artifacts that are never changed in the same slice as an
implementation.

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

- **ADR-005 C2–C10** — registry-artifact parity, byte-exact resolution,
  transitive closure, snapshots, SBOM, API surface, examples, diff, trust.
- **Bitbucket live re-verification** — the C1 live gate is green for GitLab;
  Bitbucket live is blocked by an anonymous HTTP 429 on this host (no
  `BITBUCKET_TOKEN`). The offline fixture suite covers Bitbucket correctness;
  re-run the live gate with a token to fully close C1.
- **Private Bitbucket archive auth** — `BITBUCKET_TOKEN` is attached only to
  `api.bitbucket.org`, so private Bitbucket archive downloads (`bitbucket.org`)
  are unauthenticated. Public repos (the anonymous default) are unaffected.
- **Collect the 29 missing required results** so the assessment resolves to a
  real score instead of honest bounds. Collect evidence; never relax policy.
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
