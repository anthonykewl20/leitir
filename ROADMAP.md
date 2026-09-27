# Leitir Roadmap

## Product goal

Leitir is the AI coding agent's **GitHub code scavenger** for the research-and-plan
phase. Given a task (for example "build Next.js authentication"), the agent should be able
to find the most mature working OSS implementations, understand and compare them from
byte-verified, commit-pinned source, choose a base and references, and then copy, port or
adapt with a durable provenance record. The purpose is to stop agents from hand-waving
architecture and code: suggestions are grounded in mature, cited, verified source.

This is code referencing with more power than IDE suggestion matching (GitHub Copilot code
referencing): it works *before* code is written, on whole implementations rather than
~150-character matches, with commit pinning and replayable evidence. Owner decisions
(2026-09-27): official-documentation tooling is out of scope; license is informational
(shown accurately per path, never a gate — the agent decides to copy, adapt or learn).

Evidence: [real-user audit 2026-09-27](docs/evidence/audit-2026-09-27/README.md) and
[competitive landscape 2026-09](docs/research/competitive-landscape-2026-09.md).

## Current milestone — v0.3.000 GitHub Code Scavenger

[Milestone 7](https://github.com/anthonykewl20/leitir/milestone/7), tracked by epic
[#410](https://github.com/anthonykewl20/leitir/issues/410). Phases are an ordering guide;
priority labels decide within a phase.

- **Phase 0 — first-minute blockers and integrity defects:** package-scoped search fails on
  every registry shelf (#349), monorepo shelf collisions (#350), `lock` fails open (#368),
  `ask --pin` source selection (#369), dropped monorepo subpath (#351), onboarding (#402),
  opaque GitHub errors (#373), docs truth (#367).
- **Phase 1 — analysis quality on real packages (TS/JS first):** TS/JS API extraction
  (#353), JS/TS predicates (#371), tsx/jsx (#370), examples (#355), global coverage (#372),
  corpus eligibility (#359), parity (#352), original-source preference (#405), lockfile
  coverage (#403), npm ranges (#404), PyPI tags (#361), license display (#357, #358), test
  detection (#356), Go API (#354), Rust/Java API (#389), non-GitHub hosts (#360), ref
  syntax (#374), metadata (#366), diff notes (#362), output fixes (#375), `check` mixed
  directories (#363), non-Python BTS (#364), comparison evidence (#365).
- **Phase 2 — scavenger core (find, rank, understand, compare):** maturity signals (#380),
  project-grouped discovery (#381), BM25 ranking (#382), task compilation (#384), task
  scouting (#376), comparison (#383), token-budgeted reads (#386), architecture map
  (#387), tests-for-symbol (#391), research pack (#377), grounding enforcement (#378).
- **Phase 3 — reuse with provenance:** advisory license (#398), adoption records (#393),
  base from a mature subtree (#379), winnowing fingerprints (#394), origin lookup (#395),
  adopted-code drift (#396), attribution export (#397), TS/JS hallucinated-API gate
  (#399), non-Python adaptation (#400), unwired subsystems (#406), real BTS integration
  (#346).
- **Phase 4 — agent surface, depth and growth:** MCP expansion (#401), def/refs (#388),
  history mining (#390), PyPI and registry distribution (#407), competitor benchmark
  (#408), README and recipes (#409).

Execution order for agents (dependency waves) is in the epic #410; every issue carries
explicit `Blocked by` links and its design decisions, so no owner input is pending.
Closed as not planned: semantic-search (#385) and LLM repository Q&A (#392) extras — the
calling agent is the model, and ADR-0001 keeps the core model-free.

Milestone definition of done: the north-star journey in #410 runs end to end on a clean
machine and offline from recorded snapshots; the benchmark is published; the README first
screen reflects the scavenger positioning with CI-verified commands; v0.3.000 is released
per ADR-0038 and published to PyPI and the MCP registry.

## Versioning philosophy

- **Public versions** use `MAJOR.MINOR.PATCH` with exactly three patch digits (`0.2.000`,
  `0.2.001`, …) per [ADR-0038](docs/adr/0038-release-versioning-and-publication.md).
  Substantial capability or compatibility changes advance the minor version and reset the
  patch; corrective releases advance the patch. Python packaging normalizes `0.2.000` to
  `0.2.0`.
- **"Production-ready"** — a quality label, not a version number. Achieved within the 0.x
  series when the Critical/High audit findings are resolved, the self-scorecard passes, and
  real load testing confirms behavior at scale.
- **v1.0** — reserved as a **major adoption milestone** (target: 10,000 users), not a
  feature or quality milestone.

## Distribution

**Current: GitHub-only.**

- Install: `pip install git+https://github.com/anthonykewl20/leitir.git@<tag>`; optional
  extras from a checkout or git URL (for example `pip install '.[mcp]'`).
- Release artifacts: GitHub Releases. Publication requires green CI for the exact commit,
  verified CI-built artifacts, provenance attestation and committed release notes
  (ADR-0038); the release workflow publishes the CI-tested artifacts rather than
  rebuilding them.
- Update notifications: poll the GitHub Releases API on a 24h cache.

**Planned (#407): PyPI and agent registries.** Trusted publishing to PyPI gated on the same
release verification; `uvx`/`pipx` one-line installs; listing in the official MCP registry
and agent skill/plugin marketplaces.

## Release history

- **v0.2.000** (2026-09-05) — accumulated remediation and release-verification tooling;
  runtime digest re-ratified (`sha256:901bf7ac…`). Notes: `docs/releases/0.2.000.md`.
- **v0.1.6** (2026-08-25), **v0.1.5** (2026-08-24, milestone "Scavenger reliability &
  hardening").
- **v0.1.4** (2026-08-17) — Search v2 (wide+deep): local trigram index, AST/heuristic
  adapters, truncation-safe tree walk, verified streaming.
- Milestones v0.1.1–v0.1.5 are closed. Milestone "Verified Usage v1" (#255–#259) has no
  open issues; its `usage` verb shipped.

## Initially implemented (v0.1.0 scope)

- v0.1.0: ADR-006 load-time tree verification (#17, #18, #19, #20 — all closed)
- ADR-005: corpus-v2 capabilities (C1-C10 complete)
- ADR-004: local source materialization
- ADR-003: categorized HTTP retry
- ADR-002: deterministic evidence scoring engine (standalone repository scorer)
- ADR-001: deterministic code-search kernel

## Earlier programs (historical)

- v0.1.2 BTS program via PR #127, implementing ADR-0008 through ADR-0011; ratified
  2026-08-17 and proven by Phase-C main run 32018948262 (5/5 donors). The runtime digest
  was re-ratified on 2026-09-05 for v0.2.000.
- v0.1.3 composition and multi-language wave via PRs #131–#139: composition,
  architecture, duplicates, lineage, cost, and occupied-recipient validation; ADR-0012
  stage-1 policy/registry and stage-2 JavaScript/TypeScript/Rust/Go graph producers; and
  ADR-0013 through ADR-0019.
- #148's CLI surfaces: `bts-compute`, architecture/lineage analysis, capability funnel,
  pipeline, transplant, occupied validation, and runnable exit-corpus gates. #75's six-task
  benchmark is published; #346 tracks the real-integration gaps it exposed.
- PRs #163–#179 completed the contained Phase-A evidence, security P2 fixes, release-pinned
  rootfs (`containment-rootfs-v1`,
  `sha256:ec28886a5e448e9d6b088470c85ee2e0d170e16002bd78ecc835e9d4161155ac`), and the
  ratification ceremony.

## v0.1.1 — production-ready audit criteria (all engineering issues closed)

Tracked at epic #42. All Critical/High/Medium/Low engineering issues below are **closed**.
The real ≥100-package load-test gate passed with 116 packages (including 29
sampled-boundary cases), independent dogfood evidence is recorded, and two post-#163
security reviews recorded no P0/P1 findings; PR #166 remediated all P2 findings.

- Critical: #22 ADR-002 contract drift; #23 missing-evidence-as-zero; #41 self-scorecard
  `decision=pass`.
- High: #24 trust age factor; #28 symlink escape; #31 snapshot binding; #33 corpus bench
  mocked; #34 uncovered raises; #35 trust weighted score tests.
- Medium/Low: #25–#27, #29, #30, #32, #36–#39.

## Post-production-ready (still v0.x)

- [x] Manifest authenticity (#40) — shipped as ADR-0018 optional detached publisher
  authentication (`--require-manifest-auth`).
- [x] Real load testing with 100+ package corpora — passed with 116 exercised packages;
  see `docs/evidence/loadtest-100-2026-08.md`.
- TOCTOU hardening via filesystem snapshots.

## Retired / historical

- v1 PRD: docs/PRD.md
- v1 smoke evaluation: docs/smoke-evaluation.md
- Manual scorecards: docs/leitir-engine-scorecard.html, leitir-engine-scorecard-v2.html,
  leitir-engine-scorecard.png

These are retained for context but are never scorer evidence.

## How to contribute

AI agents: see AGENTS.md for workflow conventions. Pick up issues from the
[v0.3.000 milestone](https://github.com/anthonykewl20/leitir/milestone/7) in phase order;
issues labelled `ready-for-agent` can be started directly, and `adr-required` issues start
with an ADR PR. Humans: start with the epic
[#410](https://github.com/anthonykewl20/leitir/issues/410); `good first issue` labels mark
small, well-scoped fixes.
