# Leitir

Leitir is a deterministic, provenance-bound dependency-source corpus plus a deterministic code-search kernel for AI coding agents.

**Status: implementation-complete; design-stage software. Not production-ready.**

## Why

LLM coding agents frequently hallucinate library internals, edge cases, and version-specific behavior. Public type signatures only show declarations, not control flow. Even docs can miss implementation detail, deprecated paths, and calling conventions.

Getting the right source is the hard part in a machine-safe way: which lockfile version is actually used, which commit that version refers to, whether downloaded bytes match the claim, and how to reuse the same source again offline. It also needs a reproducible citation form, not a fresh inference each run.

## How it works

Leitir treats source as the answer surface and runs a strict materialization pipeline: resolve an exact version, fetch a bounded set of candidate artifacts, verify fail-closed, shelf a provenance-rich local tree, extract analysis surfaces, and emit immutable snapshots.

```mermaid
flowchart TD
    S["Spec<br/>npm: · pypi: · crates: · go: · github: · gitlab: · bitbucket:"] --> R["Resolve exact version<br/>lockfile pin → registry latest"]
    R --> AF{"Registry source<br/>artifact available?"}
    AF -- "yes" --> DL1["Download artifact<br/>npm tarball · PyPI sdist · crate"]
    DL1 --> CV["Verify published checksum<br/>sha512 / sha256 — fail-closed"]
    AF -- "no / retrieval fails" --> DL2["Fetch pinned git commit tree<br/>GitHub · GitLab · Bitbucket"]
    DL2 --> TV["Verify blobs vs host tree API<br/>fail-closed"]
    CV --> SH
    TV --> SH["Shelve under corpus root<br/>repos/host/owner/repo/<sha>"]
    SH --> M["Provenance manifest<br/>commit SHA · checksum · source · parity: exact|drift|unknown"]
    M --> OUT["POINTERS.md · API index · examples · SBOM · trust · diff"]
```

## What it gives you

- Multi-host source support: GitHub, GitLab (including nested subgroup slugs), Bitbucket, Codeberg, and Sourcehut (`~user/repo`); plus package ecosystems npm, PyPI, crates.io, and Go — including non-GitHub Go modules (`gitlab.com/`, `bitbucket.org/`, `golang.org/x/`) — for lockfile-aware resolution.
- Byte-exact artifact-first fetch for registry ecosystems using published checksums, with checksum mismatch treated as fail-closed.
- Git-tree verification against host APIs for the git-commit path.
- Explicit artifact parity as `exact`, `drift`, or `unknown` recorded in manifests.
- Per-source provenance manifests with immutable commit, checksum, source type, fetch root, and resolution metadata.
- `leitir info <spec>` — one-shot agent context (provenance + API summary + top examples + trust + parity in a single JSON call).
- API surface indexes with stdlib `ast` extraction for Python and conservative JS/TS heuristics behind a plugin hook.
- Ranked usage-example extraction from practical entry points (`README`, `docs`, `examples`, `tests`) with symbol evidence.
- SPDX 2.3 / CycloneDX 1.5 SBOM generation with deterministic license inference and explicit confidence.
- BTS reuse licensing uses a separate verified-byte-only, per-source REUSE 3.3
  resolver. It emits authoritative canonical `obligations.json` and derives
  `ATTRIBUTION.md` from that closed manifest; missing, ambiguous, deferred, or
  recipient-incompatible evidence fails closed.
- Deterministic trust scoring on a 0–100 scale, with factor weights (20,15,15,10,10,15,15) fixed to verification, parity, license, documentation, tests, checksum, and age (sum 100).
- Version diffing for file changes plus API-symbol changes between two resolved versions, including release-note notes when available.
- Transitive dependency closure via `leitir lock` and closure metadata in manifests.
- Immutable `export`/`import` snapshots with fail-closed rehydration checks.
- Optional, anonymous-by-default credentials: per-host tokens (GitHub/GitLab/Bitbucket incl. app-password Basic, Codeberg, Sourcehut) and registry tokens (npm/PyPI/crates) for private/authenticated access — HTTPS-only, never logged.
- Deterministic, stdlib-only code-search kernel from ADR-001.
- Standalone ADR-002 repository self-assessment engine that drives its own
  six-dimension gate decisions without model calls; it is separate from runtime
  corpus trust scoring.

```mermaid
flowchart LR
    subgraph Materialize
      GET["get / fetch"]
      LOCK["lock — closure"]
    end
    subgraph Analyze
      API["api — symbol index"]
      EX["examples — ranked snippets"]
      TR["trust — 0–100 score"]
      SB["sbom — SPDX / CycloneDX"]
      DF["diff — file + API deltas"]
    end
    subgraph Reproduce
      EXP["export — corpus.lock + tarball"]
      IMP["import — verify-all, fail-closed"]
    end
    TREE[("Shelved source trees<br/>+ provenance manifests")]
    GET --> TREE
    LOCK --> TREE
    TREE --> API & EX & TR & SB & DF
    EXP -. reads .-> TREE
    IMP -. writes .-> TREE
```

## Installation

```bash
# Install the latest from GitHub
pip install git+https://github.com/anthonykewl20/leitir.git

# Or pin to a specific release tag
pip install git+https://github.com/anthonykewl20/leitir.git@v0.1.0

# Then use the `leitir` command
leitir info npm:zod@3.22.0
```

Leitir is distributed via GitHub. The runtime is stdlib-only (`dependencies = []`),
so no third-party runtime dependencies are pulled in.

Behavioral-transplant donor execution is default-off and Linux-only. It requires
the exact opt-in `LEITIR_ENABLE_DONOR_EXECUTION=1` and a release-pinned external
native **nsjail** binary and policy; missing or unverifiable containment rejects,
with no portable or unsandboxed fallback. NsJail is not a Python dependency.
See [SECURITY.md](SECURITY.md) and [ADR-0009](docs/adr/0009-transplant-validation.md).

Relocated contract tests are rerun with the donor excluded by the read-only
filesystem mount plan, not by Python import hooks. The rerun report requires the
exact pinned canonical test-ID set, pass/fail/skip totals, and per-ID outcomes;
the runtime import recorder remains diagnostic-only. The contained interpreter
uses a sanitized environment with `PYTHONHASHSEED=0` and never uses `-I`.

From a source checkout:

```bash
pip install .
# or for an editable checkout:
pip install -e .
```

### For contributors

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development setup. For quick feedback:

```bash
pip install -e '.[dev]'
PYTHONPATH=src python -m pytest -q
```

`./requirements.txt` is a pinned development/CI dependency closure, not a runtime requirement.

From a checkout where installation is unavailable, invoke commands as `PYTHONPATH=src python -m leitir.cli ...` instead.

## Quick start

```bash
# Materialize a real package and read it from the returned path
path="$(leitir get npm:zod@3.22.0)"
rg "parse" "$path"
cat "$path/package.json"

# Run search and benchmark commands
leitir search --package zod --version 3.22.0 --ecosystem npm --must symbol_definition:parse
leitir index
leitir search --package zod --version 3.22.0 --ecosystem npm --must exact_text:parse --index
leitir bench
```

## The agent workflow (required)

Before writing behavior against a library/framework, run `leitir info <spec>` and synthesize from its extracted public signatures, docstrings, and top usage code with provenance. Do not hand-roll behavior the source already defines. Read full files only for behavior beyond that surface: fetch missing sources with `leitir get <spec>`, read `POINTERS.md` and files (`rg`, `cat`, `find`), and cite used files as `<owner>/<repo>/<file>@<commit-SHA>` using the manifest commit SHA.

```mermaid
flowchart LR
    A["AI coding agent"] -->|"needs library internals"| G["leitir get &lt;spec&gt;"]
    G -->|"absolute path to proven tree"| A
    A -->|"rg / cat / find the source"| T["real files @ pinned commit"]
    T -->|"cite owner/repo/file@sha"| CODE["grounded, non-hallucinated code"]
```

## Commands

### Search and benchmark
- `search`: resolve spec+predicate scope and return provenance-bound results.
- `index [scope ...] [--root ROOT|--local]`: explicitly build deterministic local
  trigram indexes for eligible materialized shelves. A shelf is eligible only with
  `source=git-commit`, `parity=exact`, and a full materialized-tree hash.
  `search --index` reports uncovered fallback scopes as partial;
  `search --require-index` rejects them. Search never builds or repairs an index.
  Export/import excludes index artifacts and `gc` preserves them.
- `bench`: run the pinned `search-v1` benchmark with fixed tasks and strict output shape.

### Diagnostics
- `doctor [--json] [--quiet] [--no-network]`: check the Python/install environment,
  internal imports, corpus filesystem capabilities, cache manifests and integrity,
  credential formatting, service reachability, and release availability. It returns
  0 when healthy, 1 for warnings, and 2 for errors; credential values are never shown.

### Corpus
- `get`: materialize sources and print absolute local path(s).
- `fetch`: prefetch materialized sources without printing paths.
- `list`: show current corpus entries and trust/verification state.
- `remove`: delete a shelved source entry.
- `clean`: clear corpus metadata and cached materialization.
- `gc`: remove abandoned repository staging and obsolete backups under target locks;
  a sole `.old-` generation is left in place when its target is absent.

### Analysis
- `info`: one-shot agent context with provenance, bounded public signatures and docstrings, top usage code, trust, and parity. Use this first.
- `api`: extract, cache, and return a bounded public-symbol contract with signatures, docstrings, and provenance.
- `examples`: extract and rank usage snippets for that source.
- `trust`: compute cached trust score and factor breakdown.
- `sbom`: emit SPDX 2.3 or CycloneDX 1.5 SBOM artifacts from the corpus.
- `diff`: compare two resolved versions with file and API-symbol deltas.

### Closure and reproducibility
- `lock`: materialize the project's transitive dependency closure.
- `export`: write a v2 `corpus.lock` plus compressed snapshot and emit the lock digest.
- `import`: verify and rehydrate a v2 snapshot into an empty destination; the trusted
  `--lock-sha256` is mandatory. Existing v1 snapshots must be re-exported.

#### Screenshots

Real captures, run against live sources.

```bash
$ leitir get npm:is-number@7.0.0
~/.leitir/repos/github.com/jonschlinkert/is-number/98e8ff1da1a89f93d1397a24d7413ed15421c139
leitir: resolving npm:is-number@7.0.0
leitir: materializing npm:is-number@7.0.0

$ leitir list
markdown-it-py 3.0.0 executablebooks/markdown-it-py@bee6d1953be75717a3f2f6a917da6f464bed421d verified trust=unknown
is-number      7.0.0 jonschlinkert/is-number@98e8ff1da1a89f93d1397a24d7413ed15421c139        verified trust=unknown
octocat/Hello-World … @7fd1a60b01f91b314f59955a4e4d4e80d8edf11d                                verified trust=unknown

$ leitir trust npm:is-number@7.0.0
is-number trust=56
  age:               50/100  weight=15   (unknown — no cached release/commit timestamp)
  artifact_checksum: 100/100 weight=15   (present — npm-tarball)
  documentation:     100/100 weight=10   (docs + entry points)
  license:           25/100  weight=15   (low confidence)
  parity:             0/100  weight=15   (drift — artifact vs git tree)
  tests:              0/100  weight=10   (absent — no tests/ in git tree)
  verification:      100/100 weight=20   (verified=True)
```

```bash
$ leitir diff npm:is-number@6.0.0 npm:is-number@7.0.0
Added files (0):
Removed files (0):
Modified files (4):
  LICENSE
  README.md
  index.js
  package.json
Added symbols (0):
Removed symbols (0):
Changed signatures (0):
```

```bash
$ leitir api pypi:markdown-it-py@3.0.0
~/.leitir/api/pypi/markdown-it-py/3.0.0/index.json
  → 223 symbols extracted (method: ast)
    e.g. function markdown_it._punycode.decode
         function markdown_it._punycode.encode
```

```bash
$ leitir sbom --format cyclonedx | jq '.components[0]'
{
  "type": "library",
  "name": "octocat/Hello-World",
  "version": "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d",
  "licenses": [],
  "properties": [
    { "name": "leitir:license_method",   "value": "unknown" },
    { "name": "leitir:license_confidence","value": "low" },
    { "name": "leitir:source",            "value": "git-commit" },
    { "name": "leitir:parity",            "value": "unknown" }
  ]
}
```

Paths shown are under the corpus root (for example `~/.leitir/...` or project-local `./.leitir-refs/...`).

## Honesty guarantees

- Provenance-bound corpus outputs resolve to immutable provenance and source-specific manifests. Verified corpus shelves are re-hashed against `materialized_tree_hash` on every load; unverified shelves may omit the digest. Global search results are not necessarily materialized shelves.
- Fail-closed verification: checksum or tree mismatches remove or reject materialization and never create a trusted cache entry. Archive symlink chains are resolved lexically before extraction, so confinement does not depend on host symlink behavior.
- Legacy verified caches require `leitir upgrade-cache` to add a materialized-tree digest and gain load-time verification; until upgraded they are rejected as cache misses.
- Runtime `leitir trust` turns unknown factors into neutral numeric scores (50/100), rather than `indeterminate`. Only the ADR-002 repository assessment gate preserves `indeterminate` as a decision.
- Trust evidence is never fabricated: age requires a real source timestamp, missing
  license evidence is neutral (50), and legacy manifests without `has_tests` treat
  tests as unknown until `upgrade-cache` or re-materialization refreshes evidence.
- Deterministic behavior: stable outputs for fixed inputs and hash-safe operation independent of interpreter hash order.
- Local trigram candidates are only a reduction step: the original predicates still
  run against source bytes while the materialization lock is held. Missing, stale,
  malformed, sampled, drifted, or schema-incompatible index shelves cannot produce
  complete indexed coverage.
- Stdlib-only runtime: core operations do not require external Python dependencies, model calls, or credentials.
- BTS validation requires an explicit maintainer-reviewed, content-pinned probe set over every applicable `TESTED_BY` edge. Each probe runs in a fresh donor-absent contained child; probe failures and observed donor imports reject independently. V1 never generates semantic probes autonomously.
- Optional host tokens are read from environment, used only on HTTPS, never logged, and global discovery remains `INDETERMINATE`, never exhaustive.
- Global discovery pins every result to the immutable commit SHA exposed by the search index, verifies fetched bytes at that commit against the indexed git blob SHA, and records an `indexed_commit` resolution strategy and UTC `as_of` time. It paginates with a fixed cap and reports pin, fetch, decode, provenance, adapter, and duplicate exclusions. Duplicate candidates are collapsed from repeated repository paths and then the index's claimed blob SHA; only the elected representative (or a deterministic promoted replacement after failure) is fetched, so `deduplicated` does not claim byte verification of members that remain collapsed. The `max_results` budget bounds fetch attempts, including promoted retries within a collapsed content group. Verification failures can therefore produce an honestly incomplete report that does not include every distinct candidate.
- Global discovery rejects unsupported must predicates such as REGEX. Structural and
  PATH predicates use GitHub only as a candidate superset and are locally re-verified.
- Irreducible limit: a remote search index is not itself a pinned input. Two live runs at different wall-clock times may see an advancing index, server-side ranking changes, or different `incomplete_results`; reproducibility holds for the recorded pinned hit set, not for re-querying the live index.

## Update notifications

When run interactively (TTY stdout + stderr, not in CI, not in `--json` mode), leitir
makes at most one anonymous GET request per 24 hours to GitHub's Releases API
(`https://api.github.com/repos/anthonykewl20/leitir/releases/latest`) to check for a
newer release. The `User-Agent` is `leitir/<version> update-check`; the request contains
no username, repository path, project data, command arguments, or telemetry. Set
`LEITIR_NO_UPDATE_CHECK=1` to disable.

## Scoring

`tools/score_engine.py` is the ADR-002 repository/engine assessment scorer. It evaluates the Leitir project itself—code health, test adequacy, supply chain, and related evidence—across six weighted dimensions. It does **not** implement, mirror, or independently verify the runtime `leitir trust` seven-factor corpus-trust model in `src/leitir/trust.py`. The two systems assess different subjects and share only the abstract principle that “unknown is neither zero nor pass.” The published pinned assessment reports `decision=indeterminate`, while a current-worktree offline rerun reports `decision=fail` because one fixed-gate test is skipped; neither reaches pass. Details, exact scores, and subject identity are tracked in [docs/scoring.md](docs/scoring.md).

## Tests

```bash
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest
```

Offline is default. Live network checks are opt-in behind `LEITIR_ENABLE_LIVE_E2E=1`. Current status: **1355 passed, 55 skipped**.

## Repository layout

- `src/leitir/` — kernel and corpus implementation: `resolver`, `materialize`, `parity`, `snapshot`, `sbom`, `apisurface`, `examples`, `diff`, `trust`, `lockfiles`, `cli`, plus search, ranking, and benchmark code.
- `src/leitir/benchmarks/search-v1/` — deterministic ranked-search benchmark manifest.
- `src/leitir/benchmarks/corpus-v1/` — corpus fetch-correctness benchmark manifest.
- `tools/score_engine.py` — standalone ADR-002 scorer.
- `scorecard/` — policy, assessment schema, and published canonical outputs.
- `skills/leitir/SKILL.md` — normative corpus workflow for AI coding agents.
- `docs/` — ADRs, status, scoring docs, and historical notes.
- `tests/` — offline suite with opt-in live gates and fixtures.
- `requirements.txt` — pinned development/CI dependency closure, not a runtime requirement.

## Documentation

- ADRs: [0001](docs/adr/0001-remove-hy3-deterministic-search.md), [0002](docs/adr/0002-deterministic-evidence-scoring-engine.md), [0003](docs/adr/0003-categorized-http-retry.md), [0004](docs/adr/0004-local-source-materialization.md), [0005](docs/adr/0005-corpus-v2-capabilities.md), [0006](docs/adr/0006-load-time-tree-verification.md)
- [docs/STATUS.md](docs/STATUS.md)
- [docs/scoring.md](docs/scoring.md)
- [skills/leitir/SKILL.md](skills/leitir/SKILL.md)

Historical, retired v1 references: [docs/PRD.md](docs/PRD.md), [docs/operations.md](docs/operations.md), [docs/smoke-evaluation.md](docs/smoke-evaluation.md), plus the manual v1 scorecards — [docs/leitir-engine-scorecard.html](docs/leitir-engine-scorecard.html), its [historical PNG snapshot](docs/leitir-engine-scorecard.png), and the manual [v2 editorial scorecard](docs/leitir-engine-scorecard-v2.html). These manual
snapshots are never scorer evidence.
