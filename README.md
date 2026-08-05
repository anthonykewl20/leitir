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
- Deterministic trust scoring on a 0–100 scale, with factor weights (20,15,15,10,10,15,15) fixed to verification, parity, license, documentation, tests, checksum, and age (sum 100).
- Version diffing for file changes plus API-symbol changes between two resolved versions, including release-note notes when available.
- Transitive dependency closure via `leitir lock` and closure metadata in manifests.
- Immutable `export`/`import` snapshots with fail-closed rehydration checks.
- Optional, anonymous-by-default credentials: per-host tokens (GitHub/GitLab/Bitbucket incl. app-password Basic, Codeberg, Sourcehut) and registry tokens (npm/PyPI/crates) for private/authenticated access — HTTPS-only, never logged.
- Deterministic, stdlib-only code-search kernel from ADR-001.
- Standalone evidence-scoring engine from ADR-002 that drives gate decisions without model calls.

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
pip install leitir
leitir info npm:zod@3.22.0
```

Leitir is not yet published to PyPI, so `pip install leitir` will only work once a release exists. Until then, install from source — the runtime is stdlib-only (`dependencies = []`), so no third-party dependencies are pulled in:

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

### Analysis
- `info`: one-shot agent context with provenance, bounded public signatures and docstrings, top usage code, trust, and parity. Use this first.
- `api`: extract, cache, and return a bounded public-symbol contract with signatures, docstrings, and provenance.
- `examples`: extract and rank usage snippets for that source.
- `trust`: compute cached trust score and factor breakdown.
- `sbom`: emit SPDX 2.3 or CycloneDX 1.5 SBOM artifacts from the corpus.
- `diff`: compare two resolved versions with file and API-symbol deltas.

### Closure and reproducibility
- `lock`: materialize the project's transitive dependency closure.
- `export`: write immutable `corpus.lock` plus compressed corpus snapshot tarball.
- `import`: verify and rehydrate a snapshot into an empty destination, fail-closed.

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
- Deterministic behavior: stable outputs for fixed inputs and hash-safe operation independent of interpreter hash order.
- Stdlib-only runtime: core operations do not require external Python dependencies, model calls, or credentials.
- Optional host tokens are read from environment, used only on HTTPS, never logged, and global discovery remains `INDETERMINATE`, never exhaustive.

## Update notifications

When run interactively (TTY stdout + stderr, not in CI, not in `--json` mode), leitir
makes at most one anonymous GET request per 24 hours to PyPI's public project metadata
endpoint (`https://pypi.org/pypi/leitir/json`) to check for a newer release. The request
contains only the leitir version in its `User-Agent` — no username, repository path,
project data, command arguments, or telemetry. Set `LEITIR_NO_UPDATE_CHECK=1` to disable.

## Scoring

`tools/score_engine.py` is the ADR-002 repository/engine assessment scorer. It evaluates the Leitir project itself—code health, test adequacy, supply chain, and related evidence—across six weighted dimensions. It does **not** implement or independently verify the runtime `leitir trust` seven-factor trust model. The two systems share only the abstract principle that “unknown is neither zero nor pass.” At current HEAD the scorer reports `decision=fail`, `observed_score_bps=9980`, and bounds `475..9999`: 29 required results are missing and one fixed-gate test in `engine.offline_contracts` is skipped and therefore a known failed check. Details are tracked in [docs/scoring.md](docs/scoring.md).

## Tests

```bash
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest
```

Offline is default. Live network checks are opt-in behind `LEITIR_ENABLE_LIVE_E2E=1`. Current status: **1262 passed, 52 skipped**.

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
