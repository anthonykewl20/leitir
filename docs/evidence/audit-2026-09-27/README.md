# Real-user audit — 2026-09-27

Question audited: does Leitir help an AI coding agent do what its owner built it for —
scavenge GitHub for the most mature working OSS implementation of a task, understand it
from verified source, and use it as a base or reference to plan and create code?

Method: the code and real command behaviour were the only source of truth (README, ADRs
and other docs were not trusted). Everything below was reproduced with the installed
`leitir 0.2.000` (main `bdceeb1`), Python 3.14.7, Linux, `GH_TOKEN` set unless stated,
against fresh scratch corpora (`--root`). Four independent probes covered: the owner's
Next.js-authentication journey end to end; analysis surfaces across npm/PyPI/crates/Go;
discovery, `ask` and lockfile flows; and the copy/adapt/port path. A fifth pass audited
docs against code. Nothing in the repository was modified during the audit.

Tracking: milestone [v0.3.000 — GitHub Code Scavenger](https://github.com/anthonykewl20/leitir/milestone/7),
epic [#410](https://github.com/anthonykewl20/leitir/issues/410). Every finding below links
the issue that carries its reproduction, root cause (file:line) and acceptance criteria.

## Suite state at audit time

Full offline suite on `bdceeb1`: 3746 passed, 166 skipped (environment-gated), 0 failed
(13m15s); `ruff check .` clean; `mypy src` clean (119 files). The defects below are
therefore not caught by the existing suite.

## Headline journey: "build Next.js authentication from the most mature OSS reference"

| Step | Command | Result |
|---|---|---|
| Discover implementations | `leitir search --global --must call:NextAuth --language typescript --max-results 10` | Without a token: bare `HTTP 401`. With a token: 7 arbitrary apps (ecommerce stores, a chat app), **all score 1.0**, ordered by repo slug; `nextauthjs/next-auth`, Better-Auth, Lucia absent. |
| Study the library | `leitir info npm:next-auth@4.24.11 --json` | Verified npm tarball, commit `6bca388f`, 114 API symbols, 3 README examples; **license `unknown`** although `LICENSE` and `package.json` say ISC; routing `study-only/license-undetermined`; parity `drift`. |
| Pull a discovered repo | `leitir get github:ndom91/next-auth-example-sign-in-page@5a1ccb44…` | Verified in 2.4 s. |
| Search what was pulled | `leitir search --corpus --must call:NextAuth` | next-auth itself excluded (`registry_provenance`); only the example app searched. |
| Ask the task question | `leitir ask "protect a route with getServerSession…" --package next-auth --pin ./app` | Exit 1: `search error: cannot safely stat local blob: .eslintrc.js`; answer falls back to README snippets and unrelated error classes. |
| Search the library directly | `leitir search --package next-auth --version 4.24.11 --ecosystem npm --must identifier:getServerSession` | Exit 1, same error; the symbol exists in `src/next/index.ts`. |
| Adapt the code | `bts-*`, `bts-port-contract`, `check` | Python donors only; port target Go only; `check` rejects `.ts`. |

Correction recorded during the audit: an initial reading that `ask` hides the search
failure was wrong — it exits 1 and prints the error.

## Findings by area

### Materialization and integrity

| Finding | Issue |
|---|---|
| Package-scoped search walks the Git tree listing against registry-artifact shelves and aborts on the first Git-only path; fails for every npm/PyPI/crates package tried (zod, next-auth, @auth/core, authlib, jsonwebtoken, ms); breaks the README Quick Start and `ask`. | [#349](https://github.com/anthonykewl20/leitir/issues/349) |
| Shelves keyed by owner/repo/commit only: packages from one monorepo commit (`npm:better-auth`, `npm:@better-auth/cli`, `github:better-auth/better-auth`) overwrite one directory; a `github:` spec can return npm build output. | [#350](https://github.com/anthonykewl20/leitir/issues/350) |
| Registry artifacts always record `subpath: null` despite `repository.directory`. | [#351](https://github.com/anthonykewl20/leitir/issues/351) |
| Parity: registry artifacts are effectively always `drift` (identical shared bytes still drift); Go git shelves report `exact` with 0 files compared. | [#352](https://github.com/anthonykewl20/leitir/issues/352) |
| `lock` exits 0 with `dependencies: []` for unsupported/unparseable/missing inputs, including a nonexistent `--cwd`. | [#368](https://github.com/anthonykewl20/leitir/issues/368) |
| `ask --pin <file>` ignores the named file and prefers `node_modules`, labelling the result `lockfile`. | [#369](https://github.com/anthonykewl20/leitir/issues/369) |
| PyPI tag candidates only `v{ver}`/`{ver}`; certifi 2024.8.30 fails although a verified sdist exists. | [#361](https://github.com/anthonykewl20/leitir/issues/361) |
| Codeberg/Sourcehut materialize-only; Sourcehut `archive-only` with 0 files compared. | [#360](https://github.com/anthonykewl20/leitir/issues/360) |
| `@branch` treated as a tag with no hint; spec grammar undocumented in `--help`. | [#374](https://github.com/anthonykewl20/leitir/issues/374) |

### Analysis quality

| Finding | Issue |
|---|---|
| TS/JS export regexes are single-line and miss generics, `declare`, `abstract`, interfaces, types, enums, re-exports, multi-line signatures; stray `.d` in names. zod: 16 symbols, 0 classes; better-auth npm: 0; `diff` zod 3.22.4→3.23.8 falsely reports `custom` removed. | [#353](https://github.com/anthonykewl20/leitir/issues/353) |
| Examples empty for zod, express, authlib, golang-jwt; better-auth returns whole UI component files; mined dirs limited to exact top-level names; RST and Go `Example*` ignored. | [#355](https://github.com/anthonykewl20/leitir/issues/355) |
| Go API includes 65 `_test.go` symbols out of 238. | [#354](https://github.com/anthonykewl20/leitir/issues/354) |
| Tests detected only via a top-level `tests/` directory. | [#356](https://github.com/anthonykewl20/leitir/issues/356) |
| No Rust extractor: every crate returns 0 symbols. | [#389](https://github.com/anthonykewl20/leitir/issues/389) |
| `--corpus` excludes registry shelves and non-github.com hosts. | [#359](https://github.com/anthonykewl20/leitir/issues/359) |
| `diff` release notes fetch only the endpoint tags. | [#362](https://github.com/anthonykewl20/leitir/issues/362) |
| Go shelves lack `published_at`; crates docs point to GitHub or unversioned docs.rs. | [#366](https://github.com/anthonykewl20/leitir/issues/366) |
| Registry-first materialization hands agents compiled output (zod: `lib/*.js` + `.d.ts` only). | [#405](https://github.com/anthonykewl20/leitir/issues/405) |

### Discovery

| Finding | Issue |
|---|---|
| Ranking is match score then repo slug (`ranking.py:75`); every match scored 1.0; no repo metadata, grouping, or maturity. | [#380](https://github.com/anthonykewl20/leitir/issues/380), [#381](https://github.com/anthonykewl20/leitir/issues/381), [#382](https://github.com/anthonykewl20/leitir/issues/382) |
| `--language tsx|jsx` canonicalised to typescript/javascript; `.jsx` has no adapter. | [#370](https://github.com/anthonykewl20/leitir/issues/370) |
| `import:<module>` can never match (string literals masked); destructured exports not definitions. | [#371](https://github.com/anthonykewl20/leitir/issues/371) |
| Candidate budget consumed by non-matching files (0 matches from 122,880 eligible); qualifier-only query reports complete coverage. | [#372](https://github.com/anthonykewl20/leitir/issues/372) |
| Opaque 401/422, token-unaware rate-limit advice. | [#373](https://github.com/anthonykewl20/leitir/issues/373) |
| Task compilation drops phrases ("Next.js authentication" → `identifier:authentication`). | [#384](https://github.com/anthonykewl20/leitir/issues/384) |
| Comparison accepts caller-declared collector evidence from `--stages`. | [#365](https://github.com/anthonykewl20/leitir/issues/365) |

### Provenance, license and adaptation

| Finding | Issue |
|---|---|
| License detection ignores declared metadata and misses ISC, 0BSD, BSD-2, BSD-3 with named org, MPL, GPL/LGPL, Unlicense, dual MIT/Apache. | [#357](https://github.com/anthonykewl20/leitir/issues/357) |
| License routing reads only the repo root; a vendored GPL file in an MIT repo is reported MIT. | [#358](https://github.com/anthonykewl20/leitir/issues/358) |
| `bts-compute` for non-Python languages always PARTIAL with a false budget reason (`_total_donor_lines` counts `.py` only). | [#364](https://github.com/anthonykewl20/leitir/issues/364) |
| `check` silently skips `.ts`/`.js` in mixed directories; `--json` errors printed as text. | [#363](https://github.com/anthonykewl20/leitir/issues/363) |
| No provenance record, header or NOTICE for code copied outside the Python BTS path. | [#393](https://github.com/anthonykewl20/leitir/issues/393) |
| Unwired tested code: `cost.py` collectors, `composition.compose`, reuse packets v2 and `load_packet`, `run_occupied_corpus_gate`, `resolve_source_license`. | [#406](https://github.com/anthonykewl20/leitir/issues/406) |

### Agent surface and docs

| Finding | Issue |
|---|---|
| MCP exposes five verbs; no global search parameters; missing extra prints a traceback. | [#401](https://github.com/anthonykewl20/leitir/issues/401) |
| `ask` requires a lockfile (excludes greenfield projects); no `gh` token fallback; no path-only verb. | [#402](https://github.com/anthonykewl20/leitir/issues/402) |
| Lockfile coverage gaps (bun, pnpm v5, poetry, uv, hashed requirements, go.sum, workspaces). | [#403](https://github.com/anthonykewl20/leitir/issues/403) |
| npm dist-tags/ranges and non-GitHub npm repositories unsupported. | [#404](https://github.com/anthonykewl20/leitir/issues/404) |
| Small output inconsistencies (rerun command omits `--root`, string-sorted versions, `get --json` parity null). | [#375](https://github.com/anthonykewl20/leitir/issues/375) |
| ~20 stale or false doc claims (Quick Start fails, PyPI extras, host guarantees, stale ROADMAP/STATUS, broken citations). | [#367](https://github.com/anthonykewl20/leitir/issues/367) |

## Owner decisions recorded during the audit

1. Focus is GitHub code scavenging for the agent's research-and-plan phase; official-docs
   tooling is out of scope.
2. License is informational. Leitir must show it accurately (per path) and never block;
   the agent decides whether to copy, adapt or learn
   ([#398](https://github.com/anthonykewl20/leitir/issues/398)).
3. Leitir's purpose is to stop agents from hand-waving code: architecture and
   implementation suggestions must be grounded in mature, cited, verified source
   ([#378](https://github.com/anthonykewl20/leitir/issues/378)).

## What works well today

Byte-verified, commit-pinned materialization for GitHub specs; honest coverage reporting
on search; fail-closed load-time verification; deterministic outputs; Python API extraction
(authlib: 1162 symbols); the `check` gate's conservative Python semantics; the skill's
reference-not-dependency discipline.
