# ADR-0004: Local source materialization layer (corpus)

- Status: accepted
- Date: 2026-08-03
- Implementation: complete
- Related: [ADR-0001](0001-remove-hy3-deterministic-search.md) deterministic code-search kernel, [ADR-0003](0003-categorized-http-retry.md) categorized HTTP retry
- Layer: new `src/leitir/materialize.py`, `src/leitir/corpus.py` (index), CLI extension, `src/leitir/resolver.py` (npm)

> **Historical note:** Extended by [ADR-0005](0005-corpus-v2-capabilities.md)
> (corpus-v2 capabilities) and [ADR-0006](0006-load-time-tree-verification.md)
> (load-time tree verification). Retained for historical context.

## Goal

When coding with AI agents, proven open-source code must be the reference
instead of model-generated code. The corpus layer makes this mechanical:

1. Materialize **complete source trees** of open-source packages and repos on
   disk — full files, not line snippets — because code is interlinked across
   functions, classes, and modules.
2. Place the corpus in a **gitignored folder**, either project-local
   (`.leitir-refs/`) or global (`~/.leitir/`), so agents can browse it with
   their normal file tools.
3. Pair each source with its **official documentation pointers** where they
   exist; where no official docs exist, the code itself is the reference.
4. Every materialized source carries **immutable provenance** (registry,
   version, tag, resolved commit SHA, fetched time), so an agent can always
   state exactly which code it is citing.

Non-goals: semantic query interpretation (harness job, per ADR-001), hosting,
and building code on behalf of the agent.

## How it works (mental model for humans and agents)

Leitir's corpus layer is a **fetch, pin, verify, and shelve** pipeline:

1. **Fetch** — given a spec (`zod`, `pypi:requests@2.31.0`, `owner/repo`),
   leitir asks the registry (npm / PyPI / crates.io) which repository holds
   the source and which version your project actually uses (from lockfiles).
2. **Pin** — it resolves the version tag to an exact commit SHA. Everything
   downstream is addressed by SHA, so the corpus cannot silently drift.
3. **Verify** — it downloads the complete source tree at that SHA and checks
   file digests against the commit's tree listing on GitHub.
4. **Shelve** — it writes the full tree into a gitignored folder
   (`.leitir-refs/` in your project or `~/.leitir/` globally) with a manifest
   stating exactly what was fetched and from where, and updates `POINTERS.md`
   with documentation links and local entry points.

The result is a local shelf of complete, proven, browsable open-source code.
Agents then use their ordinary file tools (`rg`, `cat`, `find`) on it. Leitir
never returns snippets as the primary interface — the tree on disk is the
interface.

## Agent workflow (required process)

This is the process AI agents must follow when working in a project that uses
leitir. It is normative: M7's SKILL.md is derived from this section.

1. **Consult before writing.** Before writing code that uses a library,
   framework, or API present in the corpus, the agent must read the corpus
   first. Hand-rolling an implementation of behavior that proven open-source
   code already defines is a failure of this workflow.
2. **Materialize what is missing.** If the needed dependency is not in the
   corpus: `leitir get <spec>` (add `--local` for a project-local shelf).
   Never guess a library's internals from memory when its source is one
   command away.
3. **Read the pointers.** Open `POINTERS.md` in the corpus root: it lists, per
   source, the official documentation URLs (when they exist) and the local
   entry points — README, `docs/`, `examples/`, and `tests/`. The examples
   and tests are the code that *practices* what the docs describe; prefer
   them as behavioral ground truth. When no official docs exist, the source
   itself is the primary reference — say so explicitly in the answer.
4. **Browse full files.** Follow imports and call chains across complete
   files; never reduce a reference to an out-of-context snippet when the
   surrounding code changes meaning.
5. **Cite provenance.** When basing generated code on a reference, cite it as
   `<repo path>:<file path>` at the commit SHA from the manifest. This makes
   every claim checkable.
6. **Report gaps honestly.** If the corpus lacks the answer (missing package,
   unverified entry, version mismatch), state that and fetch or pin the right
   version. Never fill a gap with invented code while presenting it as
   referenced behavior.

## Prior art: opensrc

The fetch-and-cache model is taken from
[vercel-labs/opensrc](https://github.com/vercel-labs/opensrc) (Apache-2.0;
design is re-implemented in Python, no code is copied, attribution kept in
this ADR). What transfers:

1. **Spec UX** — one command accepts `zod`, `pypi:requests@2.31.0`,
   `crates:serde`, `owner/repo`, `owner/repo#ref`, and full repository URLs;
   registry prefixes (`npm:`, `pip:`, `python:`, `crates:`, `cargo:`,
   `rust:`).
2. **Registry → repository resolution** — npm registry `repository.url` +
   `directory` (monorepo subpath), PyPI `project_urls` key priority, crates.io
   `repository` field.
3. **Lockfile version detection** — resolve the version the calling project
   actually uses from its lockfiles instead of always fetching latest.
4. **Cache layout + index** — `repos/<host>/<owner>/<repo>/<version>/` under a
   single root, plus a `sources.json` index written atomically with
   corrupt-file backup.
5. **Composable CLI contract** — resolved path on stdout, progress on stderr,
   so `rg "x" $(leitir get zod)` works; plus `fetch/list/remove/clean`.
6. **Agent skill file** — a SKILL.md with trigger phrases so agents actually
   reach for the tool.
7. **Security details** — exact-host matching (reject
   `github.com.attacker.example`), tokens only over HTTPS, tokens never in
   logs.

## opensrc gaps this design fixes

Observed in opensrc at 59 commits (2026-08-03):

1. **No commit pinning.** It clones at a guessed tag name (`v{version}`,
   `{version}`); if neither exists it silently clones the default branch with
   only a stderr warning (`core/git.rs`, `clone_at_tag`). The agent can then
   read the wrong version believing it has the pinned one. Leitir resolves
   tag → commit SHA first (ADR-001 resolver) and fetches at the SHA, or fails.
2. **No integrity verification.** Nothing checks the checkout after the clone.
   Leitir verifies the extracted tree against the pinned commit's GitHub tree
   (blob digests), reusing `tree.py`.
3. **Thin provenance.** `sources.json` holds name/version/path/fetchedAt only.
   Leitir writes a per-source manifest: spec, registry, version, tag, commit
   SHA, repo URL, subpath, docs URLs, fetched time.
4. **No documentation support.** The goal requires doc pointers; opensrc is
   source-only. Leitir records docs URLs from registry metadata (npm readme,
   PyPI `Documentation`/`Homepage`, crates.io homepage) and emits a
   `POINTERS.md` per corpus root.
5. **Global cache only.** Leitir supports a project-local root with `.gitignore`
   handling, which is the stated workflow.
6. **npm-only lockfile detection.** Leitir extends detection to
   `requirements.txt`/`pyproject.toml` pins, `Cargo.lock`, and `go.mod`.
7. **Git CLI dependency.** Leitir fetches `codeload.github.com/<owner>/<repo>/tar.gz/<sha>`
   with stdlib `urllib` + `tarfile`: no git binary, exact-SHA addressing, one
   request. This keeps the ADR-001 zero-runtime-dependency invariant.

## Decision

1. **SHA-pinned fetch.** Resolution path: spec → (registry, name, version) →
   repository URL → tag → **commit SHA** (existing resolvers). Materialization
   downloads the tarball at the commit SHA. No SHA, no materialization;
   there is **no fallback to a default branch**, ever. An unresolvable tag is
   a hard, descriptive error.

   **npm tag inference.** For exact npm versions, leitir tries tags in this
   order through the existing exact tag-to-SHA resolver: `<name>@<version>`,
   `v<version>`, then `<version>`. It does not enumerate refs or fuzzy-match a
   fallback: that could select a sibling monorepo package sharing the version.
   The design adapts the package-tag conventions of
   [changesets/changesets](https://github.com/changesets/changesets), the
   independent/fixed versioning conventions of
   [lerna/lerna](https://github.com/lerna/lerna), and pnpm's exact matching of
   real refs in [pnpm/pnpm](https://github.com/pnpm/pnpm) (all MIT; design is
   re-implemented in Python, no code is copied, attribution kept in this ADR).

2. **Two roots, one layout.**
   - Global: `~/.leitir/` (override `LEITIR_HOME`).
   - Project-local: `leitir get --local ...` targets `./.leitir-refs/` and
     ensures `.leitir-refs/` is covered by `.gitignore` (append if the file
     exists or is being created by the same command; otherwise print the exact
     line to add — never rewrite unrelated ignore rules).
   - Layout under either root: `repos/<host>/<owner>/<repo>/<commit-sha>/`,
     plus `subpath/` recorded in the manifest when the registry declares a
     monorepo directory.

3. **Per-source manifest.** `<repo>/<commit-sha>/leitir-manifest.json` with
   spec, ecosystem, version, tag, commit SHA, repo URL, subpath, docs URLs,
   fetched-at, and fetch method. The root `sources.json` index mirrors
   opensrc's shape (atomic temp-file + rename write; corrupt file backed up,
   never crashed on).

4. **Verification.** After extraction, verify a sample (or all, below a size
   cap) of extracted blob digests against the pinned commit's GitHub tree
   listing (`tree.py`). Verification failure is a hard failure and removes the
    partial extraction. Manifest records `verified: true|"sampled"|false` and
    the verified-at time; `list` surfaces each verification state.

5. **Version selection order.** Explicit `@version` in the spec → lockfile
   detection in `--cwd` (default: current directory) → registry latest.
   Whichever wins is recorded in the manifest as `version_source:
   explicit|lockfile|latest`, so "why this version" is always answerable.

6. **Docs pointers + practice entry points, not docs scraping.** The manifest
   records documentation URLs discovered from registry metadata. A generated
   `POINTERS.md` at the corpus root lists, per source: version, commit SHA,
   docs URLs, local path, and the **practice entry points** found in the tree
   — README, `docs/`, `examples/`, `tests/` — because examples and tests are
   the code that practices what the docs describe. When a source has no
   official docs, `POINTERS.md` marks the source itself as the primary
   reference. Scraping doc sites is out of scope (indeterminate, fragile).

7. **Hosts.** GitHub only in this ADR, matching the existing resolvers.
   GitLab/Bitbucket support (which opensrc has) is deferred; the layout
   already namespaces by host so it is additive later.

8. **CLI.**
   - `leitir get <spec>...` — ensure cached, print absolute path(s) to stdout,
     using a recorded monorepo subpath when it exists; if it is missing on
     disk, print the repository root and warn on stderr. Progress stays on
     stderr.
   - `leitir fetch <spec>...` — pre-fetch without printing paths.
   - `leitir list [--json]`, `leitir remove <spec>`, `leitir clean [--repos]`.
   - Flags: `--root <dir>`, `--local`, `--cwd <dir>`, `--no-verify`.
   - Existing `leitir search` and `leitir bench` are untouched.

9. **Agent integration.** Ship `skills/leitir/SKILL.md` with trigger phrases
   and the `rg/cat/find $(leitir get ...)` pattern, modeled on opensrc's
   skill.

10. **Invariants carried from ADR-001.** No runtime dependencies beyond the
    stdlib, no credentials held by the tool (optional `GITHUB_TOKEN` env for
    rate limits, never logged), deterministic behavior for fixed inputs, and
    honest failure: unknown or unverifiable is reported as such, never papered
    over.

## Gate policy

Each M slice ships with offline tests and, where it touches the network,
opt-in live tests behind `LEITIR_ENABLE_LIVE_E2E=1`. A slice is not done until
its gate is green and this ADR's checkbox is ticked with the gate result
recorded in the slice entry — same discipline as ADR-001 P slices.

## Consequences

### Amendment — Git-commit shelf parity (2026-08-15; consensus-terra Decision B)

For a GitHub `git-commit` shelf, `parity` is `exact` only after complete,
unsampled, mode-bearing Git-tree enumeration proves equal regular-file and
symbolic-link path universes and raw Git-blob bytes for every comparison.
`drift` means that otherwise-complete verification was accepted only through
one or more CRLF newline-normalization fallbacks; raw mismatches remain hard
materialization failures. `unknown` covers sampled, archive-only, disabled,
unavailable, and legacy-unreproved verification. This claim covers paths and
raw Git blobs only, not directory modes or executable bits. Existing shelves
are never backfilled from `unknown`; `leitir upgrade-cache --recompute-git-parity`
may re-enumerate and fully reprove eligible GitHub Git-commit shelves under
their target locks, leaving the claim unchanged when proof is partial or
unavailable.

### Amendment — symlink mismatches fail closed on every mode-capable host (2026-08-19; issue #193 / PR #208)

For any tree source whose listing carries blob modes, an extracted
symbolic-link universe mismatch (missing or unexpected) is a hard
`VerificationError` on all hosts — previously non-GitHub sources downgraded
this to "sampled". A symbolic-link digest mismatch on any host takes the
commit-pinned re-read order `read_blob_at_commit` → `read_blob` and is
rejected with a typed error when the source offers neither method. Mode-less
sources retain the explicit "sampled" outcome unchanged (a genuine host
capability gap is never fabricated into modes). Trust assumption: the glitch
clearance — the re-read equals the extracted bytes, so the listing mismatch
is treated as an enumeration glitch — assumes an honest re-read channel
(endpoint diversity); the equality binds to the re-read channel, not
cryptographically to the listing's blob_sha. GitHub's `read_blob` is
digest-verifying (response SHA and recomputed blob SHA are both checked);
path-based re-reads are not.

- Gained: a browsable, provenance-bound local corpus; version-accurate
  references via lockfile detection; verifiable integrity; project-local
  gitignored mode.
- Cost: GitHub-only host coverage at first; tarball fetch cannot materialize
  refs that have no commit (none exist in practice — branches resolve to SHAs
  via the API before fetch).
- Risk: codeload tarball availability is a GitHub dependency; mitigated by
  the same retry policy as all other GitHub calls (ADR-003).

## Work (bite-sized)

Ordered so the tool becomes usable at the earliest point: M1–M2 deliver a
working `leitir get`; M3–M4 widen accuracy; M5–M7 harden and integrate.

- [x] M1: Materialization core. SHA-pinned tarball fetch + extraction,
      per-source manifest, atomic `sources.json` index with corrupt-file
      backup, refcounted removal.
      (`src/leitir/materialize.py`, `src/leitir/corpus.py`,
      `tests/test_materialize.py`, `tests/test_materialize_e2e.py`,
      `tests/test_materialize_e2e_live.py`)
      Gate: offline targeted 17 passed; full suite 769 passed, 35 skipped
      (Python 3.11); live 1 passed. Note: landing the gate required a
      pre-existing Python 3.11 parse fix in `tools/score_engine.py`
      (backslash in f-string expression hoisted to a variable; behavior
      unchanged).

- [x] M2: CLI + roots. `leitir get/fetch/list/remove/clean`; `--root`,
       `--local` with `.gitignore` handling; stdout/stderr contract.
       (`src/leitir/cli.py` extension, `tests/test_corpus_cli.py`,
       `tests/test_corpus_cli_e2e.py`)
      Gate: offline targeted 23 passed; full suite 792 passed, 35 skipped
      (Python 3.11).

- [x] M3: Spec parsing + npm resolver. Prefix table, `@version`/`#ref`,
      `owner/repo`, URL normalization with exact-host checks; `NpmResolver`
      (registry.npmjs.org, `repository.url` + `directory`, `dist-tags.latest`)
      added to `MultiResolver`.
       (`src/leitir/spec.py`, `src/leitir/resolver.py` extension,
       `tests/test_spec.py`, `tests/test_resolver_npm.py`)
       Gate: offline targeted 66 passed; full suite 841 passed, 35 skipped
       (Python 3.11).

- [x] M4: Lockfile version detection. npm lockfiles (package-lock, pnpm-lock,
      yarn.lock, node_modules, package.json), then `requirements.txt` /
      `pyproject.toml` `==` pins, `Cargo.lock`, `go.mod`; `version_source`
      recorded in the manifest.
       (`src/leitir/lockfiles.py`, `tests/test_lockfiles.py` with fixture
       lockfiles)
       Gate: offline targeted 50 passed; full suite 869 passed, 35 skipped
       (Python 3.11).

- [x] M5: Tree verification. Verify extracted blob digests against the pinned
       commit's GitHub tree; hard failure + cleanup on mismatch; `verified`
       field in manifest and `list` output.
       (`src/leitir/materialize.py` extension, `tests/test_verify.py`,
       `tests/test_verify_e2e_live.py`)
       Gate: offline targeted 36 passed; full suite 881 passed, 36 skipped
       (Python 3.11).

- [x] M6: Docs pointers + practice entry points. Docs URL discovery from
      registry metadata per ecosystem; entry-point discovery (README,
      `docs/`, `examples/`, `tests/`) per source; generated `POINTERS.md`
      at the corpus root, marking sources without official docs as primary
      references.
      (`src/leitir/docpointers.py`, `tests/test_docpointers.py`)
      Gate: offline targeted 40 passed; full suite 894 passed, 36 skipped
      (Python 3.11).

- [x] M7: Agent skill + benchmark. `skills/leitir/SKILL.md` derived from
      the "Agent workflow (required process)" section above (trigger
      phrases, the `rg`/`cat`/`find` on `$(leitir get ...)` pattern,
      consult-before-writing rule); bench tasks pinning fetch correctness
      (known package → expected SHA → verified extraction) added to a
      `corpus-v1` benchmark manifest.
       (`skills/leitir/SKILL.md`, `src/leitir/benchmarks/corpus-v1/`,
       bench wiring)
       Gate: full offline suite 900 passed, 37 skipped (Python 3.11); live
       suite 38 passed, 1 skipped, 898 deselected (Python 3.11).

## Progress

Tracked here and mirrored in `docs/STATUS.md`. Slice status values: not
started / in progress / done (with gate result).

| Slice | Status | Gate result |
|-------|--------|-------------|
| M1 | done | offline 17 targeted; full 769 passed, 35 skipped (3.11); live 1 |
| M2 | done | offline 23 targeted; full 792 passed, 35 skipped (3.11) |
| M3 | done | offline 66 targeted; full 841 passed, 35 skipped (3.11) |
| M4 | done | offline 50 targeted; full 869 passed, 35 skipped (3.11) |
| M5 | done | offline 36 targeted; full 881 passed, 36 skipped (3.11) |
| M6 | done | offline 40 targeted; full 894 passed, 36 skipped (3.11) |
| M7 | done | full 900 passed, 37 skipped (3.11); live 38 passed, 1 skipped, 898 deselected |

Shelf provenance and indexing (#311): only full Git materializations with full upstream verification and exact parity supply a local Git tree listing. Registry artifacts require upstream blob identities before producing Git citations; missing or mismatched local bytes fail closed. Go proxy shelves use their existing single-content-hash path for every reader and writer. Indexes store symbolic-link text as Git blob content and never follow links.

Registry artifacts without recorded upstream blob bindings cannot supply offline Git search citations. Their checksum-verified info/API/example views remain available. Existing corrupt Git shelves reject instead of silently switching to remote source. The regression fixture for offline ask explicitly represents a Git-bound package shelf.

Normalized Git archives (#311): the real Vitest 2.1.9 archive carries a CRLF file whose Git blob identity differs. Sampled, unverified, unknown-parity and drift shelves must use the upstream tree listing and verify queried bytes against it. A full local tree hash alone cannot authorize Git citations. Legacy shelves without an explicit exact-parity proof also take that checked path.
