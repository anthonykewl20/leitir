# ADR-0005: Corpus v2 — artifact parity, byte-exact resolution, snapshots, and agent-value capabilities

- Status: accepted
- Date: 2026-08-04
- Implementation: complete
- Related: [ADR-0001](0001-remove-hy3-deterministic-search.md) deterministic code-search kernel, [ADR-0003](0003-categorized-http-retry.md) categorized HTTP retry, [ADR-0004](0004-local-source-materialization.md) local source materialization layer
- Layer: `src/leitir/resolver.py` extension, new `src/leitir/parity.py`, `src/leitir/snapshot.py`, `src/leitir/sbom.py`, `src/leitir/apisurface.py`, `src/leitir/examples.py`, `src/leitir/trust.py`, `src/leitir/diff.py`, `src/leitir/lockfiles.py` extension, CLI extension

## Goal

Extend the corpus from a verified git-tree shelf into a verified, byte-exact, reproducible, analyzable dependency source.

1. Match opensrc's strongest host/resolution coverage points: GitLab/Bitbucket support and artifact parity workflows.
2. Add correctness that opensrc cannot provide structurally: byte-exact registry artifacts, immutable snapshots, transitive closure, and SBOM generation.
3. Add agent-value capabilities: API surface indexing, usage-example extraction, version diffing, and trust scoring.

Non-goals: embedding/RAG index, vulnerability scanning (OSV), docs-site scraping (this remains carried from ADR-004 D6), code building, and hosting.

## How it works (mental model)

Extend ADR-004's `fetch, pin, verify, shelve` pipeline with a second source of truth:

1. For npm/pypi/crates, treat the registry artifact as the preferred source of truth when available.
2. For each spec, resolve to a commit and fetch both sources where possible: artifact first, git commit tree as fallback.
3. Compare both trees through parity metadata to avoid false assumptions about equivalence.
4. Materialize the chosen tree, write manifest fields that track source type and provenance, and update `POINTERS.md`.
5. Build additional corpus-derived artifacts - API index, examples index, SBOM, diff data, trust score - from the same manifest + materialized tree.

`source: registry-artifact|git-commit`, `version_source`, `verified`, `manifest` fields remain first-class so every output can be traced back to immutable evidence.

## Prior art / innovation framing

**Prior art:** GitLab/Bitbucket host behavior and spec UX for repo aliases match opensrc's host model (Apache-2.0, design re-implemented, no copied code).

**Innovation:** opensrc remains strongest on host coverage and basic discovery flow. This ADR introduces the registry-artifact-centric correctness layer, immutable export/import snapshots, transitive graph-aware lock handling, and agent-facing analytical surfaces (`api`, `examples`, `diff`, `sbom`, `trust`) not represented there.

## Decision

1. **Registry-artifact parity check.** For npm/pypi/crates where the registry publishes a source artifact (npm tarball with `integrity` sha512 from registry metadata; PyPI sdist with sha256 from the JSON API; crates.io crate with sha256 from its API), leitir downloads the artifact and compares it semantically against the pinned git commit tree. Every file present in both trees must be byte-identical without transformation; artifact bytes are canonical for matching files. Files only in one tree are allowed and counted. The manifest records `parity: exact|drift|unknown` and stats `files_compared`, `only_in_git`, `only_in_artifact`. `exact` is expected to be rare; `drift` is informative and does not block materialization; `unknown` when no artifact is available. This turns the previous zod-class silent mismatch risk into explicit state.

2. **Byte-exact resolution order.** For npm/pypi/crates, resolution becomes artifact-first, then git commit fallback when no artifact exists or retrieval is impossible. Artifact provenance fields in manifest: `source: registry-artifact|git-commit`, `artifact_kind` (`npm-tarball|sdist|crate`), and `artifact_checksum`. Verification for git trees remains the ADR-004 D4 model; artifact trees are verified directly by the published checksum (`verified` remains truthful for whichever source was chosen).

3. **GitLab + Bitbucket hosts.** Add host-aware resolvers for `gitlab:owner/repo@ref` and `bitbucket:owner/repo@ref` plus URL forms. Both use host APIs for SHA pinning (`gitlab` commit API, Bitbucket commits API), tarball endpoints, and host-native content/tree checks. The directory layout is already namespace-aware by host in ADR-004 D2, so no migration is needed. Token hooks are introduced as `GITLAB_TOKEN` and `BITBUCKET_TOKEN`, with HTTPS-only usage and no token logging (ADR-004 D10 behavior preserved).

4. **Immutable snapshot corpora.** `leitir export [-o corpus.lock] [--root ROOT | --local]` writes a corpus lock file and a gzip tarball of trees/manifests/POINTERS. `corpus.lock` includes format version, corpus version, per-source spec, `version_source`, resolved commit SHA, artifact checksum, tree SHA, and shelf path. `leitir import corpus.lock` verifies all tree SHAs/checksums before shelving; import is fail-closed with no partial success on any checksum mismatch. This enables byte-identical rehydration anywhere, independent of network availability.

5. **Transitive dependency closure.** `leitir lock [--cwd <dir>]` computes the transitive dependency graph from lockfiles. npm package-lock and Cargo are complete; go.mod is complete; requirements.txt/pyproject are direct-only. Each manifest records closure metadata per source: `graph: complete|direct-only` and `deps` edges (`name`, `version`, `resolved_sha`, `spec`). After lock, `leitir get` for transitive dependencies is guaranteed cache-hit. Locking behavior is extension work in `src/leitir/lockfiles.py`.

6. **License detection + SBOM.** `leitir sbom [--format spdx|cyclonedx] [--cwd]` emits SPDX 2.3 JSON or CycloneDX 1.5 JSON from the materialized closure, including package nodes, versions, resolved SHAs, checksums, license fields, and dependency edges. License inference is explicit and deterministic: metadata field first, then LICENSE*/COPYING scans; every result records `method` and `confidence`; unresolved is `unknown`, never guessed.

7. **API surface index.** `leitir api <spec>` emits `api/<registry>/<name>/<version>/index.json` with modules, classes, functions, methods, signatures, and docstrings, and caches it under corpus root. Python parsing uses stdlib `ast` for exact extraction. JS/TS uses a conservative line-based signature/export heuristic marked `method: heuristic` and a plugin hook for a parser-backed implementation later; no core parser contract changes required.

8. **Usage-example extraction.** `leitir examples <spec>` scans `tests/`, `examples/`, `docs/`, and README for code blocks, ranks snippets by exercised public symbols (from API index), and stores top-N with `file:line` provenance in an examples index. `POINTERS.md` includes an API surface section linking this index.

9. **Version diffing.** `leitir diff <pkg>@<v1> <pkg>@<v2>` resolves versions (including bare name lockfile/latest fallback per ADR-004 D5), auto-materializes missing versions, and emits file-level changes plus API-level symbol diffs and available registry release notes. `--json` is supported and exits 0 when output is produced regardless of whether differences are empty.

10. **Trust score.** `leitir trust <spec>` computes a deterministic 0-100 score with recorded breakdown in manifest and surfaced by `leitir list`: verification state, parity result, license confidence, docs/entry-point coverage, test presence, artifact checksum presence, and release age. No live ranking; all evidence is from cached fetch-time metadata and analysis outputs.

11. **CLI surface extension.** Add commands: `leitir lock`, `leitir export`, `leitir import`, `leitir sbom`, `leitir api`, `leitir examples`, `leitir diff`, `leitir trust`; add spec prefixes `gitlab:` and `bitbucket:`. Keep existing `get/fetch/list/remove/clean` behavior unchanged and preserve the stderr progress + stdout machine output contract from ADR-004 D8.

12. **Ordering + dependencies.** Commands and implementation ordering are C1 GitLab/Bitbucket -> C2 parity -> C3 byte-exact resolution -> C4 transitive closure -> C5 snapshots -> C6 SBOM -> C7 API index -> C8 examples -> C9 diff -> C10 trust score. This is enforced in dependency order so each stage can consume prior artifacts. Phases: Phase 1 parity/parity-cheap (C1-C2), Phase 2 correctness (C3-C6), Phase 3 agent value (C7-C10).

13. **Invariants carried from ADR-001/ADR-004.** Keep stdlib-only runtime, no credentials held by the tool, deterministic behavior, and honest failure semantics. Unknown/unverifiable states are explicit, heuristics are labeled, and artifact trust is constrained to published checksums only.

14. **Attribution and provenance.** GitLab/Bitbucket host support is still an opensrc-inspired design pattern and remains attributed by ADR-004. All other functionality in this ADR is original leitir design. Registry checksum validation and SPDX/CycloneDX formats are standards-based and do not imply copied implementation.

## Gate policy

Each C slice ships with offline tests and, where it touches the network, opt-in live tests behind `LEITIR_ENABLE_LIVE_E2E=1`. A slice is not done until its gate is green and this ADR checkbox is ticked with the gate result recorded in the slice entry, matching ADR-001/004 discipline.

## Consequences

- Gained: measured parity instead of implicit source equivalence, byte-exact artifact sourcing as first-class resolution, shippable immutable snapshots, full-graph SBOMs, and agent-facing API/examples/diff/trust surfaces.
- Cost: maintaining two source-of-truth paths (artifact + git fallback), accepting common npm `drift` as measured reality, and carrying heuristic JS/TS surface parsing until parser plugins are added.
- Risks: registry artifact format changes; GitLab/Bitbucket API rate limits; import must stay sandbox-safe (reuse materialize traversal guards) and fail-closed on checksum mismatch; parity `drift` noise from npm `.npmignore`/`files` semantics and sdist/VCS omissions must be explained in parity stats.

## Work (bite-sized)

Ordered by dependency (matching decision 12): C1-C10.

- [x] C1: GitLab/Bitbucket host-aware resolvers and auth, plus host-aware
      repository materialization so `leitir get gitlab:/bitbucket:` shelves
      end-to-end. The ADR file list under-enumerated this slice: making the
      GitHub-hardcoded shelf path (`materialize.py`) host-aware was required
      for the resolvers to be usable, so `materialize.py`/`corpus.py`/`cli.py`
      were generalized behind a `_HOST_METADATA` table and the resolver object
      now drives archive fetch + native tree verification.
      (`src/leitir/resolver.py`, `src/leitir/spec.py`, `src/leitir/materialize.py`,
      `src/leitir/corpus.py`, `src/leitir/cli.py`, `tests/test_resolver_gitlab.py`,
      `tests/test_resolver_bitbucket.py`, `tests/test_materialize_gitlab.py`,
      `tests/test_materialize_bitbucket.py`, `tests/test_materialize_e2e_live.py`)
      Gate: offline targeted 137 passed; full suite 942 passed, 43 skipped
      (Python 3.11); live GitLab resolver+materialize passed; Bitbucket live
      blocked by anonymous HTTP 429 on this host (no `BITBUCKET_TOKEN`) —
      Bitbucket correctness is covered by the offline fixture suite; re-verify
      live with a token. Private archive authentication is implemented for both
      `api.bitbucket.org` and `bitbucket.org`: `BITBUCKET_USERNAME` plus
      `BITBUCKET_TOKEN` uses Basic auth, while a token without a username uses
      Bearer auth.

- [x] C2: Registry-artifact parity module and manifest parity fields.
      (`src/leitir/parity.py`, `src/leitir/materialize.py`, `src/leitir/resolver.py`,
      `src/leitir/corpus.py`, `tests/test_parity.py`, `tests/test_parity_e2e.py`)
      Gate: offline targeted 65 passed, 1 skipped; full suite 952 passed, 44 skipped
      (Python 3.11); live 3 passed (npm). Parity verdicts: `exact` (full byte+set
      identity, rare), `drift` (any byte or file-set difference, informative and
      non-blocking), `unknown` (no artifact or retrieval failure). Checksum
      mismatch is fail-closed (`ChecksumMismatchError`); artifact extraction
      reuses the tar/zip safe-extraction guards; HTTPS-only with redirect checks.

- [x] C3: Byte-exact resolution order, artifact checksum verification, and source mode in manifest.
      (`src/leitir/materialize.py`, `src/leitir/corpus.py`, `src/leitir/parity.py`,
      `tests/test_resolver_byte_exact.py`, `tests/test_materialize_artifact.py`,
      `tests/test_materialize.py`)
      Gate: offline targeted 71 passed, 2 skipped; full suite 958 passed, 45 skipped
      (Python 3.11); live 7 passed. Package resolution is artifact-first: when a
      registry artifact exists it is downloaded, checksum-verified (fail-closed
      `ChecksumMismatchError`), and shelved with `source: registry-artifact`,
      `artifact_kind`, `artifact_checksum`, `verified: true`. Artifact retrieval
      failure falls back to the git-commit path (`source: git-commit`). Parity is
      still computed: artifact-sourced trees fetch the git tree into a temp root
      for comparison (reverse parity); git-sourced trees use C2's `package_parity`.
      Repo-only sources are unaffected.

- [x] C4: Transitive dependency closure lock expansion and graph capture.
      (`src/leitir/lockfiles.py`, `src/leitir/materialize.py`, `src/leitir/corpus.py`,
      `src/leitir/cli.py`, `src/leitir/resolver.py`, `tests/test_lockfiles_closure.py`,
      `tests/test_lockfiles.py`, `tests/test_lock.py`, `tests/test_corpus_cli.py`)
      Gate: offline targeted 68 passed; full suite 968 passed, 45 skipped
      (Python 3.11); live not added (closure is offline-fixture covered;
      materialization is live-tested in C1–C3). `dependency_closures` computes
      npm package-lock v2/v3, Cargo.lock, and go.mod as `complete` and
      requirements.txt/pyproject as `direct-only`; edges are deterministic
      `{name, version, resolved_sha, spec}` with `resolved_sha` honest (null when
      the lockfile has only a version). `leitir lock [--cwd]` resolves+materializes
      every closure dep (cache-hit guarantee) and writes `graph`+`deps` into each
      manifest. Go pseudo-versions expand their 12-hex commit via the GitHub
      commits API. `leitir lock --best-effort` is implemented and tested; it
      continues past individual dependency failures while reporting them.

- [x] C5: Immutable snapshot export/import command set.
      (`src/leitir/snapshot.py`, `src/leitir/cli.py`, `src/leitir/corpus.py`,
      `tests/test_snapshot.py`, `tests/test_snapshot_e2e.py`)
      Gate: offline targeted 41 passed; full suite 977 passed, 45 skipped
      (Python 3.11); live n/a (network-independent). `leitir export` writes a
      deterministic `corpus.lock` (format/corpus version, per-source spec,
      `version_source`, commit SHA, artifact kind/checksum, shelf path, and a
      tree SHA = SHA-256 over sorted `mode path NUL git-blob-sha LF` records)
      plus a normalized gzip tarball of trees/manifests/`POINTERS.md`.
      `leitir import` extracts to staging, verifies every source's manifest
      fields + recomputed tree SHA + `POINTERS.md` checksum **before** shelving
      anything (fail-closed: any mismatch raises and shelves nothing), refuses a
      non-empty destination, and installs via atomic moves with rollback. Safe
      extraction reuses the `_extract_tarball` guards.

- [x] C6: SBOM generation over closure with SPDX/CycloneDX output.
      (`src/leitir/sbom.py`, `src/leitir/cli.py`, `tests/test_sbom.py`,
      `tests/test_sbom_spdx.py`, `tests/test_sbom_cyclonedx.py`)
      Gate: offline targeted 39 passed; full suite 986 passed, 45 skipped
      (Python 3.11); live n/a (network-independent). `leitir sbom
      [--format spdx|cyclonedx] [--cwd]` emits SPDX 2.3 or CycloneDX 1.5 JSON
      from the materialized corpus + closure (package nodes, versions, resolved
      SHAs, checksums, license fields, dependency edges). License inference is a
      deterministic ladder (manifest → LICENSE/LICENCE/COPYING SPDX marker →
      filename heuristic) recording `method`/`confidence`; unresolved is `unknown`,
      never guessed. Deterministic output (fixed timestamp, sorted
      packages/relationships, content-derived SPDX namespace).

- [x] C7: API surface extraction and index caching.
      (`src/leitir/apisurface.py`, `src/leitir/corpus.py`, `src/leitir/cli.py`,
      `tests/test_apisurface.py`, `tests/test_apisurface_heuristic.py`)
      Gate: offline targeted 43 passed; full suite 991 passed, 45 skipped
      (Python 3.11); live n/a (network-independent). `leitir api <spec>` resolves
      + materializes the spec, extracts the public API surface, and caches
      `api/<registry>/<name>/<version>/index.json` under the corpus root. Python
      uses stdlib `ast` for exact extraction (signatures, annotations, defaults,
      `*args`/`**kwargs`, docstrings; private `_`-prefixed and unparseable files
      skipped), labeled `method: "ast"`. JS/TS uses a conservative line-based
      heuristic labeled `method: "heuristic"`, with a `register_extractor` plugin
      hook so a parser-backed extractor can replace it without changing the
      `ApiIndex` contract. Deterministic (sorted symbols/modules).

- [x] C8: Usage-example extraction with symbol ranking and `POINTERS.md` API links.
      (`src/leitir/examples.py`, `src/leitir/docpointers.py`, `src/leitir/corpus.py`,
      `src/leitir/cli.py`, `tests/test_examples.py`, `tests/test_docpointers.py`)
      Gate: offline targeted 50 passed; full suite 1000 passed, 45 skipped
      (Python 3.11); live n/a (network-independent). `leitir examples <spec>`
      scans `tests/`/`examples/`/`docs/`/`README*` for fenced markdown blocks and
      whole code files, matches them against the C7 API index's public symbols
      (identifier-boundary), drops zero-symbol snippets, and ranks top-N (default
      10) by matched-symbol count then path/line/length, with `file:line`
      provenance. Cached at `examples/<registry>/<name>/<version>/index.json`.
      `POINTERS.md` gains a per-source "API surface" section linking the API +
      examples indexes when present (additive, no existing sections changed).

- [x] C9: Version diffing command and JSON output.
      (`src/leitir/diff.py`, `src/leitir/apisurface.py`, `src/leitir/resolver.py`,
      `src/leitir/cli.py`, `tests/test_diff.py`, `tests/test_diff_e2e.py`)
      Gate: offline targeted 35 passed, 1 skipped; full suite 1007 passed, 46 skipped
      (Python 3.11); live 3 passed (PyPI). `leitir diff <spec_a> <spec_b> [--json]`
      resolves both versions (lockfile/latest fallback via a shared
      `resolve_corpus_spec`), auto-materializes missing versions, and emits a typed
      `DiffReport`: file-level changes (added/removed/modified by exact bytes,
      excluding the manifest), API-level symbol diff (added/removed/signature-changed
      via `diff_api_indexes`), and best-effort GitHub release notes (omitted
      honestly when unavailable). `--json` is stable/sorted; exit 0 whenever output
      is produced (empty diff is valid).

- [x] C10: Trust scoring and `leitir list` surfacing.
      (`src/leitir/trust.py`, `src/leitir/cli.py`, `src/leitir/materialize.py`,
      `src/leitir/corpus.py`, `tests/test_trust.py`, `tests/test_cli_list.py`)
      Gate: offline targeted 37 passed; full suite 1013 passed, 46 skipped
      (Python 3.11); live n/a (cached/offline). `leitir trust <spec>` computes a
      deterministic 0–100 score (weights: verification 20, parity 15, license 15,
      docs 10, tests 10, artifact checksum 15, age 15) from cached evidence +
      the materialized tree, records `trust_score`/`trust_breakdown` in the
      manifest, and `leitir list` surfaces it. No network/wall-clock: age is
      measured at cached fetch time; missing evidence is `unknown` + neutral,
      never guessed.

## Progress

Tracked here and mirrored in `docs/STATUS.md`. Slice status values: not started / in progress / done (with gate result).

| Slice | Status | Gate result |
|-------|--------|-------------|
| C1 | done | offline targeted 137; full 942 passed, 43 skipped (3.11); live GitLab passed, Bitbucket blocked by anonymous 429 (no token) |
| C2 | done | offline targeted 65, 1 skipped; full 952 passed, 44 skipped (3.11); live 3 (npm) |
| C3 | done | offline targeted 71, 2 skipped; full 958 passed, 45 skipped (3.11); live 7 |
| C4 | done | offline targeted 68; full 968 passed, 45 skipped (3.11); live not added (offline-covered) |
| C5 | done | offline targeted 41; full 977 passed, 45 skipped (3.11); live n/a (network-independent) |
| C6 | done | offline targeted 39; full 986 passed, 45 skipped (3.11); live n/a (network-independent) |
| C7 | done | offline targeted 43; full 991 passed, 45 skipped (3.11); live n/a (network-independent) |
| C8 | done | offline targeted 50; full 1000 passed, 45 skipped (3.11); live n/a (network-independent) |
| C9 | done | offline targeted 35, 1 skipped; full 1007 passed, 46 skipped (3.11); live 3 (PyPI) |
| C10 | done | offline targeted 37; full 1013 passed, 46 skipped (3.11); live n/a (cached/offline) |

API evidence integrity (issue #310): `info` derives signatures and examples from the verified source under its shelf lock and compares derived cache content before reuse. Altered cache entries are rebuilt; unchanged cache files are not rewritten. Publisher manifest authentication does not authenticate independently mutable API-cache JSON. No cache-local checksum substitutes for verified source evidence.

Issue #310 also covers example content: `info` re-derives snippets and classifications from verified source; recomputed metadata beside fabricated cache text cannot authenticate that text. The `examples` command also derives its API symbol input from source.
