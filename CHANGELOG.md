# Changelog

All notable changes to leitir will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):
within the 0.x series, patch releases (0.1.1, 0.1.2, ...) carry all incremental
work — audit fixes, bug fixes, and feature/behavior increments alike. Breaking
changes are permitted within 0.x (pre-1.0) and must be called out here.

<!-- leitir-sync-changelog start -->

## [Unreleased]

### ⚠ BREAKING CHANGES
- retire the v1 Hy3 synthesis pipeline (`kernel`)

### Added
- add --max-results, --max-pages, and --language global controls (`search`)
- add --whole-file required-predicate mode with deduplicated file-wide evidence (`search`)
- add a local trigram index and indexed searcher for fast regex search (`search`)
- add leitir agent skill for the corpus workflow (`corpus`)
- add opt-in Python AST adapter with heuristic fallback (`search`)
- add symtable lexical classification to the Python AST adapter (`search`)
- add tier-2 heuristic adapters for JavaScript, TypeScript, Java, C, and C++ (`search`)
- ADR-002 S1 assessment contracts, policy schema, gate algebra (`score`)
- ADR-002 S2 canonical evidence and subject provenance (`score`)
- ADR-002 S3 offline engine-correctness collectors (`score`)
- ADR-002 S4 ranked-output effectiveness adapter (`score`)
- ADR-002 S5 code-health and test-adequacy adapters (`score`)
- ADR-002 S6 process and supply-chain adapter (`score`)
- ADR-002 S7 controlled performance adapter (`score`)
- ADR-002 S8 deterministic renderer and release profile (`score`)
- ADR-002 S9 dogfood on Leitir, retire the manual scorecards (`score`)
- ADR-003 categorized retry layer for transport and resolver sites (`http`)
- ADR-004 local source materialization layer (`corpus`)
- ADR-005 C1 GitLab/Bitbucket host-aware resolvers and materialization (`corpus`)
- ADR-005 C10 trust scoring (`corpus`)
- ADR-005 C2 registry-artifact parity (`corpus`)
- ADR-005 C3 byte-exact artifact-first resolution (`corpus`)
- ADR-005 C4 transitive dependency closure (`corpus`)
- ADR-005 C5 immutable snapshot export/import (`corpus`)
- ADR-005 C6 SBOM generation (SPDX/CycloneDX) (`corpus`)
- ADR-005 C7 API surface extraction (`corpus`)
- ADR-005 C8 usage-example extraction (`corpus`)
- ADR-005 C9 version diffing (`corpus`)
- ASV performance benchmark suite + scorecard performance dimension (`perf`)
- changesets-style tag inference and subpath-aware get (`corpus`)
- Codeberg + Sourcehut git hosts (`corpus`)
- deduplicate global hits by content digest and repo path (#50) (`search`)
- enforce canonical predicate-language routing in scoped and global modes (`search`)
- generate CHANGELOG from conventional commits + drift gate (`changelog`)
- GitHub-only release pipeline + PyPI deferred path (`distribution`)
- Go module multi-host (gitlab/bitbucket/golang.org/x) (`corpus`)
- leitir doctor, version-aware update check, easy install, skill rewrite
- leitir info one-shot context + --json for get/trust/api/examples (`corpus`)
- load-time tree verification + bounded sampling (`materialize`)
- P1 deterministic search contracts + real-data e2e gate (`search`)
- P2-P4 engine, resolvers, adapters + ADR slice revision (`search`)
- P4+P5 deterministic CLI shell + global discovery (ADR-001) (`search`)
- P6 deterministic ranking + pinned search-v1 benchmark (`bench`)
- publish reproducible offline decision=pass (#41) (`scorecard`)
- stream and verify large blobs with incremental Git SHA-1 over line-aligned windows (`search`)
- unified credentials + private repo/registry auth (`corpus`)
- widen pinned search benchmark to eight languages (`bench`)

### Fixed
- address review findings (qwen) (`corpus`)
- apply deterministic P6 ordering to normal search output (#48) (`search`)
- certify clean CI environments and handle closed-pipe/hash-seed determinism (#43) (`doctor`)
- forward-compatible global reports and offline-gate fix; regenerate canonical assessment (#41) (`scorecard`)
- GitLab subgroup (nested group) project support (`corpus`)
- honest 7-factor scoring (#22 #23 #24 #25 #35) (`trust`)
- last 4 Windows CI failures (CRLF + non-UTF-8 setup skips) (`ci`)
- pin global hits to the indexed commit SHA, eliminate moving-HEAD resolution (#51) (`search`)
- prune orphan empty parent dirs on failed materialization (`corpus`)
- recover truncated GitHub tree listings with a bounded subtree walk (`search`)
- reject archive members with concealed backslashes and drive prefixes (`parity`)
- reject unsupported predicates and verify global provenance (#49 #84 #44) (`search`)
- tolerate .gitattributes EOL normalization in tree verification (`corpus`)
- treat source checkout as healthy in install checks (#43) (`doctor`)
- trust tests fairness, Bitbucket live tolerance, lock best-effort (`corpus`)
- verify global hits, paginate to validated count, account exclusions (#45, #46, #47) (`search`)

### Security
- close fail-closed gap for non-dict GitHub tree payloads (`search`)
- close integrity residuals (#28 #39) (`materialize`)
- corpus integrity hardening (#28 #29 #30 #31 #32 #39) (`materialize`)
- cross-platform bugs caught by first Windows CI run (`ci`)
- final-state review hardening (B1 B2 B3, C1-C7) (`integrity`)
- harden global search match integrity and adapter line model (`security`)
- pin HOME/USERPROFILE and preserve SYSTEMROOT in sanitized collector env (`score`)
- redact URL fragments, exception text, and PRIVATE-TOKEN (#27) (`logging`)
- reject global reports with substituted slug, commit, path, or blob identity (`security`)
- reject plaintext HTTP for credentialled resolution (#26) (`resolver`)

[Unreleased]: https://github.com/anthonykewl20/leitir/commits/HEAD
