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
- add BTS evaluation harness and metric definitions (E5a, #74) (`bts`)
- add BTS walk, budget, dispositions, and digests (B5, #58) (`bts`)
- add deterministic reuse/reference packet format (C5, #71) (`bts`)
- add deterministic semantic example classification (C4b, #67) (`bts`)
- add diagnostic-only runtime import recorder (B6, #60) (`bts`)
- add donor-banning exact-count rerun harness (E2, #63) (`bts`)
- add end-to-end walking skeleton pipeline + test (E4a, #55) (`bts`)
- add error taxonomy and typed graph model (`bts`)
- add import-rewrite test relocator (E1, #61) (`bts`)
- add independent-dimension best-3 comparison with incomparable-comparator (C3b, #70) (`bts`)
- add leitir agent skill for the corpus workflow (`corpus`)
- add Linux-only nsjail donor-execution containment (S2, #62) (`bts`)
- add maintainer-pinned behavioral probes over TESTED_BY edges (E3, #64) (`bts`)
- add manifest-bound recipient project profiling (C4, #66) (`bts`)
- add multi-stage candidate retrieval funnel (C2, #68) (`bts`)
- add N-donor empty-project exit gate (E4b, #73) (`bts`)
- add name-resolving CALL and complete READS passes (B4, #57) (`bts`)
- add non-compensating suitability hard gates (C3a, #69) (`bts`)
- add opt-in Python AST adapter with heuristic fallback (`search`)
- add per-source license policy + obligations manifest (D1, #72) (`bts`)
- add static IMPORTS/INHERITS/RAISES extraction (B3, #56) (`bts`)
- add symtable lexical classification to the Python AST adapter (`search`)
- add tier-2 heuristic adapters for JavaScript, TypeScript, Java, C, and C++ (`search`)
- add typed CapabilitySpec + pinned behavior-contract registry (C1, #65) (`bts`)
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
- bind BTS digests to the authoritative verified donor tree (B5b, #59) (`bts`)
- BTS eval publication target, exporter, anti-gaming gate (#75) (`bench`)
- changesets-style tag inference and subpath-aware get (`corpus`)
- Codeberg + Sourcehut git hosts (`corpus`)
- deduplicate global hits by content digest and repo path (#50) (`search`)
- dependency composition conflict matrix (#76) (`composition`)
- duplicate-abstraction detection (#78) (`duplicates`)
- enforce canonical predicate-language routing in scoped and global modes (`search`)
- exit-corpus pinning manifest and validation harness (#73) (`gate`)
- generate CHANGELOG from conventional commits + drift gate (`changelog`)
- GitHub-only release pipeline + PyPI deferred path (`distribution`)
- Go module multi-host (gitlab/bitbucket/golang.org/x) (`corpus`)
- integration-cost evidence (#79) (`cost`)
- leitir doctor, version-aware update check, easy install, skill rewrite
- leitir info one-shot context + --json for get/trust/api/examples (`corpus`)
- load-time tree verification + bounded sampling (`materialize`)
- occupied-recipient validation gate (#82) (`occupied`)
- P1 deterministic search contracts + real-data e2e gate (`search`)
- P2-P4 engine, resolvers, adapters + ADR slice revision (`search`)
- P4+P5 deterministic CLI shell + global discovery (ADR-001) (`search`)
- P6 deterministic ranking + pinned search-v1 benchmark (`bench`)
- parity derivation, manifest auth, and S2 pipeline surfaces (#148 #40 #73) (`core`)
- polyglot tree-sitter graph per ADR-0012 (#81) (`graph`)
- publish reproducible offline decision=pass (#41) (`scorecard`)
- ratify exit corpus runtime digest (Phase B/C)
- real-donor exit corpus and runnable validation (#73) (`gate`)
- relocate authorized donor sibling sources
- six real agent tasks with gold and run driver (#75) (`bench`)
- stream and verify large blobs with incremental Git SHA-1 over line-aligned windows (`search`)
- structural architecture compatibility (#77) (`architecture`)
- unified credentials + private repo/registry auth (`corpus`)
- upstream tracking, drift alerts, bundle v2 (#80) (`lineage`)
- widen pinned search benchmark to eight languages (`bench`)
- wire BTS compute and analysis surfaces (#148) (`cli`)

### Changed
- serve scoped search from verified local shelves; complete Go module, license, and API-surface support (`search`)

### Fixed
- accept sampled structural candidate pins (`bench`)
- address review findings (qwen) (`corpus`)
- align containment smoke root and evidence
- align exit rerun parity with ADR-0009
- align live identity digest check
- allow contained CPython startup syscalls
- allow CPython close-on-exec ioctl under containment
- apply deterministic P6 ordering to normal search output (#48) (`search`)
- bind adapter language routing to trusted registry identity (`search`)
- bound SumDB HTTP response reads to 1 MiB fail-closed (`sumdb`)
- bypass interpreter shutdown on Windows success to avoid exit 120 (`doctor`)
- canonicalize predicate-vs-flag language comparison (`search`)
- capture nsjail launch diagnostics
- certify clean CI environments and handle closed-pipe/hash-seed determinism (#43) (`doctor`)
- consistent Go module case escaping across proxy and sumdb wire paths (`resolver`)
- containment last mile — privileged CI exec, rseq allowlist, baseline parity, span plumbing, static contract imports
- correct containment verifier wheel hash
- correct typing for mypy strict mode (`cost`)
- defer donor imports until baseline startup
- diagnose mount-source digest mismatches
- expose nsjail mount sources in CI
- expose ratification rejection evidence
- fail closed on enabled collection and mixed-phase skips (`canary`)
- force LF checkout for committed evidence and scorecard artifacts (`score`)
- forward-compatible global reports and offline-gate fix; regenerate canonical assessment (#41) (`scorecard`)
- GitLab subgroup (nested group) project support (`corpus`)
- guard AST visitor and render against untrusted-input recursion (`search`)
- guard directory fsync on POSIX (`relocate`)
- guard stdout write and force os._exit on Windows doctor paths (`doctor`)
- harden contained execution substrate
- harden tree walker validation, lowercase SHAs, and early truncation raise (`search`)
- honest 7-factor scoring (#22 #23 #24 #25 #35) (`trust`)
- honest budget exhaustion, canonical --language identity, over-limit budget rejection (`search`)
- import-safe harness bootstrap and mount-stubbed rendered-config smoke (`ci`)
- include Starred assignment targets in Python AST definitions (`search`)
- install containment ratification verifier
- kafel identifier set and ci artifact ownership
- keep doctor exit code 0 when its stdout pipe closes (`cli`)
- keep rerun mount setup off immutable rootfs
- keep sandbox tests portable (`bts`)
- last 4 Windows CI failures (CRLF + non-UTF-8 setup skips) (`ci`)
- make bts_bench tests cross-platform (PYTHONPATH os.pathsep, skip fixture test on non-Linux) (`bts`)
- make nsjail --version capture non-fatal in build script (`bts`)
- make validate_report fail-closed on span bounds without line_counts (`search`)
- map invoking user for nsjail mounts
- mount writable rerun bind after rootfs
- normalize task baseline test ids
- per-task typed failure continuation and honest partial runs (#75) (`bench`)
- permit close-on-exec epoll setup
- permit CPython allocator remaps
- permit mapped user to mount staged inputs
- phase-a4 root causes — recipient ids, nsjail probe, licence variants, spans, haversine donor (#73 #75)
- pin global hits to the indexed commit SHA, eliminate moving-HEAD resolution (#51) (`search`)
- pin phase C rootfs measurement
- pre-donor startup attestation, dynamic donors, electrumx policy, stable seed identity (#73 #75)
- precreate nsjail rootfs mount targets
- preserve collection skip nodeid on Windows (`canary`)
- preserve dangling donor links during ownership handoff
- prune orphan empty parent dirs on failed materialization (`corpus`)
- publish pinned contained rootfs
- ratify release rootfs runtime digest
- recover truncated GitHub tree listings with a bounded subtree walk (`search`)
- redirect stdout fd before shutdown to avoid Windows exit 120 (`doctor`)
- reject archive members with concealed backslashes and drive prefixes (`parity`)
- reject unsupported predicates and verify global provenance (#49 #84 #44) (`search`)
- release-pin contained rootfs
- relocate authorized module preambles
- render mandatory root mount for nsjail mount tree
- replace ref-name regex with linear validation (`lineage`)
- restore containment smoke mount chain
- run contained BTS task baselines
- seed origin filter, comprehension scope fix, drift-shelf search exclusions, nsjail identity, dogfood feedback (#42 #73)
- skip directory fsync on Windows in publish_packet (#128) (`transplant`)
- stage published rootfs phase A
- stop rewriting Tier-2 class __module__ to restore get_type_hints/getsource (`adapters`)
- tolerate .gitattributes EOL normalization in tree verification (`corpus`)
- tolerate nsjail --version non-zero exit in containment report step (`bts`)
- treat source checkout as healthy in install checks (#43) (`doctor`)
- trust tests fairness, Bitbucket live tolerance, lock best-effort (`corpus`)
- use Kafel amd64 fstat spelling (`sandbox`)
- use os.pathsep in PYTHONPATH so bts_walk subprocess runs on Windows (`tests`)
- use portable child PYTHONPATH (`bts`)
- verify buffered blob SHA, bind tree response SHA, and require truncated field (`search`)
- verify global hits, paginate to validated count, account exclusions (#45, #46, #47) (`search`)
- writable scratch bind replaces tmpfs; mount-target and evidence hardening

### Security
- bind gate evidence to pinned attachment policy (`occupied`)
- close fail-closed gap for non-dict GitHub tree payloads (`search`)
- close integrity residuals (#28 #39) (`materialize`)
- corpus integrity hardening (#28 #29 #30 #31 #32 #39) (`materialize`)
- cross-platform bugs caught by first Windows CI run (`ci`)
- final-state review hardening (B1 B2 B3, C1-C7) (`integrity`)
- generate Kafel from typed model, enforce real containment barrier or refuse, directory-tree rootfs digest (security re-review) (`bts`)
- harden containment verification, seccomp validation, and digest binding (security review) (`bts`)
- harden global search match integrity and adapter line model (`security`)
- pin HOME/USERPROFILE and preserve SYSTEMROOT in sanitized collector env (`score`)
- preserve staged mount integrity
- redact URL fragments, exception text, and PRIVATE-TOKEN (#27) (`logging`)
- reject global reports with substituted slug, commit, path, or blob identity (`security`)
- reject plaintext HTTP for credentialled resolution (#26) (`resolver`)

[Unreleased]: https://github.com/anthonykewl20/leitir/commits/HEAD
