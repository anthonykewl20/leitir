# Changelog

All notable changes to leitir will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):
within the 0.x series, patch releases (0.1.1, 0.1.2, ...) carry all incremental
work — audit fixes, bug fixes, and feature/behavior increments alike. Breaking
changes are permitted within 0.x (pre-1.0) and must be called out here.

<!-- leitir-sync-changelog start -->

## [Unreleased]

### Added
- add --impact to intersect version deltas with real usage (`diff`)
- add a docs-truth gate for command, version, and tag claims (`ci`)
- add evidence-assisted cross-language port (ADR-0033) (`bts`)
- add the agent-facing code-supply verbs and close two coverage falsifications
- add the self-calibration loop (ADR-0037) (`calibration`)
- derive import roots from materialized evidence, not name (`check`)
- expose leitir to non-Claude-Code agents via an optional MCP server (`mcp`)
- put the agent-facing skill under the docs-truth gate (`docs-truth`)
- replace in-memory lock epochs with writer-visible on-disk epochs (#272) (`warm`)
- thread optional WarmSession through engine and corpus read paths (#272) (`warm`)
- thread the active warm session into verb owners (#272) (`cli`)
- warm_call(root) context manager and session-aware CLI dispatch (#272) (`api`)
- WarmSession verified-manifest cache with lock-epoch invalidation (#272) (`warm`)

### Fixed
- attribute verification failures correctly under concurrent writers (#272) (`warm`)
- bind port attribution to measured BTS evidence, not caller claims (`bts`)
- close the strict-defeating laundering gap and audit IndexedSearcher (P1/P2 review findings) (`corpus`)
- fail closed on a corrupt catalog for write, artefact, and policy callers of load_sources (`corpus`)
- fall back to the digest-anchored no_follow read when O_NOFOLLOW is unavailable (#285) (`bts`)
- fetch full history in the self-calibration workflow (`calibration`)
- finish the ADR renumber and recovery-guidance content (previous commit only captured the rename) (`corpus`)
- give the check-bridge demo fixture a real top_level.txt (`bench`)
- have build_port_attribution verify its own source root (`bts`)
- inherit the ambient environment in the differential check bridge (#285) (`bench`)
- isolate platform caches and order paused validation writers (#330)
- land the strict epoch parse the round-3 message claimed (#272) (`materialize`)
- let the full-surface mypy run resolve tools/calibration (`calibration`)
- make malformed specs, search flags, and default-root creation legible (`cli`)
- make polyglot rejections actionable and wire --debug into seed resolution (`bts`)
- pass a frozenset, not a raw string, to _build_import_table (`diff`)
- preserve the malformed repository-ref diagnostic (#307) (`calibration`)
- probe the crates.io API endpoint instead of the 404-ing root (`doctor`)
- remove the caller-controlled donor-bytes channel entirely (`bts`)
- renumber ADR to 0034, add strict-failure recovery guidance, and document the amended test contract (`corpus`)
- report benchmark progress and guard usage determinism (`bench,ci`)
- resolve the epoch identity and cover the round-3 findings (#272) (`warm`)
- retire the tree-layout import-root tier as an authority (`check`)
- retry EDEADLK lock acquisition on Windows like other msvcrt contention (`tests`)
- stage manifest rewrites outside the verified shelf tree (#282) (`materialize`)
- stop laundering a corrupt catalog into absence across process boundaries (`corpus`)
- stop tier-4 import-root heuristic from guessing multi-root (`check`)
- treat non-string cached license confidence as unknown (`trust`)
- treat non-string cached parity state as unknown (`trust`)

### Security
- advance the epoch on gc shelf recovery; pin the under-lock rejection (#272) (`warm`)
- capture concurrent call_json warnings per thread (#281) (`api`)
- resolve single-shelf specs against the catalog before verifying (#279) (`corpus`)

## [0.1.6]

### Added
- add usage CLI verification, replay, and E2E harness (`usage`)
- admit verified consumers and catalog Python imports (`usage`)
- assemble deterministic usage evidence (`usage`)
- define usage evidence and replay contract (`usage`)
- resolve Python consumer usage statically (`usage`)

### Fixed
- bound regex matching for path predicates (`search`)
- handle Ctrl+C cleanly and correct example classification (`cli`)
- harden registry parsing, interrupt handling, and index caching
- support platforms without O_NOFOLLOW (`usage`)
- tolerate null fields in real registry metadata (`resolver`)

### Security
- detect broken shelves and bound regex matching (`doctor,search`)
- make replay work on real-sized files and type all errors (`usage`)

## [0.1.5]

### Added
- add dispatch inputs and allowlisted extra live tests to live canary (`ci`)
- enforce trusted-key expiry and revocation in versioned trusted-keys schema v2 (`auth`)
- enumerate truncated trees via paginated walk fallback (`tree`)
- full-coverage load-time verification via per-file digest map (`materialize`)
- include global coverage in JSON reports (`cli`)
- pin donors to latest stable release tags by default (`discovery`)
- register the live pytest marker and make the live inventory authoritative (`tests`)
- report honest coverage bounds in search output and help (`discovery`)
- resolve exact ecosystem pins local-first from verified shelves (`cli`)
- resolve lockfile pins local-first from cached shelves (`cli`)
- route every corpus/info/search source transplant-ok or study-only (`license`)

### Fixed
- accept os-native separators in live inventory skip lines (`tests`)
- apply rate-limit cap fail-fast on the final attempt too (`http`)
- assert target confinement before stale sweep; consolidate lock helper (`materialize`)
- bound archive-channel divergence and harden enumeration parsing (`resolver`)
- bound concurrent-writer reader loop to dodge msvcrt contention cap (`tests`)
- capture stderr in auth-tests zero-skip guard (`ci`)
- classify tag-lookup transport failures for the ADR-0023 fallback (`resolver`)
- close all 12 production-readiness audit findings
- consolidate atomic writes with fd sentinel + parent-dir fsync; manifest double-close fixed, durability hardened (`safeio`)
- de-flake the two environment-sensitive retry tests (#202) (`tests`)
- enumerate import-purity gate over all submodules behind a reviewed allowlist (`tests`)
- extend the registry-only fallback to crates.io (`resolver`)
- fail fast past the rate-limit cap, add max_total_wait budget and per-provider rate-limit notices (`http`)
- harden import-purity child report channel and import-path isolation (`tests`)
- make refused-connection test deterministic on Windows via reset listener (`tests`)
- make routing-warning test independent of cli logger propagation (`tests`)
- mark the --global help's bound-reason examples as non-exhaustive (`cli`)
- preserve the sole-survivor .old-* backup during the stale sweep; update-check cache writes report success again (`materialize`)
- prove concurrent-writer atomicity via serialized seam on Windows (`tests`)
- qualify re-read clearance trust comment, add glitch-clearance and no-reread tests (`materialize`)
- realistic timeout, bounded reads, shared HTTP seam (`doctor`)
- register live marker on four env-gated files per inventory invariant (`tests`)
- release recorder lock adjacent to its try, bound debug manifests, assert server joins, sweep update-check temps, GC stale .old-* backups (`hygiene`)
- render extra-live summary fail-closed; single-source allowlist (`ci`)
- report the materialized pin as identity.commit_sha (`diff`)
- require both privilege controls, reap the aborted child, bound the nsjail probe (`containment`)
- restore 34 resolver gate tests deleted by #230 merge resolution (`tests`)
- restore helpers dropped by #230 merge resolution (`tests`)
- retry the group kill before the direct-pid fallback, escalate unconfirmed kills (`containment`)
- run Ed25519/auth tests in CI via hash-locked auth provider job (`ci`)
- skip stale sweep when shelf lock is contended (`materialize`)
- state Codeberg symlink re-read verification as response self-consistency (`resolver`)
- state the tag-crawl window bound in the head-fallback pin announcement (`discovery`)
- type over-bound reads and reject duplicate keys in update_manifest (`materialize`)
- validate and normalize forge tag shas at the boundary (`resolver`)
- verify the recursive-listing sha echo live, disclose recovery-walk status, and route the canary fetch through the retry seam (`tests`)
- warn on normal inconclusive license routing; cover _prepare heads failure (#190 SP-1, #218 SP-2) (`info,diff`)

### Security
- cover objects/raw/uploads GitHub hosts in github provider (`credentials`)
- create the three missing live canary surfaces, assert workflow references, and harden read_blob_stream (`tests`)
- guard host payload shapes, split platform-capability errors from tamper, drop redundant except subtypes (`taxonomy`)
- honor GH_TOKEN in the provider table and doctor credential vars (`credentials`)
- re-read symlink-path blobs on Codeberg with digest verification (`resolver`)
- reject symlink universe and content mismatches on mode-capable hosts (`materialize`)

## [0.1.4]

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
- make donor-projection debug and rejection tests platform-portable
- make nsjail --version capture non-fatal in build script (`bts`)
- make validate_report fail-closed on span bounds without line_counts (`search`)
- map invoking user for nsjail mounts
- mount writable rerun bind after rootfs
- normalize containment smoke mount authority
- normalize operational paths in execution digests
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
- ratify normalized execution runtime
- ratify release rootfs runtime digest
- re-ratify diagnostic harness runtime
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
- stabilize donor mount digests via manifest-free donor projection (ADR-0021)
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

[Unreleased]: https://github.com/anthonykewl20/leitir/compare/v0.1.6...HEAD
[0.1.6]: https://github.com/anthonykewl20/leitir/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/anthonykewl20/leitir/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/anthonykewl20/leitir/releases/tag/v0.1.4
