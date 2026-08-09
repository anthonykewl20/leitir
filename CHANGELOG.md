# Changelog

All notable changes to leitir will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):
within the 0.x series, patch releases (0.1.1, 0.1.2, ...) ship audit fixes and
incremental work, while a minor bump (0.2.0) marks a feature or behavior milestone.
Breaking changes are permitted within 0.x (pre-1.0) and must be called out here.

## [Unreleased]

### Added
- Added `leitir gc`, which removes abandoned repository staging and obsolete
  backup generations while holding each target lock (#30).

### Changed
- **Breaking:** snapshot format v2 binds the archive bytes with mandatory
  `tarball_sha256`; v1 snapshots are no longer importable and must be re-exported.
- **Breaking:** `leitir import` now requires a trusted `--lock-sha256`; `export`
  emits `lock_sha256`. The `import_corpus` API likewise requires a trusted lock
  digest unless callers explicitly opt out (#31).
- **Breaking:** global search rejects predicates that GitHub search cannot
  preserve (including REGEX), rather than silently degrading them. Structural
  and PATH predicates are locally re-verified after server-side filtering (#49).
- Trust scoring treats missing evidence as unknown (50), not zero. Age is only
  populated from real source timestamps, license no-evidence is 50 rather than
  25, and legacy manifests without `has_tests` no longer scan the offline tree;
  run `upgrade-cache` or re-materialize to refresh that evidence (#23, #24).
- Credentialled resolution now rejects plaintext HTTP endpoints (#26).
- Versioning policy: 0.x incremental releases now use patch bumps (next release
  is 0.1.1); a minor bump is reserved for a feature/behavior milestone. See
  ROADMAP. The v0.2.0 milestone was renamed to v0.1.1 accordingly.
- Distribution model is GitHub-only (not PyPI). Install with
  `pip install git+https://github.com/anthonykewl20/leitir.git`.
- Update notifications now poll the GitHub Releases API instead of PyPI.

### Fixed
- Corpus commands acquire deduplicated target locks in canonical path order,
  preventing duplicate-target and reversed-order cross-process deadlocks.

### Security
- Snapshot import now binds both the trusted lock digest and exact archive bytes,
  closing coordinated lock/archive tampering (#31).

## [0.1.0] - 2026-08-05

### Added
- Load-time tree verification for materialized source trees (`materialized_tree_hash`,
  Go dirhash H1 algorithm with symlink records and bounded sampling). Closes #17.
- `leitir upgrade-cache` command for migrating legacy verified shelves.
- `ROADMAP.md` and `AGENTS.md` wiring the v0.2.0 milestone
  into the AI agent workflow.
- Mandatory `materialized_tree_hash` field for verified shelves; legacy
  shelves without it are rejected until `leitir upgrade-cache` is run. Closes #18, #19.

### Changed
- `_corpus_list` now routes through `read_valid_manifest` so load-time
  verification covers `leitir list`.
- `update_manifest` raises `ManifestIntegrityError` on tamper (was: returned None).

### Fixed
- Tampered shelved bytes are no longer served as `verified: true` (was the
  original load-time integrity defect; see ADR-006).
- Removed nonexistent `leitir get --force` references from ADR-006 and CLI help.
- README/STATUS test counts and scorer result updated to match current HEAD.
- README §Honesty guarantees scoped precisely (load-time verify applies to
  verified corpus shelves, not "every visible item").

<!-- Next release: add Unreleased entries under appropriate Added/Changed/Deprecated/Removed/Fixed/Security headings. Consider a dedicated Security category for tamper-rejection changes. -->
