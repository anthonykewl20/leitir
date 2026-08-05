# Changelog

All notable changes to leitir will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0.0. Before 1.0.0, minor versions may include breaking changes.

## [Unreleased]

- Background update-notification check (PyPI JSON API, 24h cache, stderr-only, fully gated). Disabled pre-PyPI-publication.

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
