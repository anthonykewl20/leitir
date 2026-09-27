# Leitir documentation

Welcome. Leitir is a deterministic, provenance-bound dependency-source corpus
plus a deterministic code-search kernel for AI coding agents.

## Start here

- [README](../README.md) — install, the agent workflow, and the headline guarantees
- [Getting started](../README.md#quick-start) — materialize a real package in 30 seconds

## Concepts

- [Why leitir](../README.md#why) — what problem it solves
- [How it works](../README.md#how-it-works) — the materialization pipeline

## Reference

- [Commands](../README.md#commands) — get, fetch, list, info, api, examples, trust, sbom, diff, lock, export, import, upgrade-cache
- Source specifications (from `SUPPORTED_SPEC_FORMS` in `src/leitir/spec.py`):
  - `npm:name[@version]`, `pypi:name[@version]`, `crates:name[@version]`, `go:module[@version]`
  - `owner/repo[@ref|#ref]` (GitHub shorthand), `github:owner/repo[@ref|#ref]`,
    `bitbucket:owner/repo[@ref|#ref]`, `codeberg:owner/repo[@ref|#ref]`
  - `sourcehut:~user/repo[@ref|#ref]`, `gitlab:group[/subgroup...]/project[@ref|#ref]`
  - an HTTPS repository URL
  - Ref syntax: `@<tag>` or `@<40-hex commit sha>`; `#<branch>`; no ref means the
    default-branch head. A non-SHA `@<name>` is always resolved as a tag, never
    a branch ([#374](https://github.com/anthonykewl20/leitir/issues/374) tracks `@branch`).
- [Honesty guarantees](../README.md#honesty-guarantees)
- [Corpus cache operations](operations.md) — current runbook: cache layout, backup, restore, cleanup, and recovery
- [Versioning and compatibility](versioning.md) — release, manifest, and snapshot compatibility policy

## Architecture

- [Current status](STATUS.md) — what is implemented and what is open
- [GitHub search capabilities](search-capabilities.md) — wide discovery, scoped search, coverage, and limitations
- [Roadmap](../ROADMAP.md) — carries the [v0.3.000 GitHub Code Scavenger milestone](https://github.com/anthonykewl20/leitir/milestone/7) (epic [#410](https://github.com/anthonykewl20/leitir/issues/410)); v1.0 reserved for adoption
- [Architecture Decision Records](adr/) — durable design decisions

## Evidence and research

- [Real-user audit, 2026-09-27](evidence/audit-2026-09-27/README.md) — dated real-user audit evidence
- [Competitive landscape, 2026-09](research/competitive-landscape-2026-09.md) — competitive teardown

## Development

- [Contributing](../CONTRIBUTING.md) — setup, test command, conventions
- [Security policy](../SECURITY.md) — vulnerability reporting and threat boundary
- [Agent instructions](../AGENTS.md) — workflow for AI coding agents
- [Scoring](scoring.md) — ADR-002 repository/engine assessment scorer
- [Calibration](calibration.md) — ADR-0037 self-calibration loop: mutation, fuzz, determinism, coverage-of-raises, perf drift, convergence ledger

## Historical (retained for context, not current documentation)

- [v1 PRD](PRD.md)
- [v1 smoke evaluation](smoke-evaluation.md)
- [Manual v1 scorecard (HTML)](leitir-engine-scorecard.html)
- [Manual v2 scorecard (HTML)](leitir-engine-scorecard-v2.html)

These historical documents are never scorer evidence.
