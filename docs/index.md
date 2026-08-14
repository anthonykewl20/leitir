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
- [Specifications](../README.md#commands) — npm:, pypi:, crates:, go:, github:, gitlab:, bitbucket:, codeberg:, sourcehut:
- [Honesty guarantees](../README.md#honesty-guarantees)
- [Corpus cache operations](operations.md) — backup, restore, cleanup, and recovery
- [Versioning and compatibility](versioning.md) — release, manifest, and snapshot compatibility policy

## Architecture

- [Current status](STATUS.md) — what is implemented and what is open
- [GitHub search capabilities](search-capabilities.md) — wide discovery, scoped search, coverage, and limitations
- [Roadmap](../ROADMAP.md) — v0.1.3/v0.1.4 milestones; v1.0 reserved for adoption
- [Architecture Decision Records](adr/) — durable design decisions

## Development

- [Contributing](../CONTRIBUTING.md) — setup, test command, conventions
- [Security policy](../SECURITY.md) — vulnerability reporting and threat boundary
- [Agent instructions](../AGENTS.md) — workflow for AI coding agents
- [Scoring](scoring.md) — ADR-002 repository/engine assessment scorer

## Historical (retained for context, not current documentation)

- [v1 PRD](PRD.md)
- [v1 operations guide](operations.md)
- [v1 smoke evaluation](smoke-evaluation.md)
- [Manual v1 scorecard (HTML)](leitir-engine-scorecard.html)
- [Manual v2 scorecard (HTML)](leitir-engine-scorecard-v2.html)

These historical documents are never scorer evidence.
