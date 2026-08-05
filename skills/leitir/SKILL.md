---
name: leitir
description: Fetch and verify proven dependency/host source for AI agents, then consult it before writing behavior code; use for read-the-source tasks, library internals, edge cases, reference implementations, and version-specific behavior across npm, PyPI, crates.io, Go, GitHub, GitLab, Bitbucket, Codeberg, and Sourcehut.
allowed-tools: Bash(leitir:*)
---

## 1. Required workflow

- **Consult before writing.** Read proven source before behavior-sensitive output; avoid memory-based inference.
- Start with `leitir info <spec>` first. It returns the extracted public contract (signatures and docstrings), top usage code, provenance, trust score, and parity in one call.
- Synthesize from the surfaced contract; read full files only when behavior beyond the extracted surface matters.
- If `info` shows low trust, mismatched version, missing examples, or unclear parity, fetch deeper immediately.
- Run `leitir get <spec>` (or `leitir fetch` for prefetch) before any deep analysis.
- Read `POINTERS.md` in the materialized source root first.
- Cite behavior only from files you inspected, not from memory.
- Read complete files using quoted paths from `leitir get` output:
  - `rg "parse" "$(leitir get <spec>)"`
  - `cat "$(leitir get <spec>)/module/file.py"`
  - `find "$(leitir get <spec>)" -name '*test*'`
- Cite relied-on files in the form `<owner>/<repo>/<file>@<commit-SHA>` using manifest SHA from `leitir-manifest.json`.
- If source is missing, unverified, or wrong revision, state that and either fetch or pin the exact version.
- Never present invented code as reference behavior.

## 1.1 Hard constraints

- Do not hand-roll framework internals, parsing behavior, retry policy, or API edge cases when source exists.
- Do not rely on unverified docs if source examples or tests disagree.
- Prefer official docs only for API surface shape; use source for behavior and invariants.
- Never write version-specific conclusions without explicit `@version`, lockfile pinning, or fetched commit.
- Keep statements scoped: package version, commit/sha, and host source.

## 2. Commands

- **Materialize**: `leitir get <spec>...` (prints absolute paths), `fetch` (no paths) with flags `--local`, `--root`, `--cwd`, `--no-verify` (avoid `--no-verify`).
- **One-shot context**: `leitir info <spec>` (use first) returns public signatures, docstrings, top usage code, and provenance. Add `--json` for machine output.
- **Analyze**: `leitir api <spec>` returns the bounded public-symbol contract with provenance; `leitir examples <spec>` returns usage code; also available: `leitir trust <spec>`, `leitir diff <a> <b>`. Synthesize from these outputs before reading full files for deeper behavior.
- **Manage**: `leitir list [--json]`, `leitir remove <spec>`, `leitir clean [--repos]`.
- **Reproducibility**: `leitir lock [--cwd] [--best-effort]` (materialize transitive closure), `leitir export [-o corpus.lock]`, `leitir import <corpus.lock>`.
- **SBOM**: `leitir sbom [--format spdx|cyclonedx]`.
- `--json` is supported on `get`, `trust`, `api`, `examples`, `list`, and `diff`.
- CLI progress logs go to `stderr`; machine-readable output uses `stdout`.

### 2.A Command notes

- Materialize paths first: `get` prints absolute paths; `fetch` does not print paths and is useful in scripts.
- Use `--local` when you want sources under `.leitir-refs/` and keep results gitignored.
- Use `--root` for a fixed global corpus root when running in tooling automation.
- Use `--no-verify` only for last-resort debugging; avoid it in normal evidence collection.
- Use `--cwd` for lockfile-aware version selection in monorepos and nested project roots.

## 3. Specs

| Source | Accepted forms |
| --- | --- |
| npm | `zod`, `npm:zod`, `npm:zod@3.22.0`, `@scope/name@version` |
| PyPI | `pypi:requests@2.31.0` (aliases `pip:`, `python:`) |
| crates.io | `crates:serde@1.0.152` (aliases `cargo:`, `rust:`) |
| Go | `go:github.com/owner/module@v`, `go:gitlab.com/...`, `go:bitbucket.org/...`, `go:golang.org/x/<pkg>@v` |
| GitHub | `owner/repo`, `owner/repo@tag`, `owner/repo#branch`, `owner/repo@<40-sha>`, `github:owner/repo`, full URL |
| GitLab | `gitlab:owner/repo@ref`, nested subgroups `gitlab:group/subgroup/repo`, URL (`/-/tree/<ref>` supported) |
| Bitbucket | `bitbucket:owner/repo@ref`, URL |
| Codeberg | `codeberg:owner/repo@ref`, URL |
| Sourcehut | `sourcehut:~user/repo@ref` (leading `~` required), URL |

- Version resolution: explicit `@version` first, then lockfile-detected under `--cwd`, then registry latest.
- `@ref` = tag, `#ref` = branch, 40-char `@ref` = immutable SHA.

- Git repository shorthands support nested slugs where allowed by ecosystem parser.
- GitLab accepts subgroup trees (example: `gitlab:group/subgroup/repo`).
- Sourcehut owners require leading `~` in shorthand and repository URLs.
- URL inputs must be HTTPS and must not include fragment/query authentication data.
- For go modules, explicit host module paths are required and preserve full import path.

## 4. Auth

- Optional tokens are HTTPS-only and never logged: `GITHUB_TOKEN`, `GITLAB_TOKEN`, `BITBUCKET_TOKEN` (+`BITBUCKET_USERNAME` for app-password Basic), `CODEBERG_TOKEN`, `SRHT_TOKEN`, `NPM_TOKEN`, `PYPI_TOKEN`/`PIP_TOKEN`, `CARGO_TOKEN`.

- Use tokens only when needed; defaults remain anonymous for public endpoints.
- Prefer minimal scopes on tokens to reduce exposure during repeated materialization.

## 5. Roots & cache

- Global corpus root is `~/.leitir/` (`LEITIR_HOME`).
- Project-local root is `--local` → `./.leitir-refs/`.
- `list/remove/clean` act on the global root by default; list can be overridden only by explicit root/local flags in implementation.
- Materialized trees are stored in `repos/<host>/<owner>/<repo>/<sha>`.
- Extracted `api/` and `examples/` caches mirror `repos/` scope and are reused across commands.

- `repos/` cache is immutable per `<sha>` once materialized.
- `api/` index stores symbol-level summaries for `leitir api` and `trust` acceleration.
- `examples/` cache stores ranked usage snippets for `leitir examples`.
- `clean` currently clears `repos/`, `api/`, `examples/`, and metadata index; keep `--repos` as a compatibility flag.

## 6. When to fetch

- Fetch when implementation internals, control-flow, edge cases, tests, examples, or strict version behavior matter.
- Start with `leitir info` and `POINTERS.md`; a simple public-API question from official docs may skip `get`.
- Do not fetch for topics already fully answered by typed docs, usage notes, or verified examples.
- If cited claims require behavior, but source is absent/unverifiable, fetch and lock the correct revision before concluding.

## 6.1 Fetch decision guardrails

- Fetch before answering questions about: internal state machines, parsing/serialization, pagination, retries, pagination cursors, concurrency, side effects.
- Fetch when tests/examples conflict with official docs or quick API references.
- Use `lock`/`export` first when you need full transitive evidence for a repository's dependency graph.
- Use `diff <a> <b>` when behavior questions span semver changes and you need file/API deltas.
- Use `import` snapshots for offline replay when network evidence must be reproducible.
