---
name: leitir
description: Use leitir when AI agents need to fetch and verify real source code for a library, framework, or dependency.
allowed-tools: Bash(leitir:*)
---

## When to use

Use leitir when you need real, verified source for internals, control flow, edge cases, tests, or version-specific behavior. Do not use it for questions that official docs or general knowledge answer completely.

## Core workflow (do this first)

```bash
# Step 1: get one-shot context: provenance, tree path, API, examples, and trust
leitir info npm:zod@3.22.0
# output starts like: npm:zod@3.22.0 owner/repo@<40-char-sha>
# and includes: tree:, version:, api:, examples:, trust:

# For machine consumption:
leitir info npm:zod@3.22.0 --json

# Step 2 (only if you need deeper source): materialize and read
path="$(leitir get npm:zod@3.22.0)"
rg "parse" "$path"
cat "$path/package.json"

# Step 3: cite the inspected file as <owner>/<repo>/<file>@<commit-SHA>
# Per jonschlinkert/is-number/index.js@98e8ff1da1a89f93d1397a24d7413ed15421c139:
```

## Spec forms (quick reference)

- `npm:zod@3.22.0` — npm package at exact version
- `pypi:requests@2.31.0` — PyPI package
- `crates:serde@1.0.152` — crates.io package
- `github:owner/repo@<40-char-sha>` — GitHub repository at a pinned commit
- `gitlab:owner/repo@ref` — GitLab repository (nested subgroups supported)

If a spec fails, leitir tells you why. Run `leitir doctor` if the environment seems broken.

## When to fetch deeper

If `info` does not cover internals, control flow, edge cases, tests, or version-specific behavior, run `leitir get`. For a simple public-API question answered by official docs, skip the fetch.

## Fail-closed rule

If leitir cannot verify, fetch, or materialize source, DO NOT fabricate or infer the code. Say "I don't have verified source for X," then fetch it or decline the source-specific part.

## Troubleshooting

- `leitir doctor` — run the full environment and integrity diagnostic.
- `leitir list` — show materialized sources; add `--json` for machine output.
- If loading fails with "materialized tree hash verification failed", the shelf changed: run `leitir remove <spec> && leitir get <spec>`.
- If a verified shelf fails with "missing materialized_tree_hash", run `leitir upgrade-cache` only if you trust its current bytes; this migrates legacy shelves.
- Tokens (`GITHUB_TOKEN`, etc.) are HTTPS-only and never logged; see `SECURITY.md` for the threat boundary.
- See `leitir --help` for the full command list.

## What leitir does NOT do

- It does not run code, execute tests, or install packages.
- It does not replace official docs; use it when docs are insufficient.
- It detects byte corruption relative to a manifest, not adversarial tampering of both bytes and manifest; that requires signatures.
- It does not use v1.0 as a production-readiness label: quality milestones ship in v0.x, while v1.0 is reserved for the 10,000-users adoption milestone.
