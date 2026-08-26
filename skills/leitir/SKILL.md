---
name: leitir
description: Invoke before writing any code that calls a third-party library not read in this session—including when confident.
allowed-tools: Bash(leitir:*)
---

## When to use

Invoke leitir before writing any code that calls a third-party library not read in this session—**including when confident**. Confidence about a library's internals is not evidence of having read them.

**Always invoke if:**
- Version is lockfile-pinned and behavior may differ across versions
- About to write a call signature with more than two parameters  
- Task mentions an error, edge case, or "why does X happen"
- Porting or adapting code from anywhere (Stack Overflow, other projects, refactored code)

**Skip only if:**
- Answer is in the language's own stdlib (`os`, `sys`, `std`, `fs`, etc.)
- You already ran `leitir info` for this exact spec in this session

## Two lanes

**Advisory lane** — info, search, examples, api: understand code without taking it.
**Admission lane** — bts-*: fully governed transplant path for taking code. Donor execution is gated (requires `LEITIR_ENABLE_DONOR_EXECUTION=1` and Linux); use it only for measured, high-confidence transplants.

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

# Step 3: search across all dependencies (offline, fully pinned)
leitir search --corpus --must call:zod.parse
# See corpus-wide search caveat below before consuming results.

# Step 4: cite the inspected file as <owner>/<repo>/<file>@<commit-SHA>
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

## Corpus-wide search caveat

With `--corpus`, exit code is always 0 unless the command itself fails. Excluded shelves (unindexed, unverified, registry-derived, unsupported host) are named in the JSON output (`shelves_excluded`), NOT in the exit code. **An agent reading only the exit status will miss that shelves were excluded.** Always parse `corpus_status` and `shelves_excluded` from the JSON; an empty matches list with `shelves_excluded` non-empty means shelves were skipped, not that the symbol is absent everywhere.

## Admission path (bts-run)

The five containment-identity digests now resolve from a committed `--containment-environment` descriptor:

```bash
leitir bts-run owner/repo@sha --seed-module M --seed-name N --contract-spec S --out D --recipient-package P
# Containment digests resolve from --containment-environment; explicit flags override.
```

Donor execution is gated: requires `LEITIR_ENABLE_DONOR_EXECUTION=1` and Linux. This is the code-reuse path, not exploration; use it only for measured transplants.

## Check your own output

After writing code against a library, check it against the pinned truth instead of trusting your own recall:

```bash
leitir check ./src/app.py --against pypi:flask@3.0.3 --json
```

Three-way outcome per usage site: `ok` (confirmed present), `violation` (provably absent — exit 1, the only failing outcome), `unresolved` (statically undecidable, e.g. dynamic dispatch; never fails the gate). Read `counts.sites_unresolved` too — a run that resolved little verified little even if `sites_violation` is 0. Existence only: it does not check arity or types. If it exits 4 (`NOTHING_INDEXED`), nothing was examined — usually because the import root differs from the distribution name (`pypi:pillow` imports as `PIL`, `pyyaml` as `yaml`); this is not a pass.

## Troubleshooting

- `leitir doctor` — full environment and integrity diagnostic.
- `leitir list` — show materialized sources (add `--json` for machine output).
- Hash verification errors: run `leitir remove <spec> && leitir get <spec>`.
- Tokens are HTTPS-only and never logged; see `SECURITY.md` for details.
- See `leitir --help` for the full command list.

## What leitir does NOT do

- It does not run code, execute tests, or install packages.
- It does not replace official docs; use it when docs are insufficient.
- It detects byte corruption relative to a manifest, not adversarial tampering of both bytes and manifest; that requires signatures.
- It does not use v1.0 as a production-readiness label: quality milestones ship in v0.x, while v1.0 is reserved for the 10,000-users adoption milestone.
