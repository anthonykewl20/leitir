---
name: leitir
description: Fetch proven dependency source and consult it before writing code. Use for "fetch source for", "read the source of", "how does X work internally", "reference implementation", "get the implementation of", "don't hand-roll", debugging library internals, checking edge cases, or any task requiring full npm, PyPI, crates.io, Go, or GitHub source beyond types and docs.
allowed-tools: Bash(leitir:*)
---

# Proven source with Leitir

## Required workflow

**Consult before writing.** If a library, framework, or API is already in the corpus, read its proven implementation before producing code. Do not hand-roll behavior that the reference already defines, and do not guess internals from memory.

Materialize missing source with `leitir get <spec>`. Add `--local` to shelve it in the current project's gitignored `.leitir-refs/` directory. `get` writes progress to stderr and absolute source paths to stdout, so browse complete files directly:

```bash
rg "parse" "$(leitir get npm:zod@3.22.0)"
cat "$(leitir get pypi:requests@2.31.0)/requests/sessions.py"
find "$(leitir get crates:serde@1.0.152)" -path "*test*"
```

Read `POINTERS.md` at the corpus root first. It records official documentation URLs and local README, `docs/`, `examples/`, and `tests/` practice entry points. Examples and tests are behavioral ground truth. A source with no official docs is marked source-as-primary; say explicitly that the source itself is the primary reference.

Follow imports and call chains across full files. Cite a relied-on file as `<owner>/<repo>/<file>@<commit-SHA>`, using the SHA in `leitir-manifest.json`. If a package is missing, unverified, or at the wrong version, say so and fetch or pin the right version. Never present invented code as referenced behavior.

## Specs and version selection

| Source | Accepted forms |
|---|---|
| npm | `zod`, `npm:zod`, `npm:zod@3.22.0`, `@scope/name@version` |
| PyPI | `pypi:requests@2.31.0`, aliases `pip:` and `python:` |
| crates.io | `crates:serde@1.0.152`, aliases `cargo:` and `rust:` |
| Go | `go:github.com/owner/module@version` |
| GitHub | `owner/repo`, `owner/repo@tag`, `owner/repo#branch`, `owner/repo@<40-char-sha>`, `github:owner/repo` |
| Full URL | `https://github.com/owner/repo` (including supported `/tree/<ref>` or `/blob/<ref>` forms) |

For packages, version choice is **explicit `@version`**, then the version detected from lockfiles under `--cwd` (the current directory by default), then registry latest. Repository `@ref` means a tag; `#ref` means a branch; a 40-character `@ref` is an immutable SHA.

Useful fetch flags, exactly as exposed by the CLI:

```bash
leitir get <spec>... [--root DIR | --local] [--cwd DIR] [--no-verify]
leitir fetch <spec>... [--root DIR | --local] [--cwd DIR] [--no-verify]
```

`fetch` prefetches without printing paths. Avoid `--no-verify` unless explicitly required; it records the source as unverified.

## Roots and cache management

The global root is `~/.leitir/`, overridden by `LEITIR_HOME`. Project shelves use `.leitir-refs/`. The management commands operate on the global/`LEITIR_HOME` root (they do not accept `--root` or `--local`):

```bash
leitir list
leitir list --json
leitir remove <spec>
leitir clean
leitir clean --repos
```

The current corpus contains repositories only, so `clean` and `clean --repos` both remove all shelved repositories, the index, and `POINTERS.md`.

## When to fetch

Fetch when implementation details, internal control flow, edge cases, tests, examples, or a proven reference implementation matter. First consult an existing `POINTERS.md`: a simple public-API question answerable from its official docs links does not require a fetch. Do not fetch for questions that types or already-linked docs fully answer.
