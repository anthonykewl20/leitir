---
name: leitir
description: Automatically use upstream code as REFERENCES, not target dependencies, when implementing algorithms, debugging edge cases, adapting patterns, or checking version-specific APIs—even if the user never mentions Leitir.
allowed-tools: Bash(leitir:*)
---

# Leitir: source references for implementation decisions

**Leitir search results and materialized code are REFERENCES, not target-project DEPENDENCIES.** A package spec identifies where to read source. A corpus shelf is a source cache. Neither establishes what the target application imports, installs, builds, or ships.

## Keep reference and dependency decisions separate

- Search, `info`, `get`, `api`, and `examples` provide evidence for understanding code. Their results do not instruct you to install packages, add imports, edit dependency manifests or lockfiles, vendor files, or execute donor code.
- Upstream imports, requirements, lockfiles, and SBOM entries describe the **reference project's** environment. Do not copy that dependency graph into the target project. Trace what the relevant implementation actually needs and respect the target's existing architecture and dependency constraints.
- Establish target dependencies from the target's manifests, actual imports/build configuration, and the user's chosen integration. A search hit, corpus lock entry, or matching package name is not evidence of a target dependency. An existing transitive dependency is not automatically a selected direct API.
- Use reference logic to inform a target-native implementation. Do not point runtime imports, `PYTHONPATH`, module resolution, or build inputs at a Leitir shelf. Preserve required attribution and licensing when adapting source.
- Installing or adopting a library is a separate target-project decision justified by the task and its constraints. A `routing.verdict` such as `transplant-ok`, trust score, or successful verification is metadata, not authorization to adopt, copy, or execute that code.

For example: studying `pypi:backoff@2.2.1` to understand jitter does not call for `pip install backoff`, `import backoff`, or adding it to requirements. Identify the relevant algorithm and implement the requested behavior using the target project's permitted facilities. If the user instead explicitly chose backoff as a dependency, inspect the chosen version to implement that integration accurately.

## Automatic activation

Load this skill without waiting for an explicit request when a coding task needs external implementation evidence. Trigger before choosing an unfamiliar implementation pattern, diagnosing behavior that depends on upstream internals, adapting another project's approach, or writing an uncertain version-specific API call. A request such as "add retry jitter," "handle URL edge cases," or "understand this library failure" can require it even without the words Leitir, search, or dependency.

Do not wait until a library has been selected: reference research can inform a dependency-free implementation. Do not force a source search for unrelated prose, formatting, or a mechanical local edit whose behavior is already established.

Use Leitir when upstream source can resolve an implementation question: control flow, error handling, edge cases, algorithm design, or version-specific API behavior. It also supports studying an already-selected target dependency; that is one use case, not the meaning of every search.

Start with the target behavior and constraints, then find relevant references. Do not choose a dependency merely to make the task fit a retrieved example. Reuse already-inspected evidence for the same version and question. Fetch deeper source only when the available context is insufficient; an API summary alone does not establish internal behavior.

## Reference workflow

```bash
# Inspect a reference package, without adding it to the target project.
leitir info pypi:backoff@2.2.1 --json
# Read paths.tree and the relevant source files. Inspect provenance, parity,
# API method/coverage, and license evidence before drawing conclusions.

# If only materialization is needed, request structured output.
leitir get pypi:backoff@2.2.1 --json
# For this single-spec request, use results[0].path after checking
# results[0].verified. Use JSON for structured verification metadata.

# Search the reference corpus, not "all project dependencies".
leitir search --corpus --must exact_text:full_jitter --json
# Inspect corpus_status and shelves_excluded before interpreting matches.
```

Read the matching definition and enough surrounding code to identify its assumptions, helpers, and failure behavior. Distinguish the observed upstream behavior from the target behavior you recommend. Explain why the reference is relevant and cite the actual file/location and recorded source identity, for example `<owner>/<repo>/<file>@<commit-SHA>` when Git parity supports that identity. For registry artifacts with drift or degraded provenance, retain the artifact checksum/version and disclose the limitation; do not present them as byte-identical Git source.

Implement and validate through the target project's real entry point with representative data. Source inspection and upstream tests are evidence about the reference; they do not prove the target integration works. In the handoff, distinguish references consulted from actual target dependency changes. If no dependency change was required, say so.

## Spec forms

- `github:owner/repo@<40-char-sha>` — repository reference pinned to a commit
- `gitlab:owner/repo@ref` — repository reference, including nested subgroups
- `npm:zod@3.22.0` — npm source at an exact package version
- `pypi:backoff@2.2.1` — PyPI source at an exact package version
- `crates:serde@1.0.152` — crate source; acquisition does not imply API-extractor support

These are source locators, not installation instructions. Bitbucket is outside this owner's usage scope.

## Verification and coverage

If source cannot be fetched or verified, report the missing evidence and avoid source-specific claims. Do not fabricate code or disable verification to make a reference usable. Byte integrity, publisher authenticity, Git parity, extraction coverage, licensing, and fitness for the target are distinct questions.

With corpus search, a successful exit can still report partial coverage. Read `corpus_status` and `shelves_excluded` from JSON. Unindexed, unverified, registry-derived, or unsupported-host shelves may be excluded. Empty matches with exclusions do not establish that a symbol is absent everywhere.

For environment problems, use `leitir doctor`. Use `leitir list --json` to inspect reference shelves and `leitir --help` for supported commands. Repair corrupt references through normal verified reacquisition; never import or execute a suspect shelf to diagnose it.

## Already-selected dependency: inspect and check usage

Only when the target actually uses or is intentionally integrating a library, inspect its selected version and optionally check the consumer:

```bash
leitir check ./src/app.py --against pypi:flask@3.0.3 --json
```

This command examines static usage; it does not adopt Flask or authorize a new dependency. Per-site `ok` confirms existence, `violation` reports provable absence, and `unresolved` remains undecidable. Inspect unresolved counts and coverage, not just the exit code. It does not verify arity, types, or runtime behavior. Exit 4 means nothing was examined, often because import-root evidence is missing; it is not a pass.

## Explicit governed transplant

Ordinary reference research does not require `bts-*`. Use the admission path only when the task explicitly calls for a governed code transplant, with recipient, contract, source/license evidence, and containment inputs established. A reference-only task does not become a transplant because a candidate is eligible.

Consult `leitir bts-run --help` for the applicable interface. Donor execution requires `LEITIR_ENABLE_DONOR_EXECUTION=1`, Linux, and verified pinned containment; enabling the environment variable alone is insufficient. Do not enable execution or fall back to running donor code on the host as part of ordinary exploration. Even an admitted transplant is copied/adapted recipient code, not an instruction to add the donor package as a dependency; validate its actual remaining requirements separately.
