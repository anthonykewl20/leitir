# Leitir

**Leitir is a proposed agentic technical search and code synthesis engine that grounds generated code in documentation and real implementations, then verifies it in a sandbox.**

## What it is

Leitir is a prototype-stage design for answering difficult, version-sensitive programming questions more reliably than a single search-and-generate pass. It is intended to orchestrate evidence retrieval, code synthesis, execution, and repair while preserving a detailed trace of how each result was produced.

This repository currently contains the v1 foundation, structured JSON trace and
replay recorder, and the fixed raw-HTTP OpenRouter Hy3 client:
side-effect-free typed contracts, validated configuration, replaceable
external-effect interfaces, secret-safe logging, exact request policies and
usage normalization, bounded retries, artifact replay references, attempt
diffs, and evidence-token accounting. It intentionally contains no workflow,
retrieval, sandbox, orchestration, or evaluation behavior yet.

## What it can do

The design is intended to:

- ground API contracts and syntax in official provider and language documentation;
- find control flow, error handling, and edge cases in real source code;
- synthesize code in a requested target language from ranked evidence;
- treat retrieved content as untrusted and flag instruction-like text;
- compile or test generated code inside an ephemeral Docker workspace;
- feed execution failures back into evidence gathering or code repair;
- record step-level latency, usage, cost, evidence, errors, and diffs for evaluation and replay.

## How it works

Leitir follows a five-step workflow:

1. Expand the request into targeted queries.
2. Discover documentation and source code across multiple search channels.
3. Extract, clean, deduplicate, and sanitize the evidence.
4. Synthesize target-language code while giving official contracts priority.
5. Run the result in a sandbox and, when it fails, route the diagnostics into another evidence or repair loop.

Evidence is prioritized through four “doors”:

1. official provider documentation and OpenAPI specifications;
2. canonical target-language documentation such as docs.rs and pkg.go.dev;
3. GitHub code search for implementation logic and edge cases;
4. a headless browser for content that direct extraction cannot recover.

Higher-authority evidence wins when sources conflict. The Docker sandbox—not model confidence—determines whether generated code passes.

## Evaluation goals

Leitir’s prototype goals are:

- **SER (Search Efficiency Ratio):** retain more than 25% of cleaned candidate evidence in the first synthesis prompt;
- **DRI (Door Resolution Index):** resolve at least 80% of accepted benchmark tasks using Tier 1 or Tier 2 evidence;
- **FPCR (First-Pass Compilation Rate):** pass the complete hidden test suite on the first valid attempt for more than 70% of benchmark tasks;
- **SCCR (Self-Correction Convergence Rate):** recover more than 85% of valid first-pass failures within three repair loops.

The full definitions, exclusions, benchmark composition, and reporting requirements are in the [Product Requirements Document](docs/PRD.md).

## Technology stack

- **Orchestrator:** Python by default.
- **Model:** exact model ID `tencent/hy3`, called through OpenRouter.
- **Reasoning policy:** Step 1 query expansion uses default no-think mode by omitting the top-level `reasoning_effort` field. Step 4 synthesis, Step 5 repair, and every Hy3 review send top-level `"reasoning_effort": "high"`. Model calls send `"include_reasoning": false`.
- **Discovery:** SearXNG or DuckDuckGo, plus GitHub Code Search.
- **Extraction:** Trafilatura, readability tooling, raw GitHub content, or GitIngest.
- **Verification:** ephemeral Docker workspaces running `cargo test`, `go test`, or `pytest` as appropriate.

## Status

**Status: Prototype foundation, trace recorder, and Hy3 transport.** See
[docs/PRD.md](docs/PRD.md) for the complete specification.

## Development

Python 3.11 or newer is required. From a clean checkout:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install --no-build-isolation --no-deps -e .
python -m pytest
```

`requirements.txt` is the fully pinned runtime, test, and build dependency
closure. Tests perform no network requests, Docker calls, or credential reads.

## Repository layout

- `README.md` — project overview
- `docs/PRD.md` — product requirements and technical specification
- `src/leitir/` — configuration, contracts, protocols, logging, and trace records
- `tests/` — offline pytest suite
- `pyproject.toml` — package and test configuration
- `requirements.txt` — exact dependency lock
