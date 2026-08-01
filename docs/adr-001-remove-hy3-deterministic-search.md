# ADR-001: Remove Hy3 and make Leitir a deterministic code-search kernel

- Status: Proposed
- Date: 2026-08-02

## Context

Leitir currently uses a fixed `tencent/hy3` model (via OpenRouter) to generate
search queries, synthesize code, and repair failures. The model identity is
hard-coded (`src/leitir/config.py:18`) and enforced
(`src/leitir/openrouter.py:294-298`), and no `seed` is sent
(`src/leitir/openrouter.py:440-475`), so runs are not reproducible.

Goal: Leitir becomes a harness-agnostic, deterministic, code-driven tool that is
accurate and exhaustive at finding correct existing code on GitHub.

## Decision

1. Remove Hy3/OpenRouter from the core. No model calls, credentials, prompts,
   synthesis, or repair inside Leitir.
2. Leitir accepts a typed `SearchSpec` and returns a `SearchReport`. Semantic
   interpretation (natural language -> spec) is the harness's job.
3. Guarantee exhaustiveness only over a declared, pinned corpus
   (`scoped_exhaustive`). Global GitHub discovery is reported as
   `INDETERMINATE_GLOBAL`, never "exhaustive".
4. Every result carries immutable provenance: repo + resolved commit SHA + blob
   digest + path + exact span.

## Consequences

- Lost: free-text synthesis, model repair, model-driven query creativity.
- Gained: determinism, reproducibility, zero model cost, harness independence.
- Breaking change: v1 five-step synthesis workflow is retired.

## Gate policy

Every P task ships with real-data e2e tests and must pass its gate before the
next P task starts. A gate has two parts:

- **Offline gate** (always runs): unit + real-data e2e tests, happy and sad
  paths. Command: `python -m pytest tests/test_search.py tests/test_search_e2e.py`
- **Live gate** (opt-in, needs network): re-verifies pinned real provenance
  against GitHub, including a sad path. Command:
  `LEITIR_ENABLE_LIVE_E2E=1 python -m pytest tests/test_search_e2e_live.py`

Real provenance is pinned in `tests/fixtures_real.py` (python/cpython @
`v3.11.0`). A P task is not done until both gates are green.

## Work (bite-sized)

- [x] P1: Define `SearchSpec`, `SearchReport`, coverage contracts + tests.
      (`src/leitir/search.py`, `tests/test_search.py`,
      `tests/test_search_e2e.py`, `tests/test_search_e2e_live.py`)
      Gate: offline 32 passed; live 3 passed.
- [ ] P2: Scoped-exhaustive MVP (strict commit pin, tree enumerate, Python adapter).
- [ ] P3: Global discovery with honest coverage reporting.
- [ ] P4: Strict package resolution + more language adapters.
- [ ] P5: Deterministic ranking + pinned benchmark.
