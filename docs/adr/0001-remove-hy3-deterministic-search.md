# ADR-0001: Remove Hy3 and make Leitir a deterministic code-search kernel

- Status: accepted
- Date: 2026-08-02
- Implementation: complete

Implementation notes: revised 2026-08-02 for slice reordering and the CLI
integration layer; completed 2026-08-03 when P0r retirement and P1–P6 landed.

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
  paths.
- **Live gate** (opt-in, needs network): re-verifies pinned real provenance
  against GitHub and registries, including a sad path.

Real provenance is pinned in `tests/fixtures_real.py` (python/cpython @
`v3.11.0`) and `tests/fixtures_resolver.py` (requests, serde, testify). A P
task is not done until both gates are green.

Gate commands (cumulative — each P task appends its test files):

```bash
# Offline (current: P1–P6)
python -m pytest tests/test_search.py tests/test_search_e2e.py \
  tests/test_engine.py tests/test_engine_e2e.py \
  tests/test_adapters_multi.py tests/test_resolver.py tests/test_resolver_e2e.py \
  tests/test_cli.py tests/test_cli_e2e.py \
  tests/test_global.py tests/test_global_e2e.py \
  tests/test_ranking.py tests/test_bench.py

# Live (current: P1–P6)
LEITIR_ENABLE_LIVE_E2E=1 python -m pytest \
  tests/test_search_e2e_live.py tests/test_engine_e2e_live.py \
  tests/test_resolver_e2e_live.py tests/test_cli_e2e_live.py \
  tests/test_global_e2e_live.py tests/test_bench_e2e_live.py
```

## Work (bite-sized)

The slices are ordered so that each produces a testable increment and the tool
becomes usable at the earliest point. Engine internals first (P1–P3), then the
thin CLI shell that wires them into an executable process (P4), then engine
enrichment behind the existing CLI (P5–P6).

- [x] P1: Define `SearchSpec`, `SearchReport`, coverage contracts + tests.
      (`src/leitir/search.py`, `tests/test_search.py`,
      `tests/test_search_e2e.py`, `tests/test_search_e2e_live.py`)
      Gate: offline 32 passed; live 3 passed.

- [x] P2: Scoped-exhaustive MVP (strict commit pin, tree enumerate, Python adapter).
      (`src/leitir/tree.py`, `src/leitir/adapters.py`, `src/leitir/engine.py`,
      `tests/test_engine.py`, `tests/test_engine_e2e.py`,
      `tests/test_engine_e2e_live.py`)
      Gate: offline 72 passed; live 8 passed.

- [x] P3: Strict package resolution + more language adapters.
      (`src/leitir/resolver.py`, `src/leitir/adapters.py` RustAdapter+GoAdapter,
      `tests/test_adapters_multi.py`, `tests/test_resolver.py`,
      `tests/test_resolver_e2e.py`, `tests/test_resolver_e2e_live.py`,
      `tests/fixtures_resolver.py`)
      Gate: offline 128 passed; live 15 passed.

- [x] P4: CLI shell + end-to-end wiring.
      Replace the v1 Hy3 CLI with a `leitir search` command that wires
      resolver → engine → report. Two input modes:
      (a) explicit scope: `--repo owner/repo --commit <sha>` + predicates;
      (b) package resolution: `--package name --version v --ecosystem pypi|crates|go`.
      Output: JSON `SearchReport` to stdout; human-readable summary to stderr.
      Retire the old `leitir run` / `leitir eval` entry points.
      (`src/leitir/cli.py` rewrite, `tests/test_cli.py`,
      `tests/test_cli_e2e.py`, `tests/test_cli_e2e_live.py`)
      Gate: offline 158 passed (P1–P4 cumulative); full suite 452 passed.

- [x] P5: Global discovery with honest coverage reporting.
      Add a `GlobalSearcher` that uses GitHub Code Search API for
      `GLOBAL_DISCOVERY` mode. Coverage is always `INDETERMINATE_GLOBAL`.
      Fetched bytes are verified against search-index git blob SHAs, and
      bounded pagination reports head-resolution, fetch, decode, provenance,
      and adapter exclusions by reason.
      Wire into the CLI as `leitir search --global`.
      (`src/leitir/discovery_search.py`, `tests/test_global.py`,
      `tests/test_global_e2e.py`, `tests/test_global_e2e_live.py`)
      Gate: offline 192 passed (P1–P5 cumulative); full suite 486 passed.

- [x] P0r: Retire the v1 Hy3 pipeline (Decision #1).
      P4 removed the v1 CLI entry points but left the pipeline shipping behind
      `__init__.py` re-exports, so Decision #1 stayed unexecuted with no slice
      of its own. Delete `config.py`, `contracts.py`, `discovery.py`,
      `evaluation.py`, `expansion.py`, `extraction.py`, `openrouter.py`,
      `orchestrator.py`, `protocols.py`, `synthesis.py`, `trace.py`,
      `verification.py`, `_jsonutil.py`, their tests, and
      `benchmarks/smoke-v1/`. `contracts.py` is v1: its only importers were v1
      modules, and the kernel's contracts live in `search.py`. Reduce
      `__init__.py` to a docstring; drop `docker`, `trafilatura` and `PyYAML`
      with their closure, leaving no runtime dependencies.
      Gate: offline 192 passed (P1–P5 cumulative); full suite 234 passed,
      25 skipped.
      Note: the import-purity gate's `urllib.request` entry is a loose proxy —
      binding those names performs no I/O. The kernel's HTTP clients defer the
      import into their calling methods so the gate holds unrelaxed; narrowing
      the list to what it actually proves is left as a separate change.

- [x] P6: Deterministic ranking + pinned benchmark.
      Score normalization, tie-breaking by provenance stability, and a
      versioned benchmark suite (12 tasks: 4 Python, 4 Rust, 4 Go) with
      expected-result pins. `leitir bench` command.
      (`src/leitir/ranking.py`, `src/leitir/bench.py`,
      `src/leitir/benchmarks/search-v1/`, `tests/test_ranking.py`,
      `tests/test_bench.py`, `tests/test_bench_e2e_live.py`)
      Ranking applies [ADR-0002](0002-deterministic-evidence-scoring-engine.md) §7's mandated total order
      `(-normalized_score, slug, commit_sha, path, blob_sha, start_line,
      end_line)` and assigns unique descending `rank_score` values, so the S4
      adapter can hand pytrec unique scores and trec_eval's equal-score
      document-ID ordering cannot reorder these results. Duplicate result
      identities are rejected per §7. Normalization is min-max over Decimal
      parsed from the score's text form, so it never depends on binary
      floating-point evaluation order.
      The runner executes every task through an injected searcher and does not
      consult `expected_results`; qrels and metrics belong to S4. Per §7 no
      metric floor or baseline ratchet is introduced here.
      Gate: offline 221 passed (P1–P6 cumulative); full suite 263 passed,
      26 skipped; live re-verification 1 passed. Run artifact byte-identical
      under PYTHONHASHSEED 0/1/12345/99999. All 12 pins re-verified against the
      GitHub contents API (blob SHA and line content) on 2026-08-02.
