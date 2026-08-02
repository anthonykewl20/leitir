# Leitir

Leitir is a deterministic code-search kernel. Given a typed `SearchSpec` it
returns a `SearchReport` in which every result carries immutable provenance:
repository, resolved commit SHA, blob digest, path, and exact line span.

It makes no model calls, holds no credentials, and has **no runtime
dependencies** — the kernel runs on the Python standard library alone.

**Status: design-stage. Not production-ready.**

## What it guarantees, and what it does not

Exhaustiveness is only ever claimed over a declared, pinned corpus
(`scoped_exhaustive`). Global GitHub discovery is always reported as
`INDETERMINATE_GLOBAL` — never as "exhaustive" — because global recall is
unknowable by contract. A search claiming otherwise would be lying, so the
scoring engine treats such a claim as a hard failure.

Semantic interpretation — turning natural language into a `SearchSpec` — is the
calling harness's job, not Leitir's.

## Use it

```bash
# Explicit scope: pin the repository and commit yourself
PYTHONPATH=src python -m leitir.cli search \
  --repo python/cpython --commit deaf509e8fc6e0363bd6f26d52ad42f976ec42f2 \
  --symbol-definition urlencode --language python

# Package scope: resolve a release to its commit first
PYTHONPATH=src python -m leitir.cli search \
  --package requests --version 2.31.0 --ecosystem pypi \
  --symbol-definition Session

# Global discovery: coverage is always INDETERMINATE_GLOBAL
PYTHONPATH=src python -m leitir.cli search --global --symbol-definition urlencode
```

A JSON `SearchReport` goes to stdout; a human-readable summary goes to stderr.

## Benchmark

`search-v1` pins 12 scoped tasks — four each in Python, Rust and Go — at
immutable commits, with expected results verified against the GitHub contents
API for both blob SHA and line content.

```bash
PYTHONPATH=src python -m leitir.cli bench
```

Ranking applies a strict total order —
`(-normalized_score, slug, commit_sha, path, blob_sha, start_line, end_line)` —
and assigns unique descending rank scores, so downstream `trec_eval`-style
scoring cannot reorder results through equal-score tie handling.

## Scoring

`tools/score_engine.py` is a standalone evidence-bound scoring engine
(ADR-002). It imports no `leitir` code, uses no model, and never downloads or
upgrades a tool.

```bash
PYTHONPATH=src python tools/score_engine.py run --profile offline \
  --json-out .leitir-score/assessment.json \
  --html-out .leitir-score/scorecard.html
```

Its central rule is that **unknown is neither zero nor pass**. Unresolved
required evidence produces `indeterminate` with honest bounds rather than a
confident number, and no scalar score can turn a failure or an indeterminate
result into a pass. Run against this repository it currently declines to pass
itself, because most required evidence has never been collected here — see
[docs/scoring.md](docs/scoring.md).

The published current result is the generated
[HTML assessment](scorecard/leitir-assessment.html), whose canonical source is
[JSON](scorecard/leitir-assessment.json).

## Tests

```bash
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest
```

No credential, network, or Docker daemon is required. Live re-verification
against GitHub is opt-in behind `LEITIR_ENABLE_LIVE_E2E=1`.

## Documentation

- [ADR-001 — deterministic code-search kernel](docs/adr-001-remove-hy3-deterministic-search.md)
- [ADR-002 — deterministic evidence-scoring engine](docs/adr-002-deterministic-evidence-scoring-engine.md)
- [Scoring operation](docs/scoring.md)
- [Current status](docs/STATUS.md)

Historical, describing the retired v1 synthesis pipeline:
[PRD](docs/PRD.md), [operations guide](docs/operations.md),
[smoke evaluation](docs/smoke-evaluation.md), and the manual
[v1 engine health scorecard](docs/leitir-engine-scorecard.html), its
[historical PNG snapshot](docs/leitir-engine-scorecard.png), and the manual
[v2 editorial scorecard](docs/leitir-engine-scorecard-v2.html). These manual
snapshots are never scorer evidence.

## Repository layout

- `src/leitir/` — the search kernel (no runtime dependencies)
- `src/leitir/benchmarks/search-v1/` — pinned 12-task benchmark corpus
- `tools/score_engine.py` — standalone ADR-002 scoring engine
- `scorecard/` — versioned policy and assessment schema
- `tests/` — offline suite plus opt-in live verification
- `requirements.txt` — test and build lock; kernel runtime deps are empty
- `requirements-score.txt` — separate hash-pinned scoring-only lock
