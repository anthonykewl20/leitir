# Contributing to leitir

## Welcome

Thank you for contributing. Leitir is a dependency-source corpus plus a
deterministic search kernel for AI coding agents. Contributions should preserve
its provenance, determinism, and fail-closed integrity boundaries.

## Before you start

For large features or cross-cutting behavior changes, open an issue before
writing code. This gives maintainers and contributors a place to agree on the
problem and design before implementation work begins.

Security reports do not belong in public issues. Follow [SECURITY.md](SECURITY.md)
and use a private GitHub security advisory.

## Prerequisites

- Python 3.11 or newer
- Git
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Setup

Clone the repository, create an environment, and install the project with its
development tools:

```bash
git clone https://github.com/anthonykewl20/leitir.git
cd leitir
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

On Windows, activate the environment with `.venv\Scripts\activate`.

The `dev` extra installs the test and development toolset (pytest, coverage,
ruff, and mypy). For the reproducible CI-pinned dependency set instead, use
`requirements.txt` through uv:

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
uv pip install -r requirements.txt
```

`requirements.txt` is a pinned development/CI dependency closure; it is not a
runtime requirement.

## Running tests

Run the complete default suite from the repository root:

```bash
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest -q
```

Live tests are opt-in behind `LEITIR_ENABLE_LIVE_E2E=1`; do not enable them in
the default test run.

## Targeted tests

During development, run the smallest relevant test module for fast feedback:

```bash
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt \
  python -m pytest tests/test_treehash.py -v
```

Run the complete suite before submitting the change.

## Code conventions

- Keep the runtime standard-library-only. The `pyproject.toml`
  `dependencies = []` declaration must remain empty.
- Begin Python modules with `from __future__ import annotations`.
- Fully type production code and new test helpers where practical.
- Keep outputs deterministic and independent of `PYTHONHASHSEED`; sort paths
  and other unordered inputs explicitly.
- Fail closed when integrity data is missing, malformed, or mismatched.
- Use atomic manifest writes following the existing `_write_manifest` pattern:
  a temporary file, `os.replace`, and `fsync`.
- Preserve the existing domain error taxonomy.

## Test discipline

Do not weaken, skip, or remove a test to make a change pass. Fix production
behavior when a test identifies a real defect.

Security and integrity changes must include a tamper/reject test that proves
malformed or mismatched data is rejected.

## Review discipline

Security, integrity, and materialization changes require independent review.
Issue [#17](https://github.com/anthonykewl20/leitir/issues/17) is the reference
example: real probes, a focused fix, tests, review, and an ADR.

## Documentation discipline

When behavior changes, update the relevant ADR and README section in the same
change. Status claims such as test counts and scorer decisions drift quickly;
re-verify them before committing.

## AI-assisted contributions

Disclose the AI tool and how it was used in the pull request description. The
human submitter remains responsible for understanding the change, validating
its behavior, and responding to review feedback.

## Out of scope without explicit authorization

- Do not create commits unless explicitly requested.
- Do not add runtime dependencies.
- Do not remove fail-closed paths.
- Do not disable load-time tree verification through
  `materialized_tree_hash`.

## More project guidance

- [AGENTS.md](AGENTS.md) defines the repository workflow for AI agents.
- [ROADMAP.md](ROADMAP.md) tracks priorities toward Production-ready v1.0.
