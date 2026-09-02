# Testing Guide

## Purpose

Leitir tests the behavior a user can observe. The primary test is an
user-level intent test: it describes what happens when a user runs a command or
uses a public workflow, and asserts the resulting exit code, stdout, JSON,
stderr summary, files on disk, or exit tier. It does not assert a private
function's return value merely because that value is convenient to inspect.

This style survives refactors. The implementation may move from one module to
another, or from a direct scan to an index, while the user's observable result
must remain the same. Internal unit tests are secondary and belong around
tricky pure logic whose behavior is not practical to exercise through a public
workflow. They are not a substitute for the intent test.

Phrase acceptance criteria as an observation:

> When a user runs X, they observe Y.

Include the failure observation when it matters:

> When the user supplies malformed or tampered input, Leitir rejects it with
> the appropriate exit tier and does not claim success or complete coverage.

## Iterational Loop

Each slice follows the same probe-driven loop. Do not write a speculative test
against an imagined implementation.

### 1. Probe

Reproduce the real behavior or defect first. Use a short script, a REPL probe,
or a focused command against the actual code and GitHub-local fixtures. Record
the input, observable output, exit code, files changed, and coverage status.
For a security issue, mutate the evidence that a real caller could mutate:
manifest bytes, source bytes, identity fields, index bytes, or transport data.

The probe answers what the system currently does. It is evidence for the test,
not a permanent replacement for the test.

### 2. Red

Write a failing user-level intent test for the desired behavior. Drive the
public CLI or workflow, use real local fixtures, and assert the complete user
contract that matters: exit code or tier, structured output, provenance,
ordering, coverage, and filesystem effects. Add the sad path or tamper case in
the same slice when the change affects integrity, validation, or failure
handling.

A red test must fail for the missing behavior, not because its fixture is
broken. Keep the failure narrow enough that the next change has a clear reason
to make it green.

### 3. Green

Implement the smallest production change that honestly satisfies the intent.
Do not weaken an assertion, skip a case, broaden an acceptance path, or turn a
rejection into a warning just to get green. Preserve fail-closed behavior:
missing, malformed, mismatched, stale, sampled, or unverified evidence must
reject or remain uncovered.

### 4. Improve and Fix

Once the intent test is green, improve the implementation without changing the
user contract. Add the relevant sad-path and property cases, then look for
determinism, provenance, coverage, and fail-closed gaps. Refactor private
details only after the observable behavior is pinned. Repeat the loop for each
new defect found.

### 5. Gate

The slice is complete only when the full suite is green, output is deterministic
across the required seeds, and static checks pass:

```text
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest -q
ruff check .
mypy src
```

The gate is zero failures; skips appear only where an environment gate holds
them back. The live pass/skip count is recorded in README's dated status
paragraph, not here. Live tests remain gated by `LEITIR_ENABLE_LIVE_E2E=1`.
Security, integrity, and materialization changes also require the dual review
defined in AGENTS.md review lanes (both reviewers, requested together).

## Leitir Patterns

### CLI intent

Use the patterns in `tests/test_cli_e2e.py`. Its offline tests call the public
`main([...])` entry point with deterministic fixture factories, then assert
`ExitCode`, JSON fields, stderr summaries, immutable source identity, and
coverage. This tests the resolver-to-engine-to-report behavior a CLI user sees
without mocking the search operation itself.

For a subprocess-sensitive contract, use `subprocess.run` as
`tests/test_corpus_cli_e2e.py` does. Assert return code, stdout, stderr, and
timeout behavior. Use in-process `main([...])` when the contract does not
depend on process boundaries and it makes the test smaller.

### Corpus and cache intent

Use `tests/test_corpus_cli_e2e.py` for materialization and cache workflows.
Its scripted local HTTP servers provide deterministic responses while the test
observes paths, manifests, pointers, cache hits, request counts, and clean
failure output. A corpus test should inspect the files a user relies on, not a
private cache helper.

When a corpus or manifest is changed, exercise a second invocation. A cache
hit, backfill, removal, or failed verification is a user-visible workflow and
must remain correct across process boundaries where relevant.

### Real-provider intent

Use `tests/test_*_e2e_live.py` for real-provider behavior. These tests are
opt-in and must remain gated in default CI. `tests/test_engine_e2e_live.py`
drives the real GitHub tree source, checks commit-pinned provenance and
deterministic ranking, verifies honest coverage, and includes a corrupted
commit sad path. Keep the offline equivalent in default CI with synthetic
corpora or scripted local HTTP servers; live tests are canaries, not the only
proof of the contract.

Live-gated tests carry the registered `pytest.mark.live` marker alongside
their `LEITIR_ENABLE_LIVE_E2E` skip gate, so
`PYTHONPATH=src python -m pytest -m live --collect-only -q` prints the
authoritative inventory of everything the gate holds back.
`tests/test_live_marker_inventory.py` fails if a test env-gates without the
marker (invisible to the inventory) or is marked without a gate (it would run
offline), and the unknown-marker-as-error discipline in `tests/conftest.py`
turns a typo'd marker name into a collection error.

## Determinism

Every test must be independent of `PYTHONHASHSEED`. Sort paths, sets, and all
other unordered iterations before producing output. Do not make a test pass by
depending on the current order of a dict or set.

For output-bearing or ranking behavior, assert byte and exit-code equality
under `PYTHONHASHSEED=0`, `1`, and `42`. The `PYTHONHASHSEED=0` matrix cell is
the regression guard, not permission to test only that seed. Include the seed
matrix in the test or gate that owns the behavior, and compare serialized
stdout/JSON where byte identity is part of the contract.

Determinism includes:

- sorted path and result traversal;
- stable tie-breaking and ranking total order;
- stable JSON or artifact serialization;
- stable exit tier and coverage status;
- stable files and manifests on disk;
- stable benchmark and scorecard digests.

## Fail-Closed Integrity

An integrity change is incomplete without a tamper/reject test. Start from a
valid fixture, tamper with one relevant fact, and assert rejection or an
explicit uncovered/partial result. Never accept corrupted evidence silently
and never report complete coverage from an unverified source.

Cover the boundary that changed. For search v2 this can include manifest
identity, source, parity, tree-hash scope, index bytes, blob bytes, declared
size, commit, path, or concurrent build/read state. Assert the observable
error taxonomy or exit tier as well as the absence of false-success output.

Tests must not bypass the verification boundary by constructing an internal
object after verification or by mocking the principal read, hash, search, or
materialization operation. Mock only edges such as a clock, token provider, or
transport adapter when the real operation remains exercised.

## Properties and Goldens

Use a property or golden test when the contract is about an invariant rather
than one example. Useful properties include:

- scorecard artifacts are byte-identical for identical inputs;
- ranking has a total, deterministic order and no duplicate source identity;
- a benchmark run has a stable digest;
- a result permalink remains pinned to the requested commit;
- a tampered artifact cannot produce a complete report;
- repeated cache reads do not fetch again and leave the same files on disk.

Golden files are contracts, not snapshots of incidental formatting. Review a
golden change as a behavior change and include the reason for it. Prefer a
small canonical fixture with explicit ordering over a large generated output.

## What Not To Do

- Do not test private functions when a public workflow can express the intent.
- Do not mock the principal operation under test; mock only external edges.
- Do not skip or xfail a failing behavior to make the suite green.
- Do not weaken a tamper assertion into a warning or an empty successful result.
- Do not assert incidental internals that will churn during refactoring.
- Do not rely on network availability for default-CI intent tests.
- Do not rely on unordered iteration, wall-clock timing, or live mutable refs.
- Do not call a result complete when the declared universe was not verified.

## Worked Example

Intent: when a user searches for a symbol in a requested repository commit,
Leitir returns the matching source pinned to that commit, in deterministic
order, with honest coverage.

### Probe

Run the search against a local fixture containing the symbol and a tree source
that returns the fixture's known path, commit, and blob SHA. Repeat with seeds
0, 1, and 42. Then alter the blob or commit evidence and observe whether the
current implementation incorrectly returns a match or complete coverage.

### Red

Drive `main([...])` as in `tests/test_cli_e2e.py` and assert that the user sees
`ExitCode.SUCCESS`, JSON source fields for `slug`, `commit_sha`, `path`, and
`blob_sha`, a stable ordered match list, and
`complete_for_declared_universe` only when all eligible files were verified.
Add a tamper test that asserts rejection or partial/uncovered coverage rather
than a complete successful report.

### Green

Make the smallest change that binds matching bytes to the requested commit and
blob identity, and that reports incomplete coverage when verification fails.
The red intent test should now pass without changing its assertions.

### Improve and Fix

Add a second fixture with equal ranking scores to pin the tie-break order, a
no-match case, and a malformed-commit case. Compare serialized output and exit
code under all three hash seeds. Check that merged results are deduplicated and
that a partial scan cannot become complete through ranking.

### Gate

Run the full suite, `ruff`, and `mypy`; retain the live canary only behind its
environment gate. For an integrity implementation, obtain independent review
before calling the intent honestly met.

## References

- `AGENTS.md` for the suite command, determinism, fail-closed rules, live-test
  gate, and review lanes.
- `tests/test_cli_e2e.py` for offline CLI and JSON intent.
- `tests/test_corpus_cli_e2e.py` for subprocess, local-server, cache, manifest,
  filesystem, and failure intent.
- `tests/test_engine_e2e_live.py` for gated real-provider provenance, ranking,
  coverage, and corrupted-commit intent.
- `docs/search-v2-spec.md` for search v2 contracts and its changelog/testing
  policy.
