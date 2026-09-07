# HTTP retry reference investigation

I used the Leitir skill at `/home/soultransit/devtony/leitir-skill-reference-semantics/skills/leitir/SKILL.md`, inspected the actual target source and manifests, and read the actual materialized upstream implementation. No repository files were changed and nothing was installed.

## Recommendation

Keep deterministic retry delays as the default. ADR-0003 section 7 explicitly requires no random jitter and exact sequences for scripted servers. Full jitter can spread simultaneous clients' retries, but silently enabling it contradicts that existing contract. If improving collision behavior becomes a selected architectural change, implement an explicit, injectable delay policy in Leitir using stdlib facilities, with deterministic behavior retained by default; revise ADR-0003 and the relevant README behavior documentation in the implementation PR. This task supplies a concrete proposal, not a verified implementation or a measured performance improvement.

Suggested design: thread `jitter: Callable[[float], float] | None = None` through `make_retry` and `retry_http`. For a retryable failure with **no valid server hint**, first calculate `upper = min(base_delay * 2**(attempt - 1), cap)`, then use `upper` when jitter is absent or `jitter(upper)` when enabled. An optional local full-jitter helper can lazily import `random` and return `random.uniform(0.0, upper)`. Applying jitter after capping keeps the distribution uniform over the intended bounded range rather than concentrating samples at the cap. Validate that a callback returns a finite float within `[0, upper]`, rejecting invalid values before sleeping; do not silently clamp malformed policy results.

Preserve server-hint behavior exactly: do not jitter Retry-After or X-RateLimit-Reset waits downward. Preserve oversized rate-limit rejection on every attempt, including the last; preserve transient-hint capping at max_delay, fatal immediate propagation, and unchanged exhaustion exceptions. Account for the actual selected sleep in max_total_wait and reject an over-budget sleep rather than adopting upstream's deadline clamp. Avoid invoking a jitter callback on fatal failures or after final-attempt exhaustion. Callers wishing to activate random jitter would need an explicit integration choice; merely adding an unused callback is not a production collision reduction.

## Actual target evidence and probe

`src/leitir/_http.py` implements categorized retries; `retry_http` begins at line 417 and computes capped exponential delays near the end of the file. Defaults are four total attempts, base delay 1 second, max transient delay 60 seconds, rate-limit cap 300 seconds. `make_retry` is the shared binding point for transports and resolvers. The module describes itself as import-pure, stdlib-only, deterministic, and has injectable sleeper/clock seams. `pyproject.toml` declares `dependencies = []`; the existing optional extras and development requirements do not select backoff.

Read-only reproduction from repository source, without loading donor code:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python - <<'PY'
from leitir._http import retry_http
waits = []
calls = 0
def operation():
    global calls
    calls += 1
    if calls < 4:
        raise TimeoutError('probe')
    return 'ok'
print({'result': retry_http(operation, sleeper=waits.append), 'calls': calls, 'waits': waits})
PY
```

Actual output: `{'result': 'ok', 'calls': 4, 'waits': [1.0, 2.0, 4.0]}`. This confirms the present contract, not a defect or a jitter implementation.

## Reference consulted, identity, and limits

Existing real CLI responses `/tmp/leitir-skill-347/info.json` and `get.json` report `pypi:backoff@2.2.1`, verified true, source `registry-artifact`, sdist SHA-256 `03f829f5bb1923180821643f8753b0502c3b682293992485b0eef2807afa5cba`. I used the verified result's actual path:

`/tmp/leitir-skill-347/corpus/repos/github.com/litl/backoff/d9d80a92d5a4483373acdaf9faa4068c85b3d268`.

The recorded Git association is `litl/backoff` at `d9d80a92d5a4483373acdaf9faa4068c85b3d268`, but parity is **drift** (13 compared files, 2 only in artifact, 15 only in Git). The inspected code is the registry-artifact shelf; its path/commit association must not be represented as proof of byte-identical Git source. Verification and checksum evidence do not by themselves establish publisher authenticity or fitness.

Actual `backoff/_jitter.py:18-28` defines full_jitter as `random.uniform(0, value)`, using only stdlib random. It draws over the full interval, unlike the same file's random_jitter, which adds up to one second. For finite nonnegative upper bounds the theoretical mean is half the upper bound; this is not evidence of measured end-to-end improvement. The helper itself does not validate bounds, classify failures, compute exponential delays, enforce Retry-After, or manage retry budgets.

`backoff/_common.py:34` (`_next_wait`) applies the jitter callback to a generator value and then limits sleep to remaining max_time. That deadline policy differs from Leitir's cumulative-sleep budget rejection and should not be transplanted. AST extraction reports 13 symbols and zero indexed examples: I read source rather than inferring internal semantics from API summaries. No corpus search was required, so no absence claims were inferred from corpus coverage.

The actual LICENSE is MIT, copyright 2014 litl, LLC. Preserve its copyright and permission notice if copying substantial source. The proposed target-native algorithm can cite this reference without vendoring the package. `routing.verdict = transplant-ok` and trust score 78 are evidence metadata, not dependency/adoption authorization. No donor code was executed.

## Proposed imports and dependency changes

- Target dependencies: **none**. Keep `pyproject.toml` runtime dependencies empty, and leave requirements/lockfiles untouched.
- Target imports: no `import backoff`; reuse the existing Callable typing import. If the optional local random helper is implemented, add a function-local stdlib `random` import so module initialization stays pure.
- Do not point target PYTHONPATH, runtime imports, or build configuration at the corpus shelf. Do not copy upstream packaging requirements, decorators, async helpers, or its dependency graph into Leitir.

## Validation for a future implementation

First write failing user-level intent tests for an explicitly opted-in transport: scripted transient responses followed by success must retain exact attempt bounds and use the injected wait samples. Use a real local HTTP server through the existing transport/resolver entry points (`tests/test_http_retry_real.py`, `tests/test_resolver_retry_real.py`) rather than claiming an upstream helper proves integration.

Cover default waits `[1, 2, 4]`; injected zero, midpoint, and upper-bound draws; cap saturation; zero base delay; no-hint rate limits; Retry-After and reset hints bypassing jitter; transient hint capping; oversized rate-limit final-attempt rejection; fatal/no-extra-call behavior; budget equality and budget overflow using actual samples; and rejection before sleep for negative, nonfinite, or over-cap callback values. Do not use statistical/flaky assertions or seed the global RNG. Retain the import-purity test and PYTHONHASHSEED-independent deterministic-default outputs. Preserve existing integrity rejection coverage; any integrity path touched additionally needs its own tamper/reject test.

After implementation and documentation updates, run the required full gates:

```sh
PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest -q
ruff check .
mypy src
```

Keep live tests gated by LEITIR_ENABLE_LIVE_E2E=1. These are proposed validation steps, not executed or passing results. Only the read-only existing-behavior probe above was run for this research task.
