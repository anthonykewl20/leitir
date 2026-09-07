Full jitter treats the exponential delay as an **upper bound**, sampling uniformly from zero to that bound on each retry.

- **Backoff**, verified cached commit `d9d80a92d5a4483373acdaf9faa4068c85b3d268`: `full_jitter(value)` returns `random.uniform(0, value)`; its exponential generator can cap the value before jitter. [Inspected jitter source](/tmp/leitir-skill-347/git-corpus/repos/github.com/litl/backoff/d9d80a92d5a4483373acdaf9faa4068c85b3d268/backoff/_jitter.py:17), [generator](/tmp/leitir-skill-347/git-corpus/repos/github.com/litl/backoff/d9d80a92d5a4483373acdaf9faa4068c85b3d268/backoff/_wait_gen.py:7).
- **Botocore**, inspected `develop` source: computes `random() * min(exponential_delay, max_backoff)` and accepts an injected random function. Thus randomness continues even after reaching the cap. [Inspected implementation](https://raw.githubusercontent.com/boto/botocore/develop/botocore/retries/standard.py).
- **Leitir** currently sleeps the capped exponential value exactly: ordinarily **1, 2, 4 seconds** with default settings. It separately handles server hints and rejects waits exceeding the cumulative budget. [HTTP retry loop](/home/soultransit/devtony/leitir/src/leitir/_http.py:419).

**Recommendation:** apply full jitter only when there is no valid server hint:

```python
ceiling = min(base_delay * 2 ** (attempt - 1), cap)
wait = uniform(0.0, ceiling)
```

Pass an injectable `uniform` callable through `make_retry` and `retry_http` so tests remain deterministic. Preserve server-hint handling, oversized-rate-limit rejection, attempt limits, and budget rejection; check the budget against the sampled wait. Cap **before** sampling.

Only a deferred stdlib `random.uniform` import is needed, preserving module import purity. **No `backoff`/`botocore` imports, package installations, or dependency-manifest changes.** Adoption would also require updating the explicit [no-jitter ADR](/home/soultransit/devtony/leitir/docs/adr/0003-categorized-http-retry.md:91), README, and retry tests.

No files changed or upstream code executed.