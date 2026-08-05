# ADR-0003: Categorized HTTP retry for the transport and resolver layer

- Status: accepted
- Date: 2026-08-03
- Implementation: complete
- Related: [ADR-0001](0001-remove-hy3-deterministic-search.md) deterministic code-search kernel (P4, P5), [ADR-0002](0002-deterministic-evidence-scoring-engine.md) §7 total order
- Layer: `src/leitir/_http.py`, `src/leitir/discovery_search.py`, `src/leitir/resolver.py`

## Context

ADR-001 retired all model calls and credentials, leaving Leitir as a
deterministic kernel that talks to GitHub and the package registries over
plain `urllib`. Until this change, every HTTP call site treated **any**
`HTTPError` as fatal, and a read `TimeoutError` could escape unwrapped:

- `discovery_search.py` — 3 sites (`search`, `resolve_head_sha`,
  `read_blob_by_path`).
- `resolver.py` — 4 classes (`GitHubTagResolver`, `PyPIResolver`,
  `CratesResolver`, `GoResolver`), 5 call sites.
- `tree.py` — 3 sites (`_get_json`, `read_blob`, `read_blob_by_path`). This is
  the **heaviest** GitHub consumer (the scoped-exhaustive path issues one tree
  list plus one blob read per eligible file).

That meant a single transient `502`, a `429` secondary rate limit, a read
timeout, or a flaky socket aborted the whole search or resolution. GitHub
imposes secondary rate limits liberally on Code Search, so this was a real
reliability gap, not a theoretical one.

The question was whether to add retries and, if so, how to do it without
violating ADR-001: no new runtime dependencies, no credentials, no model
calls, and the result for a fixed input must remain reproducible.

## Pattern lineage

The categorized-error shape is borrowed from the DeepAPI client contract
(idempotent retry with an explicit retryable-vs-fatal split and honoring the
server's wait hint). DeepAPI's API is asynchronous (`POST` -> job id -> poll
`status` until done), which does **not** map to GitHub's synchronous REST API.
What transfers is the *spirit*:

1. Classify every failure into retryable vs fatal.
2. Honor the server-advised wait when present.
3. Bound retries so a call either resolves or fails fast with the real error.

## Decision

1. **One stdlib-only helper**, `src/leitir/_http.py`, owns the policy. It holds
   no credentials, performs no model calls, and defers `urllib` and
   `email.utils` imports into function bodies so the import-purity gate
   (ADR-001 P0r) stays green.

2. **Three error kinds** (`HttpErrorKind`):
   - `RATE_LIMITED` — `429`, or `403` carrying `X-RateLimit-Remaining: 0` or a
     `Retry-After`. Wait per the server hint, then retry.
   - `TRANSIENT` — `408`/`425`, the full `5xx` range except `501 Not
     Implemented` (so edge errors `520`/`522`/`524` from
     `raw.githubusercontent.com` are retried), and any `OSError` that is not an
     `HTTPError` (`URLError`, `TimeoutError`, `ConnectionError`) plus
     `http.client.HTTPException` (`IncompleteRead`, `RemoteDisconnected`).
     Deterministic exponential backoff.
   - `FATAL` — every other `4xx` (auth, not found, malformed query) and `501`.
     Raise immediately; retrying cannot change the outcome.

3. **Server hints honored**, in order: `Retry-After` as integer seconds,
   `Retry-After` as an HTTP-date (naive dates interpreted as UTC), then
   `X-RateLimit-Reset` (epoch) when remaining is `0`. Falls back to exponential
   backoff when no hint is present.

4. **Two delay caps** — transient backoff is capped by `max_delay` (default
   60s); rate-limit hints are capped by the separate, larger
   `max_rate_limit_delay` (default 300s) so a GitHub primary limit (up to 3600s
   out) is honored rather than truncated into guaranteed-failure retries.

5. **Call sites catch `_http.RETRIABLE_EXCEPTIONS`** — a shared
   `(OSError, http.client.HTTPException)` tuple, built lazily via a PEP 562
   module `__getattr__` so importing `http.client` stays deferred (the
   import-purity gate forbids it at import time). This covers `HTTPError`,
   `URLError`, `TimeoutError`, and `IncompleteRead`, so neither a read timeout
   nor a truncated body escapes as a bare non-domain exception. Each site wraps
   the failure into its own domain error (`CodeSearchError`, `ResolutionError`,
   `TreeReadError`) via `_http.describe_failure` (HTTP status for `HTTPError`,
   the `reason` for other `OSError`s — never a misleading `HTTP ?`) and
   preserves `from exc` chaining.

6. **`Request` objects are constructed inside the retried closure**, not
   hoisted outside. `urllib`'s redirect handler mutates the caller's `Request`
   (`redirect_dict`); reusing one object across retry attempts accumulates
   loop-detection state and can synthesise a spurious `301`. A fresh
   `Request` per attempt keeps each retry clean.

7. **Deterministic backoff** — `base_delay * 2**(attempt-1)` with **no random
   jitter**. The sleeper and clock are injectable, so tests observe exact wait
   sequences and the result for a fixed scripted server is byte-identical
   across runs. The public parameter is `max_attempts` (total calls, not
   retries), validated at construction.

8. **Base URLs injectable** across all transports/resolvers so retry can be
   tested against a real local HTTP server with zero change to production
   wiring.

## Scope note and future work

- This change covers every HTTP call site in the kernel
  (`discovery_search.py`, `resolver.py`, `tree.py`). There is **no aggregate
  retry budget or deadline** across a multi-call operation (e.g. a
  `GlobalSearcher` search issues up to ~61 calls). Per-call caps bound the
  worst case, but a fully rate-limited search can still block for minutes. An
  operation-level budget with observability (using the existing `leitir.logging`
  redaction policy) is deferred as separate work.
- The retry knobs are not yet exposed via the CLI; operators cannot force a
  fail-fast run. Out of scope here.

## Consequences

- Gained: a transient GitHub/registry failure no longer aborts a search; rate
  limits are waited out; read timeouts are wrapped, not leaked.
- Gained: every retry site is observable (sleeper injection) and tested against
  real HTTP, including the redirect-mutation and timeout-escape regressions.
- Kept: zero runtime dependencies, zero credentials, zero model calls, and
  byte-identical outputs for fixed scripted inputs.
- Cost: a real search under sustained rate limiting now takes up to
  `max_rate_limit_delay` per retryable failure (default cap 300s) before
  succeeding or giving up.

## Validation

- Offline cumulative gate (ADR-001 P1-P6 plus this change): green.
- Real local-HTTP retry suite (`tests/test_http_retry_real.py`,
  `tests/test_resolver_retry_real.py`): drives the transport, all four
  resolvers, and `GitHubTreeSource` through a real
  `http.server.ThreadingHTTPServer` over real sockets, with `urllib` raising
  genuine `HTTPError`/`TimeoutError` objects carrying genuine headers. Each
  scenario is parametrized over many iterations to prove determinism.
- Regression tests for review-found defects: socket-timeout wrapping (H1),
  annotated-tag-dereference fatal wrapping (H2), redirect-chain under retry
  (M3), and `__cause__` chaining (ADR-003 §5).
- Full `GlobalSearcher` user-level path verified end-to-end against the local
  server, including a transient `502` mid-search that the search survives.
- Live gate: transport driven directly against `api.github.com` (happy path)
  plus the existing real-`404` resolver sad path.
- PYTHONHASHSEED determinism: re-verified as part of the final gate.
