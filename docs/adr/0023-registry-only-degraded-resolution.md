# ADR-0023: Registry-only degraded resolution when the repository tag lookup is unavailable

- Status: accepted
- Date: 2026-08-23
- Implementation: complete
- Related: [ADR-0004](0004-local-source-materialization.md) local source materialization, [ADR-0003](0003-categorized-http-retry.md) categorized HTTP retry
- Trigger: production-readiness audit 2026-08-23, finding P1(b)

## Context and Problem Statement

Resolving a PyPI or npm package to a materializable shelf required two
independent network services to succeed: the registry (metadata plus a
checksummed source artifact) **and** the GitHub REST API (tag-to-commit
lookup). When GitHub throttled the request (403 primary or secondary rate
limit) or was down, resolution hard-failed even though the registry artifact
was reachable, checksum-verified, and fully sufficient to materialize the
package bytes. The dependency was total and unbounded: GitHub availability
gated registry availability. An existing test enforced exactly this
fragility.

## Decision Drivers

- Registry artifacts are independently trustworthy for *bytes*: the
  checksum is published by the registry itself and verified byte-for-byte
  before extraction (ADR-0004, `materialize_artifact`).
- What the registry cannot provide is the *provenance binding*: which git
  commit the released version corresponds to. That binding is genuinely
  unavailable during a GitHub outage or throttle.
- Fail-closed discipline: a missing or degraded integrity signal must never
  be silently accepted as full provenance.
- Availability: a throttled third-party API should not make a reachable,
  checksum-verified artifact unusable.

## Considered Options

1. **Keep the hard dependency and document it.** Rejected as the only
   remedy: it leaves total availability coupling in place and the README
   already framed resolution as registry-driven.
2. **Opt-in flag for registry-only materialization.** Rejected: the
   artifact channel is the default materialization path for registry
   packages already (it is preferred over git archives whenever the registry
   publishes a source artifact); the failure being fixed is in the identity
   lookup, not the byte channel. An opt-in flag would preserve the outage
   for every default invocation.
3. **Automatic registry-only fallback with explicit degraded provenance.**
   Chosen.

## Decision

When the hosted-forge tag lookup fails for a *transport-level* reason —
throttling, secondary rate limits, outages, network errors — and the registry
metadata provides a checksum-verified source artifact, resolution succeeds
**registry-only** and records the degradation:

- `ResolvedPackage.degraded_provenance` carries the human-readable reason.
- `ResolvedPackage.require_full_provenance()` raises the new
  `DegradedProvenanceError`; provenance-sensitive consumers call it (or check
  the field) instead of trusting the shelf identity as a git commit.
- The shelf identity is deterministic and registry-derived:
  `registry/<package-name>` plus a 40-hex SHA-256 prefix over exactly
  `leitir-registry-only-v1 | ecosystem | name | version | algorithm |
  digest`. Two different artifacts can never share a shelf because the
  artifact digest is an input. npm scoped names flatten to one
  grammar-safe segment (`@scope/name` → `scope--name`); the shelf SHA
  still hashes the original scoped name, so flattened collisions never
  share a shelf.

  The `registry/` prefix is **not** grammatically unreserved — a hosted
  owner literally named "registry" can exist (reviewer-qwen 2026-08-23).
  Safety rests on three structural facts, not on the slug grammar: the
  degraded path never uses the hosted-repository channel; the shelf is
  disambiguated by the registry digest SHA; and every consumer that
  interprets a shelf as a git commit is gated on `source ==
  "git-commit"` / parity (index eligibility, git-parity recomputation,
  BTS, transplant), which degraded shelves structurally fail.
- Materialization proceeds through the existing artifact channel
  (checksum-verified before extraction); the hosted-repository fallback
  channel and the git-parity comparison are skipped — there is no git commit
  to bind — and the manifest records `degraded_provenance` plus
  `parity: "unknown"`.
- `TagAbsentError` is **not** fallback-eligible. A repository or tag that
  provably does not exist is a provenance fact, not an outage: the artifact
  exists but its binding provably does not, and resolution keeps failing
  closed exactly as before (this is the behavior the pre-existing test
  enforced, and it is retained).
- A package whose registry metadata publishes no checksummed artifact also
  keeps failing closed: there is nothing trustworthy to fall back to.
- **How transport-level failures are recognized (issue #248).** The primary
  signal is the typed `TagLookupUnavailableError`, raised by the real
  `GitHubTagResolver` transport — `resolve_tag_to_sha` and the annotated-tag
  dereference it calls — on retryable network exceptions and on
  `HTTPError`s that `_http.classify` maps to `RATE_LIMITED` or `TRANSIENT`
  (429, 403 with rate-limit headers, 5xx except 501, 408/425) once retries
  are exhausted. Eligibility follows exactly the line retry semantics draw
  (reviewer-hy3 round 2): a `FATAL` 4xx — 401 bad credentials, 403 without
  rate-limit headers (permission denied, SAML, IP policy), 410, 451, 400/422
  — raises a bare `ResolutionError` and keeps failing closed, because a
  permanent configuration or access fact hidden behind warning-only
  degraded provenance (e.g. an expired token degrading every resolution
  forever) is worse than a loud failure. `_degraded_reason` accepts the
  typed error plus, for the `_get_json` resolver family and test fakes, the
  legacy `"API call failed:"` message envelope. Before #248 the GitHub tag
  path raised bare, envelope-less `ResolutionError`s whose messages even
  claimed the tag was "not found", so every ADR-0023 headline scenario
  failed closed in production while fake-based tests (which injected
  hand-crafted envelope strings) stayed green. Regression coverage must
  therefore drive the **real** transport
  (`TestDegradedClassificationRealTransport`: refused connection,
  real-server 403 with rate-limit headers, real-server 503, real-server 404
  → `TagAbsentError`, fatal 401/403-plain/451/422 → fail-closed, malformed
  200 bodies → typed `ResolutionError`, and a PyPI resolution degraded end
  to end through a real local server), not a scripted tag resolver. 404 on
  the tag ref stays `TagAbsentError`/fail-closed; a 404 on the
  annotated-tag dereference stays a bare `ResolutionError` (absent data,
  not an outage); malformed 200 bodies raise typed `ResolutionError`
  (provenance fact, fail-closed), never a raw `JSONDecodeError`/`KeyError`
  leak. Forge-provided tag shas are additionally validated as 40-hex at the
  resolver boundary and normalized to lowercase — `resolve_commit_to_sha`
  parity — so a crafted non-hex or uppercase sha fails closed as typed
  `ResolutionError` before `RepoScope` ever sees it (issue #249; SHA-256
  object-format ids are not servable by github.com and fail the same gate).
- **Degradation reason strings are diagnostics, not identity** (reviewer
  round 2): `degraded_provenance` may embed wall-clock recovery timestamps
  and locale-derived errno text, so identical outages resolved at different
  times can carry different reason strings. The shelf identity remains the
  deterministic registry-digest SHA above; only the human-readable reason
  varies.
- **Crates is covered by the same fallback (owner-approved extension,
  2026-08-24).** `CratesResolver` originally shipped without a degraded
  branch; the owner approved extending the fallback after the #248 round
  made the classification contract trustworthy. crates.io publishes
  checksummed `.crate` artifacts (`version.checksum`, sha256), so the same
  rule applies: transport-level tag-lookup failure + checksummed artifact →
  registry-only degrade; absence, fatal client errors, and missing
  checksums keep failing closed. Pinned by
  `test_crates_resolution_degrades_over_real_transport` and
  `test_crates_absent_tag_still_fails_closed`.

The CLI announces the degradation on stderr before materialization
(`leitir: warning: <spec> resolved registry-only (...)`) so operators see
the weaker binding at the point of use.

## Consequences

- A GitHub outage or rate limit no longer blocks materialization of packages
  whose registries publish checksummed artifacts.
- **How full-provenance consumers are actually protected:** the production
  enforcement is structural — every path that consumes a shelf as a git
  commit is gated on `source == "git-commit"` and/or parity (index
  eligibility, git-parity recomputation, BTS donor selection, transplant),
  and degraded shelves record `source: registry-artifact` with
  `parity: unknown`, so they fail those gates by construction.
  `ResolvedPackage.require_full_provenance()` is the library-API guard
  for future direct consumers of resolution results; the degradation is
  additionally disclosed in every presentation surface: the CLI warning,
  the shelf manifest (`degraded_provenance`, empty `repo_url` — no
  fabricated github.com attribution), the corpus index entry, `info`
  provenance JSON, SBOM (no fabricated SHA1 checksum; the verified
  artifact checksum remains the anchor), and POINTERS.md ("registry
  digest … no git commit" instead of "Commit SHA").
- Shelves materialized degraded are distinct from any future fully-bound
  shelf of the same package (different slug), so a later healthy resolution
  produces a separate, fully provenance-bound shelf rather than overwriting.
- The pre-existing hard-fail test (tag absent) continues to pass unchanged;
  new tests cover the throttle, determinism, the no-artifact case, the
  marker-scope invariant, and an end-to-end degraded materialization.

## Compliance

- Deterministic: the fallback scope is a pure function of pinned registry
  inputs; no wall-clock or ordering dependence.
- Fail-closed: absent tags and artifact-less packages still reject; the
  degraded shelf never claims a git commit; `require_full_provenance()`
  converts degradation into a typed rejection.
- Atomicity and integrity channels unchanged (ADR-0004 `_write_manifest`
  pattern; checksum verification before extraction).
