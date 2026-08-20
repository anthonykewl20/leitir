# ADR-0022: Trusted-key lifecycle — expiry and revocation in a versioned trusted-keys schema

- Status: Accepted
- Implementation: complete
- Deciders: leitir maintainers (schema shape per the #207 Decision field: objective-level shape ratified 2026-08-18; exact serialization proposed here, frozen by the owner's merge of #207's PR)
- Date: 2026-08-20
- Technical Story: [#207 — Trusted-key lifecycle: expiry + revocation in a versioned trusted-keys schema, with rotation ceremony doc](https://github.com/anthonykewl20/leitir/issues/207)

## Context and Problem Statement

ADR-0018 trusts an out-of-band `trusted-keys.json` whose closed v1 shape is
`{"keys": [{"key_id", "public_key_b64", "note"}]}`. That schema has no
lifecycle: no expiry, no revocation, no in-band "retired" versus "compromised"
distinction. Rotation is a manual file edit, and an old key remains fully valid
until physically deleted from the file — deletion being indistinguishable from
never-having-existed. Any real key event (scheduled rotation or compromise)
currently has no safe in-band procedure.

## Decision Drivers

- Fail-closed: expired, revoked, malformed, or unknown-version key data must reject with typed errors, never silently accept.
- v1 backcompat: existing trusted-keys files must load unchanged, and `_KEY_FIELDS` strictness for v1 files must not weaken.
- The evidence trail matters: a retired or compromised key should remain visible in the file while being refused for authentication (deleting it destroys the audit trail).
- Determinism: comparisons must be injectable-clock driven, boundary-explicit, and PYTHONHASHSEED-independent.
- Stdlib-only runtime; the cryptography provider stays an optional extra.
- Schema evolution must be additive and versioned so older readers fail closed on newer files instead of half-parsing them.

## Considered Options

- Keep v1 and manage lifecycle purely operationally (delete rows during rotation).
- Per-key `schema_version` markers inside one file.
- A per-file `schema_version: 2` marker with optional per-key lifecycle fields.
- TUF-style key IDs with built-in rotation metadata and threshold signatures.

## Decision Outcome

Chosen option: "per-file `schema_version: 2` marker with optional per-key
lifecycle fields", because it keeps one unambiguous schema per file (mixed
v1/v2 rows are malformed), stays additive to the v1 shape, and expresses the
lifecycle in the smallest auditable surface. Threshold/multi-sig schemes are a
larger design and remain a possible follow-up.

### Schema (v2), as proposed by #207 and frozen by the owner's merge

```json
{
  "schema_version": 2,
  "keys": [
    {"key_id": "…sha256-hex…", "public_key_b64": "…", "note": "ceremony note",
     "expires_at": "2030-01-01T00:00:00Z"},
    {"key_id": "…", "public_key_b64": "…", "note": "superseded 2026-08",
     "revoked_at": "2026-08-01T12:00:00Z", "revocation_reason": "key-compromise"}
  ]
}
```

- A file **without** `schema_version` is v1 and must contain only v1 rows —
  a v1 row carrying any lifecycle field is malformed (one schema per file).
- A file **with** `schema_version` must declare exactly the integer `2`;
  any other value (other integers, strings, floats, booleans, `null`) is a
  typed malformed rejection. Future versions bump this integer.
- v2 rows must contain `key_id`, `public_key_b64`, and `note`, plus **at most**
  the lifecycle fields `expires_at`, `revoked_at`, `revocation_reason`.
  Unknown fields reject.
- Timestamps are strict RFC-3339 UTC — exactly `YYYY-MM-DDTHH:MM:SSZ`:
  real calendar instants, no offsets, no fractional seconds, no epoch
  numbers. Optional-ness is expressed by omitting the field; a `null` value
  is malformed. ISO-8601 text (not epoch) is chosen because the file is a
  human-audited ceremony artifact.
- `revoked_at` and `revocation_reason` must appear together; the reason is
  non-empty ASCII text (a reason-less revocation is malformed).
- `expires_at` and `revoked_at` may coexist on one key (retired, then later
  compromised): both facts are kept.

### Semantics

- **Boundary:** a key is valid strictly **before** its timestamp — expired
  when `now >= expires_at`, revoked when `now >= revoked_at`. The boundary
  instant itself is already invalid. When both apply, **revocation wins**
  (compromise is the stronger claim) and the refusal surfaces the reason.
- **Clock:** `load_trusted_keys(…, clock=…)` reads one injectable
  `Callable[[], datetime]` (UTC now when omitted) **once per load**, only
  when the file actually declares lifecycle timestamps — v1 files never read
  a clock. Naive (timezone-unaware) clock results are a typed malformed
  failure, never a silent local-time comparison. Lifecycle is evaluated once
  at load; the loaded registry is authoritative for the process invocation.
- **Load:** expired/revoked keys are excluded from the active mapping (the
  returned `TrustedKeys` is a `dict[str, bytes]` of active keys only, so all
  existing consumers and equalities are unchanged) but retained in its
  lifecycle table. A file whose keys are **all** expired/revoked fails closed
  with `ManifestAuthNoKeysError` — no fallback to anonymous acceptance.
- **Verify:** authorization records naming an expired or revoked key are
  refused with the distinct typed errors `ManifestAuthKeyExpiredError`
  (`manifest_auth_key_expired_v1`) and `ManifestAuthKeyRevokedError`
  (`manifest_auth_key_revoked_v1`, revocation reason surfaced); unknown key
  IDs keep `ManifestAuthUnknownKeyError`. Distinctness matters
  operationally: expiry says "rotate", revocation says "incident".

### Rotation ceremonies

Both ceremonies change only the trusted-keys file; committed production key
artifacts are owner-ceremony-gated and never touched by implementers.

- **Retire (scheduled rotation, the `expires_at` path):**
  1. Generate the successor key and add it to the file alongside the
     incumbent; set the incumbent's `expires_at` to the cutover instant.
  2. Sign new material with the successor; the incumbent stays verifiable
     until the boundary instant, then refuses with
     `ManifestAuthKeyExpiredError`.
  3. After cutover, the expired row **stays in the file** (with its
     `note`) as the evidence trail of when it was retired; it is never
     valid again regardless of file edits short of removing the timestamp.
- **Compromise (incident, the `revoked_at` path):**
  1. Immediately set `revoked_at` to the incident instant (UTC) and a
     `revocation_reason` that names the incident class (e.g.
     `key-compromise`).
  2. From that instant the key refuses with
     `ManifestAuthKeyRevokedError` and the reason; material signed by it
     fails closed everywhere.
  3. The revoked row stays in the file permanently as incident evidence;
     never delete it to "clean up" — deletion is exactly the
     indistinguishable-from-never-existed failure this schema removes.
- Evidence trail per ceremony: the trusted-keys file history (reviewed like
  code) is the ledger of who was trusted, from when, until when, and why a
  key left. Ad-hoc manual deletions are not a documented path.

### Positive Consequences

- Rotation and incident response have safe, in-band, auditable procedures.
- Expired/revoked keys remain listed (evidence) yet are cryptographically
  refused (safety) — no forced deletion.
- v1 files, callers, and golden vectors are untouched.

### Negative Consequences

- The trusted-keys file gains fields operators must understand; the ceremony
  docs and README section are therefore part of this change.
- Lifecycle truth freezes at load time; a long-lived process does not
  re-evaluate expiry mid-invocation (irrelevant for the CLI's one-shot
  invocation model, documented here as the boundary).

## Pros and Cons of the Options

### Keep v1 and manage lifecycle operationally

- Good, because nothing changes.
- Bad, because rotation stays a hand-edit with no trail, and deletion remains
  indistinguishable from never-having-existed — the audited operational risk.

### Per-key schema_version markers

- Good, because migration could be row-by-row.
- Bad, because mixed rows in one file are ambiguous and exactly what must be
  malformed; a file-level schema is a single total statement.

### TUF-style rotation metadata and thresholds

- Good, because battle-tested.
- Bad, because threshold/multi-sig is a bigger design explicitly out of
  scope for #207; revisit as a follow-up if multi-signer trust is needed.

## Links

- [ADR-0018 — Manifest authenticity](0018-manifest-authenticity.md)
- [#207 — Trusted-key lifecycle](https://github.com/anthonykewl20/leitir/issues/207)
- [ADR-0020 — Go module authenticity via SumDB](0020-go-module-authenticity-via-sumdb.md)
