# ADR-0018: Manifest authenticity

- Status: Accepted
- Scope: v2.0 implementation landed
- Deciders: leitir maintainers; consensus reviewers; consensus-terra review 2026-08-13 (ACCEPT-WITH-AMENDMENTS — recommendation recorded, adoption deferred)
- Date: 2026-08-13
- Technical Story: #40 — Verify manifest publisher authenticity

## Context and Problem Statement

Tree and packet digests detect corruption and bind records to content, but do not
authenticate the repository owner or publisher. A party able to replace source
and expected digests can produce internally consistent malicious artifacts. This
ADR records the consensus recommendation and its v2.0 implementation.

## Decision Drivers

- Authorization must bind immutable repository and tree identity.
- Mutable cache observations cannot be part of the signed object.
- Trust roots must not come from attacker-controlled corpus content.
- Required-auth mode must never downgrade to unsigned operation.
- `dependencies = []` remains literal for the default runtime.

## Considered Options

- Sign the complete mutable `leitir-manifest.json`.
- Discover keys from the shelf, sidecar, remote, or first use.
- Implement TUF, in-toto, or cosign keyless verification in v2.0.
- Provide opt-in detached Ed25519 authorization over a closed projection through
  an exact hash-locked `auth` extra (consensus recommendation).

## Decision Outcome

Decision: "`leitir-manifest-auth-v1`, opt-in detached Ed25519 over a
canonical authorization projection with an out-of-band trust root", because it
adds explicit publisher authorization without signing mutable local observations
or pretending content hashes authenticate an owner.

### Implementation notes

- `cryptography==50.0.0` is the optional `auth` extra. `requirements-auth.lock`
  contains all 45 PyPI cryptography wheel hashes (no sdist hashes) and the
  hash-pinned CPython 3.14 Linux x86_64 transitive wheel closure; install it
  only with `--require-hashes --only-binary :all:`. Other provider platforms
  currently fail closed at installation until their transitive wheel closure is
  release-reviewed, and the PyPI metadata must be re-reviewed before regeneration.
- Detached records are shelf-adjacent as
  `<commit>.leitir-manifest-auth.json`, rather than in the shelf. This is the
  necessary layout deviation from the illustrative in-shelf path: current tree
  hashing includes all shelf files other than the manifest, so an in-shelf
  detached signature would recursively invalidate its own signed tree digest.
  Trust roots are external `trusted-keys.json` files with the closed shape
  `{"keys":[{"key_id":"...", "public_key_b64":"...", "note":"..."}]}`;
  the default path is
  `~/.leitir/trusted-keys.json`, overridable by `--trusted-keys`.
- `--require-manifest-auth` is implemented for `get`, `info`, and `diff`; these
  command paths load-time verify the tree before authenticating the detached
  record. Golden vectors are in `tests/fixtures/manifest_auth/vectors.json`.
- The key-ceremony helper derives its record `key_id` as SHA-256 of raw public
  key bytes. Verification still selects only the exact configured key ID.

### 1. Optional dependency boundary

The implementation recommendation uses an optional `auth` extra containing an
exact version and hash-locked `cryptography` distribution, installed with
`--require-hashes`, following ADR-0012's controlled-extra precedent. The base
project keeps `dependencies = []` literally and importing Leitir without the
extra must not import or probe the provider.

Python 3.13 and 3.14's documented standard-library **Cryptographic Services**
chapter contains only `hashlib`, `hmac`, and `secrets`; it exposes no Ed25519 or
RSA-PSS signing API. This was verified against `docs.python.org`, so stdlib-only
signature verification is not claimed and a home-grown implementation is
forbidden.

### 2. Signed authorization projection

The signed object is not the mutable manifest bytes. It is canonical, closed
schema `leitir-manifest-auth-v1` authorization projection binding:

- repository `host`, `owner`, `repo`, and immutable `commit_sha`;
- source kind (exactly the authorized immutable source form); and
- `materialized_tree_hash` algorithm, scope, and digest.

The projection excludes volatile local observations such as `fetched_at`,
`verified_at`, and `trust`. It also excludes sidecars, which remain outside the
materialized tree hash. Unknown projection fields, duplicate JSON keys, Unicode
or identity aliases, malformed hashes/signatures, and noncanonical encoding
reject.

Signing the manifest bytes is rejected because `update_manifest` atomically
merges fields and cache-hit paths rewrite `leitir-manifest.json`
(`materialize.py:244-263,1174-1180`). A byte signature would either be invalidated
by legitimate local state changes or invite a dangerous signature-bypass path.
The closed projection instead remains stable exactly while the authorizing
source and tree identity remain stable.

Detached authorization records bind projection schema, canonical projection
digest, algorithm exactly `ed25519`, key ID, signature bytes in one canonical
encoding, and authorization-record schema. The verifier reconstructs the
projection from the loaded manifest and verified tree; it never trusts a
sidecar-supplied projection as an alternate subject.

### 3. Out-of-band trust root and fail-closed mode

The trust root is strictly out of band: user-controlled configuration or an
explicit CLI input outside the corpus root. It is never discovered from a shelf,
manifest, sidecar, repository remote, downloaded key URL, or first-use prompt.
TOFU here would accept an attacker-controlled source and key together and is
therefore not authentication.

When authentication is required, all of the following reject closed: absent
`auth` extra, absent trust root, malformed authorization payload, unknown key,
invalid signature, host/owner/repo/commit/source-kind identity mismatch, and
tree-hash algorithm/scope/digest mismatch. Auth-required mode never warns and
falls back to unsigned. Key selection is exact by configured key ID; manifest or
remote key material cannot extend the trusted set.

Unsigned default behavior remains the existing corruption-detection model. It
must continue to say that ADR-0006/0011 digests establish integrity and subject
binding, not authenticity. Bundles and archives are outside this ADR's scope;
ADR-0011 section 8 remains controlling, and its detached archive hash remains
non-authorizing.

### 4. Explicit non-goals and evaluated systems

This narrowly scoped recommendation does not provide TUF roles, thresholds,
expiry, rollback/freshness protection, or mix-and-match defenses.

- **TUF v1.0.32:** rejected for this v2.0 scope because delegated roles,
  thresholds, expiry, snapshot, and rollback metadata solve a larger repository
  update system than one shelf authorization.
- **in-toto v1.0.0:** rejected because supply-chain step/link attestations and
  layout verification exceed the source-owner authorization question.
- **cosign keyless:** rejected because OIDC identity, transparency-log inclusion,
  and online ecosystem policy add services and trust semantics not required by
  this detached offline-capable design.

These systems remain candidates for later freshness, delegation, threshold, or
supply-chain work. This ADR must not imply Ed25519 alone supplies those properties.

### 5. Documentation requirement

At implementation—not now—the README `Honesty` section must include this marker
text:

> **Manifest authenticity is opt-in.** By default, Leitir verifies content
> integrity and subject binding only; it does not authenticate a repository owner
> or publisher. `--require-manifest-auth` requires the separately installed,
> hash-locked `auth` extra and an explicitly configured out-of-band trust root,
> and fails closed rather than accepting unsigned or untrusted manifests.

CLI help and errors must preserve the same distinction and must not call an
unsigned shelf "trusted" or "authenticated".

### 6. Residual risks and implementation gate

- A previously valid signed shelf can be replayed; this profile has no freshness
  or rollback protection.
- Key theft authorizes manifests until out-of-band rotation removes that key.
- Loss of the sole private key blocks new authorizations. Implementation requires
  an encrypted offline backup and a documented, tested recovery ceremony.
- Trust-root configuration custody is security-critical; compromise or mistaken
  replacement authorizes an attacker.

If adopted at v2.0 planning, tests must cover exact projection vectors, mutation
of every bound field, mutation of excluded observations, unknown keys, missing
extra/root/signature, malformed and noncanonical encodings, tree substitution,
no unsigned fallback, hash-seed independence, and independently generated
Ed25519 vectors. Dependency lock hashes and supported-provider versions require
release review.

### Positive Consequences

- Publisher authorization is explicit and separable from mutable cache state.
- Default installations retain no third-party runtime dependency.
- Trust cannot bootstrap from the artifact it is supposed to authenticate.

### Negative Consequences

- The proposal does not prevent replay, key theft, or stale valid content.
- Users opting in must secure keys, trust-root configuration, and recovery media.
- A cryptographic provider becomes part of the optional trusted computing base.

## Amendment (2026-08-23): enforcement surface and the unsigned-mode boundary

The production-readiness audit found that `--require-manifest-auth` existed
only on `get`, `info`, and `diff`, so a "signed shelves only" policy could not
actually be enforced: the same shelves could be consulted through `fetch`, `list`,
`api`, `examples`, `trust`, `sbom`, `export`, `index`, `bts-compute`, and
`bts-run` with no authenticated path. The flag and its `--trusted-keys`
companion are now available and enforced on all of those commands —
spec-based commands verify the shelves they touch, and corpus-wide commands
(`list`, `index`, `sbom`, `export`, `trust`) verify every shelved source
before producing output.

The unsigned-mode boundary is unchanged and remains a documented limitation
rather than a claim: without publisher signatures, file *contents* stay
protected by the load-time tree verification (ADR-0006), but displayed
metadata — `registry_url`, source names, trust fields, and other manifest
strings that are not covered by `materialized_tree_hash` — can be edited
undetected by whoever controls the local storage. Authenticating displayed
provenance requires opting in to manifest auth (or a future projection that
covers those fields); agents and automation must not treat unsigned-mode
metadata displays as tamper-evident.

## Links

- [#40 — Manifest authenticity](https://github.com/anthonykewl20/leitir/issues/40)
- [ADR-0006 — Load-time tree verification](0006-load-time-tree-verification.md)
- [ADR-0011 — Reuse packet and attribution](0011-reuse-packet-and-attribution.md)
- [ADR-0012 — Polyglot graph via tree-sitter](0012-polyglot-graph-via-tree-sitter.md)
- [Python 3.14 Cryptographic Services](https://docs.python.org/3.14/library/crypto.html)

API evidence integrity (issue #310): `info` derives signatures from the verified source under its shelf lock and compares derived cache content before reuse. Altered cache entries are rebuilt; unchanged cache files are not rewritten. Publisher manifest authentication does not authenticate independently mutable API-cache JSON. No cache-local checksum substitutes for verified source evidence.
