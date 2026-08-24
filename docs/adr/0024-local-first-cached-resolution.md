# ADR-0024: Local-first resolution for exact ecosystem pins

- Status: Accepted
- Date: 2026-08-23
- Issue: [#245](https://github.com/anthonykewl20/leitir/issues/245)

## Context

Real-data E2E (2026-08-23) showed that spec commands (get, info, api,
examples, diff) always performed live registry resolution before
consulting the corpus, so an exact pin such as pypi:flask@3.0.3 failed
with a transport error during a registry outage even though the
checksum-verified shelf was already on disk. That contradicts the corpus
contract — pin once, cite forever, network-free — and made the
highest-frequency commands depend on registry availability for bytes
already shelved and load-time verified.

Materialization already had offline cache-hit paths for both channels,
but they were unreachable offline because resolution never got that far.

## Decision

Exact ecosystem pins (pypi/npm/crates with an explicit version) resolve
local-first:

1. Before any network lookup, the corpus index (sources.json) is
   consulted for shelved entries matching the spec's name and host.
2. Each candidate shelf must pass read_valid_manifest — the same full
   per-file tree-hash verification every load performs. A shelf that
   fails verification is skipped (never served) and the next candidate,
   then live resolution, is tried.
3. A verified manifest binds the pin only when its ecosystem, version,
   and source (registry-artifact or git-commit) match the spec exactly,
   AND the manifest's own recorded spec string (written at
   materialization from the verified resolution, e.g.
   pypi:flask@3.0.3) confirms the requested name and ecosystem. The
   unanchored sources.json name alone never binds identity: a one-field
   index edit must not relabel a shelved package. A recorded name field,
   where present, must agree as well.
4. ArtifactInfo algorithm/digest are reconstructed from the anchored
   checksum mirroring the live registry conventions in parity exactly:
   PyPI/crates sha256 with 64 lowercase hex chars, and npm sha512 where
   the digest is the base64-decoded bytes as hex — never the raw base64
   token, matching what the live npm path stores. Empty, malformed
   (non-hex, undecodable, wrong length), or unrecognized formats reject
   the candidate — fail-closed.
5. Index entries whose path escapes the corpus root (absolute or
   parent-relative) are never read — the same confinement rule as every
   other index consumer.
6. Candidate order prefers full-provenance shelves: the ADR-0023
   degraded owner is literally registry, which sorts before most real
   owners, so a degraded shelf must not shadow a coexisting
   full-provenance shelf for the same pin.
7. Any manifest shape that cannot reconstruct a valid package
   (non-HTTPS registry URL, non-HTTP docs URLs, unsafe subpath,
   tag/degraded invariants, malformed checksum) skips that candidate via
   ValueError containment — the shelf is never served and the error
   never escapes as a hard failure; live fallback is unchanged.
8. On miss, ambiguity that cannot verify, or any unsupported shelf
   shape, resolution falls back to the live registry path unchanged.

Floating/latest specs (no explicit version) always resolve live: the
notion of latest is a registry question and must not be frozen into a
stale cache answer. Go module-zip shelves stay on the live path for now
(proxy URL reconstruction is a separate change).

diff re-resolves each side internally for identity metadata; the CLI
now serves that re-resolution from the resolutions it just computed and
materialized (a cached-first facade over the live resolver), which both
keeps diff offline-capable and removes mid-run resolution drift
between the materialized bytes and the reported identity.

Both paths share the degraded-resolution announce, so a registry-only
(degraded, ADR-0023) shelf announces its missing repository tag binding
identically whether it was resolved live or from cache. The cached path
additionally announces that it resolved offline from the corpus index —
the cache is never silent.

## Consequences

- Spec commands answer exact pins fully offline once the shelf exists;
  the 2026-08-23 E2E matrix (get/info/api/examples/diff on real
  flask/zod shelves with dead registry base URLs) passes end to end.
- A tampered shelf is never served: tree-hash verification fails, the
  candidate is skipped, and offline the command fails closed while
  online it self-heals by re-materializing from the pinned source.
- Serving from cache is not a trust downgrade: the shelf was admitted
  through the same checksum-pinned materialization as a live fetch, and
  load-time verification re-runs on every read.
- The reconstructed ArtifactInfo carries the anchored checksum, so a
  later artifact fetch still verifies against the registry digest; a
  vanished shelf fails the artifact fetch closed.
- An offline get may perform the one-time license refresh the online
  cache-hit path already performs; pinned identity fields (commit,
  version, checksum, source, tag) are asserted unchanged and the second
  read is idempotent (pinned by tests).
- version_source gains the value cached-shelf (detection source
  corpus-index) for these resolutions.

## Known limitations

- The reconstructed ArtifactInfo.url is the registry project page
  (manifests persist registry_url, not the tarball URL). A re-fetch
  after the shelf vanished mid-run therefore fails closed with a
  checksum mismatch rather than a clean 404; recording the artifact URL
  at materialization time is a future improvement.
- Name matching is exact: pypi:Flask@3.0.2 does not match a shelf
  shelved as flask (registry-side normalization is not applied
  offline); such pins fall back to live resolution.
- leitir lock still resolves lockfile pins through the live resolver;
  extending local-first to lock_project is a follow-up (tracked in
  #245).
