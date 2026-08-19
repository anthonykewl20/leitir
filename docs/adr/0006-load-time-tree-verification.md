# ADR-0006: Load-time materialized-tree verification

- Status: accepted
- Date: 2026-08-05
- Implementation: complete
- Related: issues #17, #18, #19, #20, #39, #194; [ADR-0004](0004-local-source-materialization.md), [ADR-0018](0018-manifest-authenticity.md)

## Context

The corpus materializer authenticated downloaded archives or checked files
against a pinned Git tree before shelving them, but later cache hits trusted the
manifest's `verified` value without checking the bytes still on disk. Issue #17
added a materialized-tree digest and load-time verification, initially leaving
the field optional for a migration window. That compatibility path allowed a
verified legacy shelf to bypass the new check.

## Decision

Leitir stores a deterministic `materialized_tree_hash` in every newly written
shelf and recomputes it whenever a verified shelf is loaded. A missing,
malformed, unsupported, or mismatched digest makes the shelf a cache miss.
The anchor is mandatory for every shelf, including shelves whose upstream
verification result is false. This prevents deleting both `verified` and the
digest from downgrading a shelf out of load-time integrity checking.

The `get`, `info`, `api`, `examples`, `trust`, `sbom`, `diff`, and local-index
build/query commands
reacquire the same per-target advisory lock used by materialization, repeat
manifest and tree verification under that lock, and retain the lock through
their subsequent shelf-byte reads. `sbom` locks its deterministic index
snapshot and every referenced target; `diff` materializes first, then locks and
re-verifies both generations before comparing them. Writers publish by atomic
rename while holding the same target lock. Thus a cooperating writer cannot
replace a shelf during those command reads: the reader sees the verified
generation, or verification fails cleanly.

Local indexed search additionally requires `source == "git-commit"`,
`parity == "exact"`, and `materialized_tree_hash_scope == "full"`. Its own
versioned manifest binds the independently re-read source manifest, document
table, postings, and index bytes. Trigram postings can eliminate candidates but
cannot establish a match; the original predicates still run against locked
source bytes. Index construction is explicit, never a search-path cache repair.

The deliberate exceptions are precise. `remove` and `clean` are destructive
mutation commands, not read-and-serve operations; taking read lifetimes while
deleting the same targets would invert their operation. `export` needs a
corpus-wide immutable snapshot spanning the source index, pointers, every
target, and output construction; per-target read locks alone would overclaim
snapshot consistency, so that larger protocol is deferred. The internal
`enumerate_shelved_sources` helper returns paths to callers and cannot retain a
context-managed lock after return; callers that consume shelf bytes must own
the lock lifetime (as `sbom` now does). `lock` is a writer workflow rather than
a shelf-byte read command; each materialization and subsequent graph-manifest
update is protected by its target writer lock. `list` reads only the source
index, while `gc` and `upgrade-cache` are maintenance paths with their own
locking behavior.

The digest uses Go's directory `Hash1` (`h1:`) construction: each regular file
contributes a SHA-256 content digest, two spaces, its strict-UTF-8 POSIX path,
and a newline; sorted records are hashed with SHA-256 and standard-base64
encoded. The root `leitir-manifest.json` is excluded to avoid self-reference.

Symbolic links are records rather than followed files. Their extension is:

```
hex(sha256(linkname_bytes)) + " -> " + linkname + "  " + path + "\n"
```

Paths and link targets must be strict UTF-8 and contain no newline. Unsupported
filesystem entries fail closed. Link targets are read byte-exactly; Windows NT
substitution-path prefixes are removed before hashing so the digest represents
the requested target rather than a platform API artifact.

Archive symlink chains are also resolved lexically before extraction. An escape
is therefore rejected before filesystem mutation even on hosts whose
`realpath` or symlink-creation behavior differs from POSIX.

Full hashing is bounded by `MAX_FILES` (1,000 entries) and `MAX_BYTES` (64 MiB).
Larger trees use deterministic content-and-path ordering, greedily selecting
within both limits and always selecting at least one entry. The manifest marks
the scope as `full` or `sampled`; sampled verification is never represented as
complete.

### Amendment — full-coverage load-time verification via the per-file digest map (2026-08-19; issue #194)

The caps above bounded not only computation but *trust*: an above-cap shelf's
load-time anchor was a sampled aggregate, so most bytes on disk were
unanchored at load. Since issue #194 every newly materialized manifest also
carries `materialized_file_digests` — a flat Cargo-`.cargo-checksum.json`-style
map of strict-UTF-8 POSIX path to SHA-256 (`materialized_file_digests_algorithm`
`per-file-sha256-v1`). Values are exactly the per-entry digests the aggregate
summarizes: `sha256(content)` for regular files, `sha256(linkname_bytes)` for
symbolic links; the root manifest remains excluded. When the map is present,
`materialized_tree_hash` is recorded at scope `full` regardless of the caps —
every entry's digest enters the stored aggregate, so the stored digest is a
digest *of the map*.

Load-time verification of a map-carrying shelf (`verify_file_digest_map`,
reached through `read_valid_manifest`, `update_manifest`, and the public
`verify_materialized_integrity`) performs one streaming O(bytes) pass:
it checks the disk universe against the map (missing or unexpected entries
are named and rejected), compares every recomputed digest to the map entry
(a mismatch raises `VerificationError` naming the path — never
load-and-warn), and finally rebuilds the full-scope aggregate from the
verified map and compares it constant-time to the stored
`materialized_tree_hash`. That last step anchors the map in the existing
tree-hash chain — and transitively in the detached manifest-auth projection
(ADR-0018), which signs `materialized_tree_hash`:

- corrupt a file only → per-file mismatch;
- rewrite a map entry only → per-file mismatch;
- corrupt a file *and* rewrite its map entry consistently → the rebuilt
  aggregate no longer matches the stored anchor → reject;
- rewrite the stored aggregate only → it no longer matches the map → reject.

The authenticity residual is unchanged from this ADR's threat boundary: an
attacker able to replace the shelf *and* the whole manifest (including the
aggregate) was never in scope; signatures are ADR-0018's opt-in layer. The
map introduces no new trust root.

Legacy manifests without the map verify through the unchanged aggregate
path with their honest stored scope (`sampled` stays `sampled`);
`upgrade-cache` backfill is unchanged and does not add maps, because
striping the aggregate from a map-carrying manifest is treated as tampering
and rejected rather than backfilled. `verified: "sampled"` survives as the
*ingest-time* cross-check label only; it is never the load-time trust level
of a map-carrying shelf. The caps keep bounding ingest-time
re-enumeration heuristics (`_verify_extracted_tree`'s deterministic
sampling) and legacy aggregate scope, never load-time coverage.

Because the map lives inside the manifest, the serialized-manifest bound
grew from 1 MiB to 96 MiB (`MANIFEST_MAX_BYTES`). The arithmetic for why
that fits legitimate worst-case shelves within the archive member limit
(`ARCHIVE_MAX_MEMBERS` = 500,000): the written form
(`json.dumps(..., indent=2, sort_keys=True)`) costs each map entry
`len(path) + 76` bytes — 4 indent spaces, two path quotes, `": "`, two
digest quotes around the 64-hex SHA-256, a comma, and a newline. Fixed
overhead alone is 500,000 × 76 = 38,000,000 ≈ 36.2 MiB, leaving
100,663,296 − 38,000,000 ≈ 59.8 MiB for path bytes — an average member
path of ~125 bytes fits at the member cap, which covers real registry
shelves (npm/PyPI/crates member paths average well under that budget). A
pathological shelf whose serialized map still exceeds the bound fails at
write (`_write_manifest` refuses materialization — no mapless "full" shelf
is ever published) and is a cache miss on every bounded read, so the bound
never strands a shelf it had accepted.

## Migration

The migration progressed from optional digests in issue #17 to mandatory
digests for all shelves. Operators run `leitir upgrade-cache` to atomically
backfill eligible verified legacy shelves. The command is idempotent and
supports `--dry-run`. Normal manifest updates can attach a digest only through
the private verified-provenance backfill path. Legacy unverified shelves cannot
transfer trust this way: remove and re-materialize them. Hashing failures leave
the legacy manifest unchanged and fail the update.

### Migration trust transfer

`upgrade-cache` is a trust-on-first-use transfer from the legacy
(provenance-only) model to the new (load-time-verified) model. The command does
not re-verify shelf bytes against upstream registries: it computes the digest
from, and therefore locks, whatever bytes are currently on disk. Run it only on
a corpus whose existing contents you already trust, such as immediately after
materialization and before an external process could modify the cache. To
re-materialize a suspicious shelf instead, remove it first with `leitir
remove <spec>` and then run `leitir get <spec>`.

## Consequences and threat boundary

Load-time verification detects post-materialization corruption, accidental
edits, sync damage, and cache mutation. It is an integrity/corruption check, not
an authenticity system: an attacker able to replace both tree and manifest can
replace the digest. TUF metadata or signatures are separate authenticity work.

Every load currently incurs an I/O scan (bounded hashing work for large trees,
but directory enumeration and content-digest ordering still have costs). The
residual O(total-tree-bytes) initial scan is documented in `treehash.py`'s
module docstring; if benchmarks at production scale show this matters, a
follow-up will be filed. Map-carrying shelves verified through the map-aware
`verify_materialized_integrity` — the entry point the load gates use — take
a single O(bytes) streaming pass whose cost is linear in bytes with bounded
memory. However, ANY shelf verified through `verify_materialized_tree_hash`
*directly* incurs the historical sampled-then-forced-full double scan
whenever its stored scope is `full` but the caps make its natural computed
scope `sampled` — which includes map-carrying above-cap shelves: the first
computation reads the whole tree to derive the sampled ordering and
determines the sampled scope, and the stored-full mismatch then triggers a
second, forced-full recomputation of the same bytes. This is a performance
cost only, never a coverage or trust difference — the forced-full digest
still covers every entry — and the load gates never route a map-carrying
shelf that way.

The locks are advisory. They protect against leitir writers and other
cooperating processes, not a process that ignores the protocol and edits files
in place. The `get` command returns a filesystem path; a different process that
uses that path after leitir exits is outside the lock lifetime and must perform
its own verified/locked read. Windows and POSIX use different stdlib locking
primitives, so cross-platform interruption and network-filesystem semantics
remain platform-dependent.

Regular-file hashing opens with `os.open(..., O_NOFOLLOW)` where the platform
provides it, then verifies with `fstat()` that the descriptor is still the same
regular inode observed by `lstat()` before reading. Archive regular-file
creation likewise uses `O_EXCL`, `O_NOFOLLOW` where available, descriptor type
checking, and a post-open confinement check. On Windows, where `O_NOFOLLOW` is
not available, the existing lexical/realpath confinement checks and same-inode
`lstat`/`fstat` comparison remain; a hostile non-cooperating process can still
race path components around opens, so that platform residual is explicitly
accepted.
