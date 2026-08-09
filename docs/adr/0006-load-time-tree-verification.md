# ADR-0006: Load-time materialized-tree verification

- Status: accepted
- Date: 2026-08-05
- Implementation: complete
- Related: issues #17, #18, #19, #20, #39; [ADR-0004](0004-local-source-materialization.md)

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

The `get`, `info`, `api`, `examples`, `trust`, `sbom`, and `diff` commands
reacquire the same per-target advisory lock used by materialization, repeat
manifest and tree verification under that lock, and retain the lock through
their subsequent shelf-byte reads. `sbom` locks its deterministic index
snapshot and every referenced target; `diff` materializes first, then locks and
re-verifies both generations before comparing them. Writers publish by atomic
rename while holding the same target lock. Thus a cooperating writer cannot
replace a shelf during those command reads: the reader sees the verified
generation, or verification fails cleanly.

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
follow-up will be filed.

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
