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
Unverified shelves may omit the digest.

The shared `get`/`info`/`api`/`examples` read-and-serve path reacquires the same
per-target advisory lock used by materialization, repeats manifest and tree
verification under that lock, and retains the lock through its subsequent
reads. Writers publish by atomic rename while holding that lock. Thus a
cooperating writer cannot replace a shelf during those command reads: the
reader sees the verified generation, or verification fails cleanly.

Other corpus operations do not currently share that lock lifetime. In
particular, `trust`, `sbom`, `diff`, `lock`, `remove`, `clean`, `export`, and
internal source enumeration may read or mutate shelf-related bytes without
holding each target lock continuously from verification through consumption.
They retain a residual cooperating-writer TOCTOU surface; this ADR does not
claim issue #39's lock binding for those paths.

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
digests for verified shelves in issue #18. Operators run `leitir upgrade-cache`
to atomically backfill verified legacy shelves. The command is idempotent and
supports `--dry-run`. Normal manifest updates also opportunistically attach a
digest when the existing legacy provenance passes its non-tree-hash checks.
Hashing failures leave the legacy manifest unchanged and emit a warning.

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

Path confinement and pre-open `lstat()` checks reject known symlinks, but the
tree hasher's path-based regular-file open can still race a non-cooperating
attacker that swaps an entry after the check. Closing that final window needs
an fd-relative `open`/`fstat` implementation in `treehash.py` (with
`O_NOFOLLOW` where available); it is not provided by the CLI locking change.
