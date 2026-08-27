# Corpus Cache Operations

This runbook covers backup, restore, cleanup, and recovery for a Leitir corpus
cache. It describes the current corpus implementation, not the retired v1
prototype.

## Cache Location And Layout

Leitir resolves the corpus root in this order:

1. An explicit `--root <root>` argument.
2. `LEITIR_HOME` when set.
3. `~/.leitir` by default.

The main materialized-source layout is:

```text
<root>/
  repos/<host>/<owner>/<repo>/<commit-sha>/
    leitir-manifest.json
    ...materialized source files...
  sources.json
  .leitir-pointers.json
  .locks/<hashed-target>.lock
```

`repos/<host>/<owner>/<repo>/<commit-sha>/` is the canonical shelf path for a
pinned hosted repository. The manifest identifies the source and contains the
`materialized_tree_hash` integrity anchor. Registry-artifact shelves use the
same repository shelf layout. Leitir also maintains optional `api/` and
`examples/` cache trees under the root.

`.locks` contains per-target lock files used while materializing and cleaning
staging generations. Do not delete it blindly: it is part of the coordination
mechanism, and lock paths are opened without following symlinks.

## Optional Manifest Authentication Keys

The optional `leitir[auth]` extra verifies detached Ed25519 manifest records
only when a caller supplies `--require-manifest-auth`. Configure trusted public
keys out of band at `~/.leitir/trusted-keys.json` (or pass
`--trusted-keys /secure/trusted-keys.json`); the file is a canonical JSON key
set whose entries contain `key_id`, `public_key_b64`, and a human `note`.
Keep it under normal configuration-management access control, not in an
untrusted corpus. Authentication does not replace the mandatory
`materialized_tree_hash` check: an unsigned, malformed, unknown-key, projection
mismatch, or bad signature rejects when authentication is required.

## Backup

Export a complete immutable snapshot from the source corpus:

```bash
leitir export --root "$LEITIR_HOME" -o /secure/backups/corpus-2026-08-09.lock
```

If `LEITIR_HOME` is unset, use the actual root explicitly, for example
`--root "$HOME/.leitir"`. `-o`/`--output` names the lock file; when omitted,
it defaults to `corpus.lock` in the current working directory. Export writes
an adjacent gzip tarball with the same basename, such as
`corpus-2026-08-09.tar.gz` (or `corpus.tar.gz` when `-o` is omitted), and
prints JSON containing the lock path, tarball path, and `lock_sha256`.

Record the printed `lock_sha256`. Back up both the exact lock file and its
adjacent snapshot tarball as one set. The lock binds the snapshot contents and
records the tarball's `tarball_sha256`; do not rename one without preserving
the lock's adjacent tarball name, and do not edit either file.

The lock and tarball should be copied to durable storage using the storage
system's normal integrity and retention controls. A filesystem copy of the
live cache is not a substitute for an export: it can capture an in-progress
materialization.

## Restore

Restore into a new or empty destination corpus. Supply the trusted digest from
the backup record, not a digest calculated from an untrusted lock received with
the backup:

```bash
leitir import /secure/backups/corpus-2026-08-09.lock \
  --lock-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --root /srv/leitir-restored
```

`--lock-sha256` is required and must be 64 lowercase hexadecimal characters.
Import first verifies the lock digest, snapshot format, tarball digest, pointer
metadata, every source manifest, and every source tree hash. It rejects the
operation before installing sources if any check fails.

The destination must be an ordinary empty directory, or not exist. Import
builds a verified temporary corpus beside the destination, flushes files and
directories, and atomically installs it with `os.replace`. A failed import
removes its temporary install. It never merges into a non-empty destination.

After restore, verify that normal commands can load the corpus, for example:

```bash
leitir list --root /srv/leitir-restored
LEITIR_HOME=/srv/leitir-restored leitir doctor --no-network
```

The imported corpus is the destination selected by `--root`; it does not
change `LEITIR_HOME` for later commands.

## Cleanup And Disk Space

Run garbage collection for abandoned materialization generations:

```bash
leitir gc --root "$HOME/.leitir"
```

`gc` reports JSON with the root and number removed. It removes repository-level
`.<commit-sha>.tmp-*` staging directories and obsolete
`.<commit-sha>.old-*` backup generations. It holds the corresponding target lock while
deciding what to remove. If an interrupted publish left both `.tmp-` staging
and `.old-` backup generations while the target is absent, one `gc` invocation
first removes staging and then restores the sole intact, load-time-verified
backup. A corrupt backup is never restored.

To empty a corpus using the supported command:

```bash
LEITIR_HOME="$HOME/.leitir" leitir clean
```

`clean` removes `repos/`, `api/`, and `examples/`, plus `sources.json` and
`.leitir-pointers.json`. It intentionally does not remove `.locks`. Recreate
the corpus with `leitir get`, `leitir lock`, or import a snapshot.

Safe manual deletion is limited to a separately retained backup copy or files
you have positively identified as outside the active corpus. Never manually
delete `.locks`, active shelf directories, manifests, `sources.json`, or
`.leitir-pointers.json` as a cleanup shortcut. Never follow symlinks while
inspecting or deleting cache content; Leitir rejects symlink escapes and unsafe
staging candidates.

## Interrupted Or Corrupted Materialization

Materialization writes a complete staged tree and manifest, then installs it
with an atomic rename. A failed operation normally removes its staging tree;
an abrupt process termination can leave `.tmp-*` staging or `.old-*` backup
directories. Run `leitir gc --root <root>` once to clean abandoned staging and
restore a sole valid old generation when appropriate.

On corpus load, every shelf's `materialized_tree_hash` is recomputed and
compared with its manifest. Missing, malformed, unsupported, or mismatched
integrity data is rejected closed, so corrupted or downgraded shelf metadata is
not served. Do not calculate a new digest over a suspicious shelf as a
repair. Remove and re-materialize it instead:

```bash
LEITIR_HOME=<root> leitir remove github:owner/repo@<commit-sha>
leitir get github:owner/repo@<commit-sha> --root <root>
leitir gc --root <root>
```

Use the exact supported corpus spec for the source being repaired. For a
trusted legacy verified shelf that only lacks the load-time digest, use
`leitir upgrade-cache --root <root>`; this computes the digest from current
bytes, so it is appropriate only when those bytes are already trusted. Legacy
unverified shelves without a digest must be removed and re-materialized.

Target locks use normalized filesystem paths. Hosted repository aliases that
differ only by letter case are deduplicated before materialization; on
case-insensitive platforms the lock identity is case-normalized as well, so
aliases cannot enter the same target concurrently.

### Tampered Shelf Bytes: Online Self-Heal, Offline Fail-Closed

What tamper detection covers: at load time every shelf's `materialized_tree_hash`
is recomputed from the bytes currently on disk and compared against the
manifest's anchor; manifests written since issue #194 additionally carry a
flat per-file `materialized_file_digests` map that is checked file-by-file
against that anchor in one streaming pass. Editing, deleting, or adding a
single file inside a shelf is detected. This covers file *contents* only —
manifest metadata fields the digest does not cover (`registry_url`, trust
fields, and similar strings) are not tamper-evident unless
`--require-manifest-auth` is used; see "Optional Manifest Authentication
Keys" above.

A shelf that fails this check is never returned as a usable cache hit. The
internal read function (`read_valid_manifest`) treats it identically to a
shelf that was never materialized: it logs `leitir WARNING
leitir.materialize: load-time integrity verification failed for <path>` to
stderr (visible by default; log level is WARNING unless `--quiet` or a
different `LEITIR_LOG_LEVEL` is configured) and returns as if nothing were
cached there. What happens next depends on what the caller does with that
"nothing cached" result and whether the origin is reachable:

- **Materializing commands** (`get`, `info`, `fetch`, `api`, `examples`,
  `diff`, `lock`, and other commands that shelve a source): since the
  failed-verification shelf reads as absent, materialization proceeds
  exactly as it would for a first-time fetch — it re-downloads from the
  pinned commit/tarball/artifact, re-extracts, and atomically installs the
  freshly re-verified tree over the corrupted one, via the same staging
  directory + rename used for any normal materialization. The command exits
  0 with ordinary success output; nothing in that output states that the
  shelf was corrupted and replaced, only the WARNING line above does. This
  is intentional rather than incidental: ADR-0024 ("Local-First Cached
  Resolution") names it as a direct consequence of the "a tampered shelf is
  never served" rule — online, "skip this unverifiable shelf" and "cache
  miss" are the same code path, so the normal fetch logic re-materializes it
  without a separate healing step being written.
- **Read-only scoped search over an already-materialized corpus**
  (`leitir search`, `ScopedSearcher`): the same failed verification also
  makes the shelf unusable for local reads, but search does not rewrite
  anything on disk. It falls back, per scope, to reading blobs live from the
  host's tree/blob API for that one search, leaving the corrupted local
  copy in place. Because nothing is repaired, an offline-first search
  workflow will keep re-verifying the same shelf against the network on
  every run until it is actually re-materialized (see below).
- **Offline, or the origin otherwise unreachable:** the same
  failed-verification-as-absent path is taken, but the follow-up fetch then
  fails too — a transport error from the archive download, or (for the
  scoped-search fallback, or extracted-tree re-verification) a
  `TreeReadError` such as `GitHub API call failed: ...`. This surfaces as a
  generic top-level error — `leitir: error: <message>` on stderr and a
  non-zero exit (`CORPUS_FAILURE` or `INFRASTRUCTURE_FAILURE`, i.e. 1 or 3
  depending on the command) — that names the transport failure, not the
  fact that the local shelf was corrupted. A user who only reads that final
  line has no direct indication the problem is their corpus rather than
  their network; the actual signal is the `load-time integrity verification
  failed for <path>` WARNING logged just above it.

If you hit the offline rejection:

1. Look for the `leitir WARNING leitir.materialize: load-time integrity
   verification failed for <path>` line above the final error. Its presence
   confirms local corruption rather than an ordinary outage.
2. Restore connectivity to the origin (GitHub, GitLab, the package
   registry, etc.) and retry the same command; a failed-verification shelf
   is re-fetched transparently once materialization can reach the origin
   again.
3. If connectivity cannot be restored, do not hand-patch or recompute a
   digest over the shelf as a repair (`leitir upgrade-cache` recomputes a
   digest from current bytes and is only for already-trusted legacy caches,
   never for a shelf that just failed verification). Follow "Interrupted Or
   Corrupted Materialization" above once the origin is reachable, or restore
   the shelf from a trusted `leitir export` backup instead.

## Worked Backup And Restore

The following example uses explicit roots so it is independent of shell
environment:

```bash
leitir get github:octocat/Hello-World@<40-char-commit-sha> \
  --root /var/lib/leitir
leitir export --root /var/lib/leitir \
  -o /var/backups/leitir/corpus-2026-08-09.lock
# Save the emitted lock_sha256 with the backup record.
leitir import /var/backups/leitir/corpus-2026-08-09.lock \
  --lock-sha256 <saved-64-char-lowercase-lock-digest> \
  --root /var/lib/leitir-restored
leitir list --root /var/lib/leitir-restored
```

The export's `corpus-2026-08-09.tar.gz` must remain next to the lock during
import. Replace the placeholders with the real 40-character commit SHA and
the digest printed by export.
