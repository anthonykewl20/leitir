# Fail-closed catalog reads: a per-caller audit of `load_sources`'s corruption recovery

- Status: Accepted
- Deciders: anthonykewl20
- Date: 2026-08-27
- Technical Story: issue #268 (follow-on from issue #266 / PR #267)

## Context and Problem Statement

`leitir.corpus.load_sources` reads the corpus catalog (`sources.json`). When
the file is corrupt or unreadable (garbage bytes, truncated JSON, entries
that fail schema validation), the historical behavior is to back the bad
file up to `sources.json.bak` and return `[]` -- silently treating "the
catalog could not be established" as "the corpus is empty". PR #267 gave
`load_sources` a `strict: bool = False` parameter and adopted `strict=True`
for exactly one caller: the corpus-wide search eligibility path
(`index.query._corpus_eligibility`), because a corrupt catalog there
produced a live, reproduced falsification -- `search --corpus` reported
`corpus_status: complete_for_declared_universe` with zero matches while two
real, untouched shelves sat on disk.

`load_sources` also backs `list`, `export`, `sbom`, `snapshot`/`import`,
`doctor`, `diff`, `docpointers`, the trigram index builder, and the
corpus-write path (`materialize` → `_upsert`) used by every `get`/`install`.
Whether the same silent-recovery-as-empty behavior is safe on each of those
paths had never been individually judged; issue #268 required that audit.

## Decision Drivers

- A corrupt catalog must never yield an artefact (SBOM, export snapshot)
  that positively asserts the corpus is complete or empty.
- A corrupt catalog must never let a corpus-wide write (`_upsert`, `remove`)
  silently act as if the corpus held nothing, discarding or overwriting
  real catalog state while real shelf bytes remain on disk.
- `FileNotFoundError` (no catalog has ever existed) must remain a distinct,
  always-benign case, `strict` or not: absence is not corruption.
- The `.bak` rename by itself is not a sufficient record that something
  went wrong on a path that still reports success.
- Blast radius: converting every caller to `strict=True` unconditionally
  would turn benign, already-safe recovery (e.g. `list` returning an empty
  list for a human to investigate) into a hard failure with no comparable
  safety benefit.

## Considered Options

- **A: Make `strict=True` the default for everyone.** Simplest, but
  contradicts the "benign empty is sometimes correct" case explicitly
  called out in issue #268 (`list`), and would have to special-case every
  caller that already tolerates an empty result by design (fallback
  lookups, best-effort refreshes).
- **B: Per-caller judgment**, adopting `strict=True` only where a corrupt
  catalog would otherwise be indistinguishable from a genuine "false
  success" or would drive a destructive filesystem action, and leaving
  everywhere else non-strict with a documented reason and a universal
  non-strict-path warning.
- **C: Leave `load_sources` alone and push detection into each caller.**
  Rejected: duplicates the corruption test in every caller and is exactly
  the kind of inconsistency this audit exists to remove.

## Decision Outcome

Chosen option: **B**. `load_sources`'s non-strict recovery path now always
raises a `RuntimeWarning` before returning `[]`, so the `.bak` rename is
never the *only* record of corruption on any path, strict or not (issue
#268's explicit requirement). Each caller was then judged individually:

| Caller (file:function) | Command(s) | Corrupt catalog would otherwise produce | Adopted |
|---|---|---|---|
| `corpus._upsert` | every `get`/`lock`/`diff` materialize | **Destructive**: silently rewrites the index to contain only the one entry being upserted, discarding every previously catalogued source while their shelves remain on disk | `strict=True` |
| `corpus.remove_source` | `remove` | **Destructive**: `regenerate_pointers` would rewrite `POINTERS.md` as if the corpus were empty; reordered to validate the catalog *before* deleting the target shelf bytes | `strict=True`, and read moved before the delete |
| `corpus.enumerate_shelved_sources` → `snapshot.export_corpus` | `export` | **False success**: an immutable, successful-looking snapshot asserting zero sources, replayable later via `import` | `strict=True` |
| `corpus.enumerate_shelved_sources` → `sbom._packages` | `sbom` | **False success**: an SBOM asserting the corpus has zero packages | `strict=True` |
| `cli._corpus_list`'s direct `load_sources` (the `sbom` command's own pre-lock read) | `sbom` | Same false-success SBOM; additionally, if left non-strict here specifically, the rename would happen on this first read and the second (lock-verification) read would then see `FileNotFoundError` and pass an unchanged-index check, laundering the corruption into a silent pass even with `sbom._packages` fixed | `strict=True` |
| `cli._require_all_shelves_authenticated` | `export`, `sbom`, `index` with `--require-manifest-auth` | **False success**: zero iterations reads as "every shelf is authenticated" (vacuously true) | `strict=True` |
| `doctor.check_registered_shelves` | `doctor` | **False success**: reports `pass: no registered corpus entries` instead of catching exactly the corruption doctor exists to catch; already wrapped in `except Exception` that reports `status: error`, so this was a one-line change | `strict=True` |
| `cli._corpus_list` (the `list` command itself) | `list` | Benign: an empty list is what a human reads and investigates next; nothing downstream asserts completeness or acts destructively | Left non-strict, documented at the call site |
| `cli._resolve_from_cached_shelf` | local-cache-first resolution shortcut inside `get`/`remove`/etc. | Benign: falls back to live resolution exactly as a genuine cache miss would; never reports a cache hit it doesn't have | Left non-strict, documented |
| `cli._corpus_routings` | `search` (non-corpus) rendering | Benign: falls back to the already fail-closed "license-undetermined" routing | Left non-strict, documented |
| `diff._matching_entry` | `diff` | Benign: only supplies an optional catalog-recorded pin for bytes already materialized by this same invocation; `_shelf_pin` falls back to the scope that fed the materializer | Left non-strict, documented |
| `docpointers.regenerate_pointers`'s own internal load (`entries=None`) | `api`/`get`/`info` cache-refresh | Benign in practice: the one entry being refreshed was already found via a load of the same catalog moments earlier in the same command; a corrupt catalog would already have failed the command first | Left non-strict, documented |
| `corpus.find_materialized_sources` (backing `record_trust`, `info._source`) | `trust`, `get`, `info`, `api`, `examples` | Neither false success nor destructive: both callers already raise `ValueError("source is not materialized")` on an empty result, so the command fails either way -- just with a misleading stated reason under corruption | Left non-strict, documented |
| `index.builder.shelves_from_corpus` (as called by the `index` command) | `index` | Neither: `if not shelves: raise ValueError(...)` already turns an empty result into a failure; only the error message is misleading under corruption | Left non-strict, documented (the same helper already forwards `strict` for `index.query`'s adoption) |
| `index.query._corpus_eligibility` | `search --corpus` | Already fixed by PR #267 | Unchanged (`strict=True`) |

### Positive Consequences

- Every corpus-wide artefact-producing or corpus-wide-write command now
  fails closed on a corrupt catalog instead of a false success.
- The non-strict paths are each backed by a stated, call-site reason rather
  than inherited default behavior -- "silence is a decision, not an
  inheritance" per the issue's acceptance criteria.
- `load_sources`'s `RuntimeWarning` gives even the deliberately-benign
  paths (e.g. `list`) a second, independent record of corruption beyond the
  `.bak` file.

### Negative Consequences

- **Known, accepted gap**: a non-strict `load_sources` call that runs
  *before* a strict one in the same process (e.g. `_resolve_from_cached_shelf`
  during ecosystem-spec resolution for `remove`) will already have
  performed the `.bak` rename and returned `[]`. The later strict call then
  reads a genuinely missing file (`FileNotFoundError`), which is defined --
  correctly, per this issue's explicit sad-path requirement -- as always
  benign, even under `strict`. In that narrow interleaving the corruption
  is laundered into an honest-looking absence for the rest of that single
  invocation. This is not silent: the `RuntimeWarning` from the first read
  and the `sources.json.bak` file are still both left behind. Fully closing
  this gap would require a corpus-root-scoped "already observed corrupt in
  this process" memo, which is a materially larger change than "adopt
  `strict` per caller" and is out of this issue's scope.
- `get`/`install`/`lock`/`diff` now fail an entire materialize when the
  catalog is corrupt, rather than degrading. This is the intended blast
  radius: a write that cannot see the corpus's existing state must not
  proceed as if it saw an empty one. See "Recovery" below: this is not a
  dead end for the user.

## Recovery when a strict caller rejects a corrupt catalog

Before this change, a corrupt catalog self-healed on the very next command:
`load_sources`'s non-strict path renamed it to `sources.json.bak` and
returned `[]`, so `get` (for example) would just quietly rebuild the
catalog from scratch. Making the write path (`_upsert`) and the other
adopted callers `strict=True` removes that self-heal for them by design --
but a fail-closed path with no stated way out is a bricked tool, not a
safety improvement. The `VerificationError` raised by `load_sources(...,
strict=True)` therefore now names, in the message itself:

1. The exact corrupt file path and the corpus root.
2. That a backup of `sources.json`, if the user has one, can simply be
   restored in place -- the fastest, least lossy recovery.
3. The concrete self-heal step otherwise: run any non-strict command (the
   message suggests `leitir list --root <root>`) once. That performs the
   same `.bak` rename and empty-catalog reset that used to happen
   automatically, after which `leitir get <spec>` re-run for each
   previously-catalogued source re-adds it to the freshly rebuilt catalog.
4. That the materialized shelf bytes under `<root>/repos` were never
   touched by this failure -- only the catalog's *record* of them was
   unreadable, not the bytes themselves.

This keeps the fail-closed behavior (a corrupt catalog is never silently
treated as authoritative for a write or an artefact) while making the
degradation recoverable rather than a dead end. Pinned by
`test_strict_verification_error_names_recovery_path` in
`tests/test_load_sources_strict_callers.py`.

## Amended contract: the write-path self-heal test

`tests/test_materialize_e2e.py::test_corrupt_index_is_backed_up_and_rebuilt`
predates this issue and pinned exactly the behavior issue #268 reports as
the bug on the write path. Quoting the contract it pinned, in full, before
this change:

```python
def test_corrupt_index_is_backed_up_and_rebuilt(tmp_path):
    tmp_path.joinpath("sources.json").write_text("not json")
    with scripted_server([(200, {}, _tarball())]) as server:
        _add(tmp_path, server)

    assert (tmp_path / "sources.json.bak").read_text() == "not json"
    assert len(load_sources(tmp_path)) == 1
```

That is: materializing a new source against a corrupt catalog silently
backed up the corrupt file and proceeded as if the corpus held nothing but
the one source just materialized -- the exact "destructive false success"
this ADR's audit adopts `strict=True` for in `corpus._upsert` (see the
table above). The test was not exercising some other, acceptable
degradation; it was asserting the specific silent-recovery-on-write
behavior that is the defect.

**Decision**: this contract is consciously amended, not weakened. The test
is renamed to `test_corrupt_index_fails_closed_instead_of_silently_rebuilding`
and now asserts the opposite: `_add` (which calls `materialize_source` ->
`_upsert`) raises `VerificationError`, the corrupt `sources.json` is left
exactly as it was (no `.bak` rename -- under `strict`, the rename that used
to signal "silent recovery happened" never happens, because there was no
silent recovery), and the new source was not added. This is reviewable
without reading the diff: the old contract asserted `_upsert` self-heals a
corrupt catalog and treats it as empty; the new contract asserts `_upsert`
refuses to write against a catalog it cannot read, and directs the caller
to the recovery path above instead.

## Links

- Issue #268
- Issue #266, PR #267 (the corpus-search precedent this audit follows)
- `src/leitir/corpus.py` (`load_sources`, `_upsert`, `remove_source`, `enumerate_shelved_sources`, `find_materialized_sources`)
- `tests/test_load_sources_strict_callers.py` (per-caller regressions and `test_strict_verification_error_names_recovery_path`)
- `tests/test_materialize_e2e.py::test_corrupt_index_fails_closed_instead_of_silently_rebuilding` (the amended write-path contract)
