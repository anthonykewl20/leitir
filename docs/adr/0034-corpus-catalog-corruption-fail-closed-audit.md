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
raises a `RuntimeWarning` before returning `[]`. The corrupt file itself is
also left on disk, untouched, rather than renamed to `sources.json.bak` --
see "Superseded" below for why the original design renamed it, why that
was wrong, and why leaving it in place is what actually makes corruption
detectable by every later reader, not just the current process. Each
caller was then judged individually:

| Caller (file:function) | Command(s) | Corrupt catalog would otherwise produce | Adopted |
|---|---|---|---|
| `corpus._upsert` | every `get`/`lock`/`diff` materialize | **Destructive**: silently rewrites the index to contain only the one entry being upserted, discarding every previously catalogued source while their shelves remain on disk | `strict=True` |
| `corpus.remove_source` | `remove` | **Destructive**: `regenerate_pointers` would rewrite `POINTERS.md` as if the corpus were empty; reordered to validate the catalog *before* deleting the target shelf bytes | `strict=True`, and read moved before the delete |
| `corpus.enumerate_shelved_sources` → `snapshot.export_corpus` | `export` | **False success**: an immutable, successful-looking snapshot asserting zero sources, replayable later via `import` | `strict=True` |
| `corpus.enumerate_shelved_sources` → `sbom._packages` | `sbom` | **False success**: an SBOM asserting the corpus has zero packages | `strict=True` |
| `cli._corpus_list`'s direct `load_sources` (the `sbom` command's own pre-lock read) | `sbom` | Same false-success SBOM if left non-strict: a corrupt catalog would read back as `[]` and the command would proceed as though the corpus were empty before ever reaching `sbom._packages`. Must be strict, and specifically the *first* read of the invocation, so nothing downstream is built from an already-laundered empty result | `strict=True` |
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
| `index.query.IndexedSearcher._shelves` | `search --use-index`/`--require-index` for one scoped `--repo`/`--package` (never `--corpus`) | Neither false success nor destructive (found by independent review, added here): an empty result under `--require-index` already raises `VerificationError("required index does not cover declared scope")`; under plain `--use-index` it falls back to a full, correct, non-indexed scan of the exact pinned commit tree straight from disk (not through the catalog) with `incomplete=True` honestly reported, downgrading `coverage.status` away from `COMPLETE_FOR_DECLARED_UNIVERSE`. The actual search results are complete and correct either way | Left non-strict, documented |
| `_gc_abandoned_staging` (the `gc` CLI command) | `gc` | **No dependency**: `gc` never calls `load_sources` at all -- it walks `<root>/repos` on disk for `.tmp-`/`.old-` staging and backup directories under target locks. The issue's opening sad-path list named `gc` as a suspected destructive caller ("`gc` over an empty catalog may be actively dangerous depending on what it considers unreferenced"); verified false on inspection of the actual command, not merely left silent | N/A -- no catalog read to make strict |

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

- `get`/`install`/`lock`/`diff` now fail an entire materialize when the
  catalog is corrupt, rather than degrading. This is the intended blast
  radius: a write that cannot see the corpus's existing state must not
  proceed as if it saw an empty one. See "Recovery" below: this is not a
  dead end for the user.
- A corrupt catalog no longer self-heals on the next command the way it
  used to (see "Superseded" below): the corrupt `sources.json` now stays on
  disk, corrupt, until a human (or a script following the recovery
  guidance) explicitly moves it aside. This is a deliberate trade: the old
  automatic self-heal was also the mechanism that laundered corruption into
  an honest-looking absence for a later reader, which is the defect this
  ADR exists to close.

## Superseded: the ordering gap between a non-strict and a strict read

An earlier revision of this ADR described the following as a "known,
accepted gap", out of scope for this issue:

> A non-strict `load_sources` call that runs *before* a strict one in the
> same process (e.g. `_resolve_from_cached_shelf` during ecosystem-spec
> resolution for `remove`) will already have performed the `.bak` rename
> and returned `[]`. The later strict call then reads a genuinely missing
> file (`FileNotFoundError`), which is defined -- correctly, per this
> issue's explicit sad-path requirement -- as always benign, even under
> `strict`. In that narrow interleaving the corruption is laundered into
> an honest-looking absence for the rest of that single invocation.

Independent review of PR #276 reproduced this with real materialized
shelves through the ordinary, primary path the issue is about: `leitir get
pypi:<pin>` (equally `diff`/`remove`/`check` for any pinned `pypi:`/`npm:`/
`crates:` spec). `_resolve_from_cached_shelf` runs first, is non-strict by
design (see its row in the audit table -- a best-effort local-cache
shortcut with a safe live-resolution fallback), and on a corrupt catalog
performed the `.bak` rename and returned no candidates. The subsequent
`materialize_source` call reaches `corpus._upsert`'s `strict=True` read,
which -- before either fix described below -- saw a plain
`FileNotFoundError` and proceeded exactly as if the corpus had always been
empty, defeating the destructive-write protection this ADR's whole table
exists to provide. This was not a rare edge case: it is the normal shape of
the `get` command for any pinned ecosystem spec, i.e. the primary path
issue #268 is about. The prior framing understated this, and is corrected
here rather than left standing.

### First fix attempted, and why it did not close the gap

An earlier revision of this PR closed the single-process reproduction above
with a process-lifetime memo, `_observed_corrupt_roots: set[Path]`,
populated the moment *any* `load_sources` call (strict or not) for a given
corpus root hit the corrupt-catalog exception branch. A `strict=True` call
that then encountered `FileNotFoundError` for a root already in that set
refused to treat it as honest-empty. This ADR previously stated, of that
design:

> A root that was never observed corrupt in the current process is
> completely unaffected -- `FileNotFoundError` still means honest-empty
> there, exactly as required by this issue's sad path. The two states
> ("genuinely never existed" vs. "existed, was corrupt, and something
> upstream in this same run already recovered from it") are kept distinct
> by construction: only the second is remembered, and only for the process
> that observed it.

That claim -- that the memo closed the gap -- was wrong, and a second round
of independent review (same PR) demonstrated it directly: `leitir` is a
`console_scripts` entry point, so every command a user runs is its own
fresh interpreter. The memo is a bare module-level `set()`, populated in
memory and discarded the instant the process exits -- which is to say,
discarded after *every single CLI invocation*. The review ran the identical
scenario as two genuinely separate Python processes against the same
on-disk state process 1 had left behind (`sources.json` gone, renamed to
`sources.json.bak` by process 1's own non-strict cache-shortcut read):
process 2, a fresh interpreter with an empty `_observed_corrupt_roots`,
saw a plain missing file, correctly-by-its-own-logic treated it as honest
empty, and silently rewrote `sources.json` to contain only its own new
entry -- discarding the catalog entries for the shelves process 1 had
already materialized, whose bytes remained on disk, now uncatalogued. This
is exactly the "**Destructive**: silently rewrites the index to contain
only the new entry" row the audit table exists to prevent, reached in two
ordinary, unremarkable commands (a retry, or simply a different pinned
spec run afterward) -- no race or adversary required. The memo narrowed the
vulnerability window from "any two `load_sources` calls" to "any two
`load_sources` calls sharing one OS process", which does not describe how
the tool is actually invoked. **A regression test built from two `main()`
calls inside one pytest test function cannot detect this**, because pytest
itself is one process and so shares the same memo the production defect
does -- which is why the original regression test for this gap passed while
the gap remained open.

### The actual fix: stop renaming, don't try to remember

The root cause the memo worked around, rather than removed, is that **the
non-strict path's silent rename is what converts "corrupt" into "absent"**
on disk. Once that rename happens, the only true statement left on the
filesystem is "no catalog here" -- indistinguishable from a corpus that
never had one. No amount of in-memory bookkeeping can survive that,
because the bookkeeping and the destroyed evidence live in different
places with different lifetimes (memory vs. disk, one process vs. every
process to come).

The fix actually adopted: **`load_sources`'s non-strict path no longer
renames the corrupt file at all.** It still returns `[]` for that one call
(unchanged behavior for every existing non-strict caller) and still raises
the `RuntimeWarning`, but the corrupt `sources.json` is left on disk,
byte-for-byte, under its original name. Every subsequent read of that
root -- by the same call site retried, by a different caller in the same
process, or by an entirely fresh process -- parses the same bytes and
re-detects the same corruption honestly, strict or not, with no memo of
any kind. `_observed_corrupt_roots` is removed entirely; there is nothing
left for it to compensate for.

This also resolves `FileNotFoundError`'s status cleanly: it is *unconditionally*
an honest empty corpus now, `strict` or not, with no memoized-root
exception carved out of that rule -- because a non-strict read can no
longer manufacture a `FileNotFoundError` out of a corrupt file. The
"genuinely never existed" and "existed, was corrupt" cases stay distinct
by construction, without runtime state: the former has no `sources.json`
at all; the latter still does, and it still fails to parse.

Of the options considered for closing this gap -- (a) the process-lifetime
memo above (superseded), (b) keeping the rename but writing a *durable*
(on-disk) corruption signal with a defined writer/clearer/lifecycle that
every strict caller consults, (c) not renaming on the non-strict path at
all -- **(c) was chosen**. It is the smallest change (removes code and
state rather than adding more), and it removes the laundering class at its
source instead of building a second detection mechanism to guard against
it. (b) was rejected: the "Negative Consequences" section already recorded
that a stale `.bak` file can legitimately outlive its corruption (`clean`
unlinks `sources.json` but not `sources.json.bak`), which is precisely why
reusing `.bak` itself as a durable signal is unsound -- and a *new*,
purpose-built durable marker (a sentinel file, a timestamp, a lock) would
need its own writer, its own clearing rule, and its own interaction with
`clean`, adding a second piece of on-disk state to reason about for no
benefit over simply not destroying the first piece of on-disk state that
already told the truth. (a) is documented above for the record, but no
longer describes the shipped behavior.

Regression tests:
- `tests/test_load_sources_strict_callers.py::test_upsert_protection_survives_laundering_through_the_ordinary_get_cli_path`
  drives the real `get` CLI command end to end (real HTTP-served tarball
  via `routed_server`, no injected fakes for `load_sources`) with a real,
  previously-materialized shelf, a corrupted catalog, and a second `get` of
  the same pinned spec, within a single process -- confirming the fix holds
  even without the memo.
- `tests/test_load_sources_strict_callers.py::test_three_successive_processes_never_launder_a_corrupt_catalog`
  is the test the P1 review explicitly required and the one that would have
  caught the original gap: it drives the real installed `leitir` console
  script as three genuinely separate `subprocess.run` invocations (not
  three `main()` calls in one pytest process) against the same on-disk
  corpus root -- two ordinary `get`s that each materialize a real shelf,
  then a corrupted catalog, then a third `get` for an unrelated pinned
  spec -- and asserts the third process fails closed, the corrupt catalog
  bytes are never silently overwritten (no rename to `.bak`, no rebuild
  containing only the third spec), and both earlier shelves' materialized
  bytes are still present on disk.

## Recovery when a strict caller rejects a corrupt catalog

Before this change, a corrupt catalog self-healed on the very next command:
`load_sources`'s non-strict path renamed it to `sources.json.bak` and
returned `[]`, so `get` (for example) would just quietly rebuild the
catalog from scratch. That automatic self-heal is exactly the mechanism
the "Superseded" section above identifies as the root cause of the
laundering gap, so it is gone: no command performs it as a side effect
any more, non-strict or otherwise. Making the write path (`_upsert`) and
the other adopted callers `strict=True`, combined with removing the
automatic rename, means a corrupt catalog no longer self-heals at all --
but a fail-closed path with no stated way out is a bricked tool, not a
safety improvement. The `VerificationError` raised by `load_sources(...,
strict=True)` therefore now names, in the message itself:

1. The exact corrupt file path and the corpus root.
2. That a backup of `sources.json`, if the user has one, can simply be
   restored in place -- the fastest, least lossy recovery.
3. The concrete manual step otherwise: move the corrupt file aside
   yourself (the message gives the literal command, e.g. `mv sources.json
   sources.json.bak`), which resets the catalog to empty; then re-run
   `leitir get <spec>` for each previously-catalogued source to re-add it
   to the rebuilt catalog. This is now a deliberate, explicit user action
   rather than something any command does automatically as a side effect
   of an unrelated read -- that automaticity is what made the corruption
   launderable in the first place.
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
- `tests/test_load_sources_strict_callers.py` (per-caller regressions,
  `test_strict_verification_error_names_recovery_path`, and
  `test_three_successive_processes_never_launder_a_corrupt_catalog`, the
  three-genuinely-separate-processes regression required by the second
  round of independent review)
- `tests/test_materialize_e2e.py::test_corrupt_index_fails_closed_instead_of_silently_rebuilding` (the amended write-path contract)
- `tests/test_materialize_e2e.py::test_structurally_corrupt_index_reads_empty_without_being_renamed_away` (the amended non-strict-read contract: no `.bak` rename)
