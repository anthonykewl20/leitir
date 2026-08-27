# Warm process mode (#272): test plan

Companion to [ADR-0035](../adr/0035-warm-process-invalidation-contract.md) and
`warm-mode-premise-2026-08-27.md`. Written for whoever implements #272 after
#271 lands. Nothing here is implemented yet; this states what the tests must
prove and how to make them offline and deterministic per `docs/testing.md`.

## 1. The load-bearing tamper test

This is the acceptance criterion the issue names explicitly: "a tampered
shelf is still never served, in warm mode, proven by a tamper test that
mutates bytes after the warm process has already verified and cached that
shelf."

### Probe (docs/testing.md step 1)

Before writing the test, reproduce it by hand against the real
implementation once it exists:

1. Materialize a small real shelf into a temp corpus root (a scripted local
   HTTP server per `tests/test_corpus_cli_e2e.py`'s pattern — no live
   network).
2. Start a warm session/handle against that corpus root (the #271-provided
   in-process entry point).
3. Touch the shelf once (e.g. an in-process `info` or `search` call) so the
   session's per-shelf cache is populated and the warm process's own
   verification has run and returned success.
4. **Without going through leitir** — directly via `Path.write_bytes` /
   `os.utime` on a regular file inside the shelf, or by editing a
   `materialized_file_digests` entry in the manifest, or by mutating a
   symlink target — mutate one byte inside the shelf on disk. This must be a
   filesystem-level mutation outside leitir's protocol, since that is the
   uncooperating-process threat ADR-0006 and ADR-0035 describe. Record
   exactly what was mutated (a single file's content, vs. the manifest's
   `materialized_tree_hash`, vs. a `materialized_file_digests` entry) as
   separate probe cases — they exercise different code paths in
   `verify_file_digest_map`/`verify_materialized_tree_hash`.
5. Touch the *same shelf* again through the same warm session, using the
   same handle, without restarting the process.
6. Record what is actually returned: does the second touch serve the
   pre-mutation cached content, the mutated bytes, or a rejection? This is
   the probe's evidence — it answers "what does the current implementation
   actually do," which the red test in step 2 then pins as the desired
   behavior if it isn't already correct.

### Red / Green (docs/testing.md steps 2-3)

Assert, through the public in-process API (not a private cache attribute):

- The second touch must reject — either an exception matching leitir's
  existing `VerificationError`/`MaterializationError` taxonomy, or (for a CLI-
  facing contract) the same exit tier and stderr shape a cold invocation
  produces for a tampered shelf today. It must **not** return the shelf's
  content, cached or fresh.
- The rejection must happen regardless of whether step 4's mutation was to a
  regular file's bytes, a symlink target, an entry in
  `materialized_file_digests`, or the top-level `materialized_tree_hash`
  itself — one test case per mutation kind, matching the existing
  `verify_file_digest_map` mismatch cases ADR-0006's amendment documents
  (corrupt file only; rewrite map entry only; corrupt file *and* map entry
  consistently, which must still be caught by the aggregate mismatch;
  rewrite the aggregate only).
- Assert this holds under **both** invalidation triggers from ADR-0035's
  contract, as separate test cases:
  - **Lock-release path**: the warm session releases and reacquires the
    per-target lock between the first and second touch (simulating two
    separate tool calls in the same agent task) — the mandatory re-verify
    must fire and catch the mutation.
  - **Continuous-lock path**: if the implementation's session model allows a
    single held-lock interval to span multiple logical touches (e.g. a
    caller batches two operations on the same shelf without releasing), the
    tamper must still be introduced *before* the lock is first acquired by
    the warm session for that interval — the test should confirm the design
    does not claim to catch mutation injected *during* a continuously-held
    lock by an uncooperating process (that residual is explicitly accepted
    in ADR-0035 §4 and must not be misrepresented as covered).
- A third variant: verify a *different, untouched* shelf's cached state is
  unaffected by another shelf's tamper — invalidation must be per-shelf, not
  a blanket cache flush that could mask a bug where the wrong shelf's
  verification result is being reused.
- A fourth variant covering the "must not serve even if it succeeded
  earlier in the same session" sad path explicitly: verify the shelf once
  (success, cached), tamper it, force a re-verify that fails, then attempt a
  *third* touch in the same session without any further mutation — confirm
  the third touch still fails (the failure itself must be sticky for that
  shelf within the session, not just the one call that observed it) per
  ADR-0035 §5.

### Determinism

Run the tamper test under `PYTHONHASHSEED=0,1,42` per `docs/testing.md` —
rejection must be exit-code- and message-identical across seeds, since
nothing about which byte was mutated or which path was walked should depend
on hash order.

## 2. Fallback tests (fail-closed on warm-state failure)

- Simulate the warm session failing to establish (e.g. the corpus root
  becomes unwritable/unlockable when the session tries its own bookkeeping,
  or the #271 in-process handle raises during construction). Assert the
  caller falls back to a full cold-path call with byte-identical output to
  today's cold `leitir` invocation for the same inputs — never a degraded or
  unverified fast path. Compare against literally running the existing cold
  code path in the same test for the same fixture, so the assertion is "same
  output as cold," not a hand-maintained golden string that could drift.
- Simulate a lock acquisition failure mid-session (another process holds the
  lock). Assert the warm session's behavior matches whatever the cold path
  already does under lock contention (existing tests in
  `tests/test_corpus_cli_e2e.py` likely already cover the cold contention
  behavior — the warm session must not introduce a new, different outcome).

## 3. Cold-path parity tests

- For a representative set of commands (`info`, `get`, `search --corpus`,
  `api`, `diff`), run each once via the cold path and once via a warm
  session's first touch (which should itself do full cold-equivalent
  verification), and assert byte-identical stdout/stderr/exit-code/JSON.
  This is the "cold-path behaviour... stays byte-identical" acceptance
  criterion — test it directly, not by inference from other tests passing.
- Run the same pair under `PYTHONHASHSEED=0,1,42`.

## 4. Honest before/after latency measurement methodology

The issue requires *measured* numbers, never a claimed speedup that wasn't
measured. For whoever implements #272:

1. **Fixture, not production `~/.leitir`.** Build a deterministic, scripted
   local corpus (reusing `tests/test_corpus_cli_e2e.py`'s local-HTTP-server
   materialization pattern) with a stated, fixed shelf count and total byte
   size — e.g. 20 shelves, ~5MB each — committed as a benchmark fixture, not
   measured against a developer's real `~/.leitir` (which drifts over time
   and isn't reproducible in CI). Report the fixture's exact shape (shelf
   count, total files, total bytes) alongside every number, the same way
   this ADR's premise report states "160 entries / 119 shelves" rather than
   just "a corpus."
2. **Sequence, not a single call.** Measure a realistic multi-call sequence
   matching the issue's stated usage pattern — "ten to twenty consultations
   in a single task" — e.g. `info` once, then `search --corpus` three times
   with different predicates touching overlapping shelves, then `api` twice.
   A single before/after call comparison understates warm mode's benefit
   (most of the win is on the *second and later* touch of a given shelf) and
   overstates it if only repeat-heavy sequences are measured — report both a
   worst case (every call touches a disjoint shelf, no reuse) and a realistic
   case (shelves reused across calls) explicitly labeled as such.
3. **Report wall-clock and call-count**, not a synthetic FLOPS/throughput
   number: total wall-clock for the sequence, cold-path total vs. warm-path
   total, and how many of the N calls in the sequence were "warm hits"
   (reused a still-valid cached verification) vs. "warm misses" (paid full
   verification anyway, e.g. first touch or post-lock-release re-verify).
   State the OS page cache state explicitly (cold vs. warm), the same way
   `warm-mode-premise-2026-08-27.md` reports both, since page cache state
   alone produced roughly a 2x swing in this ADR's premise measurements —
   conflating that with warm mode's own effect would misattribute the win.
4. **Run in CI-representative conditions** (the same machine class / container
   the actual test suite runs in, not a developer laptop), and note if this
   is impractical to gate in CI (multi-second-plus timing assertions are
   usually excluded from strict CI gates); if so, keep the measurement as a
   documented benchmark script (see `benchmarks/` for the existing pattern)
   whose *output* is checked into evidence, not as a pass/fail CI assertion
   on absolute latency.
5. **State the null result plainly if warm mode doesn't help for some
   command shape** — e.g. if a session with no shelf reuse shows no
   improvement (expected, per ADR-0035's Negative Consequences), report that
   explicitly rather than cherry-picking only the repeat-heavy sequence.
