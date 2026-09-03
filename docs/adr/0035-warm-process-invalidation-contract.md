# ADR-0035: Warm process mode — the invalidation contract for verified state held in memory

- Status: accepted (amended 2026-09-03 — owner decision on issue #272)
- Deciders: anthonykewl20
- Date: 2026-08-27 (amendment 2026-09-03)
- Implementation: complete (option (b) epoch contract; issue #272)
- Related: issue #272 (A5, split out of #266; owner decision 2026-09-03: option (b)),
  issue #282 (writer staging race — landed via PR #286 before this contract was built on the read path),
  issue #271 (C4, callable Python API — blocking dependency),
  issue #279 (a distinct, cold-path defect this ADR's own measurement uncovered: `info`/`get`/`api`/`examples`/`trust`
  pay O(catalog) re-verification to resolve a single-shelf spec, with no warm process involved — see the framing note below),
  [ADR-0006](0006-load-time-tree-verification.md) (load-time tree verification),
  [ADR-0018](0018-manifest-authenticity.md) (manifest authenticity),
  `docs/evidence/warm-mode-premise-2026-08-27.md` (measured premise report backing this decision)

## Context and Problem Statement

Every `leitir` invocation is a cold Python process. `docs/evidence/warm-mode-premise-2026-08-27.md`
measured this against a real ~120-160-shelf corpus and found that interpreter
startup and import cost (~100ms) are negligible; the dominant, repeated cost
(routinely tens of seconds per invocation on a realistic corpus) is full
load-time re-verification of `materialized_tree_hash` / the per-file digest
map (ADR-0006) across every shelf a spec resolution or search touches — and,
worse than issue #272's framing suggested, this fan-out is not confined to
`search --corpus`: **any** spec-resolving command (`info`, `get`, `api`,
`examples`, `trust`, `diff`, ...) re-verifies the *entire* catalog via
`corpus.enumerate_shelved_sources`/`find_materialized_sources` before
narrowing to the shelf(s) the spec names. `mcp/bridge.py` pays this cost on
every tool call because it shells out to a fresh `python -m leitir.cli`
subprocess per call, with no in-process entry point available (that gap is
issue #271).

That O(catalog) re-verification-per-call cost is filed and tracked
separately as **issue #279**, because it is a cold-path defect that exists
today with no warm process anywhere in the picture — a single-shelf `info`
call pays it on the very first, uncached invocation, which no amount of
warm-mode caching changes for that first call. It directly contradicts the
premise ADR-0031's advisory-lane split and #266 A2's `info --brief`
recommendation are built on: that these are the *cheap* verbs an agent
calls freely and often. Warm mode (this ADR) and issue #279 are related but
distinct: #279 is about not doing O(catalog) work *within one call* in the
first place; this ADR is about not repeating O(one-shelf) verification
*across calls* within a session once #279's fix (or the unfixed status quo)
has produced a verified result. A warm-mode cache built only on top of
today's `find_materialized_sources` would still pay #279's full-catalog
cost on every session's first touch of any spec; fixing #279 shrinks what
this ADR's session cache needs to hold, but does not remove the need for
it — repeated touches of the *same* shelf across a session still benefit
from not re-verifying every time, even once #279 makes a single touch
verify only the shelves it needs.

*(Update 2026-08-30, issue #279 fix: `find_materialized_sources` now resolves
candidate identity against the catalog entries and pays
`read_valid_manifest`/ADR-0006 verification only for candidates, so a
single-shelf spec no longer re-verifies the catalog on first touch — measured
107.7s → 2.0s on the real corpus, `docs/evidence/single-shelf-resolution-2026-08-30.md`.
This ADR's contract is unchanged and still needed: first-touch of each shelf
still verifies it in full, and *repeat* touches within a session are what
this ADR's per-shelf memoization addresses.)*

A warm process — one that stays alive across an agent's ten-to-twenty
consultations in a single task and avoids repeating this work — is an
obvious answer to the latency problem. It is also, if built carelessly, a
direct threat to the security property ADR-0006 established: that a
tampered shelf is never served. The honest design question this ADR exists
to answer is not "should there be a cache" but **what invalidates verified
state held in memory, and can we state the residual TOCTOU window precisely
enough to accept it.**

This ADR decides the invalidation contract. It does not implement warm mode.
Issue #272 depends on #271 (no callable Python API exists yet — the only
entry point is a subprocess boundary), so implementation is deferred until
#271 lands; this ADR is written now so #271's API shape can be designed with
warm mode's needs in view.

## Decision Drivers

- ADR-0006's guarantee — a tampered shelf is never served — is a security
  property, not a performance target, and must survive warm mode unweakened.
- The measured cost (Finding 2) is dominated by catalog-wide re-verification
  during spec resolution, not by search's fan-out alone. Caching must
  therefore cover the catalog-enumeration path, not only per-scope search
  state, or most of the win is left on the table.
- `AGENTS.md`'s non-negotiables: fail-closed, stdlib-only, deterministic
  across `PYTHONHASHSEED`, no disabling of load-time tree verification.
- The issue's explicit sad paths: cached verified state must never outlive
  evidence the underlying bytes changed; a shelf whose verification failed
  must never be served even if it succeeded earlier in the same session;
  failure to establish warm state must fall back to cold, never to an
  unverified fast path.

## Considered Options

*Amendment note (2026-09-03):* the original §2 contract contained two rules
that cannot both hold — locks must be released between unrelated tool calls,
and any release forces a full re-verify — which confines cache reuse to a
single held-lock interval and makes the cross-call win unreachable. The
owner resolved this on issue #272 by choosing **(b) writer-visible
epochs** (this ADR's amendment below) over (a) task-scoped lock holding
(rejected: starves writers or requires a new contention contract) and (c)
within-interval-only reuse (rejected: post-#279 that leaves almost nothing
to win). Nothing below the amendment line is rewritten; where the original
text and the amendment differ, the amendment governs.

1. **Trust-on-first-verify, unbounded lifetime** — verify a shelf once per
   warm process lifetime, serve it from memory forever after. Rejected: this
   is exactly the "one-time check trusted indefinitely" the issue calls out
   as unacceptable. A warm process could live for hours across many agent
   tasks; an attacker (or an ordinary concurrent `leitir remove`/`get`/`gc`)
   mutating a shelf mid-session would be served stale-verified bytes with no
   bound on how stale.

2. **mtime/inode/size stat-based invalidation, checked on every read** — before
   serving cached verified state for a shelf, `stat()` (or `lstat()`) the
   manifest and a cheap tree-level signal, and treat any change as a cache
   miss. Cheap (a handful of syscalls, not a full re-hash), but **not
   sufficient on its own**: mtime granularity, clock skew, and the fact that a
   sufficiently fast attacker can restore mtime after mutation (or mutate
   within the same mtime tick) mean stat-based invalidation detects *most*
   accidental and slow-attacker mutation but is not itself the security
   boundary. Useful as a fast-path invalidation *signal* (skip the syscalls
   only when nothing could plausibly have changed), never as a substitute
   for re-verification.

3. **Per-shelf lazy re-verify on first use per session, unconditionally** —
   the first touch of a given shelf within a warm session always does the
   full ADR-0006 verification (paying the real hashing cost once), and the
   *same session* may reuse that verified result for subsequent touches of
   the *same shelf* **only if nothing has been given a chance to invalidate
   it** — see the chosen option below for what "nothing has been given a
   chance to" means concretely. Cheaper than option 1 in that it does not
   trust forever, but on its own says nothing about how long "the same
   session" is allowed to be, which is the actual load-bearing question.

4. **Bounded state lifetime tied to a single agent task, with mandatory
   invalidation on any signal a writer might have run** — combine option 3's
   lazy per-shelf re-verify with a hard ceiling on how long any cached
   verified result may be trusted, tied to the warm process's own lifetime
   (bounded to one task/session, not a long-lived daemon) plus an explicit,
   fail-closed invalidation trigger keyed to the same primitives ADR-0006
   already uses to detect writer activity: the per-target advisory lock. If
   the warm process cannot prove no writer has touched a target lock since
   its cached verification, it re-verifies. **This is the chosen option.**

5. **Full daemon with filesystem-event invalidation (inotify/FSEvents)** —
   watch the corpus tree for writes and invalidate reactively. Rejected for
   this design: adds a non-stdlib dependency surface (or a large amount of
   bespoke, platform-divergent stdlib-only polling code) for a benefit stat-
   based fast-pathing already captures more cheaply; also reintroduces the
   "how long does a daemon live, and what resets its trust on restart"
   problem that option 4's task-bounded lifetime sidesteps by construction.
   Not stdlib-portable across the Windows/POSIX split ADR-0006 already
   documents as a live constraint (locking primitives differ per platform).
   Revisit only if a future measurement shows option 4's per-touch stat
   overhead is itself a bottleneck.

## Decision Outcome

Chosen option: **4 — per-shelf lazy verification with a session bounded to a
single agent task, using stat-based signals only as a fast-path skip and the
existing advisory lock as the invalidation trigger of record**, because it is
the only option that (a) never trusts a shelf beyond direct evidence it was
just re-checked, (b) bounds the exposure window to something an operator can
reason about (one task, not "until the daemon is restarted"), and (c) reuses
the exact primitives ADR-0006 already established as the security boundary
(the per-target advisory lock, `materialized_tree_hash` / the per-file
digest map) rather than inventing a parallel trust mechanism.

### The invalidation contract

1. **What is memoized.** Only the *result* of a specific shelf's
   `verify_materialized_integrity` call — a boolean-shaped
   "this exact manifest, on this exact target, verified against these exact
   digests, at this instant" fact — plus the parsed manifest payload it
   verified. Never the shelf's raw bytes, never a "trust this shelf" flag
   detached from the manifest instance it was computed against. The
   catalog-wide `enumerate_shelved_sources` scan (Finding 2) is memoized as
   a *collection* of these same per-shelf verified results, not as a
   separately-trusted "the catalog is fine" bit — invalidating one shelf's
   entry must not require re-trusting or re-scanning entries that were not
   touched.

2. **What invalidates a cached verified result, in order of authority:**
   - **Definitive (must invalidate, always checked before serving from
     cache):** the warm process could not hold the per-target advisory lock
     across the interval from "verified" to "served" without releasing it in
     between. Every writer path (`get`, `remove`, `clean`, `upgrade-cache`,
     concurrent `leitir` processes) takes this same lock (ADR-0006). If the
     warm process ever released the lock — and it must release it between
     unrelated tool calls, since holding locks across an open-ended agent
     session would starve legitimate writers — the next use of that shelf
     re-acquires the lock and re-verifies before trusting the cached result,
     full stop. The cached parse is a hint for what to expect, never a
     substitute for the check.
   - **Fast-path skip (may skip re-verification only when this signal proves
     nothing plausibly changed, never used to affirmatively serve unverified
     data):** `stat()` the manifest file and target directory's top-level
     mtime; if unchanged since the last verification *and* the lock was held
     continuously, the re-verify may be skipped. Any stat mismatch, any
     stat() failure (ENOENT, permission error, symlink where a directory was
     expected), or any ambiguity forces a full re-verify — never a cache
     hit on ambiguous evidence.
   - **Session boundary (hard ceiling regardless of the above):** cached
     verified state does not outlive the warm process's bound task/session.
     A warm process is scoped to one agent task, not a long-running daemon
     serving unrelated tasks over hours; when that scope ends, all cached
     verified state is discarded, not persisted or handed to the next
     session. This bounds the "how long could a TOCTOU window be exploited"
     question to "at most one task's duration" rather than "however long an
     operator forgot to restart a daemon."

3. **The load-bearing guarantee: a tampered shelf must never be served, even
   if bytes are mutated after the warm process already verified and cached
   that shelf.** The contract above guarantees this as follows: between the
   warm process's verification and any later serve of that shelf's content,
   either (a) the warm process held the advisory lock continuously — in
   which case ADR-0006's existing guarantee applies unchanged, no cooperating
   writer could have mutated the shelf, and a non-cooperating process editing
   files in place is the same residual ADR-0006 already accepts (advisory
   locks do not bind an uncooperative process); or (b) the lock was released
   and reacquired — in which case the contract mandates a full re-verify
   before serving, so any mutation in the gap is caught by the same hashing
   ADR-0006 already performs on every cold load. There is no third path: no
   cache entry may be served without either continuous lock possession, an
   unchanged writer-visible epoch plus unchanged stat signature (the 2026-09-03
   amendment below), or a fresh re-verify gating it.

4. **Residual TOCTOU window — stated honestly, not zero.** Within a single
   held-lock interval, the window is identical to ADR-0006's existing
   residual: the advisory lock does not bind a non-cooperating process that
   edits files in place outside the leitir protocol, and on Windows
   (`O_NOFOLLOW` unavailable) the same platform-dependent residual ADR-0006
   already documents applies unchanged. Warm mode adds exactly one new
   window beyond what ADR-0006 already accepted: the interval between
   `verify_materialized_integrity` returning inside the warm process and the
   moment its result is read by the code serving a tool call, which for an
   in-process call (no subprocess boundary, once #271 lands) is bounded by a
   single Python function call — sub-millisecond, no I/O, no scheduling point
   where another process's write could interleave in a way the *next* lock
   acquisition wouldn't catch. This window is not eliminated (a lock is
   advisory, not a mutex enforced against the OS), but it is not enlarged
   relative to cold-path leitir today: a cold invocation has the identical
   window between its own verify-then-serve. Warm mode's only new exposure
   is what happens *between* tool calls, and that is exactly the interval
   the lock-release rule above forces back through a full re-verify. Stated
   as a bound: **the maximum interval during which a cached verified result
   for a given shelf could be stale is the time between the warm process's
   last continuous-lock-holding verification of that shelf and its next
   lock acquisition for that shelf** — which the contract guarantees is
   re-verified at that next acquisition, so no stale result is ever *served*,
   only ever *discarded and replaced*.

   The 2026-09-03 amendment widens that interval by design: between tool
   calls the lock is released and no re-verify occurs, so the bound becomes
   "unchanged epoch plus unchanged stat signature" — see the amendment's own
   residual statement.

5. **Failure handling.**
   - Failure to establish warm state at all (the warm process cannot start,
     cannot acquire a lock it needs for its own bookkeeping, or hits any
     unexpected error while trying to set up the cache) falls back to the
     cold path for that invocation — a full fresh process/verification —
     never to an unverified fast path. Warm mode is purely an optimization
     layered on top of the cold path's existing correctness; it must never
     become a second, weaker code path that risk being reached when the fast
     path degrades.
   - A shelf whose verification fails (raises `VerificationError`) is never
     cached as valid, is never retried silently, and must not be served even
     if an *earlier* verification of the same shelf within the same session
     succeeded. The moment a re-verify (triggered by the rules above) fails,
     any prior cached "verified" result for that shelf is discarded
     immediately, not just marked stale for the next check — a failed
     shelf is fail-closed for the remainder of the session, matching
     ADR-0006's "reject, never load-and-warn."

6. **Cold-path behaviour, exit codes, output, and determinism.** Warm mode
   must not change what the cold path does when invoked directly — byte-
   identical stdout/stderr, identical exit codes, identical
   `PYTHONHASHSEED`-independence for both paths. Warm mode is additive: it
   changes *when* verification work happens (once per lock-held interval
   instead of once per invocation), never *what* gets verified, *how*
   ADR-0006's hashing works, or *what* a caller observes on success or
   failure. No new runtime dependency; the state cache itself is a plain
   stdlib in-memory structure (dict-of-manifests keyed by target path plus
   the lock-continuity bookkeeping), never a new persisted store, since a
   persisted cross-process cache reintroduces exactly the "trust survives
   process restart" problem option 1 was rejected for.

### Why load-time tree verification is a security property, not an optimization target

ADR-0006 exists because a materialized shelf's bytes can be mutated after
materialization — by cache corruption, a cooperating-but-buggy writer, or an
adversary with filesystem access — and `verified: true` recorded in a
manifest is not evidence about *current* bytes, only about bytes at
materialization time. Re-hashing at every load is what converts "we checked
once" into "we know right now." Treating that re-hash as a pure performance
cost to be memoized away — the naive reading of "add a cache" the issue
explicitly warns against — would silently reintroduce the exact
time-of-check/time-of-use gap issue #17 and ADR-0006 closed. What warm mode
is allowed to memoize is narrow and stated above: a verification *result*,
scoped to an interval during which the invalidation contract can prove
nothing could have used the mutation window undetected. What it may never
memoize: the *decision* to skip verification based on anything weaker than
that contract (elapsed wall-clock time alone, a request count, an assumed
"nobody else touches this corpus" heuristic, or trusting a shelf because it
was fine the last N times).

### API shape needed from #271

Issue #271 currently commits to callable, structured-result functions per
verb, extracted from `cli.py`'s dispatch. For warm mode to be buildable on
top of that refactor without re-litigating this ADR's contract, the
extracted API should additionally expose (this ADR does not require #271 to
implement these, only to leave room):

- A corpus-root-scoped **session/handle object** whose lifetime the caller
  (the MCP bridge, once it can call in-process instead of subprocessing)
  controls explicitly — construct it once per agent task, discard it at task
  end. This is what "session" in this ADR's contract binds to; #271 splitting
  dispatch into free functions with no shared state would make that lifetime
  unrepresentable.
- Per-verb functions that accept an optional pre-verified-state cache (the
  session handle above) and are fully correct when it is absent — i.e. the
  cold path remains the default and the only thing warm mode adds is an
  optional accelerant, never a required argument that changes behavior if
  omitted.
- Exposure of the per-target advisory lock's acquire/release as something a
  session can observe was "held continuously" across two verification
  touches, since that continuity is the actual invalidation trigger (§2
  above) — not just a black-box context manager `cli.py` currently uses
  internally.
- No behavior change to argparse-facing CLI semantics; this ADR's needs are
  additive to #271's committed scope (byte-identical `--help`, exit codes,
  and JSON), not in tension with it.

### Amendment — writer-visible lock epochs (2026-09-03; issue #272 owner decision, option (b))

Every real acquisition of the per-target advisory lock advances a
**lock-adjacent epoch file** — `.locks/<sha256-of-target>.epoch`, a decimal
counter atomically replaced under the lock, living outside every verified
tree — *before* the acquiring code performs any mutation. The bump therefore
precedes the write, so even a writer that crashes mid-mutation leaves an
epoch no earlier reader can still trust. A bump that cannot be written fails
the acquisition (fail-closed), and a malformed counter resets to 1 while
still changing the file.

Cache validity across released-lock intervals is then:

1. **Lock-free resolution gate** (manifest reads on the `info`/`api`/`get`/
   `trust`/`examples` resolution paths, corpus enumeration, and eligibility):
   the memo is served iff the epoch file's bytes are unchanged *and* the
   whole-tree stat signature — per regular file `(relative path, inode,
   mtime_ns, ctime_ns, size)` plus the manifest's own stat — is unchanged
   since the recorded full verification. The session holds no target locks
   on this path. Entries are recorded only when BOTH the epoch reads and
   BOTH the stat sweeps bracketing the full verification agree: the epoch
   brackets acquisitions, not mutations — a cooperating writer swaps the
   shelf at the *end* of a long held interval, after its bump — so epoch
   agreement alone cannot prove the hashed bytes and the pinned signature
   describe one shelf state (review round 2, F1).

   **Failure attribution (review round 2, F3).** A failed verification
   drops the memo and fails that touch. A lock-free failure cannot be
   attributed: a racing writer that swaps and restores mid-verification
   leaves evidence net-neutral and indistinguishable from corruption, so
   the session never blacklists a shelf — every later touch re-verifies
   cold, exactly the cold path's per-invocation contract, never weaker and
   never session-permanent. No cached success survives a failure (the memo
   is dropped), and nothing unverified is ever served (re-serving requires
   a fresh successful full verification). This refines §5's original
   session-sticky wording, which assumed verification failure implied
   corruption.

2. **Under-lock streaming gate** (engine local-shelf streaming, which in the
   cold path holds the per-target lock across the stream): the caller
   acquires the lock — advancing the epoch by exactly one — and may serve
   the memo iff the current counter equals the recorded counter (the
   caller's take was a reentrant borrow of a continuously held lock, so no
   other process could have acquired) or the recorded counter plus exactly
   one (the caller's own acquisition is the only bump since). Any other
   total forces the unchanged cold full verification under the lock. The
   lock is held across the stream exactly as in the cold path.

3. **Who advances the epoch:** every real `_target_lock` acquisition in any
   process — writers (`get`, `remove`, `clean`, `upgrade-cache`, trust and
   license manifest updates, index builds) and also cold readers that
   historically hold the lock (cold local-shelf streaming, cold
   eligibility). Cold callers may therefore spuriously invalidate a warm
   session's memo; that direction only costs a re-verification and never
   serves unverified bytes.

**Honest residual, versus the cold path.** The cold path re-hashes on every
load, so it detects any byte mutation at the next invocation. Warm mode
under this amendment serves from the memo without re-hashing when epoch and
stat signature are unchanged, so a *non-cooperating* process that mutates
bytes in place **and restores the stat signature** (and, on POSIX, also
defeats the ctime component, which `utime` cannot restore — inode or clock
manipulation is required) is detected at the next *cold* load but not until
the session ends under warm mode. One further pin-time edge (review round 3,
finding 2): sweep+epoch agreement across a verification is the *precondition*
for pinning, not a proof that one shelf state produced both observations —
a writer that swaps in a fully-valid alternate state before the reader's
manifest read and restores the original directory node after the tree hash
could pin a crossed (manifest, signature) pair. No leitir writer has that
shape (publish rollback only acts while the target path is absent; gc
recovery is restore-only), and the adversarial version is subsumed by
residual (ii) below. "Cooperating writers are caught with certainty"
therefore scopes to memo *invalidation* — any lock acquisition invalidates
— not to pin-time state pairing. On Windows the bar is lower: `st_ctime` is
creation time there and does not move on a content write, so the
stat-restoring adversary needs only size and mtime restoration — the
platform-divergent residual ADR-0006 already documents, unchanged by this
amendment. Cooperating writers are caught with
certainty: taking the lock advances the epoch regardless of what they do to
the shelf bytes or metadata. Two further accepted edges: (i) leitir
binaries predating this amendment do not advance epoch files (version
skew — the same trust class as any stale writer); (ii) the epoch file
itself is not adversarially protected (an attacker who restores an old
epoch snapshot after mutating is equivalent to the stat-restoring
adversary above). Both are bounded by the session-scoped lifetime of the
memo and by the unchanged cold gate that every first touch still pays. On
filesystems whose `st_ino` is unstable (FAT/exFAT-class removable media)
the signature silently degrades to its mtime/ctime/size components — the
same direction as the Windows residual, and likewise detected by the next
cold load.

## Positive Consequences

- Removes the ~97%-of-wall-time cost measured in the premise report for an
  agent session's second and later touches of an already-verified shelf,
  without weakening ADR-0006's guarantee.
- Fixes the cost for *any* spec-resolving command, not only `search
  --corpus`, because the contract covers the catalog-enumeration path
  (Finding 2), not just per-search-scope state.
- Gives implementers of #272 a concrete, arguable invalidation rule instead
  of an open design question, and gives #271 a concrete shape to leave room
  for.

## Negative Consequences

- A warm session still pays full verification on its first touch of each
  shelf, and again after any lock release — this is not a "verify once,
  ever" cache, so worst-case (a session that never reuses a shelf, or one
  where every tool call is interleaved with contention forcing lock
  release/reacquire) sees no improvement over cold. That is intentional: the
  alternative (option 1/3 without the session bound) is the design this ADR
  rejects.
- The advisory-lock-continuity bookkeeping adds real implementation
  complexity to whatever data structure #272 builds — "did we hold this lock
  continuously since we last verified" is a stateful question, not a stat
  comparison, and platform lock semantics already diverge (ADR-0006's
  Windows/POSIX note applies unchanged here).
- Does not help a workload dominated by first-touch verification of many
  distinct shelves in one session (e.g., a single `search --corpus` sweep of
  a corpus none of which was touched before) — that workload's actual fix is
  making the underlying scan itself faster (Finding 3's `pathlib` overhead),
  which is explicitly out of this ADR's scope.

## Links

- Issue [#272](https://github.com/anthonykewl20/leitir/issues/272) (A5: warm process mode)
- Issue [#271](https://github.com/anthonykewl20/leitir/issues/271) (C4: callable Python API — blocking dependency)
- Issue [#279](https://github.com/anthonykewl20/leitir/issues/279) — the O(catalog) re-verification-per-call defect this ADR's premise measurement uncovered; a distinct, cold-path bug tracked separately, not fixed by warm mode
- [ADR-0006](0006-load-time-tree-verification.md) — load-time materialized-tree verification (the security property this ADR must not weaken)
- [ADR-0018](0018-manifest-authenticity.md) — manifest authenticity (the detached-signature layer this ADR does not touch)
- `docs/evidence/warm-mode-premise-2026-08-27.md` — the measured premise report backing this decision
- `docs/evidence/dogfood-2026-08-15.md` — corroborating real-corpus scale (131 shelves) for the measurement
