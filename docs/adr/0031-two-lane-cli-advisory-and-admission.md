# Two CLI lanes: advisory exploration vs. admission gating

- Status: accepted
- Deciders: leitir CLI-UX contributors
- Date: 2026-08-27
- Technical Story: issue #266 item C2

## Context and Problem Statement

Leitir's 31 subcommands read, in the docs and in `--help`, as one undifferentiated
list. In practice they split into two operations with entirely different
stakes: verbs that let an agent look something up, and verbs that decide
whether code or evidence is admitted into a project or a corpus. Because the
docs never named that split, every command appeared to carry the same
ceremony. An independent dogfooder driving only `--help` and error messages
described the polyglot path (spec → shelf → BTS compute → contained run →
exit gate) as "a five-step gauntlet with three opaque messages" — a direct
symptom of exploration work reading as if it carried admission-lane weight.
This ADR names the two lanes so the docs, and future verb additions, can
stop conflating them.

## Decision Drivers

- Exploration (`info`, `search`, ...) and admission (`bts-run`,
  `exit-gate-run`, ...) have different failure economics: a wrong exploration
  answer costs the caller some tokens and is visible immediately in the
  output; a wrong admission answer is a false "this is safe to use" that is
  discovered later, if at all.
- The fix must be legible in `--help` text and README structure without
  touching any check, containment boundary, or fail-closed path.
- New verbs will keep being added; without a stated rule, each one is placed
  by instinct instead of by a repeatable test.

## Considered Options

- Leave the CLI flat and rely on prose in each command's help text to imply
  weight (status quo — this is what produced the "five-step gauntlet"
  complaint; nothing forces consistency across 31 commands maintained by
  different contributors over time).
- Split the CLI into two literal subcommand groups or binaries
  (`leitir-advise` / `leitir-admit`) (rejected — a breaking surface change
  far out of scope for a docs-only item, and orthogonal to the actual
  problem, which is conceptual clarity, not argv shape).
- Name the two lanes as a documentation and UX taxonomy over the existing,
  unchanged command set, with an explicit placement rule for future verbs
  (chosen).

## Decision Outcome

Chosen option: name two lanes, **advisory** and **admission**, as a
documentation/UX taxonomy over the existing 31 subcommands. No command's
implementation, flags, or checks change as a result of this ADR.

### The two lanes

**Advisory lane** — read, materialize, describe, diagnose, or maintain the
local corpus. No containment, no ratification, no donor-code execution. A
wrong answer costs tokens and the caller sees it immediately in the output
(different text, an error, an empty result) — nothing downstream silently
trusts it.

`doctor`, `search`, `index`, `bench`, `get`, `fetch`, `list`,
`upgrade-cache`, `trust`, `remove`, `clean`, `lock`, `sbom`, `api`,
`examples`, `info`, `ask`, `diff`, `export`, `gc`

**Admission lane** — render a verdict (accept/reject, complete/partial,
valid/tampered, ok/violation) that something is entitled to enter a
recipient project or a ratified corpus: donor code via the BTS pipeline,
composition/lineage claims, contained execution, evidence bundles, or
corpus snapshots. Full fail-closed behaviour, containment where code
actually runs, ratification, and provenance receipts apply. A wrong answer
here is a false "this may proceed" — it is silent until something downstream
consumes the verdict, and by then the cost is a correctness failure, not a
few wasted tokens.

`bts-compute`, `bts-run`, `bts-funnel`, `analysis-architecture`,
`analysis-lineage`, `occupied-validate`, `exit-gate-validate`,
`exit-gate-run`, `check`, `import`, `usage`

That is 20 advisory + 11 admission = 31, matching every subcommand
registered in `src/leitir/cli.py` as of this writing.

Two placements are worth explaining because they are not obvious from the
verb name alone:

- `analysis-architecture` and `analysis-lineage` render a compatibility /
  lineage verdict consumed by the same composition-acceptance pipeline as
  `occupied-validate` (ADR-0014, ADR-0016, ADR-0017); they carry no
  containment step themselves, exactly like `occupied-validate` and
  `exit-gate-validate`, which are admission-lane despite being pure,
  offline artifact validators. Containment is not the test — verdict-issuing
  is.
- `usage` (`assemble` / `verify` / `replay`) is admission-lane for the same
  reason: `verify` and `replay` render a pass/fail verdict on whether an
  evidence report is structurally sound and byte-identical to on-disk
  corpus/requirements bytes, and its own ADR-0029 explicitly models its CLI
  dispatch on `occupied-validate`'s convention. `assemble` shares the lane
  because it self-verifies through the same code path before writing
  anything, and a bad `report.json` is exactly the kind of artifact other
  admission-lane consumers would otherwise trust silently. It performs no
  containment or ratification of its own — like the two `analysis-*` verbs,
  it is grouped by what it decides, not by whether it runs anything.

No verb here was hard to assign once the test below was applied; both of
the above needed the reasoning spelled out because they are not named
`*-validate` or `*-run` yet behave like the artifact-validating admission
verbs that are.

### Decision rule for placing a new verb

Ask two questions about the verb's own output, not about the code it
happens to touch:

1. **What does a wrong answer cost?** If it's tokens and a visibly odd
   result (empty search, a stale-looking `info`), advisory. If it's a false
   claim that something is safe/valid/compatible/complete that something
   *else* will act on, admission.
2. **Does the caller find out immediately, or only when something
   downstream trusts the verdict?** Advisory failures surface in the same
   invocation. Admission failures surface later — in a merged PR, a shipped
   transplant, a corrupted corpus import — if at all.

If the verb issues a pass/fail, accept/reject, or complete/partial verdict
that another process is expected to rely on without re-deriving it itself,
it is admission-lane, regardless of whether it performs containment,
network access, or donor-code execution — `occupied-validate`,
`exit-gate-validate`, `analysis-architecture`, `analysis-lineage`, and
`usage verify`/`usage replay` are all admission-lane and none of them
executes anything. If the verb only reads, materializes, lists, scores, or
reports — with no downstream consumer expected to treat its output as a
trust boundary — it is advisory, regardless of how much it materializes
into the corpus (`get`, `fetch`, and `lock` all write shelves into the
corpus and are still advisory: nothing downstream treats "I fetched a
shelf" as a verdict that the shelf is fit for any particular purpose).

### Explicit constraint: this is documentation and UX only

This ADR draws a naming and presentation boundary. It is not licence to
weaken any fail-closed behaviour anywhere, and it must never be read as
one:

- No verb changes lanes by having a check removed. Lane membership is
  fixed by what the verb's output means, not by how expensive its checks
  currently are.
- `bts-compute`, `bts-run`, `bts-funnel`, `occupied-validate`,
  `exit-gate-validate`, `exit-gate-run`, `check`, `analysis-architecture`,
  `analysis-lineage`, `usage`, and `import` keep every fail-closed check,
  containment boundary, and ratification requirement they have today.
  Nothing in this ADR touches `src/leitir/cli.py`'s dispatch, any
  `MaterializationError`/`VerificationError`/`TreeHashError` path, or the
  load-time `materialized_tree_hash` check.
- Advisory does not mean unverified. Every advisory verb that touches
  materialized bytes still verifies them at load time (the same
  `materialized_tree_hash` check admission-lane verbs rely on). What
  advisory verbs skip is containment, ratification, and donor-code
  execution — not verification.
- A future contributor proposing to relax a check on the grounds that "it's
  only advisory" is misreading this ADR. Lane is about what the *caller*
  should expect from the *verdict*, not about how carefully leitir should
  verify its own outputs.

### Positive Consequences

- The README and `--help` surface can now tell a caller, in one sentence,
  which commands are safe to run speculatively and which ones are load-bearing.
- Future verb proposals get a repeatable placement test instead of an
  ad hoc call.
- Names an actual root cause of the "five-step gauntlet" dogfooding
  complaint: the polyglot BTS→contained-run→exit-gate path is, correctly,
  all admission-lane and inherently heavier than a `search`/`info` lookup;
  now that this is named, the remaining UX work is to make the advisory
  lane feel lighter, not to lighten admission's ceremony.

### Negative Consequences

- Some advisory-lane verbs still carry admission-lane *cost* today, even
  though they carry none of its correctness stakes: every invocation pays a
  cold Python process start, and `search --corpus` re-verifies every
  eligible shelf's parity on each call rather than caching a session-level
  verification result. Closing that gap — making the advisory lane cheap in
  wall-clock time, not just in ceremony — is tracked as issue #266 item A5
  and is unbuilt as of this ADR. Until then, "advisory" describes what a
  verb *risks*, not yet how fast it *feels*. *(Update 2026-08-30: the
  worst slice of that cost — single-shelf spec resolution re-verifying the
  entire catalog — is fixed as issue #279, measured 107.7s → 2.0s in
  `docs/evidence/single-shelf-resolution-2026-08-30.md`; the session-level
  caching half remains #272/ADR-0035.)*
- A two-lane taxonomy is a simplification. A few verbs (`analysis-*`,
  `usage`) required the reasoning above to place confidently; a reader
  skimming only the verb lists, without the placement rule, could
  reasonably guess differently. The rule section exists specifically so
  that disagreement is resolvable by re-applying the test, not by
  re-litigating each verb from scratch.

## Links

- [ADR-0014](0014-structural-architecture-compatibility.md) — `analysis-architecture`'s
  underlying compatibility model.
- [ADR-0016](0016-lineage-and-drift-tracking.md) — `analysis-lineage`'s
  underlying model.
- [ADR-0017](0017-occupied-recipient-validation-gate.md) — `occupied-validate`'s
  trust binding; the composition-acceptance pipeline this ADR's admission
  lane is centered on.
- [ADR-0025](0025-usage-evidence-and-replay-contract.md),
  [ADR-0029](0029-offline-usage-cli-verification-and-replay.md) — the
  `usage` verb's data contract and CLI convention.
- [ADR-0030](0030-check-command-conservative-symbol-existence-gate.md) —
  `check`'s verdict semantics, the clearest existing example of an
  admission-lane verb that performs no containment.
- Issue #266 (item C2 — this ADR; item A5 — the unbuilt advisory-lane
  cost work noted in Negative Consequences).
