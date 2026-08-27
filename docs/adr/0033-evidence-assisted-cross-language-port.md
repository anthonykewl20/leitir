# ADR-0033: Evidence-assisted cross-language port

- Status: Accepted
- Implementation: in-progress (portable-contract translation and port attribution land in this change; containment execution of an agent-written target-language implementation is explicitly out of scope -- see Decision 5 and the tracked remainder, issue #277)
- Deciders: leitir maintainers
- Date: 2026-08-27
- Technical Story: Issue #270 ("D1: evidence-assisted cross-language port"), split out of #266

## Context and Problem Statement

ADR-0008 through ADR-0011 give Leitir a same-language Python transplant path:
extract a minimal, evidence-bounded Behavioral Transplant Set (BTS) from a
Python donor, relocate it, prove it under containment absent the donor, and
package it with attribution. `bts-compute --language` already accepts
`javascript`, `typescript`, `rust`, and `go`, but per ADR-0012 that feeds
**graph production only** -- BTS relocation, rerun, probes, and donor-line
accounting remain Python-only (`src/leitir/relocate.py`,
`src/leitir/transplant.py`). An agent can copy Python behaviour into a
Python project with a proof and a license manifest. It cannot port that
behaviour into a Rust or TypeScript project at all.

This ADR decides how Leitir participates in a **cross-language port**
without weakening any existing fail-closed guarantee, and records exactly
what is proven end-to-end in this change versus what remains explicitly
unproven.

## Decision Drivers

- Leitir must never perform automatic source-to-source translation. Writing
  the target-language implementation is a non-deterministic, judgment-laden
  act that belongs to the agent, not to a deterministic tool.
- A behavioural contract that cannot be faithfully expressed in the target
  language must reject, never degrade into a weaker or approximated
  assertion. The issue's own illustrative case is normative: a Python
  contract asserting `ValueError` has no faithful equivalent in Go's
  error-return model, and pretending `err != nil` captures it is a silent
  loss of information the recipient never agreed to accept.
- No existing fail-closed path (BTS `COMPLETE`-only admission, donor-ban
  proof, exact behavioural parity, license/obligation resolution) may be
  weakened to make a port easier.
- Containment (nsjail + pytest) is Linux/Python-oriented today (ADR-0009,
  Amendment 1). A rootfs change requires a new published release asset, a
  fresh Phase-A measurement, and an out-of-band re-ratification ceremony
  (ADR-0009 S2) -- it is explicitly not a same-PR decision.
- `bts._total_donor_lines` counts only `.py` files today
  (`tests/test_bts_cli.py::test_go_compute_is_partial_until_non_python_donor_line_accounting_is_ratified`
  documents that a *non-Python donor* BTS is structurally capped at
  `PARTIAL` until donor-line accounting is ratified for polyglot donors).
  This ADR does not touch that gate: the donor in a port stays Python. Only
  the *target* of the contract translation is non-Python.

## Considered Options

1. Translate donor Python source directly into target-language source
   (source-to-source translation). Rejected outright -- this is exactly the
   hard boundary the issue asks this ADR to draw a line against; a tool
   that silently reinterprets semantics across a language boundary can
   introduce behavioural drift no proof step would catch, because the
   "proof" would be checking the tool's own translation against itself.
2. Extract donor behaviour as a **portable contract** -- a closed,
   declarative subset of assertions with a mechanical target-language
   rendering -- and require the agent to write the implementation
   independently. **Chosen.**
3. Defer the entire issue until a target-language-capable containment
   rootfs exists. Rejected: the containment gap blocks only the
   *proof-under-containment* half of the pipeline, not the
   translation/attribution half, which is independently useful, testable,
   and the harder design problem the issue asks for. Building it now, and
   stating plainly what containment cannot yet do, is more honest than
   deferring everything behind a rootfs ratification that has its own
   process and is out of a single PR's control.

## Decision Outcome

Chosen option: extract donor behaviour into a **portable contract**, expose
a deterministic, offline translator into the target language, and gate
admission on typed rejection for anything unfaithful. Real, in-process
execution proof of an agent-written implementation under containment is
explicitly deferred to a follow-up that first extends the containment
rootfs; this change ships the deterministic evidence-and-gate half honestly,
labeled as such, rather than a plausible-looking pipeline that was never
run.

### 1. The portable-contract subset (what CAN be faithfully expressed)

A **portable contract** (`leitir.port_contract.PortableContractSuite`,
schema `leitir-portable-contract-v1`) is a closed, declarative,
JSON-representable set of `(args) -> outcome` cases bound to one donor
function by BTS digest. It is not a translation of arbitrary pytest source;
Leitir never parses or reinterprets pytest assertion semantics for this
path. It is a caller-declared claim (from the agent computing the donor BTS
and reading its behaviour) that Leitir independently validates for
portability before translating it.

**Portable (v1):**

- `PortableValueKind`: `bool`, `int` (must fit Go's `int64`,
  `[-2**63, 2**63-1]`), `float` (must be finite -- no `NaN`/`Inf`, which
  have no single canonical decimal literal), `string` (strict UTF-8), and
  `list` of exactly one of the four scalar kinds (a slice type has one
  element type; a heterogeneous or nested list has no single Go type and is
  therefore not part of the v1 subset).
- `OutcomeKind.RETURN`: the donor function returns a portable value for a
  given portable argument tuple. This is a pure `got == want` comparison,
  which both Python and Go can express with the same semantics for closed,
  scalar/list-of-scalar values -- exactly the case where "faithful" is not
  in doubt.

**Not portable (v1) -- must reject, never degrade:**

- `OutcomeKind.RAISES`: a donor function raises a specific Python exception
  *type* (with its class identity, MRO, and `args`). Go has no exception
  mechanism; its nearest analogue, a returned `error` value, has no type
  identity comparable to a Python exception class. Reducing "raises
  `ValueError`" to "returns a non-nil error" silently discards which error
  the recipient contracted for -- to reject this outright is precisely
  what "reject the rest honestly rather than approximating" means. Every
  `RAISES` case rejects at `classify_case` with
  `BTSRejectReason.REJECT_UNSUPPORTED_CONSTRUCT`,
  `detail_code="port_contract_raises_not_portable_go_v1"`, naming the donor
  exception type in the evidence message.
- Nested lists, heterogeneous lists, integers outside Go's `int64` range,
  and non-finite floats each reject with their own `detail_code`
  (`port_contract_nested_list_v1`, `port_contract_heterogeneous_list_v1`,
  `port_contract_int_overflow_go_v1`, `port_contract_nonfinite_float_v1`).
- Anything outside this closed vocabulary (mutation-through-reference
  semantics, generator/iterator protocols, duck typing, side effects,
  concurrency/ordering guarantees, floating-point rounding-mode
  sensitivity) is simply not representable in `PortableContractSuite` at
  all -- there is no escape hatch or "best effort" tag. A caller who cannot
  express a behaviour in the closed vocabulary cannot submit it; this is a
  structural rejection, not a runtime one.

`translate_contract` rejects the **entire suite** on the first
non-portable case, in caller-stable case-name order -- never a silently
narrowed subset with the unportable cases dropped. This mirrors ADR-0009's
"no compensating success path" discipline: a port is fully evidenced or it
is rejected.

### 2. Donor-line accounting and attribution: behavioural descent, not line reuse

ADR-0011's reuse-packet attribution and REUSE 3.3 obligation resolution
assume shared bytes: a bundled source file is hashed, its license header is
resolved, and obligations (license text, copyleft boundary, modification
marking) are recorded against the bytes actually shipped to the recipient.

A port shares **zero bytes** with the donor. The translated Go test file is
Leitir's own deterministic rendering of a caller-declared contract; the
agent's implementation is never bundled, inspected, or taken into Leitir's
custody at all (see Decision 4). There is no donor line range to account
for in the ADR-0011 sense, and the reuse-packet attribution mode does not
apply -- not because attribution is skipped, but because its precondition
(shared bytes) is absent.

What **does** still apply, unchanged: donor license admissibility.
`build_port_attribution` calls `leitir.license_policy.evaluate_license_policy`
-- the exact same function a reuse packet calls, with no modification --
over the donor's own BTS member source bytes (the behaviour actually read
to author the portable contract). If that resolution is missing, ambiguous,
or recipient-incompatible, `build_port_attribution` raises the same
`BTSRejectReason` (`REJECT_LICENSE_UNKNOWN` /
`REJECT_LICENSE_INCOMPATIBLE` / `REJECT_LICENSE_OBLIGATION_MISSING`) a
reuse packet would raise today. A port is never admitted on a donor whose
license Leitir cannot resolve, even though no donor bytes leave the
pipeline.

The resulting `PortAttributionEvidence.attribution_mode` is a new,
explicit tag, `"behavioral_descent"` -- distinct from ADR-0011's reuse-line
attribution -- naming this precisely: the port's provenance runs from
*behaviour read*, bound by BTS digest and donor commit, not from *bytes
shared*. `ATTRIBUTION.md` and `obligations.json` are still produced (via
the unmodified `render_attribution`), so a human or downstream tool sees
the donor's license and notice obligations exactly as it would for a
same-language reuse -- the port just never claims those obligations were
discharged by bundling source, because it never bundles source.

This directly answers the issue's "harder half": donor-line accounting for
a port is not extended, weakened, or reinterpreted -- it is correctly
recognized as inapplicable, while the license-admissibility half of
attribution, which does not depend on shared lines, is reused verbatim.

### 3. Containment: what runs today, and what is explicitly deferred

ADR-0009's containment stack (nsjail + a pinned, Python-CPython rootfs +
pytest) proves that transplanted Python bytes pass their original contract
with the donor provably absent. Running a Go (or any non-Python) contract
suite inside that same rootfs is not possible without adding a Go toolchain
to the pinned rootfs -- and per ADR-0009 S2, a rootfs substrate change is
categorically an out-of-band, separately ratified change (new published
asset, fresh Phase-A measurement, re-ratification), not something one PR
can decide unilaterally.

This environment has no `nsjail` binary, no published
`containment-rootfs-v1` materialization, and no Go toolchain installed
(verified: `which nsjail go rustc` all report not found). Faking a
containment proof here -- writing code that pretends to invoke nsjail, or
asserting a "PASS" without ever running anything -- would be exactly the
dishonesty this project's fail-closed discipline forbids. This ADR
therefore scopes v1 to the deterministic, offline half of the pipeline:

- `leitir bts-port-contract` computes the donor's COMPLETE Python BTS
  (unchanged `run_bts_compute`), translates the portable contract into a
  Go test file, and builds port attribution evidence.
- It **never executes** agent-written target-language code. Its own JSON
  output says so explicitly (`"containment_proof": "not_executed_v1"`,
  with a `containment_proof_detail` explaining exactly why and what would
  be required).
- Proving an agent-written Go implementation against the translated
  contract under containment requires a Go-capable containment rootfs.
  That is out of this change's scope and is tracked as explicit follow-up
  work (see "What remains unproven" below), not silently implied to exist.

Choosing **Go** as the v1 target language (rather than JavaScript, which
this environment could actually execute via a locally available Node.js
runtime) was deliberate: Go's error-return model is the concrete case the
issue itself uses to motivate the whole ADR, so Go gives the strongest,
most honest demonstration of the reject path this ADR is centrally about.
A future PR that adds containment for a scripting language with a real
exception mechanism (JavaScript, for example) would need a materially
different -- and looser -- portable subset; that is a separate design
decision, not a free extension of this one.

### 4. The hard boundary (normative, unconditional)

Leitir **never** performs automatic source-to-source translation, in this
change or any future extension of it. The division of labour is fixed:

1. Leitir extracts donor behaviour (an ADR-0008 `COMPLETE` BTS) and, from a
   caller-declared portable contract, deterministically renders the
   **assertions about behaviour** in the target language --
   `translate_contract` never reads or transforms the donor's Python
   source text into target-language source.
2. The **agent** writes the target-language implementation. Leitir never
   takes custody of that file: it is not read, bundled, hashed, or
   inspected by any function in this module.
3. A future `bts-run`-equivalent for the target language proves the
   agent's implementation against the translated contract under
   containment before admission. Until that exists, no port artifact from
   this module may be represented as "proven" -- it is translated and
   attributed evidence only, and its own output says so.

The deterministic steps (evidence extraction, contract translation, license
resolution, attribution) stay with the tool. The non-deterministic step
(writing the implementation) belongs to the agent. Nothing in this ADR
collapses that boundary.

### 5. What is proven end-to-end vs. explicitly unproven

**Proven in this change** (deterministic, offline, covered by
`tests/test_port_contract.py` and `tests/test_port_contract_cli.py`,
byte-identical across four `PYTHONHASHSEED` values):

- Donor behaviour extraction: an unmodified `run_bts_compute` produces a
  `COMPLETE` Python BTS from the same fixture shelf
  `tests/test_bts_cli.py` uses.
- Portable-contract classification and translation into a deterministic Go
  test file, driven end to end through `leitir bts-port-contract`.
- The reject path: a `RAISES` case is rejected with a typed, actionable
  `BTSRejectReason` and no output directory is left behind -- never
  approximated.
- Port attribution: `evaluate_license_policy` runs unmodified over donor
  source bytes; an incompatible recipient license policy fails closed with
  `REJECT_LICENSE_INCOMPATIBLE`, exactly as it would for a same-language
  reuse packet.
- Cross-digest integrity: a portable contract whose `bts_digest` does not
  match the recomputed donor BTS is rejected with
  `REJECT_PROVENANCE_MISMATCH`.

**Explicitly unproven, not claimed, and not faked:**

- Executing an agent-written Go implementation and observing it pass (or
  correctly fail) the translated contract. This requires either a
  Go-capable containment rootfs (ADR-0009 S2 ratification territory) or an
  uncontained execution path this project's fail-closed discipline does
  not permit as a substitute. `bts-port-contract` says this plainly in its
  own JSON output rather than implying it. Tracked as issue #277.
- Any donor-ban or exact-parity proof analogous to ADR-0009 Decision 5/6
  for the target-language side, since no execution occurs.
- Any target language other than Go.

## Links

- Issue #270 -- D1: evidence-assisted cross-language port
- Issue #277 -- D1 remainder: execute an agent-written port against the translated contract under containment (tracks the containment-proof half this ADR explicitly scopes out; see Decision 5)
- [ADR-0008 -- BTS foundation](0008-behavioral-transplant-set.md)
- [ADR-0009 -- Transplant validation, including Amendment 1](0009-transplant-validation.md)
- [ADR-0010 -- Capability and suitability](0010-capability-and-suitability.md)
- [ADR-0011 -- Reuse packet and attribution](0011-reuse-packet-and-attribution.md)
- [ADR-0012 -- Polyglot graph via tree-sitter](0012-polyglot-graph-via-tree-sitter.md)
- `src/leitir/port_contract.py`, `tests/test_port_contract.py`,
  `tests/test_port_contract_cli.py`
