# ADR-0017: Occupied-recipient validation gate

- Status: Accepted
- Deciders: leitir maintainers; consensus reviewers; consensus-terra review 2026-08-13 (ACCEPT-WITH-AMENDMENTS, amendments applied same day)
- Date: 2026-08-13
- Technical Story: #82 — Validate attachment to occupied recipients

## Context and Problem Statement

ADR-0009 proves an isolated transplant against an empty recipient. It does not
prove that attaching the same BTS to an occupied project avoids binding and path
collisions or preserves that project's behavior. Occupied-recipient evidence must
extend, not reinterpret, the existing validation receipt.

## Decision Drivers

- Recipient code and tests are untrusted and require the full S2 boundary.
- Collision absence requires exhaustive manifest-bound parsing, not a lossy API
  index or observed runtime use.
- Recipient behavior needs a pre-attachment baseline that cannot be refreshed to
  excuse a failed attachment.
- Composition conflicts must be resolved before any attachment is mounted.
- Corpus membership and case outcomes must remain non-compensating.

## Considered Options

- Amend ADR-0009's two plans and overload its donor baseline.
- Use API-surface diffs and observed use as collision authority.
- Add a distinct post-ADR-0009 occupied-recipient gate with two additional roles,
  strict inventories, a recipient baseline, and exact parity (chosen).

## Decision Outcome

Chosen option: "a separate occupied-recipient validation gate consuming the
ADR-0009 receipt", because donor-isolation proof and recipient-attachment proof
have different subjects, roles, collision authority, and baselines.

This is a **new ADR, not an amendment to ADR-0009**. ADR-0009 section 3 continues
to pin one backend and two mount plans. This decision adds two role-distinct
plans—`recipient-baseline` (recipient present; BTS and donor absent) and
`occupied-rerun` (recipient and attached BTS present; donor absent)—for four plans
in total. ADR-0009 remains unchanged, is a prerequisite, and its accepted receipt
is consumed.

### 1. Strict recipient binding inventory

Collision authority is a new, strict, fail-closed recipient binding inventory
derived from **every** source file declared by a verified recipient manifest in
the supported language set. Parse failure, unsupported language, duplicate
identity, missing declared bytes, or omitted source rejects.

`extract_api_surface` and `diff_api_indexes` are supplementary diagnostics only.
The current extractor silently skips unreadable and syntactically invalid source
and does not report same-name duplicates (`apisurface.py:100-177,314-342`), so it
cannot establish collision absence.

The collision algorithm is normative:

1. validate the recipient source manifest and derive the exhaustive inventory;
2. derive every emitted BTS identity from BTS member identity plus `ModuleMap`
   prefix replacement, matching `relocate.py:673-718` emission semantics;
3. sort recipient and emitted identities by canonical
   `(language, module, qualified_name, scope, kind)` tuples and intersect them;
4. reject every overlap, regardless of observed use, with
   `REJECT_UNRESOLVED_EDGE` and a closed collision detail code; and
5. reject module-path collisions independently.

"Actually used" is neither stable nor sufficient: an unexecuted recipient
binding can still be shadowed later. This extends, rather than replaces, the
`RecipientBindingManifest` discipline at `relocate.py:205-236,703-718`.

### 2. Recipient baseline and exact parity

`RecipientBaselineEvidence` is separate from, and never overloads, ADR-0009's
donor `ContractBaselineEvidence`. It is captured under the recipient-baseline S2
plan from the verified attached-recipient-absent snapshot and requires
`failed == 0`.

A baseline is **QUALIFIED** only after two executions under the identical plan
produce identical canonical ID tuples, complete outcome vectors, and counts. It
binds the recipient manifest digest, test-set/runner/config/plugin closure,
mount-plan digest, execution-policy digest, canonical IDs, all per-ID outcomes,
counts, and its evidence digest.

The post-attachment run must have exactly the same canonical ID tuple,
`OutcomeCounts`, and per-ID outcomes. Any delta rejects with
`REJECT_HARD_GATE_FAILED`. Missing, malformed, stale, or same-change-refreshed
baseline evidence rejects. No baseline refresh may make an attachment pass, and
a failed attachment run is never retried to seek a pass. Flakiness is honestly
indistinguishable from transplant breakage at this gate; either is failure.

### 3. Containment and threat rejection

Recipient tests are arbitrary untrusted code and execute under the same S2
nsjail contract: release-pinned closure, read-only verified inputs, bounded
tmpfs, namespaces, cgroup v2, seccomp, exact opt-in, and an authoritative
applied-state receipt (`exec_sandbox.py:145-190,632-644,921-934`). Linux-only
support is deliberate. Unsupported Windows or other platforms reject rather
than run unsandboxed, consistent with ADR-0009 section 3 and README honesty.

`REJECT_EXECUTION_THREAT` covers unsupported OS/architecture, absent opt-in,
backend/rootfs/mount/policy/input-digest mismatch, unavailable applied-state
receipt, donor visibility, writable authorizing inputs, failed cgroup/network/
seccomp controls, resource exhaustion, and non-authoritative teardown. No
diagnostic hook, process timeout, or host test command is a fallback.

### 4. ConflictMatrix prerequisite

Before attachment, this gate consumes issue #76's validated `ConflictMatrix`
from ADR-0013. Every conflict row is retained in canonical sort order and pinned
dispositions are applied. Hard or unresolved rows reject before mounting.
Unknown row versions, duplicate keys, candidate/recipient identity mismatches,
or an absent matrix reject fail closed; no conflict is regenerated from weaker
ambient evidence.

### 5. Typed contract

All records are frozen, slotted dataclasses, with closed schemas and canonical
tuple ordering.

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

class OccupiedRole(str, Enum):
    RECIPIENT_BASELINE = "recipient_baseline"
    OCCUPIED_RERUN = "occupied_rerun"

@dataclass(frozen=True, slots=True, order=True)
class RecipientBindingIdentity:
    language: str
    module: str
    qualified_name: str
    scope: str
    kind: str
    source_path: str
    source_digest: str

@dataclass(frozen=True, slots=True)
class RecipientBaselineEvidence:
    schema_version: str
    status: str                    # exactly qualified
    recipient_manifest_digest: str
    test_set_digest: str
    runner_closure_digest: str
    config_closure_digest: str
    mount_plan_digest: str
    execution_policy_digest: str
    canonical_test_ids: tuple[str, ...]
    outcomes: tuple[TestOutcomeEvidence, ...]
    counts: OutcomeCounts
    qualification_runs: int        # exactly 2
    evidence_digest: str

@dataclass(frozen=True, slots=True)
class OccupiedAttachmentPolicy:
    schema_version: str
    authority: str
    policy_id: str
    policy_version: str
    supported_languages: tuple[str, ...]
    recipient_manifest_schema: str
    inventory_rule_id: str
    inventory_rule_version: str
    collision_detail_registry_digest: str
    conflict_policy_digest: str
    recipient_baseline_mount_plan_digest: str
    occupied_rerun_mount_plan_digest: str
    recipient_baseline_execution_policy_digest: str
    occupied_rerun_execution_policy_digest: str
    corpus_manifest_digest: str
    content_digest: str
```

The policy additionally pins all prospective source/file/byte/binding/test/work
limits through its content digest. Unknown fields, malformed digests, booleans as
integers, unsupported schema values, unordered language/identity tuples, and
duplicate exhaustive keys reject.

### 6. Occupied corpus and test gate

The occupied corpus contains at least five donor-recipient cases and at least two
required recipient profile classes: asynchronous web/API-style and synchronous
CLI-style. Membership is monotonic under the E4b model
(`bts_exit_gate.py:24-27,176-240,314-333`). Removal requires ADR-0009's tombstone,
independent-review, superseding-manifest, and release-note process. Every case
runs; corpus acceptance is a non-compensating AND and no failed case is omitted.

The implementation gate is `tests/test_bts_occupied.py`. It covers exhaustive
inventory failures, binding and module collisions, both profiles, qualified
baseline reproducibility, stale/tampered baselines, parity deltas, conflict
matrix failures, S2 receipt failures, corpus monotonicity, ordering permutations,
and hash-seed independence.

### Positive Consequences

- Attachment cannot hide recipient bindings behind lossy extraction.
- Recipient regressions and flaky evidence fail honestly and deterministically.
- ADR-0009 remains a stable prerequisite rather than acquiring role ambiguity.

### Negative Consequences

- Occupied validation requires two more contained executions plus qualification.
- Strict language and parser support rejects projects that diagnostics could
  partially inspect.
- Linux/nsjail remains the only execution path.

## Links

- [#82 — Occupied-recipient validation gate](https://github.com/anthonykewl20/leitir/issues/82)
- [ADR-0009 — Transplant validation](0009-transplant-validation.md)
- [ADR-0013 — Dependency composition conflict matrix](0013-dependency-composition-conflict-matrix.md)
