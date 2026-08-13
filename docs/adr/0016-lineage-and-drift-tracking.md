# ADR-0016: Lineage and drift tracking

- Status: Accepted
- Deciders: leitir maintainers; consensus reviewers; consensus-terra review 2026-08-13 (ACCEPT-WITH-AMENDMENTS, amendments applied same day)
- Date: 2026-08-13
- Technical Story: #80 — Source lineage and upstream drift tracking

## Context and Problem Statement

A BTS is bound to an immutable donor commit, so the BTS itself cannot drift.
Maintainers nevertheless need reproducible evidence that the branch or tag from
which it was assembled has moved and whether recorded members changed. That
observation must not weaken the immutable provenance or historical packet.

## Decision Drivers

- The authoritative donor remains one immutable Git commit.
- A moving reference is observation scope, never donor identity.
- Missing repositories, commits, symbols, and network evidence must fail closed.
- ADR-0011's fixed v1 packet layout cannot be silently widened.
- Content identifiers should be computable offline with the stdlib.
- Reports and manifests must be closed, digest-bound, and deterministic.

## Considered Options

- Embed branch and lineage fields in v1 `donor.json`.
- Treat a branch or tag as the authoritative donor.
- Add a versioned lineage manifest to a new bundle format and compare a separately
  tracked ref against the immutable baseline (chosen).

## Decision Outcome

Chosen option: "a non-authoritative tracked Git ref and a required, digest-bound
lineage manifest in bundle v2", because this preserves immutable BTS authority
while making later changes observable and reproducible.

### 1. Immutable baseline and non-authoritative tracked reference

Pinned commits cannot drift. `DonorSnapshot` requires `source == "git-commit"`
and a full 40-character commit SHA (`bts.py:49-74`). The separately recorded
`TrackedGitRef` names a branch or tag by its full `refs/...` name. It is explicitly
non-authoritative. At assembly, its resolved target must equal the authoritative
donor commit; otherwise construction rejects.

At check time Leitir resolves that same ref, materializes the resulting new
commit under the existing verified-snapshot discipline, and compares every
recorded member's bytes and symbol identity to the baseline. Ref movement never
rewrites the baseline commit, BTS, packet, or predecessor record.

### 2. Typed records and outcomes

All records are frozen, slotted dataclasses. Enums serialize by `.value`.
Closed-schema decoding rejects missing/unknown fields, versions, malformed
digests or refs, duplicate identities, and noncanonical ordering.

```python
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

@dataclass(frozen=True, slots=True)
class TrackedGitRef:
    repository_id: str
    ref_name: str                 # full refs/heads/... or refs/tags/...
    observed_commit_sha: str      # equals authoritative commit at assembly
    resolver_id: str
    resolver_version: str

@dataclass(frozen=True, slots=True)
class LineageMember:
    node: NodeId
    source: SourceRef
    locator_version: str
    member_bytes_sha256: str
    swhid_cnt: str | None

@dataclass(frozen=True, slots=True)
class LineageManifest:
    schema_version: str           # exactly leitir-lineage-v1
    bts_digest: str
    baseline_commit_sha: str
    tracked_ref: TrackedGitRef
    members: tuple[LineageMember, ...]
    predecessor_bundle_digests: tuple[str, ...]
    lineage_digest: str

class DriftAlertKind(str, Enum):
    SYMBOLS_CHANGED = "symbols_changed"
    BYTES_CHANGED = "bytes_changed"

@dataclass(frozen=True, slots=True)
class DriftAlert:
    kind: DriftAlertKind
    baseline_member: LineageMember
    observed_source: SourceRef | None
    observed_member_bytes_sha256: str | None
    detail_code: str

@dataclass(frozen=True, slots=True)
class DriftReport:
    schema_version: str
    lineage_digest: str
    observed_commit_sha: str | None
    alerts: tuple[DriftAlert, ...]
    rejection_reason: BTSRejectReason | None
    detail_code: str | None
    report_digest: str
```

`members` is exhaustive, sorted by the complete `(NodeId, SourceRef)` identity,
and unique. `predecessor_bundle_digests` is sorted and unique. Every ordering key
is exhaustive; genuine ties reject rather than using insertion order.

Outcomes are exact:

- **COMMIT_DELETED:** an unreachable baseline commit rejects with
  `REJECT_MOVING_REFERENCE` and
  `lineage_baseline_commit_unreachable_v1`; an unreachable tracked ref uses
  `lineage_tracked_ref_unreachable_v1`.
- **SYMBOLS_CHANGED:** emits an alert. The locator is an explicitly versioned
  derivation from the complete `NodeId` and `SourceRef` contract in
  `graph/model.py:82-135`. Missing or ambiguous location is conservatively
  changed. A regex or API-surface name match never proves sameness.
- **BYTES_CHANGED:** emits an alert for a member-span SHA-256, path, or Git blob
  identity difference.
- Resolver, network, or authentication failure rejects the check with
  `REJECT_FETCH_FAILED` and `lineage_ref_resolution_unavailable_v1`.
- A demonstrably gone repository is COMMIT_DELETED and rejects; it is never
  reported as clean.

A rejection rejects **that drift check only**. It never invalidates the historical
BTS or packet, whose integrity remains bound to the original commit, tree, blob,
and member identities. This preserves ADR-0006's integrity-not-authenticity
boundary and ADR-0011 section 8.

### 3. Bundle-v2 placement and binding

This decision explicitly **replaces** issue #80's requirement to embed lineage
inside `donor.json`. ADR-0011 section 2 fixes the v1 layout, and the exact-field
loader at `transplant.py:43-53,905-934` rejects additional donor fields.

A new `leitir-transplant-bundle-v2` therefore adds required `lineage.json`. The
v2 loader validates its closed schema, includes it in `bundle.json`'s file
inventory and logical bundle digest, and requires its `bts_digest` to equal the
subject in both `packet.json` and `bts.json`. V1 bundles remain readable strictly
as v1; loaders do not reinterpret or upgrade them silently.

### 4. Offline SWH content identifiers

When present, `LineageMember.swhid_cnt` is exactly
`swh:1:cnt:<40 lowercase hex>` and must equal
`f"swh:1:cnt:{source.blob_sha}"`. The Software Heritage SWHID specification,
Semantics section, states: **"for contents, the intrinsic identifier is the
`sha1_git` hash returned by `swh.hashutil.MultiHash.digest`, i.e., the SHA1 of a
byte sequence obtained by juxtaposing the ASCII string `\"blob\"` (without
quotes), a space, the length of the content as decimal digits, a NULL byte, and
the actual content of the file."** This is exactly the existing `_git_blob_sha`
implementation at `bts.py:660-661`.

No `swh.model` dependency or subprocess is needed. This corrects the issue's
premise that an SWHID needs network access: computation is wholly offline; only
optional remote resolution needs a network. Resolution is advisory-only, never
gates construction, loading, BTS status, or drift success, and volatile remote
resolution state is never serialized.

### 5. Canonicalization and test gate

Canonical JSON uses strict UTF-8, sorted keys, compact separators,
`ensure_ascii=False`, `allow_nan=False`, and one LF. Digests are lowercase
`sha256:<64 hex>` over the canonical payload with the digest field omitted.

The implementation gate is `tests/test_lineage.py`. It covers fixture commit
deltas, offline operation and network failure, deleted repositories, conservative
symbol matching, manifest/bundle tampering and digest binding, hash-seed
determinism, and published Software Heritage/Git blob vectors.

### Positive Consequences

- Historical artifacts remain immutable while upstream movement is visible.
- Symbol uncertainty cannot be mistaken for proof of sameness.
- SWH content IDs add interoperable identity without runtime dependencies.

### Negative Consequences

- Bundle v2 requires a new writer, strict loader, and migration-aware tooling.
- Network and repository deletion can make a check reject without changing the
  validity of the historical artifact.
- Conservative symbol location may alert on harmless refactors.

## Links

- [#80 — Source lineage and upstream drift tracking](https://github.com/anthonykewl20/leitir/issues/80)
- [ADR-0006 — Load-time tree verification](0006-load-time-tree-verification.md)
- [ADR-0011 — Reuse packet and attribution](0011-reuse-packet-and-attribution.md)
- [Software Heritage persistent identifiers](https://docs.softwareheritage.org/devel/swh-model/persistent-identifiers.html)
