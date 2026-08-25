"""Conservative distribution -> import-root cataloging (issue #256).

Given only local, static evidence about what import roots a distribution
declares (e.g. the textual contents of a ``top_level.txt``-shaped record,
handed in by the caller -- never installed, never imported, never fetched
over the network), this module decides whether that distribution can be
catalogued as a resolved :class:`~leitir.usage.ImportMapping`, or must be
recorded as typed-unresolved.

Three ways a distribution ends up typed-unresolved, using only members of
the frozen :class:`~leitir.usage.UnresolvedState` enum:

- no local evidence at all (missing), or evidence recorded via a source
  kind this catalog does not know how to interpret (unsupported packaging
  shape) -> :attr:`~leitir.usage.UnresolvedState.UNSUPPORTED_SYNTAX`
- more than one candidate root and no single coherent piece of evidence
  ties them together, or two distinct distributions both claim the same
  import root -> :attr:`~leitir.usage.UnresolvedState.AMBIGUOUS_BINDING`

A distribution backed by one coherent, supported piece of evidence that
declares multiple import roots (a legitimate multi-root distribution, e.g.
a package that ships both ``foo`` and ``foo_ext``) is still resolved --
multi-root is not, by itself, ambiguous.

Distribution names are normalized per PEP 503 for grouping and collision
detection only; normalization is never used to *invent* an import root --
absent evidence is always typed-unresolved, never guessed.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from .contract import IMPORT_MAPPING_SCHEMA_VERSION, MAX_IMPORT_MAPPINGS, MAX_IMPORT_ROOTS_PER_MAPPING, ImportMapping
from .contract import UnresolvedState as _UnresolvedState
from .errors import UsageErrorEvidence, UsageUnsupportedError

CATALOG_SCHEMA_VERSION = "leitir-usage-import-catalog-v1"
DISTRIBUTION_RECORD_SCHEMA_VERSION = "leitir-usage-distribution-record-v1"
UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION = "leitir-usage-unresolved-distribution-v1"

# Re-exported so callers of this module don't also need to import contract.py.
UnresolvedState = _UnresolvedState

#: Local-evidence source kinds this catalog knows how to interpret
#: conservatively. Anything else is an unsupported packaging shape.
SUPPORTED_EVIDENCE_SOURCES = frozenset({"top-level-txt", "record-derived-single-root"})

MAX_DISTRIBUTION_RECORDS = MAX_IMPORT_MAPPINGS

_PEP503_NORMALIZE_PATTERN = re.compile(r"[-_.]+")


def normalize_distribution_name(name: str) -> str:
    """Return the PEP 503 normalized form of a distribution name (lowercased, ``-``-joined)."""

    return _PEP503_NORMALIZE_PATTERN.sub("-", name).lower()


@dataclass(frozen=True, slots=True)
class DistributionRecord:
    """One local, static piece of evidence about a distribution's declared import roots.

    ``declared_roots`` is empty when the evidence source is present but
    states no root was found (a "missing mapping" record); ``source``
    identifies the kind of local evidence this came from and is preserved
    verbatim for the catalog's evidence trail.
    """

    schema_version: str
    distribution: str
    declared_roots: tuple[str, ...]
    source: str

    def __post_init__(self) -> None:
        if self.schema_version != DISTRIBUTION_RECORD_SCHEMA_VERSION:
            raise ValueError("distribution_record.schema_version is unsupported")
        if not self.distribution:
            raise ValueError("distribution_record.distribution must be non-empty")
        if not self.source:
            raise ValueError("distribution_record.source must be non-empty")
        if len(set(self.declared_roots)) != len(self.declared_roots):
            raise ValueError("distribution_record.declared_roots must not contain duplicates")
        if any(not root for root in self.declared_roots):
            raise ValueError("distribution_record.declared_roots entries must be non-empty")


@dataclass(frozen=True, slots=True)
class UnresolvedDistribution:
    """A distribution that could not be conservatively catalogued, with preserved evidence."""

    schema_version: str
    distribution: str
    state: _UnresolvedState
    reason: str
    evidence: tuple[DistributionRecord, ...]

    def __post_init__(self) -> None:
        if self.schema_version != UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION:
            raise ValueError("unresolved_distribution.schema_version is unsupported")
        if not self.distribution:
            raise ValueError("unresolved_distribution.distribution must be non-empty")
        if self.state not in (_UnresolvedState.AMBIGUOUS_BINDING, _UnresolvedState.UNSUPPORTED_SYNTAX):
            raise ValueError("unresolved_distribution.state must be AMBIGUOUS_BINDING or UNSUPPORTED_SYNTAX")
        if not self.reason:
            raise ValueError("unresolved_distribution.reason must be non-empty")
        if not self.evidence:
            raise ValueError("unresolved_distribution.evidence must be non-empty")


@dataclass(frozen=True, slots=True)
class ImportCatalog:
    """The outcome of cataloging a batch of :class:`DistributionRecord` evidence."""

    schema_version: str
    mappings: tuple[ImportMapping, ...]
    unresolved: tuple[UnresolvedDistribution, ...]

    def __post_init__(self) -> None:
        if self.schema_version != CATALOG_SCHEMA_VERSION:
            raise ValueError("import_catalog.schema_version is unsupported")
        if len(self.mappings) > MAX_IMPORT_MAPPINGS:
            raise ValueError("import_catalog.mappings exceeds the cap")
        distributions = [mapping.distribution for mapping in self.mappings]
        if len(set(distributions)) != len(distributions):
            raise ValueError("import_catalog.mappings must not repeat a distribution")


def _reject_records_cap(records: object) -> None:
    if isinstance(records, (list, tuple)) and len(records) > MAX_DISTRIBUTION_RECORDS:
        raise UsageUnsupportedError(
            UsageErrorEvidence(
                message="distribution record batch exceeds the supported cap",
                stage="validate",
                field="records",
                expected=f"<= {MAX_DISTRIBUTION_RECORDS}",
                actual=str(len(records)),
            )
        )


def build_import_catalog(records: tuple[DistributionRecord, ...]) -> ImportCatalog:
    """Conservatively catalog a batch of distribution evidence.

    Records are grouped by :func:`normalize_distribution_name`. Within a
    normalized group:

    - if more than one raw distribution name is present, the group is
      ambiguous (two distributions claim the same normalized identity);
    - otherwise, if any record in the group uses an unsupported evidence
      source, or every record declares zero roots, the distribution is
      typed-unresolved as unsupported (this also covers "no evidence
      found at all" -- the caller passes a zero-root record for that);
    - otherwise, if more than one record disagrees on the declared root
      set, the distribution is ambiguous;
    - otherwise the (single, coherent) declared root set becomes one
      :class:`~leitir.usage.ImportMapping` -- including when it declares
      more than one root (a legitimate multi-root distribution).

    Across groups, any import root claimed by more than one distribution's
    resolved mapping is retroactively ambiguous for every distribution
    that claims it -- never silently assigned to one of them.
    """

    _reject_records_cap(records)

    groups: dict[str, list[DistributionRecord]] = defaultdict(list)
    for record in records:
        groups[normalize_distribution_name(record.distribution)].append(record)

    mappings: dict[str, ImportMapping] = {}
    unresolved: dict[str, UnresolvedDistribution] = {}

    for normalized, group in sorted(groups.items()):
        raw_names = sorted({record.distribution for record in group})
        if len(raw_names) > 1:
            for distribution in raw_names:
                unresolved[distribution] = UnresolvedDistribution(
                    schema_version=UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
                    distribution=distribution,
                    state=_UnresolvedState.AMBIGUOUS_BINDING,
                    reason=f"multiple distinct distribution names normalize to {normalized!r}",
                    evidence=tuple(sorted(group, key=lambda item: item.distribution)),
                )
            continue

        distribution = raw_names[0]
        unsupported_sources = sorted({r.source for r in group if r.source not in SUPPORTED_EVIDENCE_SOURCES})
        if unsupported_sources:
            unresolved[distribution] = UnresolvedDistribution(
                schema_version=UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
                distribution=distribution,
                state=_UnresolvedState.UNSUPPORTED_SYNTAX,
                reason=f"unsupported evidence source kind(s): {', '.join(unsupported_sources)}",
                evidence=tuple(group),
            )
            continue

        if all(not record.declared_roots for record in group):
            unresolved[distribution] = UnresolvedDistribution(
                schema_version=UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
                distribution=distribution,
                state=_UnresolvedState.UNSUPPORTED_SYNTAX,
                reason="no local evidence declares any import root for this distribution",
                evidence=tuple(group),
            )
            continue

        candidate_root_sets = {tuple(sorted(record.declared_roots)) for record in group if record.declared_roots}
        if len(candidate_root_sets) > 1:
            unresolved[distribution] = UnresolvedDistribution(
                schema_version=UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
                distribution=distribution,
                state=_UnresolvedState.AMBIGUOUS_BINDING,
                reason="local evidence sources disagree on this distribution's import roots",
                evidence=tuple(group),
            )
            continue

        (roots,) = candidate_root_sets
        if len(roots) > MAX_IMPORT_ROOTS_PER_MAPPING:
            unresolved[distribution] = UnresolvedDistribution(
                schema_version=UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
                distribution=distribution,
                state=_UnresolvedState.UNSUPPORTED_SYNTAX,
                reason="declared import roots exceed the supported per-mapping cap",
                evidence=tuple(group),
            )
            continue

        mappings[distribution] = ImportMapping(
            schema_version=IMPORT_MAPPING_SCHEMA_VERSION,
            distribution=distribution,
            import_roots=roots,
        )

    # Cross-distribution collision: the same import root resolved for more
    # than one distribution is ambiguous for all of them -- never assigned.
    root_owners: dict[str, list[str]] = defaultdict(list)
    for distribution, mapping in mappings.items():
        for root in mapping.import_roots:
            root_owners[root].append(distribution)
    contested_roots = {root: owners for root, owners in root_owners.items() if len(owners) > 1}
    if contested_roots:
        contested_distributions = sorted({distribution for owners in contested_roots.values() for distribution in owners})
        for distribution in contested_distributions:
            group = [record for record in records if record.distribution == distribution]
            unresolved[distribution] = UnresolvedDistribution(
                schema_version=UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION,
                distribution=distribution,
                state=_UnresolvedState.AMBIGUOUS_BINDING,
                reason="import root is claimed by more than one distribution",
                evidence=tuple(group),
            )
            del mappings[distribution]

    return ImportCatalog(
        schema_version=CATALOG_SCHEMA_VERSION,
        mappings=tuple(mappings[key] for key in sorted(mappings)),
        unresolved=tuple(unresolved[key] for key in sorted(unresolved)),
    )


__all__ = [
    "CATALOG_SCHEMA_VERSION",
    "DISTRIBUTION_RECORD_SCHEMA_VERSION",
    "MAX_DISTRIBUTION_RECORDS",
    "SUPPORTED_EVIDENCE_SOURCES",
    "UNRESOLVED_DISTRIBUTION_SCHEMA_VERSION",
    "DistributionRecord",
    "ImportCatalog",
    "UnresolvedDistribution",
    "UnresolvedState",
    "build_import_catalog",
    "normalize_distribution_name",
]
