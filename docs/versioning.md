# Versioning And Compatibility

## Release Versioning

Leitir follows SemVer within the 0.x series:

- Patch releases (0.1.1, 0.1.2, 0.1.3, ...) carry all incremental work: audit
  findings, bug fixes, and feature/behavior increments alike (e.g. the
  Behavioral Transplant Set, composition/multi-language, Search v2). The patch
  number is an incrementing counter per thematic milestone, not a bugfix-only
  gate.
- There is no currently planned minor bump; if one is ever cut it denotes a
  deliberate compatibility boundary within 0.x, not a feature gate.
- Breaking changes are permitted before 1.0 and must be called out in the
  changelog.
- `v1.0` is reserved for the 10,000-user adoption milestone, not for a single
  feature or the production-ready quality label.

Production-ready quality is a quality bar achieved within 0.x when the
required audit, scorecard, and real-load criteria are satisfied. It is not
automatically implied by a version number.

## Manifest Compatibility

Materialized shelves carry `leitir-manifest.json`. Verified shelves must carry
the load-time `materialized_tree_hash`, its algorithm, and its scope. On load,
Leitir validates the manifest and verifies the materialized tree; missing,
malformed, unsupported, or mismatched integrity data is rejected fail-closed.

A manifest schema or integrity-contract bump therefore means existing corpora
are not silently accepted as compatible. A legacy verified shelf that lacks the
load-time digest can be refreshed with:

```bash
leitir upgrade-cache --root <root>
```

`upgrade-cache` computes and persists the digest for eligible legacy verified
shelves. It must only be used when the bytes already on disk are trusted. If a
shelf is suspicious or its contents are corrupted, remove and re-materialize
it instead:

```bash
LEITIR_HOME=<root> leitir remove <spec>
leitir get <spec> --root <root>
```

New materializations write the current manifest integrity fields as part of
their atomic staged install.

## Snapshot Compatibility

Snapshot locks and their tarballs have an explicit format and corpus version.
The current implementation exports format v2/corpus v2 locks and requires the
adjacent tarball's `tarball_sha256` to match the tarball bytes. Export also
prints `lock_sha256`, the SHA-256 of the exact lock bytes, and import requires
that trusted digest through `--lock-sha256`.

Existing v1 snapshots are no longer importable. Re-export the source corpus to
produce a v2 lock and tarball:

```bash
leitir export --root <root> -o <new-lock>
```

Keep the resulting lock and adjacent `.tar.gz` together. Import verifies the
lock, tarball, metadata, manifests, and source tree hashes before installing
the corpus.

## Breaking-Change Disclosure

Breaking CLI, manifest, snapshot, and compatibility changes are documented in
`CHANGELOG.md` under `[Unreleased]` before release, with the affected behavior
and migration action. The changelog is the release-facing record; this policy
document explains the compatibility rules and does not replace release notes.

The current `[Unreleased]` entries document the snapshot v2 change,
`--lock-sha256` requirement, and legacy cache refresh behavior.
