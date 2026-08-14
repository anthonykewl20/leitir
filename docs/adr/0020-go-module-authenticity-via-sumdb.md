# ADR-0020: Go module authenticity via SumDB

- Status: Accepted
- Deciders: leitir maintainers; consensus adjudication 2026-08-14
- Date: 2026-08-14
- Technical Story: #147 — Authenticate vanity Go modules from the public proxy

## Context and Problem Statement

Go module paths are not reliable GitHub repository identities. Vanity hosts must
not be accepted as GitHub sources: a live `go-get` probe for
`google.golang.org/protobuf` resolved to `go.googlesource.com`, not GitHub. The
2026-08-14 consensus adjudication therefore rejected a go-get-to-GitHub
fallback for unsupported Go module hosts.

## Decision Drivers

- A module archive needs an authenticity authority independent of its delivery
  endpoint.
- Historical checksum lookup heads must remain valid without permitting local
  rollback or equivocation.
- Missing, malformed, mismatched, or unverifiable evidence must reject.

## Considered Options

- Reject every Go module without a supported Git repository host.
- Follow vanity metadata and infer a GitHub repository.
- Shelf the public Go proxy module zip only after mandatory SumDB authentication
  (chosen).

## Decision Outcome

Chosen option: "a `go-module-zip` source authenticated by the public Go proxy
and SumDB", because it preserves a verifiable source path for vanity modules
without inventing a GitHub identity.

For unsupported Go module hosts, Leitir downloads the versioned zip from
`proxy.golang.org` and treats it as the distinct `go-module-zip` source. Before
extraction, it must authenticate the corresponding `sum.golang.org` lookup
record: verify the signed tree note with the pure-Python RFC 8032 Ed25519
implementation, verify the record's tile inclusion proof, calculate the Go
`h1:` directory hash, and require it to equal the authenticated SumDB value.
The manifest records `module_path`, `module_version`, `proxy_url`, `zip_sha256`,
and `sumdb_h1`.

A lookup's signed head authenticates the lookup record at its historical tree
size; it need not equal the locally persisted latest head. Leitir separately
authenticates `/latest`, proves it is consistent with the persisted
`sumdb-tree-head.json` head, rejects rollback or same-size hash changes, and
persists only an advancing latest head. Every malformed signature, tree head,
tile, inclusion proof, consistency proof, archive, module root, or hash is a
hard failure; there is no unauthenticated proxy or GitHub fallback.

Go major-version suffixes such as `/v2` are module identity, not repository
subpaths. They remain part of the module path for proxy and SumDB operations and
are not recorded as a Git subpath.

### Positive Consequences

- `google.golang.org`, `gopkg.in`, and other vanity module paths can resolve
  without a guessed repository mapping.
- The delivered zip is bound to the public checksum database and a
  rollback-resistant local tree-head history.
- Manifests retain enough source and checksum provenance to inspect the shelf.

### Negative Consequences

- Module zips are module projections, not full repositories.
- Scoped search over `go-module-zip` shelves remains GitHub-tree-based and does
  not use those shelves as scoped-search sources.
- `sumdb_h1` is not yet exported as an SBOM checksum.

## Links

- [#147 — Go module authenticity](https://github.com/anthonykewl20/leitir/issues/147)
- [ADR-0004 — Local source materialization](0004-local-source-materialization.md)
- [ADR-0006 — Load-time tree verification](0006-load-time-tree-verification.md)
