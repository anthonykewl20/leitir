# Official SBOM schema validation — 2026-09-05

Four unmodified outputs from the actual release-source CLI pass their official version-matching schemas: Requests corpus SPDX2.3/CycloneDX1.5 (two entries) and Packaging corpus SPDX2.3/CycloneDX1.5 (one entry). All CLI exits are0. Generation and validation ran in network-disabled `unshare -Urn` subprocesses against existing verified materialized shelves. `cli-commands.json` and `validation-command.json` record exact invocations, head, environment source path, output hashes and exits.

Official schemas were downloaded unchanged from the SPDX spdx-spec `v2.3` tag and CycloneDX specification `1.5` tag. The canonical CycloneDX website URL previously failed; the official versioned repository supplies the same declared schema identity. Both external CycloneDX references (`spdx.schema.json` and `jsf-0.82.schema.json`) are present unmodified and registered under their official declared IDs. Every schema passes its own declared JSON Schema metaschema. `validation-results.json` records source URLs, byte counts, SHA256 hashes, versions and results.

Validation uses isolated `jsonschema[format]==4.26.0` and `referencing==0.37.0`, with all formats declared by the official schemas enabled: date-time, idn-email, iri-reference and uri. No project or runtime dependencies changed. No invented schemas, removed constraints, disabled formats or unresolved reference fallbacks were used.

Two mutations of real emitted documents reject: an invalid SPDX external-reference category and a CycloneDX license absent from the official referenced license schema. Original output files remain unchanged. `requests-*-altered.json` and the negative results preserve that evidence.

This establishes schema conformance for these actual outputs, not correctness of every package fact or complete dependency-graph coverage. The CLI ran with this evidence directory as --cwd, so no project lockfile augmented dependency edges. Schema validation does not prove completeness of the dependency graph. No production defect was found in this bounded validation.

The accompanying `evidence.tar.gz` preserves every original evidence file, including the exact executed Python scripts. It excludes the downloaded corpus. Extract it into a separate directory to inspect the recorded scripts and original filenames.
