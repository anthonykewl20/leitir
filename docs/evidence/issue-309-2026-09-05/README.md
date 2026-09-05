# Live remediation evidence for #309

Packaging 24.1 parse() previously returned COMPLETE while omitting dependencies owned by the reached Version class. Traverse runtime dependencies of nested source included by each definition, preserve graph ownership/provenance, charge traversal work, and bump the resolver identity to v2. The real published Packaging CLI probe now rejects the unsupported closure and rejects tampered donor bytes.

Inputs come from actual published sources and the production CLI/transports. `live.txt` is the live-gated regression execution, not a mocked provider. Default-suite and static checks are regression/hygiene gates and do not substitute for that evidence. The initial raw audit is retained in the assigned workspace under `/tmp/leitir-audit-20260905`; the issue records the original pins and defect. Full-suite/CI output and review disposition are recorded in the PR.
