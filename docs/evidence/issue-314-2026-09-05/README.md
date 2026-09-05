# Live remediation evidence for #314

Published rsc/quote v1.5.2 contains valid quoted go.mod tokens that lock rejected. Parse Go quoted strings/comments for both installed-version detection and closure extraction. Label one go.mod direct-only in filesystem and verified-manifest paths and update the parser identity. The official Go parser and real module graph establish the syntax and omitted transitive dependency; public lock now materializes the actual requirement with honest graph metadata.

Inputs come from actual published sources and the production CLI/transports. `live.txt` is the live-gated regression execution, not a mocked provider. Default-suite and static checks are regression/hygiene gates and do not substitute for that evidence. The initial raw audit is retained in the assigned workspace under `/tmp/leitir-audit-20260905`; the issue records the original pins and defect. Full-suite/CI output and review disposition are recorded in the PR.
