# Live remediation evidence for #328

The actual full CLI benchmark returned zero eligible files for four fmt C++ tasks because the C++ adapter omitted .h. Include ordinary .h headers for explicit C++ selection while preserving default C routing. All four real pinned fmt definitions are re-fetched, byte-verified and found through the public CLI.

Inputs come from actual published sources and the production CLI/transports. `live.txt` is the live-gated regression execution, not a mocked provider. Default-suite and static checks are regression/hygiene gates and do not substitute for that evidence. The initial raw audit is retained in the assigned workspace under `/tmp/leitir-audit-20260905`; the issue records the original pins and defect. Full-suite/CI output and review disposition are recorded in the PR.
