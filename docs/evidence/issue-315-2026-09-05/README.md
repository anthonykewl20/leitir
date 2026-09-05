# Live remediation evidence for #315

Requests parse_header_links exists in requests.utils, but check previously marked invalid requests.parse_header_links access ok. Preserve qualified consumer imports and attribute chains, map source modules to established import roots, and follow explicit module-level reexports before accepting an exact definition. Bare-name collisions are unresolved, never ok. Actual Requests consumers exercise invalid top-level access, valid utils access, and get/Session public reexports.

Inputs come from actual published sources and the production CLI/transports. `live.txt` is the live-gated regression execution, not a mocked provider. Default-suite and static checks are regression/hygiene gates and do not substitute for that evidence. The initial raw audit is retained in the assigned workspace under `/tmp/leitir-audit-20260905`; the issue records the original pins and defect. Full-suite/CI output and review disposition are recorded in the PR.
