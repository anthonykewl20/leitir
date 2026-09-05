# Live remediation evidence for #316

Repeated benchmark queries recovered the same truncated immutable tree separately. Cache only successfully validated complete listings by repository and exact commit within the GitHub tree-source instance, bounded to four listings and 600,000 retained blob entries. Preserve recovery/coverage metadata and never cache failed walks or partial prefixes.

Inputs come from actual published sources and the production CLI/transports. `live.txt` is the live-gated regression execution, not a mocked provider. Default-suite and static checks are regression/hygiene gates and do not substitute for that evidence. The initial raw audit is retained in the assigned workspace under `/tmp/leitir-audit-20260905`; the issue records the original pins and defect. Full-suite/CI output and review disposition are recorded in the PR.

Review exposed a shared-instance cache eviction race using five actual upstream listings. The real public API raised KeyError between membership and read. A short cache lock fixes lookup/eviction atomicity; the same scheduling probe now returns the original immutable listing without error. `concurrency-before.txt` and `live.txt` record the failing/passing real-data probe.
