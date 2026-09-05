# Live remediation evidence for #310

A valid signed manifest previously accompanied fabricated cached API signatures. Re-derive API evidence under the verified target lock and compare it with the cache before returning it. Rebuild altered caches; preserve unchanged cache writes and the existing single-lock contract. The live Packaging 24.1 probe uses an actual Ed25519 signature, fabricated cache contents, and a corrupted-signature rejection.

Inputs come from actual published sources and the production CLI/transports. `live.txt` is the live-gated regression execution, not a mocked provider. Default-suite and static checks are regression/hygiene gates and do not substitute for that evidence. The initial raw audit is retained in the assigned workspace under `/tmp/leitir-audit-20260905`; the issue records the original pins and defect. Full-suite/CI output and review disposition are recorded in the PR.

Additional actual signed-cache probe: a real Packaging example was modified and its classification recomputed. The previous implementation returned fabricated code. Both API and examples now derive from verified source; the live test covers cache repair and signature rejection.
