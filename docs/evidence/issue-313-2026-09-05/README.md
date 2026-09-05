# Live remediation evidence for #313

attrs funding metadata previously resolved to github.com/sponsors/hynek, while BeautifulSoup4 could not materialize despite a valid PyPI sdist. Prioritize repository/source links, exclude funding and reserved GitHub routes, and use the existing explicitly degraded registry-only channel when no supported repository is declared. Missing checksum evidence still rejects. Real attrs 24.2.0 and BeautifulSoup4 4.12.3 downloads plus tampered-source rejection pass.

Inputs come from actual published sources and the production CLI/transports. `live.txt` is the live-gated regression execution, not a mocked provider. Default-suite and static checks are regression/hygiene gates and do not substitute for that evidence. The initial raw audit is retained in the assigned workspace under `/tmp/leitir-audit-20260905`; the issue records the original pins and defect. Full-suite/CI output and review disposition are recorded in the PR.
