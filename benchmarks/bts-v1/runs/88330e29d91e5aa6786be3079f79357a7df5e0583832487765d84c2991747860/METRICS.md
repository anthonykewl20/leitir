# BTS evaluation metrics

- Run digest: `88330e29d91e5aa6786be3079f79357a7df5e0583832487765d84c2991747860`
- Manifest digest: `9ebc44bf1903e0635976175a770ea93c3842884c4b4ed9cf90ae2c62bc58b7fc`
- Task count: 6

| Metric | Value | Status |
| --- | --- | --- |
| adaptation_integrity | 0 bps (0/9) | applicable |
| candidate_top1 | — | excluded: unranked_no_comparison_evidence (6) |
| candidate_top10 | — | excluded: unranked_no_comparison_evidence (6) |
| candidate_top3 | — | excluded: unranked_no_comparison_evidence (6) |
| donor_import_free | 10000 bps (5/5) | applicable |
| example_recall | — | excluded: no_upstream_example_is_relocated_for_this_component_task (4); no_upstream_example_is_relocated_for_this_composition_task (1); snapshot_validation:reject_provenance_mismatch:bts_cli_parity_v1:python/mypy@d6d7295e6721a6d97bd474569820f6ea10e983dd (1) |
| hallucinated_dependency_rate | 0 bps (0/7) | applicable |
| helper_recall | 1818 bps (2/11) | applicable |
| integration_success | 0 bps (0/5) | applicable |
| license_accuracy | 10000 bps (6/6) | applicable |
| missing_dependency_rate | 8182 bps (9/11) | applicable |
| probe_success | — | excluded: no_task_specific_probe_set_is_pinned_yet (5); snapshot_validation:reject_provenance_mismatch:bts_cli_parity_v1:python/mypy@d6d7295e6721a6d97bd474569820f6ea10e983dd (1) |
| seed_symbol_exact | 10000 bps (5/5) | applicable |
| seed_symbol_line_overlap | 10000 bps (52/52) | applicable |
| test_recall | 10000 bps (15/15) | applicable |
| time_saved | — | excluded: advisory_timing_in_envelope (6) |

## Execution failures

| Task ID | Donor | Reason | Detail code |
| --- | --- | --- | --- |
| worker-shutdown-predicate | python/mypy@d6d7295e6721a6d97bd474569820f6ea10e983dd | reject_provenance_mismatch | bts_cli_parity_v1 |
