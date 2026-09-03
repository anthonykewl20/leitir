## Summary

<!-- What changed, and why? -->

## Related issue

<!-- Closes #N, or explain why no issue applies. -->

## Security/integrity impact

<!-- Required: write "None" or describe the impact, such as changed verification behavior, a new fail-closed path, or a manifest schema change. -->

## Test plan

<!-- List exact commands and results. -->

## Checklist

- [ ] Tests added (or N/A with explanation)
- [ ] Tamper/reject test added for security/integrity changes (or N/A)
- [ ] README/ADR updated for behavior changes (or N/A)
- [ ] No runtime dependency added (`pyproject.toml` `dependencies = []` preserved)
- [ ] Determinism verified (`PYTHONHASHSEED`-independent)
- [ ] Fail-closed paths preserved
- [ ] Full suite passes: `PYTHONPATH=src uv run --no-project --with-requirements requirements.txt python -m pytest -q`
- [ ] Review lane marked: ordinary (one review) / sensitive (security, integrity, or materialization — two reviews)
- [ ] Follow-ups: none, or filed as issues with acceptance criteria
- [ ] AI assistance disclosed (tool and use described) — required if used
