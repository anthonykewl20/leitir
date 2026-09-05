set -euo pipefail
# NOTE: the workflow file is ci.yml - the GitHub API resolves
# workflow file names case-sensitively, so 'CI.yml' would 404.
runs="$(gh run list --workflow ci.yml --commit "$COMMIT_SHA" --json databaseId,headSha,conclusion,status,event)"
# PR run.headSha names the head, but default checkout builds its
# merge ref. Only push/dispatch checkout is the named commit itself.
eligible_runs="$(printf '%s' "$runs" | jq --arg c "$COMMIT_SHA" '[.[] | select(.headSha == $c and (.event == "push" or .event == "workflow_dispatch"))]')"
run_id="$(printf '%s' "$eligible_runs" | jq -r '[.[] | select(.status == "completed" and .conclusion == "success")] | .[0].databaseId // empty')"
if [ -n "$run_id" ]; then
  echo "Green CI run for commit ${COMMIT_SHA} (audit trail):"
  echo "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${run_id}"
  echo "run_id=${run_id}" >> "$GITHUB_OUTPUT"
  exit 0
fi
# No green run: fail closed with a precise reason.
pending="$(printf '%s' "$eligible_runs" | jq '[.[] | select(.status != "completed")] | length')"
if [ "${pending:-0}" -gt 0 ]; then
  echo "::error::Push/dispatch CI for commit ${COMMIT_SHA} is still in progress; re-run this workflow after it completes." >&2
elif [ "$eligible_runs" != "[]" ]; then
  echo "::error::Push/dispatch CI ran for commit ${COMMIT_SHA} but no run concluded 'success'; refusing to publish." >&2
else
  echo "::error::No release-qualified CI run found for commit ${COMMIT_SHA}; run CI with workflow_dispatch on this commit or use its successful main push. Pull-request merge-ref builds cannot qualify a release." >&2
fi
exit 1

