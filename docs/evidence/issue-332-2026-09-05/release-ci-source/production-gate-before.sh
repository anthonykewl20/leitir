set -euo pipefail
# NOTE: the workflow file is ci.yml - the GitHub API resolves
# workflow file names case-sensitively, so 'CI.yml' would 404.
runs="$(gh run list --workflow ci.yml --commit "$COMMIT_SHA" --json databaseId,headSha,conclusion,status)"
run_id="$(printf '%s' "$runs" | jq -r --arg c "$COMMIT_SHA" '[.[] | select(.headSha == $c) | select(.status == "completed" and .conclusion == "success")] | .[0].databaseId // empty')"
if [ -n "$run_id" ]; then
  echo "Green CI run for commit ${COMMIT_SHA} (audit trail):"
  echo "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${run_id}"
  echo "run_id=${run_id}" >> "$GITHUB_OUTPUT"
  exit 0
fi
# No green run: fail closed with a precise reason.
pending="$(printf '%s' "$runs" | jq --arg c "$COMMIT_SHA" '[.[] | select(.headSha == $c and .status != "completed")] | length')"
if [ "${pending:-0}" -gt 0 ]; then
  echo "::error::CI for commit ${COMMIT_SHA} is still in progress; re-run this workflow after it completes." >&2
elif [ -n "$runs" ] && [ "$runs" != "[]" ]; then
  echo "::error::CI ran for commit ${COMMIT_SHA} but no run concluded 'success'; refusing to publish." >&2
else
  echo "::error::No CI workflow run found for commit ${COMMIT_SHA}; publication requires a green CI run for the exact tagged commit." >&2
fi
exit 1
