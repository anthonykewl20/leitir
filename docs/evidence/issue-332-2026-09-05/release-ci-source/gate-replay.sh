#!/usr/bin/env bash
set -euo pipefail
proof_dir="/tmp/leitir-remediation-20260905/release-evidence/release-ci-source"
commit_sha="9d61335fe19176dc1facda3182913ae1305a5252"
# Component dry-run on unchanged captured actual GitHub metadata. No publication.
jq -r --arg c "$commit_sha" '[.[] | select(.headSha == $c) | select(.status == "completed" and .conclusion == "success")] | .[0].databaseId // empty' "$proof_dir/gate-input-106.json" > "$proof_dir/gate-before.txt"
jq -r --arg c "$commit_sha" '[.[] | select(.headSha == $c) | select(.event == "push" or .event == "workflow_dispatch") | select(.status == "completed" and .conclusion == "success")] | .[0].databaseId // empty' "$proof_dir/gate-input-106.json" > "$proof_dir/gate-after.txt"
test "$(cat "$proof_dir/gate-before.txt")" = "31579743105"
test ! -s "$proof_dir/gate-after.txt"
