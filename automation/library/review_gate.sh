#!/usr/bin/env bash
# Usage: review_gate.sh <pr|issue> <subject> <repo> <author> [head-sha]
# The head SHA is required for PRs; an extra SHA is ignored for issues.
# Exits non-zero when the independent review requirement is not satisfied.
set -Eeuo pipefail
SCRIPT_NAME=review-gate
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

kind="${1:?usage: review_gate.sh <pr|issue> <subject> <repo> <author>}"
subject="${2:?missing subject}"
repo="${3:?missing repo}"
author="${4:?missing author}"
head_sha="${5:-}"

case "$kind" in
  pr|issue) ;;
  *) echo "invalid review kind: $kind (expected pr or issue)" >&2; exit 2 ;;
esac

args=("$subject" --kind "$kind" --repo "$repo" --author "$author")
if [[ "$kind" == "pr" ]]; then
  [[ -n "$head_sha" ]] || { echo "missing head SHA for PR review gate" >&2; exit 2; }
  args+=(--head-sha "$head_sha")
elif [[ -n "$head_sha" ]]; then
  echo "warning: ignoring head SHA for issue review gate" >&2
fi
saturnin review gate "${args[@]}"
