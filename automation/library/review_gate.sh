#!/usr/bin/env bash
# Usage: review_gate.sh <pr|issue> <subject> <repo> <author> [legacy-sha]
# PR gates always resolve the head SHA from GitHub; issue gates ignore any supplied SHA.
# Exits non-zero when the independent review requirement is not satisfied.
set -Eeuo pipefail
SCRIPT_NAME=review-gate
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

kind="${1:?usage: review_gate.sh <pr|issue> <subject> <repo> <author> [legacy-sha]}"
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
  pr_number="${subject##*#}"
  [[ "$subject" == *"#"* && "$pr_number" =~ ^[0-9]+$ ]] || {
    echo "invalid PR subject; expected owner/repo#number" >&2
    exit 2
  }
  github_headers=(-H "Accept: application/vnd.github+json")
  [[ -z "${GITHUB_TOKEN:-${GH_TOKEN:-}}" ]] || \
    github_headers+=(-H "Authorization: token ${GITHUB_TOKEN:-${GH_TOKEN:-}}")
  pr_json="$(curl --fail --silent --show-error --location --max-time 30 \
    "${github_headers[@]}" "https://api.github.com/repos/${repo}/pulls/${pr_number}")"
  head_sha="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["head"]["sha"])' <<<"$pr_json")"
  [[ -n "$head_sha" ]] || { echo "GitHub PR response contained no head SHA" >&2; exit 2; }
  args+=(--head-sha "$head_sha")
elif [[ -n "$head_sha" ]]; then
  echo "warning: ignoring head SHA for issue review gate" >&2
fi
saturnin review gate "${args[@]}"
