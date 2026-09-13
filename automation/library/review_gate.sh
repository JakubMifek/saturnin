#!/usr/bin/env bash
# Usage: review_gate.sh pr <subject> <repo>
#        review_gate.sh issue <subject> <repo> <author-role> <issue-digest>
# PR gates resolve the head SHA and preserve the GitHub author identity.
# Issue gates require the digest of the exact reviewed title and body.
# Exits non-zero when the independent review requirement is not satisfied.
set -Eeuo pipefail
SCRIPT_NAME=review-gate
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

kind="${1:?usage: review_gate.sh <pr|issue> <subject> <repo> [author] [issue-digest]}"
subject="${2:?missing subject}"
repo="${3:?missing repo}"
author="${4:-}"
review_target="${5:-}"

case "$kind" in
  pr|issue) ;;
  *) echo "invalid review kind: $kind (expected pr or issue)" >&2; exit 2 ;;
esac

args=("$subject" --kind "$kind" --repo "$repo")
if [[ "$kind" == "pr" ]]; then
  subject_repo="${subject%#*}"
  pr_number="${subject##*#}"
  [[ "$subject" == *"#"* && "$pr_number" =~ ^[0-9]+$ && "$subject_repo" == "$repo" ]] || {
    echo "invalid PR subject; expected owner/repo#number" >&2
    exit 2
  }
  reviewer_logins="$(
    saturnin_python -c '
import json, sys, yaml
policy = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
settings = policy.get("review", {}).get("pr", {})
logins = settings.get("github_reviewer_logins")
if logins is None:
    logins = [settings.get("github_reviewer_login", "")]
elif isinstance(logins, str):
    logins = [logins]
print(json.dumps([login for login in logins if isinstance(login, str) and login]))' \
      "${SATURNIN_HOME}/policies/governance.yaml"
  )"
  [[ "$reviewer_logins" != "[]" ]] || {
    echo "review.pr.github_reviewer_logins is not configured" >&2
    exit 2
  }
  github_headers=(-H "Accept: application/vnd.github+json")
  [[ -z "${GITHUB_TOKEN:-${GH_TOKEN:-}}" ]] || \
    github_headers+=(-H "Authorization: token ${GITHUB_TOKEN:-${GH_TOKEN:-}}")
  pr_json="$(curl --fail --silent --show-error --location --max-time 30 \
    "${github_headers[@]}" "https://api.github.com/repos/${repo}/pulls/${pr_number}")"
  head_sha="$(saturnin_python -c 'import json, sys; print(json.load(sys.stdin)["head"]["sha"])' <<<"$pr_json")"
  [[ -n "$head_sha" ]] || { echo "GitHub PR response contained no head SHA" >&2; exit 2; }
  args+=(--head-sha "$head_sha")
  pr_author="$(saturnin_python -c 'import json, sys; print(json.load(sys.stdin)["user"]["login"])' <<<"$pr_json")"
  [[ -n "$pr_author" ]] || { echo "GitHub PR response contained no author login" >&2; exit 2; }
  author="github:${pr_author}"
  args+=(--author "$author")
  IFS=$'\t' read -r github_verdict github_reviewer < <(
    saturnin_python - "$repo" "$pr_number" "$head_sha" "$pr_author" "$reviewer_logins" <<'PY'
import json
import os
import sys
import urllib.request

repo, pr_number, head_sha, pr_author, reviewer_logins_json = sys.argv[1:]
reviewer_logins = {
    str(login).casefold(): str(login) for login in json.loads(reviewer_logins_json)
}
headers = {"Accept": "application/vnd.github+json", "User-Agent": "saturnin-review-gate"}
token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
if token:
    headers["Authorization"] = f"token {token}"

latest = {}
for page in range(1, 11):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews?per_page=100&page={page}",
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        reviews = json.load(response)
    if not reviews:
        break
    for review in reviews:
        if review.get("commit_id") != head_sha:
            continue
        review_user = review.get("user") or {}
        user = review_user.get("login", "")
        state = str(review.get("state", "")).lower()
        if (
            not user
            or review_user.get("type") != "Bot"
            or user.casefold() == pr_author.casefold()
            or user.casefold() not in reviewer_logins
            or state not in {"approved", "changes_requested", "rejected", "dismissed"}
        ):
            continue
        latest[user.casefold()] = (state, user)

blocking = [review for review in latest.values() if review[0] in {
    "changes_requested", "rejected", "dismissed"
}]
approved = [review for review in latest.values() if review[0] == "approved"]
if blocking:
    state, user = blocking[-1]
    print(f"{'dismissed' if state == 'dismissed' else 'changes_requested'}\t{user}")
elif approved:
    _, user = approved[-1]
    print(f"approved\t{user}")
else:
    print("none\t")
PY
  )
  if [[ "$github_verdict" != "none" ]]; then
    attestation="$(saturnin review attest "$subject" --kind pr --author "$author" \
      --reviewer pr-reviewer --verdict "$github_verdict" --head-sha "$head_sha")"
    saturnin review record "$subject" --kind pr --author "$author" \
      --reviewer pr-reviewer --verdict "$github_verdict" --head-sha "$head_sha" \
      --attestation "$attestation" \
      --notes "Imported from GitHub reviewer ${github_reviewer} for CI." >/dev/null
  fi
else
  [[ -n "$author" ]] || {
    echo "missing issue author role" >&2
    exit 2
  }
  [[ -n "$review_target" ]] || {
    echo "missing reviewed issue-content digest" >&2
    exit 2
  }
  issue_digest="$review_target"
  args+=(--author "$author" --issue-digest "$issue_digest")
fi
saturnin review gate "${args[@]}"
