#!/usr/bin/env bash
set -Eeuo pipefail

subject="${1:?usage: publish_issue_review.sh <source-owner/repo#number> <destination-repo> <labels-json> <ttl-seconds> <issue-digest>}"
destination="${2:?missing destination repository}"
labels_json="${3:?missing labels JSON}"
ttl="${4:?missing TTL}"
issue_digest="${5:?missing approved issue digest}"
: "${SATURNIN_ISSUE_REVIEWER_APP_ID:?missing reviewer App ID}"
: "${SATURNIN_ISSUE_REVIEWER_PRIVATE_KEY_FILE:?missing reviewer App private key file}"

[[ "$SATURNIN_ISSUE_REVIEWER_APP_ID" =~ ^[1-9][0-9]*$ ]] || {
  echo "invalid reviewer App ID" >&2
  exit 2
}
[[ "$subject" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*$ ]] || {
  echo "invalid source issue subject" >&2
  exit 2
}
[[ "$destination" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "invalid destination repository" >&2
  exit 2
}
[[ "$ttl" =~ ^[0-9]+$ ]] || { echo "invalid marker TTL" >&2; exit 2; }
[[ "$issue_digest" =~ ^[0-9a-f]{64}$ ]] || {
  echo "invalid approved issue digest" >&2
  exit 2
}
[[ -f "$SATURNIN_ISSUE_REVIEWER_PRIVATE_KEY_FILE" ]] || {
  echo "reviewer App private key file is unavailable" >&2
  exit 2
}

b64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

now="$(date +%s)"
header="$(printf '%s' '{"alg":"RS256","typ":"JWT"}' | b64url)"
payload="$(printf '{"iat":%d,"exp":%d,"iss":"%s"}' \
  "$((now - 30))" "$((now + 540))" "$SATURNIN_ISSUE_REVIEWER_APP_ID" | b64url)"
unsigned="${header}.${payload}"
signature="$(printf '%s' "$unsigned" |
  openssl dgst -sha256 -sign "$SATURNIN_ISSUE_REVIEWER_PRIVATE_KEY_FILE" |
  b64url)"
jwt="${unsigned}.${signature}"

source_repo="${subject%#*}"
source_name="${source_repo#*/}"
installation_id="$(
  curl --fail-with-body --silent --show-error \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${jwt}" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/${source_repo}/installation" |
  python3 -c '
import json, sys
item = json.load(sys.stdin)
value = item.get("id")
permissions = item.get("permissions")
if (
    type(value) is not int
    or item.get("app_id") != int(sys.argv[1])
    or item.get("repository_selection") != "selected"
    or permissions != {"issues": "write", "metadata": "read"}
):
    raise SystemExit("source repository GitHub App installation is malformed")
print(value)
' "$SATURNIN_ISSUE_REVIEWER_APP_ID"
)"
token_scope="$(
  SOURCE_NAME="$source_name" python3 -c '
import json, os
print(json.dumps({
    "repositories": [os.environ["SOURCE_NAME"]],
    "permissions": {"issues": "write", "metadata": "read"},
}, separators=(",", ":")))
'
)"
token_response="$(
  curl --fail-with-body --silent --show-error -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${jwt}" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "Content-Type: application/json" \
    --data "$token_scope" \
    "https://api.github.com/app/installations/${installation_id}/access_tokens"
)"
token="$(
  printf '%s' "$token_response" | python3 -c '
import json, sys
item = json.load(sys.stdin)
value = item.get("token")
repositories = item.get("repositories")
permissions = item.get("permissions")
if (
    not isinstance(value, str)
    or not value
    or item.get("repository_selection") != "selected"
    or permissions != {"issues": "write", "metadata": "read"}
    or not isinstance(repositories, list)
    or len(repositories) != 1
    or str(repositories[0].get("full_name", "")).casefold()
    != sys.argv[1].casefold()
):
    raise SystemExit("GitHub App installation token response is malformed")
print(value)
' "$source_repo"
)"

SATURNIN_ISSUE_REVIEWER_TOKEN="$token" python3 - "$subject" "$destination" \
  "$labels_json" "$ttl" "$issue_digest" <<'PY'
import json
import os
import subprocess
import sys

subject, destination, labels_json, ttl, issue_digest = sys.argv[1:]
labels = json.loads(labels_json)
if not isinstance(labels, list) or any(not isinstance(item, str) for item in labels):
    raise SystemExit("labels must be a JSON string array")
command = [
    "saturnin", "review", "publish-issue-review", subject,
    "--repo", destination, "--issue-digest", issue_digest,
    "--ttl-seconds", ttl,
]
for label in labels:
    command.extend(["--label", label])
subprocess.run(command, check=True, env=os.environ, close_fds=True)
PY
