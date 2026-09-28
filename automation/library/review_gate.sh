#!/usr/bin/env bash
# Import independently-authorized GitHub evidence, record it, then run the gate.
set -Eeuo pipefail
SCRIPT_NAME=review-gate
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

kind="${1:?usage: review_gate.sh <pr|issue> <owner/repo#number> <destination-repo>}"
subject="${2:?missing subject}"
destination="${3:?missing destination repository}"
[[ "$kind" == pr || "$kind" == issue ]] || { echo "invalid review kind" >&2; exit 2; }
[[ "$subject" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*$ ]] || {
  echo "subject must be owner/repository#number" >&2
  exit 2
}

# Caller-supplied review claims are placeholders only.  The service ignores
# them and returns fields derived from GitHub over TLS.
attestation="$(saturnin review attest "$subject" --kind "$kind" \
  --repo "$destination" --author github:ignored --reviewer "${kind}-reviewer" \
  --verdict approved)"
readarray -t fields < <(saturnin_python - "$attestation" <<'PY'
import json, sys
value=json.loads(sys.argv[1])
for name in ("author","reviewer","verdict","head_sha","issue_digest","destination_repo"):
    print(value[name])
PY
)
args=("$subject" --kind "$kind" --author "${fields[0]}" --reviewer "${fields[1]}" \
  --verdict "${fields[2]}" --repo "${fields[5]}" --attestation "$attestation" \
  --notes "Authorized by dedicated GitHub attestation service.")
gate=("$subject" --kind "$kind" --repo "${fields[5]}" --author "${fields[0]}")
if [[ "$kind" == pr ]]; then
  args+=(--head-sha "${fields[3]}")
  gate+=(--head-sha "${fields[3]}")
else
  args+=(--issue-digest "${fields[4]}")
  gate+=(--issue-digest "${fields[4]}")
fi
saturnin review record "${args[@]}" >/dev/null
saturnin review gate "${gate[@]}"
