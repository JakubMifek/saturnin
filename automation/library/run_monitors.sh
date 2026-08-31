#!/usr/bin/env bash
# Run the synthetic monitors of every managed application, unattended.
#
# This is the FALLBACK path for projects that do not yet emit metrics and logs
# to a stack that can alert on them. Preferred is the pipeline in
# docs/observability.md: the project alerts, the alert becomes an issue, and
# `saturnin discover` adopts it. A curl from this host proves an endpoint
# answers and nothing more - it cannot tell an outage from a local network
# problem, and it never sees a slow burn.
#
# Monitors are declared per repository in .saturnin/repo.yaml under `monitors:`
# and are the autonomous half of the end-to-end tests: same assertions, run
# against the live system on a timer. A failure is not a log line - it becomes a
# P0 board task, and a second consecutive failure escalates to a human.
#
# Usage: run_monitors.sh <path-to-managed-repo> [...]
set -Eeuo pipefail
SCRIPT_NAME=monitors
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

RESULTS_DIR="${SATURNIN_HOME}/var/monitors"
mkdir -p "$RESULTS_DIR"

if (( $# == 0 )); then
  log "usage: run_monitors.sh <managed-repo-path> [...]"
  exit 64
fi

for repo_path in "$@"; do
  manifest="${repo_path%/}/.saturnin/repo.yaml"
  if [[ ! -f "$manifest" ]]; then
    log "no .saturnin/repo.yaml in $repo_path - see docs/managed-repo-contract.md"
    continue
  fi
  app="$(basename "${repo_path%/}")"
  results="${RESULTS_DIR}/${app}.jsonl"

  # monitors: [{name, url, expect_status, timeout_seconds}]
  count="$(python3 -c '
import sys, yaml
data = yaml.safe_load(open(sys.argv[1])) or {}
print(len(data.get("monitors") or []))' "$manifest")"

  for (( i = 0; i < count; i++ )); do
    read -r name url expect timeout < <(python3 -c '
import sys, yaml
monitor = (yaml.safe_load(open(sys.argv[1])) or {})["monitors"][int(sys.argv[2])]
print(monitor["name"], monitor["url"], monitor.get("expect_status", 200),
      monitor.get("timeout_seconds", 10))' "$manifest" "$i")

    started="$(date -Is)"
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time "$timeout" "$url" || echo 000)"
    if [[ "$code" == "$expect" ]]; then
      printf '{"ts":"%s","app":"%s","monitor":"%s","status":"%s","ok":true}\n' \
        "$started" "$app" "$name" "$code" >> "$results"
      log "$app/$name ok ($code)"
      continue
    fi

    printf '{"ts":"%s","app":"%s","monitor":"%s","status":"%s","ok":false}\n' \
      "$started" "$app" "$name" "$code" >> "$results"
    log "$app/$name FAILED (got $code, expected $expect)"

    # Two consecutive failures mean the humans need to know.
    recent_failures="$(tail -n 2 "$results" | grep -c '"ok":false' || true)"
    if (( recent_failures >= 2 )); then
      saturnin escalate "Monitor $app/$name failing repeatedly" \
        --context "Expected HTTP $expect from $url, got $code twice in a row." \
        --checklist "Confirm the service is meant to be up" \
        --checklist "Check deploy history and infrastructure" \
        --urgency high \
        --unblock "State whether to roll back, patch or accept the outage" || true
    else
      saturnin task add "Monitor $app/$name failed: HTTP $code from $url" \
        --body "Expected $expect, observed $code at $started. Monitor declared in $manifest." \
        --label incident --label monitor --priority P0 --dispatch || true
    fi
  done
done
