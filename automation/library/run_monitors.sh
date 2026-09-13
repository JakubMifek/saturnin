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

if [[ -x "${SATURNIN_HOME}/.venv/bin/python" ]]; then
  PYTHON="${SATURNIN_HOME}/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="$(command -v python3)"
else
  log "Python interpreter not found"
  exit 69
fi

if (( $# == 0 )); then
  log "usage: run_monitors.sh <managed-repo-path> [...]"
  exit 64
fi

exit_code=0
for repo_path in "$@"; do
  manifest="${repo_path%/}/.saturnin/repo.yaml"
  if [[ ! -f "$manifest" ]]; then
    log "no .saturnin/repo.yaml in $repo_path - see docs/managed-repo-contract.md"
    continue
  fi
  app="$(basename "${repo_path%/}")"
  repo_slug="$("$PYTHON" -c '
import pathlib, sys, yaml
repo_path = pathlib.Path(sys.argv[1]).resolve()
policy = yaml.safe_load(open(sys.argv[2])) or {}
for source in (policy.get("discovery") or {}).get("sources") or []:
    if not isinstance(source, dict):
        continue
    checkout = source.get("checkout")
    slug = source.get("slug")
    if not checkout or not slug:
        continue
    path = pathlib.Path(str(checkout)).expanduser()
    if not path.is_absolute():
        path = pathlib.Path(sys.argv[3]) / path
    if path.resolve() == repo_path:
        print(slug)
        break
else:
    engine = (policy.get("repos") or {}).get("engine") or {}
    slug = engine.get("slug")
    if slug and pathlib.Path(sys.argv[3]).resolve() == repo_path:
        print(slug)
' "$repo_path" "${SATURNIN_HOME}/policies/repos.yaml" "$SATURNIN_HOME")"
  repo_key="$("$PYTHON" -c '
import hashlib, pathlib, sys
path = str(pathlib.Path(sys.argv[1]).resolve())
print(f"{pathlib.Path(path).name}-{hashlib.sha256(path.encode()).hexdigest()[:12]}")' "$repo_path")"
  results="${RESULTS_DIR}/${repo_key}.jsonl"
  if [[ -z "$repo_slug" ]]; then
    log "$app is not registered as a managed discovery source; refusing to create incidents"
    exit_code=1
    continue
  fi

  # monitors: [{name, url, expect_status, timeout_seconds}]
  count="$("$PYTHON" -c '
import sys, yaml
data = yaml.safe_load(open(sys.argv[1])) or {}
print(len(data.get("monitors") or []))' "$manifest")"

  for (( i = 0; i < count; i++ )); do
    IFS=$'\t' read -r name url expect timeout < <("$PYTHON" -c '
import sys, yaml
monitor = (yaml.safe_load(open(sys.argv[1])) or {})["monitors"][int(sys.argv[2])]
print(monitor["name"], monitor["url"], monitor.get("expect_status", 200),
      monitor.get("timeout_seconds", 10), sep="\t")' "$manifest" "$i")
    if [[ ! "$name" =~ ^[A-Za-z0-9_.-]+$ ]]; then
      log "$app monitor has unsafe name: $name"
      continue
    fi
    url_check="$("$PYTHON" -c '
import ipaddress, socket, sys
from urllib.parse import urlsplit
url = sys.argv[1]
parts = urlsplit(url)
if parts.scheme not in {"http", "https"}:
    print("ERR\tunsupported scheme")
elif not parts.hostname:
    print("ERR\tmissing hostname")
elif parts.username or parts.password:
    print("ERR\tembedded credentials")
else:
    host = parts.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        print("ERR\tlocal hostname")
    else:
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError:
            print("ERR\tinvalid port")
            raise SystemExit
        try:
            direct = ipaddress.ip_address(host)
        except ValueError:
            direct = None
        if direct is not None and str(direct) != host:
            print("ERR\tnon-canonical numeric host")
        else:
            try:
                infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except socket.gaierror as exc:
                print(f"ERR\tcannot resolve hostname: {exc}")
                raise SystemExit
            addresses = []
            for info in infos:
                address = info[4][0]
                if address not in addresses:
                    addresses.append(address)
            blocked = []
            for value in addresses:
                address = ipaddress.ip_address(value)
                if (
                    address.is_private
                    or address.is_loopback
                    or address.is_link_local
                    or address.is_reserved
                    or address.is_multicast
                    or address.is_unspecified
                ):
                    blocked.append(value)
            if blocked:
                print(f"ERR\tnon-public address: {blocked[0]}")
            else:
                chosen = addresses[0]
                resolved = f"[{chosen}]" if ":" in chosen else chosen
                print(f"OK\t{host}:{port}:{resolved}")
' "$url")"
    IFS=$'\t' read -r url_status url_detail <<< "$url_check"
    if [[ "$url_status" != "OK" ]]; then
      log "$app/$name has unsupported monitor URL: $url"
      continue
    fi

    started="$(date -Is)"
    curl_args=(-q -sS --noproxy '*' -o /dev/null -w '%{http_code}' --max-time "$timeout")
    if [[ -n "$url_detail" ]]; then
      curl_args+=(--resolve "$url_detail")
    fi
    curl_args+=(-- "$url")
    if ! code="$(curl "${curl_args[@]}" 2>/dev/null)"; then
      code=000
    fi
    if [[ "$code" == "$expect" ]]; then
      monitor_ok_results="${RESULTS_DIR}/${repo_key}_${name}.jsonl"
      printf '{"ts":"%s","app":"%s","monitor":"%s","status":"%s","ok":true}\n' \
        "$started" "$app" "$name" "$code" >> "$monitor_ok_results"
      printf '{"ts":"%s","app":"%s","monitor":"%s","status":"%s","ok":true}\n' \
        "$started" "$app" "$name" "$code" >> "$results"
      task_marker="${RESULTS_DIR}/${repo_key}_${name}.task"
      if [[ -f "$task_marker" ]]; then
        incident_task="$(<"$task_marker")"
        if saturnin task move "$incident_task" cancelled --actor monitors \
          --note "$app/$name recovered with HTTP $code before intervention" >/dev/null; then
          rm -f "$task_marker"
          rm -f "${RESULTS_DIR}/${repo_key}_${name}.escalated"
        else
          log "$app/$name recovered, but task $incident_task could not be closed; keeping marker"
        fi
      else
        rm -f "${RESULTS_DIR}/${repo_key}_${name}.escalated"
      fi
      log "$app/$name ok ($code)"
      continue
    fi

    printf '{"ts":"%s","app":"%s","monitor":"%s","status":"%s","ok":false}\n' \
      "$started" "$app" "$name" "$code" >> "$results"
    log "$app/$name FAILED (got $code, expected $expect)"

    # Two consecutive failures for THIS monitor mean the humans need to know.
    monitor_results="${RESULTS_DIR}/${repo_key}_${name}.jsonl"
    printf '{"ts":"%s","app":"%s","monitor":"%s","status":"%s","ok":false}\n' \
      "$started" "$app" "$name" "$code" >> "$monitor_results"
    task_marker="${RESULTS_DIR}/${repo_key}_${name}.task"
    if [[ -s "$task_marker" ]]; then
      incident_task="$(<"$task_marker")"
      if ! incident_state="$(saturnin --json task show "$incident_task" 2>/dev/null | "$PYTHON" -c \
        'import json, sys; print(json.load(sys.stdin).get("state", ""))')" \
        || [[ "$incident_state" == "done" || "$incident_state" == "cancelled" ]]; then
        rm -f "$task_marker" "${RESULTS_DIR}/${repo_key}_${name}.escalated"
        incident_task=""
      fi
    else
      incident_task=""
    fi
    if [[ -z "$incident_task" ]]; then
      task_add_args=(--repo "$repo_slug" --label incident --label monitor --priority P0 --dispatch)
      incident="$(
        saturnin --json task add "Monitor $app/$name failed: HTTP $code from $url" \
        --body "Expected $expect, observed $code at $started. Monitor declared in $manifest." \
        "${task_add_args[@]}"
      )"
      incident_task="$(printf '%s' "$incident" | "$PYTHON" -c \
        'import json, sys; print(json.load(sys.stdin)["id"])')"
      printf '%s' "$incident_task" > "$task_marker"
    fi
    recent_failures="$(tail -n 2 "$monitor_results" | grep -c '"ok":false' || true)"
    if (( recent_failures >= 2 )); then
      # Only escalate once per consecutive-failure streak.  The marker is
      # removed when the monitor recovers (ok=true path above).
      escalation_marker="${RESULTS_DIR}/${repo_key}_${name}.escalated"
      if [[ ! -f "$escalation_marker" ]]; then
        saturnin escalate "Monitor $app/$name failing repeatedly" \
          --context "Expected HTTP $expect from $url, got $code twice in a row." \
          --item "Confirm the service is meant to be up" \
          --item "Check deploy history and infrastructure" \
          --urgency high \
          --unblock "State whether to roll back, patch or accept the outage" \
          --task "$incident_task" \
          --push
        touch "$escalation_marker"
      fi
    fi
  done
done
exit "$exit_code"
