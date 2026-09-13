#!/usr/bin/env bash
# Poll for results Saturnin is waiting on, so that Saturnin never waits.
#
# Tasks dispatched with the `poller` result contract have nothing that reports
# back on its own: a long build, an external deployment, a third-party review.
# Instead of blocking the CEO, this script - scheduled by the saturnin-poller
# timer - checks the agreed signal and pushes the answer onto the board.
#
# Each poller is one file in var/pollers/<task-id>.sh, written by a worker
# (never by the CEO). It exits 0 when the awaited thing is done, 2 when it is
# still pending, anything else on error.
set -Eeuo pipefail
SCRIPT_NAME=result-poller
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

POLLERS_DIR="${SATURNIN_HOME}/var/pollers"
mkdir -p "$POLLERS_DIR"

shopt -s nullglob
probes=("$POLLERS_DIR"/*.sh)
if (( ${#probes[@]} == 0 )); then
  log "no pollers registered; nothing to watch"
  exit 0
fi

exit_code=0
exec {poller_lock_fd}>"${POLLERS_DIR}/.result-poller"
if ! flock -n "$poller_lock_fd"; then
  log "another result-poller run is active; leaving probes to that run"
  exit 0
fi

task_state() {
  saturnin --json task show "$1" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("state",""))' 2>/dev/null || true
}

for probe in "${probes[@]}"; do
  task_id="$(basename "$probe" .sh)"
  status=0
  output="$(timeout 300 bash "$probe" 2>&1)" || status=$?
  if [[ "$status" -eq 124 ]]; then
    # timeout(1) returns 124 when the child is killed.
    output="probe timed out after 300 seconds"
    status=1
  fi
  case "$status" in
    0)
      log "$task_id: signal received - handing back to the board"
      # Clear any escalation deduplication marker from a previous failure episode.
      rm -f "${POLLERS_DIR}/${task_id}.escalated"
      # The task may be in blocked (previous probe error) or in_progress.
      # Transition through in_progress first so blocked->review is never attempted.
      current_state="$(task_state "$task_id")"
      if [[ "$current_state" == "blocked" ]]; then
        if ! saturnin task move "$task_id" in_progress --actor result-poller \
          --note "poller recovered - retrying"; then
          log "$task_id: failed to move task from blocked to in_progress; leaving probe for retry"
          exit_code=1
          continue
        fi
      fi
      if saturnin task move "$task_id" review --actor result-poller \
        --note "poller reported completion: ${output:0:200}"; then
        mv "$probe" "$probe.done"
      else
        log "$task_id: failed to move task to review; leaving probe for retry"
        exit_code=1
      fi
      ;;
    2)
      log "$task_id: still pending"
      ;;
    *)
      note="poller failed (exit $status): ${output:0:200}"
      log "$task_id: $note"
      # Deduplicate: only escalate once per failure episode.  The marker file
      # is removed on recovery (exit 0 branch) so a *new* failure after
      # recovery will escalate again.
      escalation_marker="${POLLERS_DIR}/${task_id}.escalated"
      escalation_ref=""
      if [[ -f "$escalation_marker" ]]; then
        escalation_ref="$(<"$escalation_marker")"
        if [[ -n "$escalation_ref" ]]; then
          log "$task_id: reusing escalation $escalation_ref"
        else
          # Markers from before escalation references were persisted cannot
          # safely satisfy Board's blocked-state invariant.
          rm -f "$escalation_marker"
        fi
      fi
      if [[ -z "$escalation_ref" ]]; then
        # Submit escalation BEFORE moving to blocked so the task is never
        # left blocked without an attached escalation issue.
        escalation_json=""
        if ! escalation_json="$(saturnin --json escalate "Poller failed for task $task_id" \
          --context "$note" \
          --item "Check the poller probe at var/pollers/${task_id}.sh" \
          --item "Confirm whether the awaited signal still applies" \
          --urgency high \
          --task "$task_id" \
          --unblock "State whether to retry the poller or resolve the task manually" \
          --push)"; then
          escalation_ref="$(python3 -c 'import json,sys; print((json.load(sys.stdin).get("url") or ""))' <<<"$escalation_json" 2>/dev/null || true)"
          if [[ -z "$escalation_ref" ]]; then
            log "$task_id: failed to submit escalation issue - not blocking task"
            exit_code=1
            continue
          fi
        else
          escalation_ref="$(python3 -c 'import json,sys; print((json.load(sys.stdin).get("url") or ""))' <<<"$escalation_json" 2>/dev/null || true)"
        fi
        if [[ -z "$escalation_ref" ]]; then
          log "$task_id: failed to submit escalation issue - not blocking task"
          exit_code=1
          continue
        fi
        printf '%s\n' "$escalation_ref" > "$escalation_marker"
      fi
      current_state="$(task_state "$task_id")"
      if [[ "$current_state" != "blocked" ]]; then
        if ! saturnin task move "$task_id" blocked --actor result-poller \
          --escalation "$escalation_ref" --note "$note"; then
          log "$task_id: failed to move task to blocked - board is out of sync"
          exit_code=1
          continue
        fi
      fi
      ;;
  esac
done
exit "$exit_code"
