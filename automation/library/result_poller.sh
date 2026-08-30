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

for probe in "${probes[@]}"; do
  task_id="$(basename "$probe" .sh)"
  status=0
  output="$(bash "$probe" 2>&1)" || status=$?
  case "$status" in
    0)
      log "$task_id: signal received - handing back to the board"
      saturnin task move "$task_id" review --actor result-poller \
        --note "poller reported completion: ${output:0:200}" || true
      mv "$probe" "$probe.done"
      ;;
    2)
      log "$task_id: still pending"
      ;;
    *)
      log "$task_id: poller failed (exit $status): ${output:0:200}"
      saturnin task move "$task_id" blocked --actor result-poller \
        --note "poller failed (exit $status): ${output:0:200}" || true
      ;;
  esac
done
