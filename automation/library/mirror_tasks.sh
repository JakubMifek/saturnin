#!/usr/bin/env bash
# Mirror every open board task as a GitHub issue (rule 8).
#
# The local board is fast; GitHub is durable. Run on a timer so that losing this
# machine costs a `git clone`, not a week of work. PUSH=1 actually files the
# issues; without it you get a preview, which is what you want the first time.
set -Eeuo pipefail
SCRIPT_NAME=task-mirror
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

if [[ "${PUSH:-0}" == "1" ]]; then
  saturnin task sync --all --push
else
  log "preview only; re-run with PUSH=1 to file the issues"
  saturnin task sync --all
fi
