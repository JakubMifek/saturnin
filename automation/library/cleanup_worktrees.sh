#!/usr/bin/env bash
# Stale worktree/branch cleanup. Dry run unless APPLY=1.
# Recovery guidance: docs/runbooks/ops-safety.md
set -Eeuo pipefail
SCRIPT_NAME=cleanup-worktrees
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

if [[ "${APPLY:-0}" == "1" ]]; then
  log "applying cleanup plan"
  saturnin worktree cleanup --apply
else
  log "dry run (set APPLY=1 to remove)"
  saturnin worktree cleanup
fi
