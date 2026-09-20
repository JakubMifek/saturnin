#!/usr/bin/env bash
# Stale worktree/branch cleanup.
# Recovery guidance: docs/runbooks/ops-safety.md
set -Eeuo pipefail
SCRIPT_NAME=cleanup-worktrees
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

apply="${APPLY:-}"
if [[ -z "$apply" ]]; then
  apply="$(saturnin_python - <<'PY'
from saturnin.config import default_config

value = default_config().cleanup.get("safety", {}).get("dry_run_default")
if not isinstance(value, bool):
    raise SystemExit("cleanup safety.dry_run_default must be a boolean")
print("0" if value else "1")
PY
)"
fi

if [[ "$apply" == "1" ]]; then
  log "applying cleanup plan"
  saturnin worktree cleanup --apply
elif [[ "$apply" == "0" ]]; then
  log "planning cleanup"
  saturnin worktree cleanup
else
  log "APPLY must be 0 or 1"
  exit 2
fi
