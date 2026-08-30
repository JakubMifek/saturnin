#!/usr/bin/env bash
# Shared helpers for every automation in the library.
set -Eeuo pipefail

SATURNIN_HOME="${SATURNIN_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
export SATURNIN_HOME

log() { printf '%s [%s] %s\n' "$(date -Is)" "${SCRIPT_NAME:-automation}" "$*"; }

saturnin() {
  if command -v saturnin >/dev/null 2>&1; then
    command saturnin "$@"
  else
    PYTHONPATH="${SATURNIN_HOME}/src:${PYTHONPATH:-}" python3 -m saturnin "$@"
  fi
}
