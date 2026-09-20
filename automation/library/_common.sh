#!/usr/bin/env bash
# Shared helpers for every automation in the library.
set -Eeuo pipefail
umask 077

SATURNIN_HOME="${SATURNIN_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
export SATURNIN_HOME

log() { printf '%s [%s] %s\n' "$(date -Is)" "${SCRIPT_NAME:-automation}" "$*"; }

saturnin() {
  local trusted="${SATURNIN_HOME}/.venv/bin/saturnin"
  if [[ ! -x "$trusted" ]]; then
    log "trusted saturnin executable missing: $trusted"
    return 127
  fi
  "$trusted" "$@"
}

saturnin_python() {
  if [[ -x "${SATURNIN_HOME}/.venv/bin/python" ]]; then
    "${SATURNIN_HOME}/.venv/bin/python" "$@"
  else
    python3 "$@"
  fi
}
