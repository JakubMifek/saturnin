#!/usr/bin/env bash
# Day-1 bootstrap: virtualenv, package, runtime directories, health check.
# Idempotent - safe to run after every pull. Never needs root.
set -Eeuo pipefail

SATURNIN_HOME="${SATURNIN_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$SATURNIN_HOME"

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Refusing to bootstrap as root; Saturnin runs unprivileged (rule 7)." >&2
  exit 1
fi

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -e ".[dev]"
python -m saturnin.mcp install github

mkdir -p board/tasks board/checkpoints board/reviews var/logs var/worktrees var/reports var/secrets
chmod 700 var/secrets
if [[ ! -f var/secrets/review-attestation.env ]]; then
  umask 077
  python - <<'PY' > var/secrets/review-attestation.env
import secrets

print(f"SATURNIN_REVIEW_ATTESTATION_KEY={secrets.token_urlsafe(48)}")
PY
fi

echo "--- saturnin doctor ---"
saturnin doctor

cat <<'MSG'

Saturnin is installed. Next:
  source .venv/bin/activate
  set -a; source var/secrets/review-attestation.env; set +a
  saturnin task add "<your first task>" --dispatch
  scripts/install_user_units.sh    # scheduled janitor + improvement workers
See docs/runbooks/day-1-startup.md.
MSG
