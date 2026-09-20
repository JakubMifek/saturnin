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

mkdir -p board/tasks board/checkpoints board/reviews var/logs var/worktrees var/reports

echo "--- saturnin doctor ---"
saturnin doctor

echo "--- companion repositories ---"
echo "Roles (including scribe/chief-of-staff task orchestration) do not require dedicated repos."
python - <<'PY'
from pathlib import Path
import yaml

policy = yaml.safe_load(Path("policies/repos.yaml").read_text(encoding="utf-8")) or {}
repos = policy.get("repos", {})
engine_slug = str(repos.get("engine", {}).get("slug", "")).strip()
companions = []
for name, entry in repos.items():
    slug = str((entry or {}).get("slug", "")).strip()
    if not slug or slug.casefold() == engine_slug.casefold():
        continue
    companions.append((name, slug, str((entry or {}).get("visibility", "private"))))

if not companions:
    print("No companion repositories configured in policies/repos.yaml.")
else:
    print("Configured companion repositories:")
    for name, slug, visibility in companions:
        print(f"  - {name}: {slug} ({visibility})")
PY
if command -v gh >/dev/null 2>&1; then
  while IFS=: read -r name slug visibility; do
    [[ -z "$slug" ]] && continue
    if gh repo view "$slug" >/dev/null 2>&1; then
      echo "  [ok] $slug exists"
    else
      echo "  [todo] create: gh repo create \"$slug\" --${visibility:-private}"
    fi
  done < <(
    python - <<'PY'
from pathlib import Path
import yaml

policy = yaml.safe_load(Path("policies/repos.yaml").read_text(encoding="utf-8")) or {}
repos = policy.get("repos", {})
engine_slug = str(repos.get("engine", {}).get("slug", "")).strip()
for name, entry in repos.items():
    slug = str((entry or {}).get("slug", "")).strip()
    visibility = str((entry or {}).get("visibility", "private")).strip().lower()
    if not slug or slug.casefold() == engine_slug.casefold():
        continue
    if visibility not in {"public", "private"}:
        visibility = "private"
    print(f"{name}:{slug}:{visibility}")
PY
  )
else
  echo "  [note] gh CLI not found; create missing companion repos manually."
fi

cat <<'MSG'

Saturnin is installed. Next:
  source .venv/bin/activate
  export SATURNIN_REVIEW_ATTESTATION_KEY='<trusted-supervisor-secret>'
  saturnin task add "<your first task>" --dispatch
  scripts/install_user_units.sh    # scheduled janitor + improvement workers
  # if missing: create companion repos declared in policies/repos.yaml
See docs/runbooks/day-1-startup.md.
MSG
