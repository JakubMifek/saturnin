#!/usr/bin/env bash
# Install the Saturnin systemd *user* units (rule 7: user scope only, no root).
set -Eeuo pipefail

SATURNIN_HOME="${SATURNIN_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

if [[ "$(id -u)" -eq 0 ]]; then
  echo "Refusing to install units as root; Saturnin units are user scoped." >&2
  exit 1
fi

mkdir -p "$UNIT_DIR"
if [[ ! "$SATURNIN_HOME" =~ ^[A-Za-z0-9/._-]+$ ]]; then
  cat >&2 <<'ERR'
SATURNIN_HOME contains characters that cannot be rendered safely for all
systemd directives used by Saturnin units.
Use a checkout path containing only [A-Za-z0-9/._-].
ERR
  exit 1
fi
for unit in "$SATURNIN_HOME"/systemd/saturnin-*; do
  name="$(basename "$unit")"
  SATURNIN_HOME_ESCAPED="$SATURNIN_HOME" SATURNIN_HOME_ENV_ESCAPED="$SATURNIN_HOME" \
    TEMPLATE="$unit" DEST="$UNIT_DIR/$name" python3 -c '
from pathlib import Path
import os
template = Path(os.environ["TEMPLATE"]).read_text()
Path(os.environ["DEST"]).write_text(
    template.replace("@SATURNIN_HOME@", os.environ["SATURNIN_HOME_ESCAPED"])
    .replace("@SATURNIN_HOME_ENV@", os.environ["SATURNIN_HOME_ENV_ESCAPED"])
)
'
  if command -v systemd-analyze >/dev/null 2>&1; then
    if ! systemd-analyze --user verify "$UNIT_DIR/$name"; then
      echo "systemd-analyze verify failed for $name; refusing to enable invalid units" >&2
      exit 1
    fi
  fi
  echo "installed $UNIT_DIR/$name"
done

systemctl --user daemon-reload
systemctl --user enable --now \
  saturnin-janitor.timer saturnin-improve.timer \
  saturnin-poller.timer saturnin-discovery.timer \
  saturnin-resume.timer
systemctl --user list-timers 'saturnin-*' || true

cat <<'MSG'

Timers enabled. If Saturnin must run without an open login session:
  loginctl enable-linger "$USER"
The janitor runs in dry-run mode; set APPLY=1 in saturnin-janitor.service once
you trust its plans (see docs/runbooks/ops-safety.md).
MSG
