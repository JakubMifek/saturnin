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
for unit in "$SATURNIN_HOME"/systemd/saturnin-*; do
  name="$(basename "$unit")"
  sed "s|@SATURNIN_HOME@|$SATURNIN_HOME|g" "$unit" > "$UNIT_DIR/$name"
  echo "installed $UNIT_DIR/$name"
done

systemctl --user daemon-reload
systemctl --user enable --now saturnin-janitor.timer saturnin-improve.timer
systemctl --user list-timers 'saturnin-*' || true

cat <<'MSG'

Timers enabled. If Saturnin must run without an open login session:
  loginctl enable-linger "$USER"
The janitor runs in dry-run mode; set APPLY=1 in saturnin-janitor.service once
you trust its plans (see docs/runbooks/ops-safety.md).
MSG
