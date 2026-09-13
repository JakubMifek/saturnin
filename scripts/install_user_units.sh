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
mkdir -p "$SATURNIN_HOME/var/secrets"
chmod 700 "$SATURNIN_HOME/var/secrets"
if [[ ! -f "$SATURNIN_HOME/var/secrets/review-attestation.env" ]]; then
  umask 077
  python3 - <<'PY' > "$SATURNIN_HOME/var/secrets/review-attestation.env"
import secrets

print(f"SATURNIN_REVIEW_ATTESTATION_KEY={secrets.token_urlsafe(48)}")
PY
fi
mapfile -t escaped_values < <(SATURNIN_HOME="$SATURNIN_HOME" python3 -c '
import os
value = os.environ["SATURNIN_HOME"]

def escape_for_unit():
    safe = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/._-"
    escaped = []
    for byte in value.encode("utf-8"):
        if byte in safe:
            escaped.append(chr(byte))
        else:
            escaped.append(f"\\x{byte:02x}")
    return "".join(escaped).replace("%", "%%")

print(escape_for_unit())
print(escape_for_unit())
')
escaped_home="${escaped_values[0]}"
escaped_home_env="${escaped_values[1]}"
for unit in "$SATURNIN_HOME"/systemd/saturnin-*; do
  name="$(basename "$unit")"
  SATURNIN_HOME_ESCAPED="$escaped_home" SATURNIN_HOME_ENV_ESCAPED="$escaped_home_env" \
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
