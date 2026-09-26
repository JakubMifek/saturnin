#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

readonly UNIT=saturnin-attestation.service
readonly SCRIPT_PATH="${BASH_SOURCE[0]}"
readonly SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd -P)"
readonly DETECTED_HOME="$(cd "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/lib/user_unit_install.sh
source "$SCRIPT_DIR/lib/user_unit_install.sh"

action="${1:-}"
if [[ "$#" -ne 1 || ! "$action" =~ ^(install|status|uninstall)$ ]]; then
  echo "Usage: scripts/install_attestation_unit.sh {install|status|uninstall}" >&2
  exit 2
fi

saturnin_require_unprivileged_user
SATURNIN_HOME="${SATURNIN_HOME:-$DETECTED_HOME}"
saturnin_validate_render_path "$SATURNIN_HOME"
if [[ "$SATURNIN_HOME" != "$DETECTED_HOME" ]] \
  || [[ "$(realpath "$SATURNIN_HOME")" != "$SATURNIN_HOME" ]]; then
  echo "SATURNIN_HOME must identify the canonical checkout containing this installer." >&2
  exit 1
fi

readonly EXPECTED_SCRIPT="$SATURNIN_HOME/scripts/install_attestation_unit.sh"
readonly RUNTIME="$SATURNIN_HOME/.venv/bin/saturnin"
readonly TEMPLATE="$SATURNIN_HOME/systemd/$UNIT"
for trusted in "$EXPECTED_SCRIPT" "$RUNTIME" "$TEMPLATE"; do
  if [[ -L "$trusted" || ! -f "$trusted" ]]; then
    echo "Refusing unsafe or missing trusted file: $trusted" >&2
    exit 1
  fi
  if [[ "$(stat -c %u "$trusted")" -ne "$(id -u)" ]] \
    || (( 8#$(stat -c %a "$trusted") & 8#022 )); then
    echo "Trusted files must be owner-controlled and not group/world writable." >&2
    exit 1
  fi
done
if [[ "$(realpath "$SCRIPT_PATH")" != "$EXPECTED_SCRIPT" || ! -x "$RUNTIME" ]]; then
  echo "Refusing untrusted installer or Saturnin runtime executable identity." >&2
  exit 1
fi

readonly CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
if [[ "$CONFIG_HOME" != "$HOME/.config" ]]; then
  echo "Signer installation requires the canonical user configuration directory." >&2
  exit 1
fi
readonly UNIT_DIR="$CONFIG_HOME/systemd/user"
readonly CREDENTIAL_DIR="$UNIT_DIR/saturnin-credentials"
readonly CURRENT="$CREDENTIAL_DIR/saturnin-review-attestation-key.cred"
readonly PREVIOUS="$CREDENTIAL_DIR/saturnin-review-attestation-previous-key.cred"
readonly INSTALLED="$UNIT_DIR/$UNIT"
readonly WANTS="$UNIT_DIR/default.target.wants/$UNIT"

for parent in "$HOME" "$CONFIG_HOME" "$CONFIG_HOME/systemd" "$UNIT_DIR"; do
  if [[ -L "$parent" ]]; then
    echo "Refusing symlinked user-unit path: $parent" >&2
    exit 1
  fi
done

verify_unit_identity() {
  UNIT_PATH="$1" HOME_VALUE="$SATURNIN_HOME" python3 -c '
from pathlib import Path
import os

lines = Path(os.environ["UNIT_PATH"]).read_text(encoding="utf-8").splitlines()
home = os.environ["HOME_VALUE"]
expected = {
    "WorkingDirectory": [home],
    "Environment": [
        f"SATURNIN_HOME=\"{home}\"",
        f"PYTHONPATH=\"{home}/src\"",
    ],
    "ExecStart": [f"{home}/.venv/bin/python -m saturnin.attestation_service serve"],
    "LoadCredentialEncrypted": [
        "saturnin-review-attestation-key:%h/.config/systemd/user/saturnin-credentials/saturnin-review-attestation-key.cred",
        "saturnin-review-attestation-previous-key:%h/.config/systemd/user/saturnin-credentials/saturnin-review-attestation-previous-key.cred",
    ],
}
actual = {
    key: [line.split("=", 1)[1] for line in lines if line.startswith(f"{key}=")]
    for key in expected
}
if "@SATURNIN_HOME" in "\n".join(lines) or actual != expected:
    raise SystemExit("rendered attestation unit identity mismatch")
'
}

if [[ "$action" == status ]]; then
  if [[ ! -d "$UNIT_DIR" || -L "$INSTALLED" || ! -f "$INSTALLED" ]]; then
    echo "Canonical attestation unit is not installed safely." >&2
    exit 1
  fi
  if [[ "$(stat -c %u "$UNIT_DIR")" -ne "$(id -u)" ]] \
    || (( 8#$(stat -c %a "$UNIT_DIR") & 8#022 )); then
    echo "User-unit directory must be owner-controlled and not group/world writable." >&2
    exit 1
  fi
  verify_unit_identity "$INSTALLED"
  exec systemctl --user status --no-pager "$UNIT"
fi

mkdir -p -m 0700 "$UNIT_DIR"
if [[ "$(stat -c %u "$UNIT_DIR")" -ne "$(id -u)" ]] \
  || (( 8#$(stat -c %a "$UNIT_DIR") & 8#022 )); then
  echo "User-unit directory must be owner-controlled and not group/world writable." >&2
  exit 1
fi

readonly TRANSACTION="$UNIT_DIR/.saturnin-attestation-transaction.$$"
readonly STAGE="$TRANSACTION/stage"
readonly BACKUP="$TRANSACTION/backup"
mkdir -m 0700 "$TRANSACTION" "$BACKUP"
mutating=0
was_active=0
had_unit=0
had_wants=0
had_wants_dir=0

cleanup() {
  rm -rf "$TRANSACTION"
}

restore_entry() {
  local target=$1 backup=$2 present=$3
  rm -f "$target"
  if [[ "$present" -eq 1 ]]; then
    mkdir -p "$(dirname "$target")"
    cp -a "$backup" "$target"
  fi
}

rollback() {
  set +e
  if [[ "$was_active" -eq 0 ]]; then
    systemctl --user stop "$UNIT" >/dev/null 2>&1
  fi
  restore_entry "$INSTALLED" "$BACKUP/unit" "$had_unit"
  restore_entry "$WANTS" "$BACKUP/wants" "$had_wants"
  if [[ "$had_wants_dir" -eq 0 ]]; then
    rmdir "$(dirname "$WANTS")" 2>/dev/null || true
  fi
  systemctl --user daemon-reload >/dev/null 2>&1
  if [[ "$was_active" -eq 1 ]] && ! systemctl --user is-active --quiet "$UNIT"; then
    systemctl --user start "$UNIT" >/dev/null 2>&1
  fi
}

on_exit() {
  local status=$?
  if [[ "$mutating" -eq 1 && "$status" -ne 0 ]]; then
    rollback
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

if systemctl --user is-active --quiet "$UNIT"; then
  was_active=1
fi
if [[ -e "$INSTALLED" || -L "$INSTALLED" ]]; then
  had_unit=1
  cp -a "$INSTALLED" "$BACKUP/unit"
fi
if [[ -e "$WANTS" || -L "$WANTS" ]]; then
  had_wants=1
  cp -a "$WANTS" "$BACKUP/wants"
fi
if [[ -d "$(dirname "$WANTS")" ]]; then
  had_wants_dir=1
fi

if [[ "$action" == uninstall ]]; then
  if [[ "$had_unit" -eq 0 && "$had_wants" -eq 0 ]]; then
    echo "$UNIT is already uninstalled; encrypted credentials were left untouched"
    exit 0
  fi
  mutating=1
  if [[ "$was_active" -eq 1 ]]; then
    systemctl --user stop "$UNIT"
  else
    systemctl --user stop "$UNIT" >/dev/null 2>&1 || true
  fi
  rm -f "$WANTS" "$INSTALLED"
  systemctl --user daemon-reload
  mutating=0
  echo "uninstalled $UNIT; encrypted credentials were left untouched"
  exit 0
fi

if [[ -L "$CREDENTIAL_DIR" || ! -d "$CREDENTIAL_DIR" ]] \
  || [[ "$(stat -c %u "$CREDENTIAL_DIR")" -ne "$(id -u)" ]] \
  || [[ "$(stat -c %a "$CREDENTIAL_DIR")" != 700 ]]; then
  echo "Attestation credential directory is missing or unsafe." >&2
  exit 1
fi
for credential in "$CURRENT" "$PREVIOUS"; do
  if [[ -L "$credential" || ! -f "$credential" ]] \
    || [[ "$(stat -c %u "$credential")" -ne "$(id -u)" ]] \
    || [[ "$(stat -c %a "$credential")" != 600 ]]; then
    echo "Attestation credential pair is incomplete or unsafe." >&2
    exit 1
  fi
done
credential_status="$("$RUNTIME" credential status review-attestation)"
if [[ "$credential_status" != *"rotation=ready"* || "$credential_status" != *"signer=ready"* ]]; then
  echo "Attestation provisioning must report rotation=ready and signer=ready." >&2
  exit 1
fi
unset credential_status

saturnin_render_unit "$TEMPLATE" "$STAGE" "$SATURNIN_HOME"
verify_unit_identity "$STAGE"
if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze --user verify "$STAGE"
fi

chmod 0644 "$STAGE"
mutating=1
mv -f "$STAGE" "$INSTALLED"
systemctl --user daemon-reload
systemctl --user enable "$UNIT"
systemctl --user start "$UNIT"
mutating=0
echo "installed and started $UNIT"
