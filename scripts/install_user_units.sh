#!/usr/bin/env bash
# Install the Saturnin systemd *user* units (rule 7: user scope only, no root).
set -Eeuo pipefail
umask 077

SATURNIN_HOME="${SATURNIN_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/user_unit_install.sh
source "$SCRIPT_DIR/lib/user_unit_install.sh"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
ENABLED_TIMERS=(
  saturnin-janitor.timer
  saturnin-improve.timer
  saturnin-poller.timer
  saturnin-discovery.timer
  saturnin-resume.timer
)
MANAGED_UNITS=()
declare -A WAS_ACTIVE=()

saturnin_require_unprivileged_user

if ! saturnin_validate_render_path "$SATURNIN_HOME"; then
  cat >&2 <<'ERR'
SATURNIN_HOME contains characters that cannot be rendered safely for all
systemd directives used by Saturnin units.
Use a checkout path containing only [A-Za-z0-9/._-].
ERR
  exit 1
fi

mkdir -p "$UNIT_DIR"
if [[ -L "$SATURNIN_HOME/var" ]]; then
  echo "Refusing symlinked Saturnin transaction directory." >&2
  exit 1
fi
mkdir -p "$SATURNIN_HOME/var"
TRANSACTION_DIR="$SATURNIN_HOME/var/install-user-units.$$.$RANDOM"
mkdir -m 0700 "$TRANSACTION_DIR"
STAGE_DIR="$TRANSACTION_DIR/stage"
BACKUP_DIR="$TRANSACTION_DIR/backup"
mkdir -m 0700 "$STAGE_DIR" "$BACKUP_DIR"
installing=0
cleanup() {
  rm -rf "$TRANSACTION_DIR"
}
rollback() {
  set +e
  for unit in "${MANAGED_UNITS[@]}"; do
    if [[ "${WAS_ACTIVE[$unit]}" -eq 0 ]]; then
      systemctl --user stop "$unit"
    fi
  done
  for unit in "${MANAGED_UNITS[@]}"; do
    while IFS= read -r -d '' entry; do
      rm -f "$entry"
    done < <(find "$UNIT_DIR" -mindepth 1 -name "$unit" -print0)
  done
  rm -f "$UNIT_DIR"/saturnin-*.tmp
  cp -a "$BACKUP_DIR/tree/." "$UNIT_DIR/"
  while IFS= read -r -d '' directory; do
    relative="${directory#"$UNIT_DIR"/}"
    if [[ ! -d "$BACKUP_DIR/dirs/$relative" ]]; then
      rmdir "$directory" 2>/dev/null || true
    fi
  done < <(find "$UNIT_DIR" -mindepth 1 -depth -type d -print0)
  systemctl --user daemon-reload
  for unit in "${MANAGED_UNITS[@]}"; do
    definition="$UNIT_DIR/$unit"
    if [[ "${WAS_ACTIVE[$unit]}" -eq 1 ]] \
      && ! systemctl --user is-active --quiet "$unit" \
      && [[ -e "$definition" ]] \
      && [[ ! -L "$definition" || "$(readlink "$definition")" != "/dev/null" ]]; then
      systemctl --user start "$unit"
    fi
  done
}
on_exit() {
  status=$?
  if [[ "$installing" -eq 1 && "$status" -ne 0 ]]; then
    rollback
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

for unit in "$SATURNIN_HOME"/systemd/saturnin-*; do
  name="$(basename "$unit")"
  if [[ "$name" == saturnin-attestation.service ]]; then
    continue
  fi
  MANAGED_UNITS+=("$name")
  saturnin_render_unit "$unit" "$STAGE_DIR/$name" "$SATURNIN_HOME"
  if command -v systemd-analyze >/dev/null 2>&1; then
    if ! systemd-analyze --user verify "$STAGE_DIR/$name"; then
      echo "systemd-analyze verify failed for $name; refusing to enable invalid units" >&2
      exit 1
    fi
  fi
done

for unit in "${MANAGED_UNITS[@]}"; do
  if systemctl --user is-active --quiet "$unit"; then
    WAS_ACTIVE["$unit"]=1
  else
    WAS_ACTIVE["$unit"]=0
  fi
done

mkdir -p "$BACKUP_DIR/tree" "$BACKUP_DIR/dirs"
while IFS= read -r -d '' directory; do
  relative="${directory#"$UNIT_DIR"/}"
  mkdir -p "$BACKUP_DIR/dirs/$relative"
done < <(find "$UNIT_DIR" -mindepth 1 -type d -print0)
for staged in "$STAGE_DIR"/saturnin-*; do
  name="$(basename "$staged")"
  while IFS= read -r -d '' entry; do
    relative="${entry#"$UNIT_DIR"/}"
    mkdir -p "$BACKUP_DIR/tree/$(dirname "$relative")"
    cp -a "$entry" "$BACKUP_DIR/tree/$relative"
  done < <(find "$UNIT_DIR" -mindepth 1 -name "$name" -print0)
done

installing=1
for staged in "$STAGE_DIR"/saturnin-*; do
  name="$(basename "$staged")"
  install -m 0644 "$staged" "$UNIT_DIR/$name.tmp"
  mv -f "$UNIT_DIR/$name.tmp" "$UNIT_DIR/$name"
  echo "installed $UNIT_DIR/$name"
done

systemctl --user daemon-reload
systemctl --user enable --now "${ENABLED_TIMERS[@]}"
installing=0
systemctl --user list-timers 'saturnin-*' || true

cat <<'MSG'

Timers enabled. If Saturnin must run without an open login session:
  loginctl enable-linger "$USER"
Janitor cleanup mode follows policies/cleanup.yaml; see
docs/runbooks/ops-safety.md.
MSG
