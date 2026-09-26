#!/usr/bin/bash
set -Eeuo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH
unset BASH_ENV ENV CDPATH PYTHONHOME PYTHONPATH
IFS=$' \t\n'

readonly UNIT=saturnin-attestation.service
readonly ID=/usr/bin/id
readonly REALPATH=/usr/bin/realpath
readonly STAT=/usr/bin/stat
PYTHON="$("$REALPATH" /usr/bin/python3)"
readonly PYTHON
readonly SYSTEMCTL=/usr/bin/systemctl
readonly SYSTEMD_ANALYZE=/usr/bin/systemd-analyze
readonly FLOCK=/usr/bin/flock
readonly MKDIR=/usr/bin/mkdir
readonly RM=/usr/bin/rm
readonly CP=/usr/bin/cp
readonly MV=/usr/bin/mv
readonly CHMOD=/usr/bin/chmod
readonly RMDIR=/usr/bin/rmdir
readonly RAW_SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_PATH="$("$REALPATH" -- "$RAW_SCRIPT_PATH")"
readonly SCRIPT_PATH
readonly SCRIPT_DIR="${SCRIPT_PATH%/*}"
DETECTED_HOME="$(cd "$SCRIPT_DIR/.." && pwd -P)"
readonly DETECTED_HOME

action="${1:-}"
if [[ "$#" -ne 1 || ! "$action" =~ ^(install|status|uninstall)$ ]]; then
  echo "Usage: scripts/install_attestation_unit.sh {install|status|uninstall}" >&2
  exit 2
fi

CURRENT_UID="$("$ID" -u)"
CURRENT_GID="$("$ID" -g)"
readonly CURRENT_UID CURRENT_GID
if [[ "$CURRENT_UID" -eq 0 ]]; then
  echo "Refusing to manage user units as root." >&2
  exit 1
fi
SATURNIN_HOME="${SATURNIN_HOME:-$DETECTED_HOME}"
if [[ ! "$SATURNIN_HOME" =~ ^/[A-Za-z0-9/._-]+$ ]]; then
  echo "SATURNIN_HOME must be an absolute canonical path using only [A-Za-z0-9/._-]." >&2
  exit 1
fi
if [[ "$SATURNIN_HOME" != "$DETECTED_HOME" ]] \
  || [[ "$("$REALPATH" "$SATURNIN_HOME")" != "$SATURNIN_HOME" ]]; then
  echo "SATURNIN_HOME must identify the canonical checkout containing this installer." >&2
  exit 1
fi

readonly EXPECTED_SCRIPT="$SATURNIN_HOME/scripts/install_attestation_unit.sh"
readonly RUNTIME="$SATURNIN_HOME/.venv/bin/saturnin"
readonly SOURCE="$SATURNIN_HOME/src/saturnin"
readonly TEMPLATE="$SATURNIN_HOME/systemd/$UNIT"

for tool in "$ID" "$REALPATH" "$STAT" "$PYTHON" "$SYSTEMCTL" \
  "$SYSTEMD_ANALYZE" "$FLOCK" "$MKDIR" "$RM" "$CP" "$MV" "$CHMOD" "$RMDIR"; do
  if [[ -L "$tool" || ! -x "$tool" ]] \
    || [[ "$("$STAT" -c %u "$tool")" -ne 0 ]] \
    || (( 8#$("$STAT" -c %a "$tool") & 8#022 )); then
    echo "Refusing unsafe canonical system tool: $tool" >&2
    exit 1
  fi
done

for trusted in "$EXPECTED_SCRIPT" "$RUNTIME" "$TEMPLATE"; do
  if [[ -L "$trusted" || ! -f "$trusted" ]]; then
    echo "Refusing unsafe or missing trusted file: $trusted" >&2
    exit 1
  fi
  if [[ "$("$STAT" -c %u "$trusted")" -ne "$CURRENT_UID" ]] \
    || (( 8#$("$STAT" -c %a "$trusted") & 8#022 )); then
    echo "Trusted files must be owner-controlled and not group/world writable." >&2
    exit 1
  fi
done
if [[ -L "$RAW_SCRIPT_PATH" || "$SCRIPT_PATH" != "$EXPECTED_SCRIPT" || ! -x "$RUNTIME" ]]; then
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
readonly INSTALLED_RUNTIME="$UNIT_DIR/saturnin-attestation-runtime.pyz"
readonly WANTS="$UNIT_DIR/default.target.wants/$UNIT"

validate_parent_chain() {
  "$PYTHON" -I - "$1" "$CURRENT_UID" "$CURRENT_GID" <<'PY'
import grp
import os
import pwd
import stat
import sys
from pathlib import Path

target = Path(sys.argv[1])
uid = int(sys.argv[2])
gid = int(sys.argv[3])
parts = target.parts
current = Path(parts[0])
for part in parts[1:]:
    current /= part
    try:
        metadata = current.lstat()
    except FileNotFoundError:
        break
    if stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(f"refusing symlinked trusted path component: {current}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise SystemExit(f"trusted path component is not a directory: {current}")
    writable = metadata.st_mode & 0o022
    safe_sticky_root = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
    private_group = False
    if metadata.st_uid == uid and metadata.st_gid == gid and metadata.st_mode & 0o020:
        group = grp.getgrgid(gid)
        primary_users = [entry.pw_uid for entry in pwd.getpwall() if entry.pw_gid == gid]
        private_group = not group.gr_mem and set(primary_users) == {uid}
    unsafe_write = metadata.st_mode & 0o002 or (
        metadata.st_mode & 0o020 and not private_group
    )
    if metadata.st_uid not in (0, uid) or (unsafe_write and not safe_sticky_root):
        raise SystemExit(f"trusted path component is not owner-controlled: {current}")
PY
}

validate_parent_chain "$SATURNIN_HOME"
validate_parent_chain "$UNIT_DIR"
validate_parent_chain "$SOURCE"

for parent in "$HOME" "$CONFIG_HOME" "$CONFIG_HOME/systemd" "$UNIT_DIR"; do
  if [[ -L "$parent" ]]; then
    echo "Refusing symlinked user-unit path: $parent" >&2
    exit 1
  fi
done

snapshot_trusted_file() {
  SOURCE_PATH="$1" DESTINATION_PATH="$2" DESTINATION_MODE="$3" \
    EXPECTED_UID="$CURRENT_UID" "$PYTHON" -I -c '
import hashlib
import os
import stat

source = os.environ["SOURCE_PATH"]
destination = os.environ["DESTINATION_PATH"]
mode = int(os.environ["DESTINATION_MODE"], 8)
expected_uid = int(os.environ["EXPECTED_UID"])
source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    before = os.fstat(source_fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_uid
        or before.st_mode & 0o022
    ):
        raise SystemExit("trusted source descriptor has unsafe metadata")
    first = bytearray()
    while chunk := os.read(source_fd, 65536):
        first.extend(chunk)
    after_first = os.fstat(source_fd)
    os.lseek(source_fd, 0, os.SEEK_SET)
    second_digest = hashlib.sha256()
    while chunk := os.read(source_fd, 65536):
        second_digest.update(chunk)
    after_second = os.fstat(source_fd)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        identity(before) != identity(after_first)
        or identity(after_first) != identity(after_second)
        or hashlib.sha256(first).digest() != second_digest.digest()
    ):
        raise SystemExit("trusted source changed while being snapshotted")
    destination_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        view = memoryview(first)
        while view:
            view = view[os.write(destination_fd, view):]
        os.fchmod(destination_fd, mode)
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
finally:
    os.close(source_fd)
'
}

snapshot_runtime_tree() {
  SOURCE_PATH="$SOURCE" HOME_PATH="$SATURNIN_HOME" DESTINATION_PATH="$1" \
    EXPECTED_UID="$CURRENT_UID" \
    "$PYTHON" -I -c '
import os
import stat
import sys
import zipfile
from pathlib import Path

source = Path(os.environ["SOURCE_PATH"])
home = Path(os.environ["HOME_PATH"])
destination = Path(os.environ["DESTINATION_PATH"])
expected_uid = int(os.environ["EXPECTED_UID"])
python_version = f"python{sys.version_info.major}.{sys.version_info.minor}"
yaml_candidates = list((home / ".venv" / "lib" / python_version / "site-packages").glob("yaml"))
if len(yaml_candidates) != 1:
    raise SystemExit("canonical PyYAML runtime source is unavailable")

entries = []
for package, package_name in ((source, "saturnin"), (yaml_candidates[0], "yaml")):
    for root_path, directory_names, file_names, root_fd in os.fwalk(
        package, topdown=True, follow_symlinks=False
    ):
        root_metadata = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != expected_uid
            or root_metadata.st_mode & 0o022
        ):
            raise SystemExit(
                f"attestation runtime directory has unsafe metadata: {root_path}"
            )
        for name in directory_names:
            metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise SystemExit(
                    f"refusing symlinked attestation runtime source: {root_path}/{name}"
                )
        relative_root = Path(root_path).relative_to(package)
        for name in sorted(file_names):
            metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise SystemExit(
                    f"refusing symlinked attestation runtime source: {root_path}/{name}"
                )
            if not stat.S_ISREG(metadata.st_mode) or Path(name).suffix != ".py":
                continue
            if metadata.st_uid != expected_uid or metadata.st_mode & 0o022:
                raise SystemExit(
                    f"attestation runtime source has unsafe metadata: {root_path}/{name}"
                )
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
            try:
                before = os.fstat(descriptor)
                content = bytearray()
                while chunk := os.read(descriptor, 65536):
                    content.extend(chunk)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            identity = lambda value: (
                value.st_dev,
                value.st_ino,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )
            if (
                identity(metadata) != identity(before)
                or identity(before) != identity(after)
                or not stat.S_ISREG(before.st_mode)
                or before.st_uid != expected_uid
                or before.st_mode & 0o022
            ):
                raise SystemExit(
                    f"attestation runtime changed during snapshot: {root_path}/{name}"
                )
            relative = relative_root / name
            entries.append((f"{package_name}/{relative}", bytes(content)))

if not entries or not any(name == "saturnin/attestation_service.py" for name, _ in entries):
    raise SystemExit("attestation source snapshot is incomplete")
with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
    for name, content in entries:
        info = zipfile.ZipInfo(name)
        info.external_attr = 0o400 << 16
        archive.writestr(info, content)
os.chmod(destination, 0o400)
'
}

credential_identity() {
  CREDENTIAL_PATH="$1" EXPECTED_UID="$CURRENT_UID" "$PYTHON" -I -c '
import hashlib
import os
import stat

path = os.environ["CREDENTIAL_PATH"]
expected_uid = int(os.environ["EXPECTED_UID"])
descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_uid
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise SystemExit("credential descriptor metadata mismatch")
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 65536):
        digest.update(chunk)
    after = os.fstat(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise SystemExit("credential changed during validation")
    print(f"{before.st_dev}:{before.st_ino}:{digest.hexdigest()}")
finally:
    os.close(descriptor)
'
}

trusted_file_identity() {
  TRUSTED_PATH="$1" EXPECTED_MODE="$2" EXPECTED_UID="$CURRENT_UID" "$PYTHON" -I -c '
import hashlib
import os
import stat

descriptor = os.open(
    os.environ["TRUSTED_PATH"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
)
try:
    before = os.fstat(descriptor)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 65536):
        digest.update(chunk)
    after = os.fstat(descriptor)
finally:
    os.close(descriptor)
identity = lambda value: (
    value.st_dev,
    value.st_ino,
    value.st_size,
    value.st_mtime_ns,
    value.st_ctime_ns,
)
if (
    identity(before) != identity(after)
    or not stat.S_ISREG(before.st_mode)
    or before.st_uid != int(os.environ["EXPECTED_UID"])
    or stat.S_IMODE(before.st_mode) != int(os.environ["EXPECTED_MODE"], 8)
):
    raise SystemExit("trusted file identity mismatch")
print(f"{before.st_dev}:{before.st_ino}:{digest.hexdigest()}")
'
}

trusted_fd_identity() {
  TRUSTED_FD="$1" EXPECTED_MODE="$2" EXPECTED_UID="$CURRENT_UID" "$PYTHON" -I -c '
import hashlib
import os
import stat

descriptor = int(os.environ["TRUSTED_FD"])
os.lseek(descriptor, 0, os.SEEK_SET)
before = os.fstat(descriptor)
digest = hashlib.sha256()
while chunk := os.read(descriptor, 65536):
    digest.update(chunk)
after = os.fstat(descriptor)
os.lseek(descriptor, 0, os.SEEK_SET)
identity = lambda value: (
    value.st_dev,
    value.st_ino,
    value.st_size,
    value.st_mtime_ns,
    value.st_ctime_ns,
)
if (
    identity(before) != identity(after)
    or not stat.S_ISREG(before.st_mode)
    or before.st_uid != int(os.environ["EXPECTED_UID"])
    or stat.S_IMODE(before.st_mode) != int(os.environ["EXPECTED_MODE"], 8)
):
    raise SystemExit("trusted descriptor identity mismatch")
print(f"{before.st_dev}:{before.st_ino}:{digest.hexdigest()}")
'
}

stable_symlink_target() {
  LINK_PATH="$1" EXPECTED_UID="$CURRENT_UID" "$PYTHON" -I -c '
import os
import stat

path = os.environ["LINK_PATH"]
before = os.lstat(path)
target = os.readlink(path)
after = os.lstat(path)
identity = lambda value: (
    value.st_dev,
    value.st_ino,
    value.st_size,
    value.st_mtime_ns,
    value.st_ctime_ns,
)
if (
    identity(before) != identity(after)
    or not stat.S_ISLNK(before.st_mode)
    or before.st_uid != int(os.environ["EXPECTED_UID"])
):
    raise SystemExit("enablement link identity mismatch")
print(target)
'
}

verify_unit_identity() {
  UNIT_PATH="$1" EXPECTED_MODE="$2" RUNTIME_SHA256_VALUE="$3" \
    EXPECTED_UID="$CURRENT_UID" \
    HOME_VALUE="$SATURNIN_HOME" "$PYTHON" -I -c '
import os
import stat

path = os.environ["UNIT_PATH"]
expected_mode = int(os.environ["EXPECTED_MODE"], 8)
expected_uid = int(os.environ["EXPECTED_UID"])
descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
before = os.fstat(descriptor)
if (
    not stat.S_ISREG(before.st_mode)
    or before.st_uid != expected_uid
    or stat.S_IMODE(before.st_mode) != expected_mode
):
    raise SystemExit("rendered attestation unit descriptor metadata mismatch")
content = bytearray()
while chunk := os.read(descriptor, 65536):
    content.extend(chunk)
after = os.fstat(descriptor)
os.close(descriptor)
if (
    before.st_dev,
    before.st_ino,
    before.st_size,
    before.st_mtime_ns,
    before.st_ctime_ns,
) != (
    after.st_dev,
    after.st_ino,
    after.st_size,
    after.st_mtime_ns,
    after.st_ctime_ns,
):
    raise SystemExit("rendered attestation unit changed during validation")
lines = content.decode("utf-8").splitlines()
home = os.environ["HOME_VALUE"]
runtime_sha256 = os.environ["RUNTIME_SHA256_VALUE"]
expected = [
    ("Unit", [
        "Description=Saturnin private review attestation signer",
        f"Documentation=file://{home}/docs/runbooks/ops-safety.md",
    ]),
    ("Service", [
        "Type=simple",
        f"WorkingDirectory={home}",
        f"Environment=SATURNIN_HOME=\"{home}\"",
        f"Environment=SATURNIN_RUNTIME_SHA256=\"{runtime_sha256}\"",
        "ExecStart=/usr/bin/python3 -I -c '\''import hashlib,os,runpy,stat,sys;p=os.path.expanduser(\"~/.config/systemd/user/saturnin-attestation-runtime.pyz\");f=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);m=os.fstat(f);d=hashlib.file_digest(os.fdopen(os.dup(f),\"rb\"),\"sha256\").hexdigest();assert stat.S_ISREG(m.st_mode) and m.st_uid==os.getuid() and stat.S_IMODE(m.st_mode)==0o400 and d==os.environ[\"SATURNIN_RUNTIME_SHA256\"];sys.path.insert(0,f\"/proc/self/fd/{f}\");runpy.run_module(\"saturnin.attestation_service\",run_name=\"__main__\")'\'' serve",
        "LoadCredentialEncrypted=saturnin-review-attestation-key:%h/.config/systemd/user/saturnin-credentials/saturnin-review-attestation-key.cred",
        "LoadCredentialEncrypted=saturnin-review-attestation-previous-key:%h/.config/systemd/user/saturnin-credentials/saturnin-review-attestation-previous-key.cred",
        "RuntimeDirectory=saturnin-attestation",
        "RuntimeDirectoryMode=0700",
        "PrivateMounts=yes",
        "PrivateTmp=yes",
        "PrivateNetwork=yes",
        "ProtectHome=read-only",
        "ProtectSystem=strict",
        "ProtectProc=invisible",
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_UNIX",
    ]),
    ("Install", [
        "WantedBy=default.target",
    ]),
]
actual = []
current = None
for line in lines:
    if not line:
        continue
    if line.startswith("[") and line.endswith("]"):
        current = (line[1:-1], [])
        actual.append(current)
    elif current is None or line.startswith("#") or "=" not in line:
        raise SystemExit("rendered attestation unit has invalid structure")
    else:
        current[1].append(line)
if actual != expected:
    raise SystemExit("rendered attestation unit identity mismatch")
print(f"{before.st_dev}:{before.st_ino}")
'
}

verify_manager_loaded_unit() {
  local manager_view=$1 expected_unit=${2:-$INSTALLED_SNAPSHOT}
  MANAGER_VIEW_PATH="$manager_view" UNIT_PATH="$expected_unit" \
    INSTALLED_PATH="$INSTALLED" "$PYTHON" -I -c '
import os
from pathlib import Path

manager = Path(os.environ["MANAGER_VIEW_PATH"]).read_text(encoding="utf-8").splitlines()
expected = Path(os.environ["UNIT_PATH"]).read_text(encoding="utf-8").splitlines()
if not manager or manager[0] != f"# {os.environ['"'"'INSTALLED_PATH'"'"']}":
    raise SystemExit("systemd manager reported an unexpected unit fragment")
if manager[1:] != expected:
    raise SystemExit("systemd manager-loaded unit representation mismatch")
'
}

if [[ ! -d "$UNIT_DIR" ]]; then
  if [[ "$action" == status ]]; then
    echo "Canonical attestation unit is not installed safely." >&2
    exit 1
  fi
  "$MKDIR" -p -m 0700 "$UNIT_DIR"
fi
validate_parent_chain "$UNIT_DIR"
if [[ "$("$STAT" -c %u "$UNIT_DIR")" -ne "$CURRENT_UID" ]] \
  || (( 8#$("$STAT" -c %a "$UNIT_DIR") & 8#022 )); then
  echo "User-unit directory must be owner-controlled and not group/world writable." >&2
  exit 1
fi

exec {LIFECYCLE_LOCK_FD}<"$HOME"
readonly LIFECYCLE_LOCK_FD
if ! "$FLOCK" --exclusive --nonblock "$LIFECYCLE_LOCK_FD"; then
  echo "Another attestation unit lifecycle operation is in progress." >&2
  exit 1
fi
UNIT_DIR_DEVICE_INODE="$("$STAT" -Lc %d:%i "$UNIT_DIR")"
readonly UNIT_DIR_DEVICE_INODE
verify_unit_directory() {
  if [[ -L "$UNIT_DIR" || "$("$STAT" -Lc %d:%i "$UNIT_DIR")" != "$UNIT_DIR_DEVICE_INODE" ]]; then
    echo "User-unit directory identity changed during lifecycle operation." >&2
    return 1
  fi
}

if [[ "$action" == status ]]; then
  verify_unit_directory
  STATUS_RUNTIME_ID="$(trusted_file_identity "$INSTALLED_RUNTIME" 0400)"
  verify_unit_identity "$INSTALLED" 0644 "${STATUS_RUNTIME_ID##*:}" >/dev/null
  exec "$SYSTEMCTL" --user status --no-pager "$UNIT"
fi

readonly TRANSACTION="$UNIT_DIR/.saturnin-attestation-transaction.$$"
readonly STAGE="$TRANSACTION/stage"
readonly BACKUP="$TRANSACTION/backup"
readonly MANAGER_VIEW="$TRANSACTION/manager-view"
readonly RUNTIME_SNAPSHOT="$TRANSACTION/saturnin"
readonly RUNTIME_TREE_SNAPSHOT="$TRANSACTION/saturnin-attestation-runtime.pyz"
readonly TEMPLATE_SNAPSHOT="$TRANSACTION/$UNIT.template"
readonly INSTALLED_SNAPSHOT="$TRANSACTION/$UNIT.installed"
cleanup() {
  if verify_unit_directory >/dev/null 2>&1; then
    "$RM" -rf "$TRANSACTION"
  fi
}
trap cleanup EXIT
"$MKDIR" -m 0700 "$TRANSACTION" "$BACKUP"
snapshot_trusted_file "$RUNTIME" "$RUNTIME_SNAPSHOT" 0500
snapshot_runtime_tree "$RUNTIME_TREE_SNAPSHOT"
exec {RUNTIME_TREE_FD}<"$RUNTIME_TREE_SNAPSHOT"
readonly RUNTIME_TREE_FD
RUNTIME_TREE_ID="$(trusted_fd_identity "$RUNTIME_TREE_FD" 0400)"
readonly RUNTIME_TREE_ID
RUNTIME_TREE_SHA256="${RUNTIME_TREE_ID##*:}"
readonly RUNTIME_TREE_SHA256
if [[ "$(trusted_file_identity "$RUNTIME_TREE_SNAPSHOT" 0400)" != "$RUNTIME_TREE_ID" ]]; then
  echo "Attestation runtime path changed after snapshot construction." >&2
  exit 1
fi
snapshot_trusted_file "$TEMPLATE" "$TEMPLATE_SNAPSHOT" 0400
mutating=0
was_active=0
had_unit=0
had_wants=0
had_wants_dir=0
had_runtime=0
unit_was_valid=0
unit_backup_identity=
runtime_backup_identity=
wants_target=

restore_file() {
  local target=$1 backup=$2 present=$3 mode=$4 expected_identity=$5
  "$RM" -f "$target"
  if [[ "$present" -eq 1 ]]; then
    if [[ "$(trusted_file_identity "$backup" "$mode")" != "$expected_identity" ]]; then
      echo "Refusing changed rollback snapshot: $backup" >&2
      return 1
    fi
    snapshot_trusted_file "$backup" "$target" "$mode"
  fi
}

rollback() {
  set +e
  if [[ "$was_active" -eq 0 ]]; then
    "$SYSTEMCTL" --user stop "$UNIT" >/dev/null 2>&1
  fi
  if ! verify_unit_directory; then
    echo "Rollback stopped because the user-unit directory was replaced." >&2
    return
  fi
  restore_file "$INSTALLED" "$BACKUP/unit" "$had_unit" 0644 "$unit_backup_identity" || return
  restore_file "$INSTALLED_RUNTIME" "$BACKUP/runtime" "$had_runtime" 0400 \
    "$runtime_backup_identity" || return
  "$RM" -f "$WANTS"
  if [[ "$had_wants" -eq 1 ]]; then
    WANT_PATH="$WANTS" WANT_TARGET="$wants_target" "$PYTHON" -I -c \
      'import os; os.symlink(os.environ["WANT_TARGET"], os.environ["WANT_PATH"])'
  fi
  if [[ "$had_wants_dir" -eq 0 ]]; then
    "$RMDIR" "${WANTS%/*}" 2>/dev/null || true
  fi
  "$SYSTEMCTL" --user daemon-reload >/dev/null 2>&1
  if [[ "$was_active" -eq 1 ]] \
    && [[ "$unit_was_valid" -eq 1 ]] \
    && verify_unit_directory \
    && verify_unit_identity "$INSTALLED" 0644 "${runtime_backup_identity##*:}" >/dev/null \
    && trusted_file_identity "$INSTALLED_RUNTIME" 0400 >/dev/null \
    && "$SYSTEMCTL" --user cat --no-pager "$UNIT" >"$MANAGER_VIEW" \
    && verify_manager_loaded_unit "$MANAGER_VIEW" "$BACKUP/unit" \
    && ! "$SYSTEMCTL" --user is-active --quiet "$UNIT"; then
    "$SYSTEMCTL" --user start "$UNIT" >/dev/null 2>&1
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

if "$SYSTEMCTL" --user is-active --quiet "$UNIT"; then
  was_active=1
fi
if [[ -e "$INSTALLED_RUNTIME" || -L "$INSTALLED_RUNTIME" ]]; then
  had_runtime=1
  snapshot_trusted_file "$INSTALLED_RUNTIME" "$BACKUP/runtime" 0400
  runtime_backup_identity="$(trusted_file_identity "$BACKUP/runtime" 0400)"
fi
if [[ -e "$INSTALLED" || -L "$INSTALLED" ]]; then
  had_unit=1
  trusted_file_identity "$INSTALLED" 0644 >/dev/null
  if [[ "$had_runtime" -eq 1 ]] \
    && verify_unit_identity "$INSTALLED" 0644 \
      "${runtime_backup_identity##*:}" >/dev/null 2>&1; then
    unit_was_valid=1
  elif [[ "$was_active" -eq 1 ]]; then
    echo "Refusing to replace an active unvalidated attestation unit." >&2
    exit 1
  fi
  snapshot_trusted_file "$INSTALLED" "$BACKUP/unit" 0644
  unit_backup_identity="$(trusted_file_identity "$BACKUP/unit" 0644)"
fi
if [[ -e "$WANTS" || -L "$WANTS" ]]; then
  had_wants=1
  wants_target="$(stable_symlink_target "$WANTS")"
fi
if [[ -d "${WANTS%/*}" ]]; then
  had_wants_dir=1
fi

if [[ "$action" == uninstall ]]; then
  if [[ "$had_unit" -eq 0 && "$had_wants" -eq 0 && "$had_runtime" -eq 0 ]]; then
    echo "$UNIT is already uninstalled; encrypted credentials were left untouched"
    exit 0
  fi
  mutating=1
  verify_unit_directory
  if [[ "$was_active" -eq 1 ]]; then
    "$SYSTEMCTL" --user stop "$UNIT"
  else
    "$SYSTEMCTL" --user stop "$UNIT" >/dev/null 2>&1 || true
  fi
  "$RM" -f "$WANTS" "$INSTALLED" "$INSTALLED_RUNTIME"
  verify_unit_directory
  "$SYSTEMCTL" --user daemon-reload
  mutating=0
  echo "uninstalled $UNIT; encrypted credentials were left untouched"
  exit 0
fi

if [[ -L "$CREDENTIAL_DIR" || ! -d "$CREDENTIAL_DIR" ]] \
  || [[ "$("$STAT" -c %u "$CREDENTIAL_DIR")" -ne "$CURRENT_UID" ]] \
  || [[ "$("$STAT" -c %a "$CREDENTIAL_DIR")" != 700 ]]; then
  echo "Attestation credential directory is missing or unsafe." >&2
  exit 1
fi
CURRENT_CREDENTIAL_ID="$(credential_identity "$CURRENT")"
PREVIOUS_CREDENTIAL_ID="$(credential_identity "$PREVIOUS")"
readonly CURRENT_CREDENTIAL_ID PREVIOUS_CREDENTIAL_ID
credential_status="$(
  PYTHONPATH="/proc/self/fd/$RUNTIME_TREE_FD" "$PYTHON" -P -m saturnin \
    credential status review-attestation
)"
if [[ "$credential_status" != *"rotation=ready"* || "$credential_status" != *"signer=ready"* ]]; then
  echo "Attestation provisioning must report rotation=ready and signer=ready." >&2
  exit 1
fi
unset credential_status
if [[ "$(credential_identity "$CURRENT")" != "$CURRENT_CREDENTIAL_ID" ]] \
  || [[ "$(credential_identity "$PREVIOUS")" != "$PREVIOUS_CREDENTIAL_ID" ]]; then
  echo "Attestation credential identity changed during readiness validation." >&2
  exit 1
fi

TEMPLATE_PATH="$TEMPLATE_SNAPSHOT" DESTINATION="$STAGE" \
  HOME_VALUE="$SATURNIN_HOME" RUNTIME_SHA256_VALUE="$RUNTIME_TREE_SHA256" \
  "$PYTHON" -I -c '
import os
from pathlib import Path

template = Path(os.environ["TEMPLATE_PATH"]).read_text(encoding="utf-8")
home = os.environ["HOME_VALUE"]
rendered = template.replace("@SATURNIN_HOME@", home).replace(
    "@SATURNIN_HOME_ENV@", home
).replace("@SATURNIN_RUNTIME_SHA256@", os.environ["RUNTIME_SHA256_VALUE"])
Path(os.environ["DESTINATION"]).write_text(rendered, encoding="utf-8")
'
verify_unit_identity "$STAGE" 0600 "$RUNTIME_TREE_SHA256" >/dev/null
"$SYSTEMD_ANALYZE" --user verify "$STAGE"

"$CHMOD" 0644 "$STAGE"
mutating=1
verify_unit_directory
if [[ "$(trusted_file_identity "$RUNTIME_TREE_SNAPSHOT" 0400)" != "$RUNTIME_TREE_ID" ]] \
  || [[ "$(trusted_fd_identity "$RUNTIME_TREE_FD" 0400)" != "$RUNTIME_TREE_ID" ]]; then
  echo "Attestation runtime changed before installation." >&2
  exit 1
fi
"$MV" -f "$RUNTIME_TREE_SNAPSHOT" "$INSTALLED_RUNTIME"
"$MV" -f "$STAGE" "$INSTALLED"
verify_unit_directory
INSTALLED_RUNTIME_ID="$(trusted_file_identity "$INSTALLED_RUNTIME" 0400)"
readonly INSTALLED_RUNTIME_ID
if [[ "$INSTALLED_RUNTIME_ID" != "$RUNTIME_TREE_ID" ]]; then
  echo "Installed attestation runtime does not match the validated snapshot." >&2
  exit 1
fi
INSTALLED_DEVICE_INODE="$(
  verify_unit_identity "$INSTALLED" 0644 "$RUNTIME_TREE_SHA256"
)"
readonly INSTALLED_DEVICE_INODE
snapshot_trusted_file "$INSTALLED" "$INSTALLED_SNAPSHOT" 0400
"$SYSTEMCTL" --user daemon-reload
verify_unit_directory
"$SYSTEMCTL" --user cat --no-pager "$UNIT" >"$MANAGER_VIEW"
verify_manager_loaded_unit "$MANAGER_VIEW"
if [[ "$(verify_unit_identity "$INSTALLED" 0644 "$RUNTIME_TREE_SHA256")" != "$INSTALLED_DEVICE_INODE" ]]; then
  echo "Installed attestation unit identity drifted after daemon-reload." >&2
  exit 1
fi
"$SYSTEMCTL" --user enable "$UNIT"
verify_unit_directory
if [[ "$(verify_unit_identity "$INSTALLED" 0644 "$RUNTIME_TREE_SHA256")" != "$INSTALLED_DEVICE_INODE" ]]; then
  echo "Installed attestation unit identity drifted before start." >&2
  exit 1
fi
if [[ "$(trusted_file_identity "$INSTALLED_RUNTIME" 0400)" != "$RUNTIME_TREE_ID" ]] \
  || [[ "$(trusted_fd_identity "$RUNTIME_TREE_FD" 0400)" != "$RUNTIME_TREE_ID" ]]; then
  echo "Installed attestation runtime identity drifted before signer start." >&2
  exit 1
fi
if [[ "$(credential_identity "$CURRENT")" != "$CURRENT_CREDENTIAL_ID" ]] \
  || [[ "$(credential_identity "$PREVIOUS")" != "$PREVIOUS_CREDENTIAL_ID" ]]; then
  echo "Attestation credential identity drifted before signer start." >&2
  exit 1
fi
verify_unit_directory
"$SYSTEMCTL" --user start "$UNIT"
mutating=0
echo "installed and started $UNIT"
