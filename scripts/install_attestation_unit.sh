#!/usr/bin/bash
set -Eeuo pipefail
trap 'exit 124' TERM INT HUP
umask 077
PATH=/usr/bin:/bin
export PATH
unset BASH_ENV ENV CDPATH PYTHONHOME PYTHONPATH
IFS=$' \t\n'

readonly UNIT=saturnin-attestation.service
readonly EXPECTED_RUNTIME_MANIFEST_SHA256=0a00057391c04203d451dc728dac4de340f7f0224ad3a9787f94a25bb8578956
readonly ID=/usr/bin/id
readonly REALPATH=/usr/bin/realpath
readonly STAT=/usr/bin/stat
PYTHON="$("$REALPATH" /usr/bin/python3)"
readonly PYTHON
readonly SYSTEMCTL=/usr/bin/systemctl
readonly SYSTEMD_ANALYZE=/usr/bin/systemd-analyze
readonly SYSTEMD_CREDS=/usr/bin/systemd-creds
readonly FLOCK=/usr/bin/flock
readonly MKDIR=/usr/bin/mkdir
readonly RM=/usr/bin/rm
readonly CP=/usr/bin/cp
readonly MV=/usr/bin/mv
readonly CHMOD=/usr/bin/chmod
readonly SLEEP=/usr/bin/sleep
readonly TIMEOUT=/usr/bin/timeout
readonly CGROUP_ROOT=/sys/fs/cgroup
readonly CGROUP_ROOT_OWNER=0
readonly RAW_SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_PATH="$("$REALPATH" -- "$RAW_SCRIPT_PATH")"
readonly SCRIPT_PATH
GOVERNED_EXECUTION=0
if [[ "${SATURNIN_GOVERNED_EXECUTION:-}" == sealed-memfd ]] \
  && [[ "$RAW_SCRIPT_PATH" =~ ^/proc/self/fd/[0-9]+$ ]]; then
  GOVERNED_EXECUTION=1
  DETECTED_HOME="${SATURNIN_HOME:-}"
else
  readonly SCRIPT_DIR="${SCRIPT_PATH%/*}"
  DETECTED_HOME="$(cd "$SCRIPT_DIR/.." && pwd -P)"
fi
readonly GOVERNED_EXECUTION
readonly DETECTED_HOME

action="${1:-}"
if [[ "$#" -ne 1 || ! "$action" =~ ^(install|status|uninstall)$ ]]; then
  echo "Usage: scripts/install_attestation_unit.sh {install|status|uninstall}" >&2
  exit 2
fi
if [[ "$GOVERNED_EXECUTION" -ne 1 ]]; then
  echo "Signer operations require governed sealed execution." >&2
  exit 1
fi
if [[ "$action" == install ]] \
  && { [[ ! "${SATURNIN_GOVERNED_RUNTIME_FD:-}" =~ ^[0-9]+$ ]] \
    || [[ ! -e "/proc/self/fd/$SATURNIN_GOVERNED_RUNTIME_FD" ]]; }; then
  echo "Signer installation requires a governed sealed runtime descriptor." >&2
  exit 1
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
readonly TEMPLATE="$SATURNIN_HOME/systemd/$UNIT"

for tool in "$ID" "$REALPATH" "$STAT" "$PYTHON" "$SYSTEMCTL" \
  "$SYSTEMD_ANALYZE" "$SYSTEMD_CREDS" "$FLOCK" "$MKDIR" "$RM" "$CP" "$MV" \
  "$CHMOD" "$SLEEP" "$TIMEOUT"; do
  if [[ -L "$tool" || ! -x "$tool" ]] \
    || [[ "$("$STAT" -c %u "$tool")" -ne 0 ]] \
    || (( 8#$("$STAT" -c %a "$tool") & 8#022 )); then
    echo "Refusing unsafe canonical system tool: $tool" >&2
    exit 1
  fi
done

SYSTEMD_CREDS_SHA256=
SYSTEMD_CREDS_DEVICE=
SYSTEMD_CREDS_INODE=
SYSTEMD_CREDS_MODE=
if [[ "$action" == install ]]; then
  read -r SYSTEMD_CREDS_SHA256 SYSTEMD_CREDS_DEVICE \
    SYSTEMD_CREDS_INODE SYSTEMD_CREDS_MODE < <(
  "$PYTHON" -I -c '
import hashlib
import os
import stat

descriptors = []
try:
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors.append(parent)
    parents = [os.fstat(parent)]
    for component in ("usr", "bin"):
        parent = os.open(
            component,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        descriptors.append(parent)
        parents.append(os.fstat(parent))
    descriptor = os.open(
        "systemd-creds",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent,
    )
    descriptors.append(descriptor)
    before = os.fstat(descriptor)
    if (
        any(
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid != 0
            or value.st_mode & 0o022
            for value in parents
        )
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or not before.st_mode & 0o111
    ):
        raise SystemExit("systemd-creds host identity is unsafe")
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 65536):
        digest.update(chunk)
    after = os.fstat(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise SystemExit("systemd-creds changed during host validation")
    print(
        digest.hexdigest(),
        before.st_dev,
        before.st_ino,
        stat.S_IMODE(before.st_mode),
    )
finally:
    for descriptor in reversed(descriptors):
        os.close(descriptor)
'
  )
fi
readonly SYSTEMD_CREDS_SHA256 SYSTEMD_CREDS_DEVICE
readonly SYSTEMD_CREDS_INODE SYSTEMD_CREDS_MODE

systemctl_bounded() {
  "$TIMEOUT" --signal=TERM --kill-after=10s 30s "$SYSTEMCTL" "$@"
}

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

if [[ ! -x "$RUNTIME" ]]; then
  echo "Refusing untrusted installer or Saturnin runtime executable identity." >&2
  exit 1
fi

readonly CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
if [[ "$CONFIG_HOME" != "$HOME/.config" ]]; then
  echo "Signer installation requires the canonical user configuration directory." >&2
  exit 1
fi
readonly UNIT_DIR="$CONFIG_HOME/systemd/user"
readonly INSTALLED="$UNIT_DIR/$UNIT"
readonly INSTALLED_RUNTIME="$UNIT_DIR/saturnin-attestation-runtime.pyz"
readonly WANTS_DIR="$UNIT_DIR/default.target.wants"
readonly WANTS="$WANTS_DIR/$UNIT"

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
        or before.st_nlink != 1
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
    or before.st_nlink != 1
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

snapshot_governed_runtime() {
  local descriptor=$1 destination=$2
  GOVERNED_FD="$descriptor" DESTINATION_PATH="$destination" \
    EXPECTED_UID="$CURRENT_UID" "$PYTHON" -I -c '
import fcntl
import hashlib
import os
import stat
import zipfile

source = int(os.environ["GOVERNED_FD"])
expected_uid = int(os.environ["EXPECTED_UID"])
required_seals = (
    fcntl.F_SEAL_WRITE
    | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_SHRINK
    | fcntl.F_SEAL_SEAL
)
before = os.fstat(source)
if (
    not stat.S_ISREG(before.st_mode)
    or before.st_uid != expected_uid
    or stat.S_IMODE(before.st_mode) != 0o400
    or fcntl.fcntl(source, fcntl.F_GET_SEALS) & required_seals != required_seals
):
    raise SystemExit("governed runtime descriptor is not an immutable sealed file")
os.lseek(source, 0, os.SEEK_SET)
destination = os.open(
    os.environ["DESTINATION_PATH"],
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
    0o400,
)
try:
    while chunk := os.read(source, 65536):
        view = memoryview(chunk)
        while view:
            view = view[os.write(destination, view):]
    os.fchmod(destination, 0o400)
    os.fsync(destination)
finally:
    os.close(destination)
after = os.fstat(source)
identity = lambda value: (
    value.st_dev,
    value.st_ino,
    value.st_size,
    value.st_mtime_ns,
    value.st_ctime_ns,
)
if identity(before) != identity(after):
    raise SystemExit("governed runtime descriptor identity changed")
os.lseek(source, 0, os.SEEK_SET)
with zipfile.ZipFile(f"/proc/self/fd/{source}") as archive:
    names = archive.namelist()
    manifest_name = "SATURNIN-RUNTIME-MANIFEST"
    if (
        len(names) != len(set(names))
        or "saturnin/attestation_service.py" not in names
        or "yaml/__init__.py" not in names
        or any(
            name.startswith("/")
            or ".." in name.split("/")
            or (
                name != manifest_name
                and (
                    not name.endswith(".py")
                    or not (
                        name.startswith("saturnin/")
                        or name.startswith("yaml/")
                    )
                )
                and name != "saturnin/governance.runtime.yaml"
            )
            for name in names
        )
    ):
        raise SystemExit("governed runtime archive manifest is invalid")
    manifest = archive.read(manifest_name)
    if hashlib.sha256(manifest).hexdigest() != "'"$EXPECTED_RUNTIME_MANIFEST_SHA256"'":
        raise SystemExit("governed runtime archive is not policy-authorized")
    expected_manifest = b"".join(
        name.encode() + b"\0" + hashlib.sha256(archive.read(name)).hexdigest().encode() + b"\n"
        for name in sorted(names)
        if name != manifest_name
    )
    if manifest != expected_manifest:
        raise SystemExit("governed runtime archive content differs from manifest")
'
}

wants_operation() {
  WANTS_OPERATION="$1" EXPECTED_UNIT_DIR_ID="$UNIT_DIR_DEVICE_INODE" \
    EXPECTED_WANTS_DIR_ID="${2:-}" LINK_TARGET_B64="${3:--}" \
    UNIT_DIR_PATH="${PINNED_UNIT_DIR:-$UNIT_DIR}" \
    UNIT_DIR_DESCRIPTOR="${UNIT_DIR_FD:-}" EXPECTED_UID="$CURRENT_UID" \
    "$PYTHON" -I -c '
import base64
import os
import stat

operation = os.environ["WANTS_OPERATION"]
expected_uid = int(os.environ["EXPECTED_UID"])
if os.environ["UNIT_DIR_DESCRIPTOR"]:
    unit_fd = os.dup(int(os.environ["UNIT_DIR_DESCRIPTOR"]))
else:
    unit_fd = os.open(
        os.environ["UNIT_DIR_PATH"],
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
    )
unit_metadata = os.fstat(unit_fd)
unit_identity = f"{unit_metadata.st_dev}:{unit_metadata.st_ino}"
if (
    unit_identity != os.environ["EXPECTED_UNIT_DIR_ID"]
    or unit_metadata.st_uid != expected_uid
    or unit_metadata.st_mode & 0o022
):
    raise SystemExit("user-unit directory identity changed during wants operation")

name = "default.target.wants"
if operation == "create":
    try:
        os.mkdir(name, 0o700, dir_fd=unit_fd)
    except FileExistsError:
        pass

try:
    wants_fd = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
        dir_fd=unit_fd,
    )
except FileNotFoundError:
    if operation == "inspect":
        print("missing 0 -")
        raise SystemExit
    raise

wants_metadata = os.fstat(wants_fd)
wants_identity = f"{wants_metadata.st_dev}:{wants_metadata.st_ino}"
expected_wants_identity = os.environ["EXPECTED_WANTS_DIR_ID"]
if (
    wants_metadata.st_uid != expected_uid
    or wants_metadata.st_mode & 0o022
    or (
        expected_wants_identity
        and expected_wants_identity != "missing"
        and wants_identity != expected_wants_identity
    )
):
    raise SystemExit("enablement directory identity changed or is unsafe")

link_name = "saturnin-attestation.service"
if operation == "inspect":
    try:
        before = os.stat(link_name, dir_fd=wants_fd, follow_symlinks=False)
    except FileNotFoundError:
        print(f"{wants_identity} 0 -")
    else:
        target = os.readlink(link_name, dir_fd=wants_fd)
        after = os.stat(link_name, dir_fd=wants_fd, follow_symlinks=False)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if (
            not stat.S_ISLNK(before.st_mode)
            or before.st_uid != expected_uid
            or identity(before) != identity(after)
        ):
            raise SystemExit("enablement link identity mismatch")
        encoded = base64.urlsafe_b64encode(os.fsencode(target)).decode("ascii")
        print(f"{wants_identity} 1 {encoded}")
elif operation in ("unlink", "link"):
    try:
        metadata = os.stat(link_name, dir_fd=wants_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != expected_uid:
            raise SystemExit("refusing non-symlink enablement entry")
        os.unlink(link_name, dir_fd=wants_fd)
    if operation == "link":
        target = os.fsdecode(
            base64.urlsafe_b64decode(os.environ["LINK_TARGET_B64"])
        )
        os.symlink(target, link_name, dir_fd=wants_fd)
elif operation == "rmdir":
    os.close(wants_fd)
    os.rmdir(name, dir_fd=unit_fd)
elif operation == "create":
    print(wants_identity)
else:
    raise SystemExit("unsupported wants operation")
'
}

verify_wants_link() {
  local state identity present target
  state="$(wants_operation inspect "$wants_dir_identity")"
  read -r identity present target <<<"$state"
  if [[ "$identity" != "$wants_dir_identity" || "$present" -ne 1 \
    || "$target" != "Li4vc2F0dXJuaW4tYXR0ZXN0YXRpb24uc2VydmljZQ==" ]]; then
    echo "Attestation enablement link identity mismatch." >&2
    return 1
  fi
}

verify_unit_identity() {
  UNIT_PATH="$1" EXPECTED_MODE="$2" RUNTIME_SHA256_VALUE="$3" \
    EXPECTED_UID="$CURRENT_UID" \
    HOME_VALUE="$SATURNIN_HOME" CURRENT_KEY_ID_VALUE="${CURRENT_KEY_ID:-}" \
    PREVIOUS_KEY_ID_VALUE="${PREVIOUS_KEY_ID:-}" \
    CREDENTIAL_GENERATION_VALUE="${CREDENTIAL_GENERATION:-}" \
    SYSTEMD_CREDS_SHA256_VALUE="${SYSTEMD_CREDS_SHA256:-}" \
    SYSTEMD_CREDS_DEVICE_VALUE="${SYSTEMD_CREDS_DEVICE:-}" \
    SYSTEMD_CREDS_INODE_VALUE="${SYSTEMD_CREDS_INODE:-}" \
    SYSTEMD_CREDS_MODE_VALUE="${SYSTEMD_CREDS_MODE:-}" \
    CURRENT_CREDENTIAL_VALUE="${CURRENT_CREDENTIAL:-}" \
    PREVIOUS_CREDENTIAL_VALUE="${PREVIOUS_CREDENTIAL:-}" "$PYTHON" -I -c '
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
    or before.st_nlink != 1
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
current_key_id = os.environ["CURRENT_KEY_ID_VALUE"]
previous_key_id = os.environ["PREVIOUS_KEY_ID_VALUE"]
credential_generation = os.environ["CREDENTIAL_GENERATION_VALUE"]
current_credential = os.environ["CURRENT_CREDENTIAL_VALUE"]
previous_credential = os.environ["PREVIOUS_CREDENTIAL_VALUE"]
systemd_creds_sha256 = ""
systemd_creds_device = ""
systemd_creds_inode = ""
systemd_creds_mode = ""
if not current_key_id or not previous_key_id or not credential_generation:
    for line in lines:
        if line.startswith("Environment=SATURNIN_CURRENT_KEY_ID="):
            current_key_id = line.rsplit("=", 1)[-1].strip("\"")
        elif line.startswith("Environment=SATURNIN_PREVIOUS_KEY_ID="):
            previous_key_id = line.rsplit("=", 1)[-1].strip("\"")
        elif line.startswith("Environment=SATURNIN_CREDENTIAL_GENERATION="):
            credential_generation = line.rsplit("=", 1)[-1].strip("\"")
        elif line.startswith(
            "Environment=SATURNIN_CURRENT_CREDENTIAL_CIPHERTEXT="
        ):
            current_credential = line.split("=", 2)[2].strip("\"")
        elif line.startswith(
            "Environment=SATURNIN_PREVIOUS_CREDENTIAL_CIPHERTEXT="
        ):
            previous_credential = line.split("=", 2)[2].strip("\"")
for line in lines:
    if line.startswith("Environment=SATURNIN_SYSTEMD_CREDS_SHA256="):
        systemd_creds_sha256 = line.rsplit("=", 1)[-1].strip("\"")
    elif line.startswith("Environment=SATURNIN_SYSTEMD_CREDS_DEVICE="):
        systemd_creds_device = line.rsplit("=", 1)[-1].strip("\"")
    elif line.startswith("Environment=SATURNIN_SYSTEMD_CREDS_INODE="):
        systemd_creds_inode = line.rsplit("=", 1)[-1].strip("\"")
    elif line.startswith("Environment=SATURNIN_SYSTEMD_CREDS_MODE="):
        systemd_creds_mode = line.rsplit("=", 1)[-1].strip("\"")
if (
    len(current_key_id) != 64
    or len(previous_key_id) != 64
    or any(character not in "0123456789abcdef" for character in current_key_id)
    or any(character not in "0123456789abcdef" for character in previous_key_id)
    or len(credential_generation) != 64
    or any(
        character not in "0123456789abcdef"
        for character in credential_generation
    )
):
    raise SystemExit("rendered attestation unit key identifiers are invalid")
if (
    not current_credential
    or not previous_credential
    or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        for character in current_credential + previous_credential
    )
):
    raise SystemExit("rendered encrypted credential literals are invalid")
if (
    len(systemd_creds_sha256) != 64
    or any(
        character not in "0123456789abcdef"
        for character in systemd_creds_sha256
    )
    or not systemd_creds_device.isdigit()
    or not systemd_creds_inode.isdigit()
    or not systemd_creds_mode.isdigit()
    or int(systemd_creds_device) <= 0
    or int(systemd_creds_inode) <= 0
    or int(systemd_creds_mode) > 0o777
    or int(systemd_creds_mode) & 0o022
    or not int(systemd_creds_mode) & 0o111
):
    raise SystemExit("rendered systemd-creds host identity is invalid")
for name, actual in (
    ("SYSTEMD_CREDS_SHA256", systemd_creds_sha256),
    ("SYSTEMD_CREDS_DEVICE", systemd_creds_device),
    ("SYSTEMD_CREDS_INODE", systemd_creds_inode),
    ("SYSTEMD_CREDS_MODE", systemd_creds_mode),
):
    expected = os.environ[f"{name}_VALUE"]
    if expected and actual != expected:
        raise SystemExit("rendered systemd-creds host identity mismatch")
expected = [
    ("Unit", [
        "Description=Saturnin private review attestation signer",
        f"Documentation=file://{home}/docs/runbooks/ops-safety.md",
    ]),
    ("Service", [
        "Type=notify",
        "NotifyAccess=main",
        f"WorkingDirectory={home}",
        "UnsetEnvironment=GCONV_PATH GETCONF_DIR GLIBC_TUNABLES HOSTALIASES LD_AUDIT LD_BIND_NOT LD_BIND_NOW LD_DEBUG LD_DEBUG_OUTPUT LD_DYNAMIC_WEAK LD_HWCAP_MASK LD_KEEPDIR LD_LIBRARY_PATH LD_ORIGIN_PATH LD_PRELOAD LD_PROFILE LD_SHOW_AUXV LD_TRACE_LOADED_OBJECTS LD_USE_LOAD_BIAS LD_VERBOSE LD_WARN LOCALDOMAIN LOCPATH MALLOC_TRACE NIS_PATH NLSPATH PYTHONHOME PYTHONPATH RESOLV_HOST_CONF RES_OPTIONS TMPDIR TZDIR",
        f"Environment=SATURNIN_HOME=\"{home}\"",
        f"Environment=SATURNIN_RUNTIME_SHA256=\"{runtime_sha256}\"",
        f"Environment=SATURNIN_SYSTEMD_CREDS_SHA256=\"{systemd_creds_sha256}\"",
        f"Environment=SATURNIN_SYSTEMD_CREDS_DEVICE=\"{systemd_creds_device}\"",
        f"Environment=SATURNIN_SYSTEMD_CREDS_INODE=\"{systemd_creds_inode}\"",
        f"Environment=SATURNIN_SYSTEMD_CREDS_MODE=\"{systemd_creds_mode}\"",
        "Environment=SATURNIN_SEALED_GOVERNANCE=runtime-archive",
        f"Environment=SATURNIN_CURRENT_KEY_ID=\"{current_key_id}\"",
        f"Environment=SATURNIN_PREVIOUS_KEY_ID=\"{previous_key_id}\"",
        f"Environment=SATURNIN_CREDENTIAL_GENERATION=\"{credential_generation}\"",
        "ExecStart=/usr/bin/python3 -I -c '\''import fcntl,hashlib,os,runpy,stat,sys;p=os.path.expanduser(\"~/.config/systemd/user/saturnin-attestation-runtime.pyz\");f=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW);a=os.fstat(f);assert stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o400;s=os.memfd_create(\"saturnin-attestation-runtime\",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);os.fchmod(s,0o400);h=hashlib.sha256();exec(\"while b:=os.read(f,65536):\\\\n h.update(b)\\\\n v=memoryview(b)\\\\n while v:\\\\n  v=v[os.write(s,v):]\");z=os.fstat(f);assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns) and h.hexdigest()==os.environ[\"SATURNIN_RUNTIME_SHA256\"];fcntl.fcntl(s,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL);os.lseek(s,0,os.SEEK_SET);os.close(f);sys.path.insert(0,f\"/proc/self/fd/{s}\");runpy.run_module(\"saturnin.attestation_service\",run_name=\"__main__\")'\'' serve",
        f"Environment=SATURNIN_CURRENT_CREDENTIAL_CIPHERTEXT=\"{current_credential}\"",
        f"Environment=SATURNIN_PREVIOUS_CREDENTIAL_CIPHERTEXT=\"{previous_credential}\"",
        "RuntimeDirectory=saturnin-attestation",
        "RuntimeDirectoryMode=0700",
        "RuntimeDirectoryPreserve=yes",
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
import sys
from pathlib import Path

manager_path = os.environ["MANAGER_VIEW_PATH"]
manager = (
    sys.stdin.read()
    if manager_path == "-"
    else Path(manager_path).read_text(encoding="utf-8")
).splitlines()
expected = Path(os.environ["UNIT_PATH"]).read_text(encoding="utf-8").splitlines()
if not manager or manager[0] != f"# {os.environ['"'"'INSTALLED_PATH'"'"']}":
    raise SystemExit("systemd manager reported an unexpected unit fragment")
if manager[1:] != expected:
    raise SystemExit("systemd manager-loaded unit representation mismatch")
'
}

verify_running_service() {
  local manager_state=$1 runtime_sha256=$2
  local expected_unit=${3:-$INSTALLED_SNAPSHOT}
  MANAGER_STATE_PATH="$manager_state" INSTALLED_PATH="$INSTALLED" \
    EXPECTED_UNIT_PATH="$expected_unit" \
    PYTHON_PATH="$PYTHON" RUNTIME_SHA256_VALUE="$runtime_sha256" \
    VERIFY_RUNNING_SERVICE=1 "$PYTHON" -I -c '
import os
import stat
import sys
from pathlib import Path

properties = {}
manager_state_path = os.environ["MANAGER_STATE_PATH"]
manager_state = (
    sys.stdin.read()
    if manager_state_path == "-"
    else Path(manager_state_path).read_text(encoding="utf-8")
)
for line in manager_state.splitlines():
    key, separator, value = line.partition("=")
    if not separator or key in properties:
        raise SystemExit("systemd reported invalid signer process state")
    properties[key] = value
expected = {
    "LoadState": "loaded",
    "ActiveState": "active",
    "SubState": "running",
    "FragmentPath": os.environ["INSTALLED_PATH"],
    "DropInPaths": "",
    "PrivateMounts": "yes",
    "PrivateTmp": "yes",
    "PrivateNetwork": "yes",
    "ProtectHome": "read-only",
    "ProtectSystem": "strict",
    "ProtectProc": "invisible",
    "NoNewPrivileges": "yes",
    "RestrictAddressFamilies": "AF_UNIX",
    "RuntimeDirectoryPreserve": "yes",
    "StatusText": (
        f"Saturnin runtime {os.environ['RUNTIME_SHA256_VALUE']} verified"
    ),
}
if any(properties.get(key) != value for key, value in expected.items()):
    raise SystemExit("systemd signer loaded or active identity mismatch")
try:
    pid = int(properties["MainPID"])
    exec_pid = int(properties["ExecMainPID"])
except (KeyError, ValueError):
    raise SystemExit("systemd signer process identity is invalid")
if pid <= 1 or exec_pid != pid:
    raise SystemExit("systemd signer process identity is invalid")
process = Path("/proc") / str(pid)
metadata = process.stat()
if metadata.st_uid != os.getuid():
    raise SystemExit("systemd signer process owner mismatch")
if Path(os.path.realpath(process / "exe")) != Path(os.environ["PYTHON_PATH"]):
    raise SystemExit("systemd signer executable identity mismatch")
exec_start = next(
    line for line in Path(os.environ["EXPECTED_UNIT_PATH"]).read_text(
        encoding="utf-8"
    ).splitlines() if line.startswith("ExecStart=")
)
prefix = "ExecStart=/usr/bin/python3 -I -c " + chr(39)
suffix = chr(39) + " serve"
if not exec_start.startswith(prefix) or not exec_start.endswith(suffix):
    raise SystemExit("systemd signer expected command identity is invalid")
expected_arguments = [
    b"/usr/bin/python3",
    b"-I",
    b"-c",
    exec_start[len(prefix):-len(suffix)].encode(),
    b"serve",
    b"",
]
if Path(os.path.realpath(expected_arguments[0])) != Path(
    os.environ["PYTHON_PATH"]
):
    raise SystemExit("systemd signer configured executable identity mismatch")
if (process / "cmdline").read_bytes().split(b"\0") != expected_arguments:
    raise SystemExit("systemd signer command identity mismatch")
control_group = properties.get("ControlGroup", "")
if not control_group.endswith("/saturnin-attestation.service"):
    raise SystemExit("systemd signer control-group identity mismatch")
memberships = (process / "cgroup").read_text(encoding="utf-8").splitlines()
if not any(line.partition("::")[2] == control_group for line in memberships):
    raise SystemExit("systemd signer process is outside its reported control group")
status = {}
for line in (process / "status").read_text(encoding="utf-8").splitlines():
    key, separator, value = line.partition(":")
    if separator:
        status[key] = value.strip()
if status.get("NoNewPrivs") != "1":
    raise SystemExit("systemd signer no-new-privileges state mismatch")
if any(status.get(name, "").strip("0") for name in ("CapInh", "CapPrm", "CapEff")):
    raise SystemExit("systemd signer retains process capabilities")
if os.stat(process / "ns/net").st_ino == os.stat("/proc/self/ns/net").st_ino:
    raise SystemExit("systemd signer private network namespace is missing")
if os.stat(process / "ns/mnt").st_ino == os.stat("/proc/self/ns/mnt").st_ino:
    raise SystemExit("systemd signer private mount namespace is missing")
'
}

verify_stopped_service() {
  systemctl_bounded --user show --no-pager \
    --property=ActiveState --property=SubState \
    --property=MainPID --property=ExecMainPID --property=ControlGroup \
    "$UNIT" >"$MANAGER_STATE" || return 1
  MANAGER_STATE_PATH="$MANAGER_STATE" CGROUP_ROOT_PATH="$CGROUP_ROOT" \
    CGROUP_ROOT_OWNER_VALUE="$CGROUP_ROOT_OWNER" \
    VERIFY_STOPPED_SERVICE=1 \
    "$PYTHON" -I -c '
import os
import stat
from pathlib import Path, PurePosixPath

properties = {}
for line in Path(os.environ["MANAGER_STATE_PATH"]).read_text(
    encoding="utf-8"
).splitlines():
    key, separator, value = line.partition("=")
    if not separator or key in properties:
        raise SystemExit("systemd reported invalid stopped signer state")
    properties[key] = value
if (
    (
        properties.get("ActiveState"),
        properties.get("SubState"),
    )
    not in {("inactive", "dead"), ("failed", "failed")}
    or properties.get("MainPID") != "0"
    or not properties.get("ExecMainPID", "").isdigit()
):
    raise SystemExit("rejected signer process is not proven stopped")
control_group = properties.get("ControlGroup", "")
if control_group and not control_group.endswith("/saturnin-attestation.service"):
    raise SystemExit("stopped signer control-group identity is invalid")
if control_group:
    relative = PurePosixPath(control_group)
    if (
        not relative.is_absolute()
        or any(part in {".", ".."} for part in relative.parts)
        or relative.name != "saturnin-attestation.service"
    ):
        raise SystemExit("stopped signer control-group path is invalid")
    root = Path(os.environ["CGROUP_ROOT_PATH"])
    root_metadata = root.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != int(os.environ["CGROUP_ROOT_OWNER_VALUE"])
        or root_metadata.st_mode & 0o022
    ):
        raise SystemExit("cgroup filesystem root has an unsafe identity")
    cgroup = root.joinpath(*relative.parts[1:])
    try:
        cgroup_metadata = cgroup.stat(follow_symlinks=False)
    except FileNotFoundError:
        cgroup_metadata = None
    if cgroup_metadata is not None:
        if not stat.S_ISDIR(cgroup_metadata.st_mode):
            raise SystemExit("stopped signer control group has an unsafe identity")
        events = {}
        for line in (cgroup / "cgroup.events").read_text(
            encoding="ascii"
        ).splitlines():
            key, separator, value = line.partition(" ")
            if not separator or key in events:
                raise SystemExit("stopped signer cgroup state is invalid")
            events[key] = value
        if events.get("populated") != "0":
            raise SystemExit("stopped signer control group still has processes")
'
}

stop_signer_service() {
  systemctl_bounded --user stop "$UNIT" >/dev/null 2>&1 || true
  systemctl_bounded --user kill --kill-whom=all --signal=KILL \
    "$UNIT" >/dev/null 2>&1 || true
  verify_stopped_service
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
exec {UNIT_DIR_FD}<"$UNIT_DIR"
readonly UNIT_DIR_FD
if ! "$FLOCK" --exclusive --nonblock "$UNIT_DIR_FD"; then
  echo "Another credential or signer installation operation is in progress." >&2
  exit 1
fi
readonly PINNED_UNIT_DIR="/proc/self/fd/$UNIT_DIR_FD"
if [[ "$("$STAT" -Lc %d:%i "$PINNED_UNIT_DIR")" != "$UNIT_DIR_DEVICE_INODE" ]]; then
  echo "User-unit directory identity changed while it was pinned." >&2
  exit 1
fi
readonly FILE_INSTALLED="$PINNED_UNIT_DIR/$UNIT"
readonly FILE_INSTALLED_RUNTIME="$PINNED_UNIT_DIR/saturnin-attestation-runtime.pyz"
verify_unit_directory() {
  if [[ -L "$UNIT_DIR" || "$("$STAT" -Lc %d:%i "$UNIT_DIR")" != "$UNIT_DIR_DEVICE_INODE" ]]; then
    echo "User-unit directory identity changed during lifecycle operation." >&2
    return 1
  fi
}

if [[ "$action" == status ]]; then
  verify_unit_directory
  STATUS_RUNTIME_ID="$(trusted_file_identity "$FILE_INSTALLED_RUNTIME" 0400)"
  verify_unit_identity "$FILE_INSTALLED" 0644 "${STATUS_RUNTIME_ID##*:}" >/dev/null
  read -r wants_dir_identity _ _ <<<"$(wants_operation inspect)"
  verify_wants_link
  systemctl_bounded --user cat --no-pager "$UNIT" \
    | verify_manager_loaded_unit - "$FILE_INSTALLED"
  systemctl_bounded --user show --no-pager \
    --property=LoadState --property=ActiveState --property=SubState \
    --property=FragmentPath --property=DropInPaths \
    --property=MainPID --property=ExecMainPID --property=ControlGroup \
    --property=PrivateMounts --property=PrivateTmp --property=PrivateNetwork \
    --property=ProtectHome --property=ProtectSystem --property=ProtectProc \
    --property=NoNewPrivileges --property=RestrictAddressFamilies \
    --property=RuntimeDirectoryPreserve \
    --property=StatusText \
    "$UNIT" \
    | verify_running_service - "${STATUS_RUNTIME_ID##*:}" "$FILE_INSTALLED"
  exec "$TIMEOUT" --signal=TERM --kill-after=10s 30s \
    "$SYSTEMCTL" --user status --no-pager "$UNIT"
fi

readonly TRANSACTION="$PINNED_UNIT_DIR/.saturnin-attestation-transaction.$$"
readonly STAGE="$TRANSACTION/$UNIT"
readonly BACKUP="$TRANSACTION/backup"
readonly MANAGER_VIEW="$TRANSACTION/manager-view"
readonly MANAGER_STATE="$TRANSACTION/manager-state"
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
if [[ "$action" == install ]]; then
  snapshot_governed_runtime \
    "$SATURNIN_GOVERNED_RUNTIME_FD" "$RUNTIME_TREE_SNAPSHOT"
else
  DESTINATION_PATH="$RUNTIME_TREE_SNAPSHOT" "$PYTHON" -I -c '
import os
descriptor = os.open(
    os.environ["DESTINATION_PATH"],
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
    0o400,
)
os.close(descriptor)
'
fi
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
wants_target_b64=-
wants_dir_identity=missing
wants_state=

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
  if declare -F downgrade_credential_lock >/dev/null \
    && ! downgrade_credential_lock; then
    return 1
  fi
  if ! stop_signer_service >/dev/null 2>&1; then
    echo "ROLLBACK FAILURE: rejected signer termination was not proven; prior files were not restored." >&2
    return 1
  fi
  if ! verify_unit_directory; then
    echo "Rollback stopped because the user-unit directory was replaced." >&2
    return 1
  fi
  restore_file "$FILE_INSTALLED" "$BACKUP/unit" "$had_unit" 0644 "$unit_backup_identity" || return 1
  restore_file "$FILE_INSTALLED_RUNTIME" "$BACKUP/runtime" "$had_runtime" 0400 \
    "$runtime_backup_identity" || return 1
  if [[ "$wants_dir_identity" != missing ]]; then
    wants_operation unlink "$wants_dir_identity" || return 1
    if [[ "$had_wants" -eq 1 ]]; then
      wants_operation link "$wants_dir_identity" "$wants_target_b64" || return 1
    fi
  fi
  if [[ "$had_wants_dir" -eq 0 && "$wants_dir_identity" != missing ]]; then
    wants_operation rmdir "$wants_dir_identity" || return 1
  fi
  if ! systemctl_bounded --user daemon-reload >/dev/null 2>&1; then
    echo "ROLLBACK FAILURE: systemd did not reload the restored signer definition." >&2
    return 1
  fi
  if [[ "$was_active" -eq 0 ]]; then
    verify_stopped_service || {
      echo "ROLLBACK FAILURE: restored signer unexpectedly became active." >&2
      return 1
    }
    return 0
  fi
  if [[ "$unit_was_valid" -ne 1 ]]; then
    verify_stopped_service || return 1
    echo "ROLLBACK FAILURE: prior disk topology was restored, but the unvalidated signer remains stopped for manual recovery." >&2
    return 1
  fi
  if ! verify_unit_directory \
    || ! verify_unit_identity "$FILE_INSTALLED" 0644 \
      "${runtime_backup_identity##*:}" >/dev/null \
    || ! trusted_file_identity "$FILE_INSTALLED_RUNTIME" 0400 >/dev/null \
    || ! systemctl_bounded --user cat --no-pager "$UNIT" >"$MANAGER_VIEW" \
    || ! verify_manager_loaded_unit "$MANAGER_VIEW" "$BACKUP/unit" \
    || ! systemctl_bounded --user start "$UNIT" >/dev/null 2>&1 \
    || ! systemctl_bounded --user cat --no-pager "$UNIT" >"$MANAGER_VIEW" \
    || ! verify_manager_loaded_unit "$MANAGER_VIEW" "$BACKUP/unit"; then
    echo "ROLLBACK FAILURE: prior signer definition could not be restarted safely." >&2
    return 1
  fi
  systemctl_bounded --user show --no-pager \
    --property=LoadState --property=ActiveState --property=SubState \
    --property=FragmentPath --property=DropInPaths \
    --property=MainPID --property=ExecMainPID --property=ControlGroup \
    --property=PrivateMounts --property=PrivateTmp --property=PrivateNetwork \
    --property=ProtectHome --property=ProtectSystem --property=ProtectProc \
    --property=NoNewPrivileges --property=RestrictAddressFamilies \
    --property=RuntimeDirectoryPreserve \
    --property=StatusText \
    "$UNIT" >"$MANAGER_STATE" \
    && verify_running_service "$MANAGER_STATE" \
      "${runtime_backup_identity##*:}" "$BACKUP/unit" || {
    echo "ROLLBACK FAILURE: prior signer process identity was not restored." >&2
    return 1
  }
}

on_exit() {
  local status=$?
  if [[ "$mutating" -eq 1 && "$status" -ne 0 ]]; then
    if ! rollback; then
      status=125
    fi
  fi
  if declare -F release_credential_lock >/dev/null \
    && ! release_credential_lock; then
    status=125
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

if systemctl_bounded --user is-active --quiet "$UNIT"; then
  was_active=1
fi
if [[ -e "$FILE_INSTALLED_RUNTIME" || -L "$FILE_INSTALLED_RUNTIME" ]]; then
  had_runtime=1
  snapshot_trusted_file "$FILE_INSTALLED_RUNTIME" "$BACKUP/runtime" 0400
  runtime_backup_identity="$(trusted_file_identity "$BACKUP/runtime" 0400)"
fi
if [[ -e "$FILE_INSTALLED" || -L "$FILE_INSTALLED" ]]; then
  had_unit=1
  trusted_file_identity "$FILE_INSTALLED" 0644 >/dev/null
  if [[ "$had_runtime" -eq 1 ]] \
    && verify_unit_identity "$FILE_INSTALLED" 0644 \
      "${runtime_backup_identity##*:}" >/dev/null 2>&1; then
    unit_was_valid=1
  elif [[ "$was_active" -eq 1 && "$action" != uninstall ]]; then
    echo "Refusing to replace an active unvalidated attestation unit." >&2
    exit 1
  fi
  snapshot_trusted_file "$FILE_INSTALLED" "$BACKUP/unit" 0644
  unit_backup_identity="$(trusted_file_identity "$BACKUP/unit" 0644)"
fi
if [[ -e "$WANTS_DIR" || -L "$WANTS_DIR" ]]; then
  had_wants_dir=1
  wants_state="$(wants_operation inspect)"
  read -r wants_dir_identity had_wants wants_target_b64 <<<"$wants_state"
fi

if [[ "$action" == uninstall ]]; then
  already_uninstalled=0
  if [[ "$had_unit" -eq 0 && "$had_wants" -eq 0 && "$had_runtime" -eq 0 ]]; then
    already_uninstalled=1
  fi
  mutating=1
  verify_unit_directory
  if [[ "$was_active" -eq 1 ]]; then
    stop_signer_service
  else
    stop_signer_service >/dev/null 2>&1 || true
    verify_stopped_service
  fi
  if [[ "$had_wants_dir" -eq 1 ]]; then
    wants_operation unlink "$wants_dir_identity"
  fi
  "$RM" -f "$FILE_INSTALLED" "$FILE_INSTALLED_RUNTIME"
  verify_unit_directory
  systemctl_bounded --user daemon-reload
  verify_stopped_service
  mutating=0
  if [[ "$already_uninstalled" -eq 1 ]]; then
    echo "$UNIT is already uninstalled; encrypted credentials were left untouched"
  else
    echo "uninstalled $UNIT; encrypted credentials were left untouched"
  fi
  exit 0
fi

readonly CREDENTIAL_LOCK_READY="$TRANSACTION/credential-lock-ready"
: >"$CREDENTIAL_LOCK_READY"
"$CHMOD" 0600 "$CREDENTIAL_LOCK_READY"
exec {CREDENTIAL_LOCK_READY_FD}>"$CREDENTIAL_LOCK_READY"
readonly CREDENTIAL_LOCK_READY_FD
readonly CREDENTIAL_LOCK_SHARED="$TRANSACTION/credential-lock-shared"
: >"$CREDENTIAL_LOCK_SHARED"
"$CHMOD" 0600 "$CREDENTIAL_LOCK_SHARED"
exec {CREDENTIAL_LOCK_SHARED_FD}>"$CREDENTIAL_LOCK_SHARED"
readonly CREDENTIAL_LOCK_SHARED_FD
UNIT_DIRECTORY_FD="$UNIT_DIR_FD" EXPECTED_UID="$CURRENT_UID" \
  EXPECTED_UNIT_DIRECTORY="$UNIT_DIR_DEVICE_INODE" \
  XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$CURRENT_UID}" \
  READY_FD="$CREDENTIAL_LOCK_READY_FD" SHARED_FD="$CREDENTIAL_LOCK_SHARED_FD" \
  PARENT_PID="$$" \
  "$PYTHON" -I -c '
import fcntl
import os
import signal
import stat
import sys
import time

for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(signum, signal.SIG_IGN)
signal.signal(signal.SIGUSR1, lambda *_: sys.exit(0))

def downgrade_lock(*_: object) -> None:
    fcntl.flock(lifecycle_fd, fcntl.LOCK_SH)
    os.write(int(os.environ["SHARED_FD"]), b"shared\n")

signal.signal(signal.SIGUSR2, downgrade_lock)
unit_fd = int(os.environ["UNIT_DIRECTORY_FD"])
expected_uid = int(os.environ["EXPECTED_UID"])
runtime = os.environ["XDG_RUNTIME_DIR"]
if not os.path.isabs(runtime) or os.path.realpath(runtime) != runtime:
    raise SystemExit("credential lifecycle runtime directory is not canonical")
runtime_fd = os.open(
    runtime,
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
)
runtime_metadata = os.fstat(runtime_fd)
if (
    not stat.S_ISDIR(runtime_metadata.st_mode)
    or runtime_metadata.st_uid != expected_uid
    or stat.S_IMODE(runtime_metadata.st_mode) != 0o700
    or runtime_metadata.st_nlink < 2
):
    raise SystemExit("credential lifecycle runtime directory is unsafe")
try:
    os.mkdir("saturnin-attestation", mode=0o700, dir_fd=runtime_fd)
except FileExistsError:
    pass
service_runtime_fd = os.open(
    "saturnin-attestation",
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    dir_fd=runtime_fd,
)
service_runtime_metadata = os.fstat(service_runtime_fd)
if (
    not stat.S_ISDIR(service_runtime_metadata.st_mode)
    or service_runtime_metadata.st_uid != expected_uid
    or stat.S_IMODE(service_runtime_metadata.st_mode) != 0o700
    or service_runtime_metadata.st_nlink < 2
):
    raise SystemExit("credential lifecycle service runtime directory is unsafe")
lock_flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
try:
    lifecycle_fd = os.open(
        ".saturnin-credential-lifecycle.lock",
        lock_flags | os.O_CREAT | os.O_EXCL,
        0o600,
        dir_fd=service_runtime_fd,
    )
except FileExistsError:
    lifecycle_fd = os.open(
        ".saturnin-credential-lifecycle.lock",
        lock_flags,
        dir_fd=service_runtime_fd,
    )
lock_metadata = os.fstat(lifecycle_fd)
if (
    not stat.S_ISREG(lock_metadata.st_mode)
    or lock_metadata.st_uid != expected_uid
    or stat.S_IMODE(lock_metadata.st_mode) != 0o600
    or lock_metadata.st_nlink != 1
):
    raise SystemExit("credential lifecycle lock is unsafe")
try:
    fcntl.flock(lifecycle_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    raise SystemExit("another credential lifecycle operation is in progress")
unit_metadata = os.fstat(unit_fd)
if (
    f"{unit_metadata.st_dev}:{unit_metadata.st_ino}"
    != os.environ["EXPECTED_UNIT_DIRECTORY"]
    or not stat.S_ISDIR(unit_metadata.st_mode)
    or unit_metadata.st_uid != expected_uid
    or unit_metadata.st_mode & 0o022
):
    raise SystemExit("pinned user-unit directory identity mismatch")
credential_fd = os.open(
    "saturnin-credentials",
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    dir_fd=unit_fd,
)
metadata = os.fstat(credential_fd)
if (
    not stat.S_ISDIR(metadata.st_mode)
    or metadata.st_uid != expected_uid
    or stat.S_IMODE(metadata.st_mode) != 0o700
):
    raise SystemExit("credential directory descriptor metadata mismatch")
os.write(
    int(os.environ["READY_FD"]),
    f"{metadata.st_dev}:{metadata.st_ino}\n".encode(),
)
parent = f"/proc/{int(os.environ['"'"'PARENT_PID'"'"'])}"
while os.path.exists(parent):
    try:
        with open(f"{parent}/stat", encoding="ascii") as status:
            state = status.read().split(") ", 1)[1].split(" ", 1)[0]
    except (FileNotFoundError, IndexError):
        break
    if state == "Z":
        break
    time.sleep(0.05)
' &
readonly CREDENTIAL_LOCK_HOLDER=$!
credential_lock_released=0
credential_lock_shared=0
downgrade_credential_lock() {
  if [[ "$credential_lock_released" -eq 0 && "$credential_lock_shared" -eq 0 ]]; then
    kill -USR2 "$CREDENTIAL_LOCK_HOLDER" 2>/dev/null || return 1
    local state=
    for _ in {1..100}; do
      if IFS= read -r state <"$CREDENTIAL_LOCK_SHARED" && [[ "$state" == shared ]]; then
        credential_lock_shared=1
        return 0
      fi
      if ! kill -0 "$CREDENTIAL_LOCK_HOLDER" 2>/dev/null; then
        return 1
      fi
      "$SLEEP" 0.05
    done
    return 1
  fi
}
release_credential_lock() {
  if [[ "$credential_lock_released" -eq 0 ]]; then
    kill -USR1 "$CREDENTIAL_LOCK_HOLDER" 2>/dev/null || true
    wait "$CREDENTIAL_LOCK_HOLDER" || return 1
    credential_lock_released=1
  fi
}
CREDENTIAL_DIRECTORY_ID=
for _ in {1..100}; do
  if IFS= read -r CREDENTIAL_DIRECTORY_ID <"$CREDENTIAL_LOCK_READY"; then
    break
  fi
  "$SLEEP" 0.05
done
if [[ ! "$CREDENTIAL_DIRECTORY_ID" =~ ^[0-9]+:[0-9]+$ ]]; then
  echo "Credential lifecycle lock could not be acquired safely." >&2
  exit 1
fi
readonly CREDENTIAL_DIRECTORY_ID

read -r CURRENT_KEY_ID PREVIOUS_KEY_ID CREDENTIAL_GENERATION \
  CURRENT_CREDENTIAL PREVIOUS_CREDENTIAL < <(
  UNIT_DIRECTORY_FD="$UNIT_DIR_FD" EXPECTED_UNIT_DIRECTORY="$UNIT_DIR_DEVICE_INODE" \
    EXPECTED_CREDENTIAL_DIRECTORY="$CREDENTIAL_DIRECTORY_ID" \
    EXPECTED_UID="$CURRENT_UID" RUNTIME_ARCHIVE_FD="$RUNTIME_TREE_FD" \
    SYSTEMD_CREDS_PATH="$SYSTEMD_CREDS" SNAPSHOT_CREDENTIALS=1 \
    "$PYTHON" -I -c '
import hashlib
import os
import re
import stat
import subprocess
import sys

unit_fd = int(os.environ["UNIT_DIRECTORY_FD"])
expected_uid = int(os.environ["EXPECTED_UID"])
unit_metadata = os.fstat(unit_fd)
unit_identity = f"{unit_metadata.st_dev}:{unit_metadata.st_ino}"
if (
    unit_identity != os.environ["EXPECTED_UNIT_DIRECTORY"]
    or not stat.S_ISDIR(unit_metadata.st_mode)
    or unit_metadata.st_uid != expected_uid
    or unit_metadata.st_mode & 0o022
):
    raise SystemExit("pinned user-unit directory identity mismatch")
credential_fd = os.open(
    "saturnin-credentials",
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    dir_fd=unit_fd,
)
credential_metadata = os.fstat(credential_fd)
if (
    not stat.S_ISDIR(credential_metadata.st_mode)
    or credential_metadata.st_uid != expected_uid
    or stat.S_IMODE(credential_metadata.st_mode) != 0o700
    or f"{credential_metadata.st_dev}:{credential_metadata.st_ino}"
    != os.environ["EXPECTED_CREDENTIAL_DIRECTORY"]
):
    raise SystemExit("credential directory descriptor metadata mismatch")

def read_file(name):
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=credential_fd,
    )
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != expected_uid
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise SystemExit(f"credential snapshot metadata mismatch: {name}")
    chunks = []
    size = 0
    while chunk := os.read(descriptor, 65536):
        size += len(chunk)
        if size > 65536:
            raise SystemExit(f"credential snapshot is too large: {name}")
        chunks.append(chunk)
    after = os.fstat(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise SystemExit(f"credential snapshot changed while read: {name}")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return descriptor, b"".join(chunks)

names = {
    "current": "saturnin-review-attestation-key.cred",
    "previous": "saturnin-review-attestation-previous-key.cred",
    "generation": ".generation",
    "enabled": ".execution-signer-enabled",
}
files = {key: read_file(name) for key, name in names.items()}
for artifact in (
    ".attestation-rotation.json",
    ".saturnin-review-attestation-key.rollback.cred",
    ".saturnin-review-attestation-previous-key.rollback.cred",
):
    try:
        os.stat(artifact, dir_fd=credential_fd, follow_symlinks=False)
    except FileNotFoundError:
        continue
    raise SystemExit("attestation credential rotation is not ready")

sys.path.insert(0, f"/proc/self/fd/{os.environ['"'"'RUNTIME_ARCHIVE_FD'"'"']}")
from saturnin.credentials import _validate_encryption_model

for key in ("current", "previous"):
    _validate_encryption_model(files[key][1])

def decrypt(key, credential_name):
    descriptor = files[key][0]
    result = subprocess.run(
        [
            os.environ["SYSTEMD_CREDS_PATH"],
            "decrypt",
            "--user",
            f"--name={credential_name}",
            f"/proc/self/fd/{descriptor}",
            "-",
        ],
        check=False,
        capture_output=True,
        pass_fds=(descriptor,),
        timeout=30,
    )
    if result.returncode != 0 or not result.stdout or len(result.stdout) > 65536:
        raise SystemExit(f"credential snapshot cannot be decrypted: {key}")
    try:
        value = result.stdout.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError:
        raise SystemExit(f"credential snapshot is not text: {key}")
    if not value or "\0" in value:
        raise SystemExit(f"credential snapshot is invalid: {key}")
    return value

generation = files["generation"][1].decode("ascii").strip()
enabled = files["enabled"][1].decode("ascii").strip()
if not re.fullmatch(r"[0-9a-f]{64}", generation) or enabled != generation:
    raise SystemExit("attestation credential generation is not signer-ready")
current = b"".join(files["current"][1].split()).decode("ascii")
previous = b"".join(files["previous"][1].split()).decode("ascii")
if not re.fullmatch(r"[A-Za-z0-9+/=]+", current + previous):
    raise SystemExit("encrypted credential literal is invalid")
credential_after = os.fstat(credential_fd)
credential_identity = lambda value: (
    value.st_dev,
    value.st_ino,
    value.st_mode,
    value.st_uid,
    value.st_mtime_ns,
    value.st_ctime_ns,
)
if credential_identity(credential_metadata) != credential_identity(credential_after):
    raise SystemExit("credential directory changed during snapshot")
print(
    hashlib.sha256(
        decrypt("current", "saturnin-review-attestation-key").encode()
    ).hexdigest(),
    hashlib.sha256(
        decrypt("previous", "saturnin-review-attestation-previous-key").encode()
    ).hexdigest(),
    generation,
    current,
    previous,
)
')
if [[ ! "$CURRENT_KEY_ID" =~ ^[0-9a-f]{64}$ ]] \
  || [[ ! "$PREVIOUS_KEY_ID" =~ ^[0-9a-f]{64}$ ]] \
  || [[ ! "$CREDENTIAL_GENERATION" =~ ^[0-9a-f]{64}$ ]] \
  || [[ ! "$CURRENT_CREDENTIAL" =~ ^[A-Za-z0-9+/=]+$ ]] \
  || [[ ! "$PREVIOUS_CREDENTIAL" =~ ^[A-Za-z0-9+/=]+$ ]]; then
  echo "Attestation credential generation identity is invalid." >&2
  exit 1
fi
readonly CURRENT_KEY_ID PREVIOUS_KEY_ID CREDENTIAL_GENERATION
readonly CURRENT_CREDENTIAL PREVIOUS_CREDENTIAL

TEMPLATE_PATH="$TEMPLATE_SNAPSHOT" DESTINATION="$STAGE" \
  HOME_VALUE="$SATURNIN_HOME" RUNTIME_SHA256_VALUE="$RUNTIME_TREE_SHA256" \
  SYSTEMD_CREDS_SHA256_VALUE="$SYSTEMD_CREDS_SHA256" \
  SYSTEMD_CREDS_DEVICE_VALUE="$SYSTEMD_CREDS_DEVICE" \
  SYSTEMD_CREDS_INODE_VALUE="$SYSTEMD_CREDS_INODE" \
  SYSTEMD_CREDS_MODE_VALUE="$SYSTEMD_CREDS_MODE" \
  CURRENT_KEY_ID_VALUE="$CURRENT_KEY_ID" PREVIOUS_KEY_ID_VALUE="$PREVIOUS_KEY_ID" \
  CREDENTIAL_GENERATION_VALUE="$CREDENTIAL_GENERATION" \
  CURRENT_CREDENTIAL_VALUE="$CURRENT_CREDENTIAL" \
  PREVIOUS_CREDENTIAL_VALUE="$PREVIOUS_CREDENTIAL" \
  "$PYTHON" -I -c '
import os
from pathlib import Path

template = Path(os.environ["TEMPLATE_PATH"]).read_text(encoding="utf-8")
home = os.environ["HOME_VALUE"]
rendered = template.replace("@SATURNIN_HOME@", home).replace(
    "@SATURNIN_HOME_ENV@", home
).replace("@SATURNIN_RUNTIME_SHA256@", os.environ["RUNTIME_SHA256_VALUE"])
rendered = rendered.replace(
    "@SATURNIN_SYSTEMD_CREDS_SHA256@",
    os.environ["SYSTEMD_CREDS_SHA256_VALUE"],
).replace(
    "@SATURNIN_SYSTEMD_CREDS_DEVICE@",
    os.environ["SYSTEMD_CREDS_DEVICE_VALUE"],
).replace(
    "@SATURNIN_SYSTEMD_CREDS_INODE@",
    os.environ["SYSTEMD_CREDS_INODE_VALUE"],
).replace(
    "@SATURNIN_SYSTEMD_CREDS_MODE@",
    os.environ["SYSTEMD_CREDS_MODE_VALUE"],
)
rendered = rendered.replace(
    "@SATURNIN_CURRENT_KEY_ID@", os.environ["CURRENT_KEY_ID_VALUE"]
).replace("@SATURNIN_PREVIOUS_KEY_ID@", os.environ["PREVIOUS_KEY_ID_VALUE"])
rendered = rendered.replace(
    "@SATURNIN_CREDENTIAL_GENERATION@", os.environ["CREDENTIAL_GENERATION_VALUE"]
)
rendered = rendered.replace(
    "@SATURNIN_CURRENT_CREDENTIAL@", os.environ["CURRENT_CREDENTIAL_VALUE"]
).replace(
    "@SATURNIN_PREVIOUS_CREDENTIAL@", os.environ["PREVIOUS_CREDENTIAL_VALUE"]
)
Path(os.environ["DESTINATION"]).write_text(rendered, encoding="utf-8")
'
verify_unit_identity "$STAGE" 0600 "$RUNTIME_TREE_SHA256" >/dev/null
"$TIMEOUT" --signal=TERM --kill-after=10s 30s \
  "$SYSTEMD_ANALYZE" --user verify "$STAGE"

"$CHMOD" 0644 "$STAGE"
mutating=1
verify_unit_directory
if [[ "$had_wants_dir" -eq 0 ]]; then
  wants_dir_identity="$(wants_operation create)"
fi
if [[ "$(trusted_file_identity "$RUNTIME_TREE_SNAPSHOT" 0400)" != "$RUNTIME_TREE_ID" ]] \
  || [[ "$(trusted_fd_identity "$RUNTIME_TREE_FD" 0400)" != "$RUNTIME_TREE_ID" ]]; then
  echo "Attestation runtime changed before installation." >&2
  exit 1
fi
"$MV" -f "$RUNTIME_TREE_SNAPSHOT" "$FILE_INSTALLED_RUNTIME"
"$MV" -f "$STAGE" "$FILE_INSTALLED"
verify_unit_directory
INSTALLED_RUNTIME_ID="$(trusted_file_identity "$FILE_INSTALLED_RUNTIME" 0400)"
readonly INSTALLED_RUNTIME_ID
if [[ "$INSTALLED_RUNTIME_ID" != "$RUNTIME_TREE_ID" ]]; then
  echo "Installed attestation runtime does not match the validated snapshot." >&2
  exit 1
fi
INSTALLED_DEVICE_INODE="$(
  verify_unit_identity "$FILE_INSTALLED" 0644 "$RUNTIME_TREE_SHA256"
)"
readonly INSTALLED_DEVICE_INODE
snapshot_trusted_file "$FILE_INSTALLED" "$INSTALLED_SNAPSHOT" 0400
systemctl_bounded --user daemon-reload
verify_unit_directory
systemctl_bounded --user cat --no-pager "$UNIT" >"$MANAGER_VIEW"
verify_manager_loaded_unit "$MANAGER_VIEW"
if [[ "$(verify_unit_identity "$FILE_INSTALLED" 0644 "$RUNTIME_TREE_SHA256")" != "$INSTALLED_DEVICE_INODE" ]]; then
  echo "Installed attestation unit identity drifted after daemon-reload." >&2
  exit 1
fi
wants_operation link "$wants_dir_identity" \
  "Li4vc2F0dXJuaW4tYXR0ZXN0YXRpb24uc2VydmljZQ=="
verify_wants_link
verify_unit_directory
if [[ "$(verify_unit_identity "$FILE_INSTALLED" 0644 "$RUNTIME_TREE_SHA256")" != "$INSTALLED_DEVICE_INODE" ]]; then
  echo "Installed attestation unit identity drifted before start." >&2
  exit 1
fi
if [[ "$(trusted_file_identity "$FILE_INSTALLED_RUNTIME" 0400)" != "$RUNTIME_TREE_ID" ]] \
  || [[ "$(trusted_fd_identity "$RUNTIME_TREE_FD" 0400)" != "$RUNTIME_TREE_ID" ]]; then
  echo "Installed attestation runtime identity drifted before signer start." >&2
  exit 1
fi
verify_unit_directory
verify_wants_link
systemctl_bounded --user cat --no-pager "$UNIT" >"$MANAGER_VIEW"
verify_manager_loaded_unit "$MANAGER_VIEW"
downgrade_credential_lock
if [[ "$was_active" -eq 1 ]]; then
  systemctl_bounded --user restart "$UNIT"
else
  systemctl_bounded --user start "$UNIT"
fi
systemctl_bounded --user cat --no-pager "$UNIT" >"$MANAGER_VIEW"
verify_manager_loaded_unit "$MANAGER_VIEW"
systemctl_bounded --user show --no-pager \
  --property=LoadState --property=ActiveState --property=SubState \
  --property=FragmentPath --property=DropInPaths \
  --property=MainPID --property=ExecMainPID --property=ControlGroup \
  --property=PrivateMounts --property=PrivateTmp --property=PrivateNetwork \
  --property=ProtectHome --property=ProtectSystem --property=ProtectProc \
  --property=NoNewPrivileges --property=RestrictAddressFamilies \
  --property=RuntimeDirectoryPreserve \
  --property=StatusText \
  "$UNIT" >"$MANAGER_STATE"
verify_running_service "$MANAGER_STATE" "$RUNTIME_TREE_SHA256"
release_credential_lock
mutating=0
echo "installed and started $UNIT"
