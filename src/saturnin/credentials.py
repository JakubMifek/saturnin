"""Systemd encrypted credential provisioning and runtime access."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
from pathlib import Path
from contextlib import contextmanager
from typing import Callable

import fcntl

from .jsonlines import PRIVATE_FILE_MODE, atomic_replace_text

ATTESTATION_CREDENTIAL = "saturnin-review-attestation-key"
PREVIOUS_ATTESTATION_CREDENTIAL = "saturnin-review-attestation-previous-key"
KNOWN_CREDENTIALS = {
    "review-attestation": ATTESTATION_CREDENTIAL,
    "review-attestation-previous": PREVIOUS_ATTESTATION_CREDENTIAL,
}
MAX_CREDENTIAL_BYTES = 16 * 1024
MINIMUM_SYSTEMD_CREDS_VERSION = 256
HOST_CREDENTIAL_SECRET = Path("/var/lib/systemd/credential.secret")
ROTATION_STATE = ".attestation-rotation.json"
ROTATION_CURRENT_BACKUP = ".saturnin-review-attestation-key.rollback.cred"
ROTATION_PREVIOUS_BACKUP = ".saturnin-review-attestation-previous-key.rollback.cred"
CREDENTIAL_GENERATION = ".generation"
EXECUTION_SIGNER_ENABLEMENT = ".execution-signer-enabled"
CREDENTIAL_LIFECYCLE_LOCK = ".saturnin-credential-lifecycle.lock"
CREDENTIAL_RUNTIME_DIRECTORY = "saturnin-attestation"
HOST_SCOPED_CREDENTIAL_ID = bytes.fromhex("55b9ed1d38594d43a8319d2ebb332ac6")


class CredentialError(RuntimeError):
    pass


@contextmanager
def _lifecycle_lock(*, exclusive: bool, validate_credentials: bool = True) -> object:
    lock_descriptor = _runtime_lock_descriptor()
    directory_descriptor: int | None = None
    try:
        fcntl.flock(
            lock_descriptor,
            fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
        )
        if validate_credentials:
            directory_descriptor = _credential_directory_descriptor()
        yield
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def _runtime_lock_descriptor() -> int:
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", ""))
    try:
        canonical_runtime = runtime.resolve(strict=True)
    except OSError as exc:
        raise CredentialError(
            "credential lifecycle runtime directory is unsafe"
        ) from exc
    if not runtime.is_absolute() or canonical_runtime != runtime:
        raise CredentialError("credential lifecycle runtime directory is unsafe")
    try:
        runtime_descriptor = os.open(
            runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        raise CredentialError("credential lifecycle runtime directory is unsafe") from exc
    service_runtime_descriptor: int | None = None
    try:
        metadata = os.fstat(runtime_descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_nlink < 2
        ):
            raise CredentialError("credential lifecycle runtime directory is unsafe")
        try:
            os.mkdir(
                CREDENTIAL_RUNTIME_DIRECTORY, mode=0o700, dir_fd=runtime_descriptor
            )
        except FileExistsError:
            pass
        service_runtime_descriptor = os.open(
            CREDENTIAL_RUNTIME_DIRECTORY,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=runtime_descriptor,
        )
        service_runtime_metadata = os.fstat(service_runtime_descriptor)
        if (
            not stat.S_ISDIR(service_runtime_metadata.st_mode)
            or service_runtime_metadata.st_uid != os.getuid()
            or stat.S_IMODE(service_runtime_metadata.st_mode) != 0o700
            or service_runtime_metadata.st_nlink < 2
        ):
            raise CredentialError("credential lifecycle runtime directory is unsafe")
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(
                CREDENTIAL_LIFECYCLE_LOCK,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=service_runtime_descriptor,
            )
        except FileExistsError:
            descriptor = os.open(
                CREDENTIAL_LIFECYCLE_LOCK,
                flags,
                dir_fd=service_runtime_descriptor,
            )
    except OSError as exc:
        raise CredentialError("credential lifecycle lock is unsafe") from exc
    finally:
        if service_runtime_descriptor is not None:
            os.close(service_runtime_descriptor)
        os.close(runtime_descriptor)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        raise CredentialError("credential lifecycle lock is unsafe")
    return descriptor


def encrypted_credential_dir() -> Path:
    config_home = Path(
        os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    ).expanduser()
    return config_home / "systemd" / "user" / "saturnin-credentials"


def encrypted_credential_path(kind: str) -> Path:
    try:
        name = KNOWN_CREDENTIALS[kind]
    except KeyError as exc:
        raise CredentialError(f"unknown credential kind: {kind}") from exc
    return encrypted_credential_dir() / f"{name}.cred"


def _credential_directory_descriptor() -> int:
    directory = encrypted_credential_dir()
    parent = directory.parent
    if parent.resolve(strict=True) != parent:
        raise CredentialError("credential directory is not canonical")
    try:
        parent_descriptor = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        raise CredentialError(
            "credential directory is not an owner-controlled directory"
        ) from exc
    try:
        parent_metadata = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or parent_metadata.st_mode & 0o022
            or parent_metadata.st_nlink < 2
        ):
            raise CredentialError(
                "credential directory is not an owner-controlled directory"
            )
        descriptor = os.open(
            directory.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
    except OSError as exc:
        raise CredentialError(
            "credential directory is not an owner-controlled directory"
        ) from exc
    finally:
        os.close(parent_descriptor)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_nlink < 2
    ):
        os.close(descriptor)
        raise CredentialError(
            "credential directory is not an owner-controlled directory"
        )
    return descriptor


def _ensure_credential_directory() -> None:
    directory = encrypted_credential_dir()
    try:
        directory.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise CredentialError(
            "credential directory could not be created safely"
        ) from exc
    descriptor = _credential_directory_descriptor()
    os.close(descriptor)


def _encrypt(name: str, value: str, destination: Path) -> None:
    if not value or "\x00" in value:
        raise CredentialError("credential value must be non-empty text")
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_CREDENTIAL_BYTES:
        raise CredentialError("credential value is too large")
    descriptor = _credential_directory_descriptor()
    os.close(descriptor)
    try:
        result = subprocess.run(
            [
                "systemd-creds",
                "encrypt",
                "--user",
                "--with-key=host",
                f"--name={name}",
                "-",
                "-",
            ],
            check=False,
            capture_output=True,
            input=encoded,
        )
    except OSError as exc:
        raise CredentialError("systemd-creds could not encrypt the credential") from exc
    if result.returncode != 0 or not result.stdout:
        raise CredentialError("systemd-creds could not encrypt the credential")
    try:
        encrypted = result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CredentialError("systemd-creds returned an invalid encrypted credential") from exc
    _validate_encryption_model(encrypted.encode("utf-8"))
    atomic_replace_text(destination, encrypted, mode=PRIVATE_FILE_MODE)


def _validate_encryption_model(ciphertext: bytes) -> None:
    try:
        decoded = base64.b64decode(b"".join(ciphertext.split()), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise CredentialError("systemd-creds returned an invalid encrypted credential") from exc
    if len(decoded) < len(HOST_SCOPED_CREDENTIAL_ID) or not hmac_compare(
        decoded[:16], HOST_SCOPED_CREDENTIAL_ID
    ):
        raise CredentialError(
            "encrypted credential is not host-key-only user-scoped data"
        )


def hmac_compare(left: bytes, right: bytes) -> bool:
    return secrets.compare_digest(left, right)


def _new_attestation_key(*, excluding: set[str] | None = None) -> str:
    excluded = excluding or set()
    for _ in range(4):
        value = secrets.token_hex(32)
        if value not in excluded:
            return value
    raise CredentialError("could not generate a distinct attestation key")


def credential_prerequisites() -> dict[str, str | int]:
    executable = shutil.which("systemd-creds")
    if not executable:
        raise CredentialError("systemd-creds is not installed")
    try:
        result = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise CredentialError("systemd-creds prerequisites could not be checked") from exc
    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    fields = first_line.split()
    if result.returncode != 0 or len(fields) < 2 or not fields[1].isdigit():
        raise CredentialError("systemd-creds version could not be determined")
    version = int(fields[1])
    if version < MINIMUM_SYSTEMD_CREDS_VERSION:
        raise CredentialError(
            f"systemd-creds {MINIMUM_SYSTEMD_CREDS_VERSION} or newer is required"
        )
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", ""))
    manager_socket = runtime / "systemd" / "private" if runtime.is_absolute() else Path()
    try:
        manager_metadata = manager_socket.stat()
        host_key_metadata = HOST_CREDENTIAL_SECRET.stat()
    except OSError as exc:
        raise CredentialError(
            "systemd credential prerequisites are incomplete; administrator setup is required"
        ) from exc
    if (
        not runtime.is_absolute()
        or not stat.S_ISSOCK(manager_metadata.st_mode)
        or manager_metadata.st_uid != os.getuid()
    ):
        raise CredentialError("the systemd user manager is not available")
    if (
        not stat.S_ISREG(host_key_metadata.st_mode)
        or host_key_metadata.st_uid != 0
        or stat.S_IMODE(host_key_metadata.st_mode) != 0o400
    ):
        raise CredentialError(
            "the systemd credential host key has unsafe ownership or mode"
        )
    return {
        "systemd_creds_version": version,
        "user_manager": "available",
        "host_key": "initialized",
    }


def _rotation_paths() -> tuple[Path, Path, Path]:
    directory = encrypted_credential_dir()
    return (
        directory / ROTATION_STATE,
        directory / ROTATION_CURRENT_BACKUP,
        directory / ROTATION_PREVIOUS_BACKUP,
    )


def credential_generation() -> str:
    return _read_private_file(encrypted_credential_dir() / CREDENTIAL_GENERATION).strip()


def _advance_generation() -> None:
    atomic_replace_text(
        encrypted_credential_dir() / CREDENTIAL_GENERATION,
        secrets.token_bytes(32).hex() + "\n",
        mode=PRIVATE_FILE_MODE,
    )


def execution_signer_ready() -> bool:
    if _rotation_state() != "ready":
        return False
    try:
        enabled = _read_private_file(
            encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT
        ).strip()
        generation = credential_generation()
    except CredentialError:
        return False
    return secrets.compare_digest(enabled, generation)


def _enable_execution_signer() -> None:
    atomic_replace_text(
        encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT,
        credential_generation() + "\n",
        mode=PRIVATE_FILE_MODE,
    )


def _read_private_file(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise CredentialError(f"credential recovery artifact is unavailable: {path.name}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
        ):
            raise CredentialError(
                f"credential recovery artifact has unsafe ownership or mode: {path.name}"
            )
        data = os.read(descriptor, MAX_CREDENTIAL_BYTES + 1)
    finally:
        os.close(descriptor)
    if not data or len(data) > MAX_CREDENTIAL_BYTES:
        raise CredentialError(f"credential recovery artifact is invalid: {path.name}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CredentialError(
            f"credential recovery artifact is invalid: {path.name}"
        ) from exc


def _rotation_state() -> str:
    state_path, current_backup, previous_backup = _rotation_paths()
    artifacts = [path.exists() for path in (state_path, current_backup, previous_backup)]
    if not any(artifacts):
        return "ready"
    try:
        data = json.loads(_read_private_file(state_path))
    except (CredentialError, json.JSONDecodeError):
        return "recovery-required"
    if data == {"version": 1, "state": "sealed-cleanup"}:
        return "sealed-cleanup"
    if all(artifacts) and data == {"version": 1, "state": "pending-seal"}:
        return "pending-seal"
    return "recovery-required"


def provision_attestation_key() -> Path:
    with _lifecycle_lock(exclusive=True, validate_credentials=False):
        _ensure_credential_directory()
        return _provision_attestation_key()


def _provision_attestation_key() -> Path:
    destination = encrypted_credential_path("review-attestation")
    (encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT).unlink(
        missing_ok=True
    )
    if destination.exists():
        raise CredentialError(
            "review-attestation is already provisioned; use rotate-attestation"
        )
    previous = _new_attestation_key()
    current = _new_attestation_key(excluding={previous})
    _encrypt(
        PREVIOUS_ATTESTATION_CREDENTIAL,
        previous,
        encrypted_credential_path("review-attestation-previous"),
    )
    _encrypt(ATTESTATION_CREDENTIAL, current, destination)
    _advance_generation()
    return destination


def rotate_attestation_key(
    *,
    previous_key_in_use: Callable[[str], bool],
) -> Path:
    with _lifecycle_lock(exclusive=True):
        return _rotate_attestation_key(previous_key_in_use=previous_key_in_use)


def _rotate_attestation_key(
    *,
    previous_key_in_use: Callable[[str], bool],
) -> Path:
    if _rotation_state() != "ready":
        raise CredentialError(
            "attestation rotation is already pending; seal or roll it back"
        )
    (encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT).unlink(
        missing_ok=True
    )
    current = _decrypt_encrypted_credential("review-attestation")
    previous = _decrypt_encrypted_credential("review-attestation-previous")
    if secrets.compare_digest(current, previous):
        raise CredentialError("current and previous attestation keys must differ")
    if previous_key_in_use(previous):
        raise CredentialError(
            "previous attestation key still protects review records; archive or retire them before rotating"
        )
    state_path, current_backup, previous_backup = _rotation_paths()
    atomic_replace_text(
        current_backup,
        _read_private_file(encrypted_credential_path("review-attestation")),
        mode=PRIVATE_FILE_MODE,
    )
    atomic_replace_text(
        previous_backup,
        _read_private_file(encrypted_credential_path("review-attestation-previous")),
        mode=PRIVATE_FILE_MODE,
    )
    atomic_replace_text(
        state_path,
        json.dumps({"version": 1, "state": "pending-seal"}) + "\n",
        mode=PRIVATE_FILE_MODE,
    )
    _encrypt(
        PREVIOUS_ATTESTATION_CREDENTIAL,
        current,
        encrypted_credential_path("review-attestation-previous"),
    )
    destination = encrypted_credential_path("review-attestation")
    _encrypt(
        ATTESTATION_CREDENTIAL,
        _new_attestation_key(excluding={current, previous}),
        destination,
    )
    _advance_generation()
    return destination


def attestation_rotation_values() -> tuple[str, str]:
    with _lifecycle_lock(exclusive=False):
        return _attestation_rotation_values()


def _attestation_rotation_values() -> tuple[str, str]:
    if _rotation_state() != "pending-seal":
        raise CredentialError("no attestation rotation is pending sealing")
    return (
        _decrypt_encrypted_credential("review-attestation"),
        _decrypt_encrypted_credential("review-attestation-previous"),
    )


def seal_attestation_rotation(sealer: Callable[[str, str], Path]) -> Path:
    with _lifecycle_lock(exclusive=True):
        current, previous = _attestation_rotation_values()
        result = sealer(current, previous)
        _complete_attestation_rotation()
        return result


def complete_attestation_rotation() -> None:
    with _lifecycle_lock(exclusive=True):
        _complete_attestation_rotation()


def _complete_attestation_rotation() -> None:
    state = _rotation_state()
    if state not in {"pending-seal", "sealed-cleanup"}:
        raise CredentialError("no attestation rotation is pending sealing")
    state_path, current_backup, previous_backup = _rotation_paths()
    if state == "pending-seal":
        atomic_replace_text(
            state_path,
            json.dumps({"version": 1, "state": "sealed-cleanup"}) + "\n",
            mode=PRIVATE_FILE_MODE,
        )
    _enable_execution_signer()
    for path in (current_backup, previous_backup, state_path):
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise CredentialError("could not remove attestation rotation recovery data") from exc


def rollback_attestation_rotation() -> Path:
    with _lifecycle_lock(exclusive=True):
        return _rollback_attestation_rotation()


def _rollback_attestation_rotation() -> Path:
    state_path, current_backup, previous_backup = _rotation_paths()
    state = _rotation_state()
    if state == "ready":
        raise CredentialError("no attestation rotation recovery data exists")
    if state == "sealed-cleanup":
        raise CredentialError("sealed attestation rotation may not be rolled back")
    if not current_backup.exists() or not previous_backup.exists():
        raise CredentialError("attestation rotation recovery data is incomplete")
    current = encrypted_credential_path("review-attestation")
    previous = encrypted_credential_path("review-attestation-previous")
    atomic_replace_text(current, _read_private_file(current_backup), mode=PRIVATE_FILE_MODE)
    atomic_replace_text(previous, _read_private_file(previous_backup), mode=PRIVATE_FILE_MODE)
    _decrypt_encrypted_credential("review-attestation")
    _decrypt_encrypted_credential("review-attestation-previous")
    _advance_generation()
    (encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT).unlink(
        missing_ok=True
    )
    for path in (state_path, current_backup, previous_backup):
        path.unlink(missing_ok=True)
    return current


def revoke_credential(kind: str) -> list[Path]:
    with _lifecycle_lock(exclusive=True):
        return _revoke_credential(kind)


def _revoke_credential(kind: str) -> list[Path]:
    kinds = (
        ["review-attestation", "review-attestation-previous"]
        if kind == "review-attestation"
        else [kind]
    )
    removed: list[Path] = []
    for credential_kind in kinds:
        path = encrypted_credential_path(credential_kind)
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise CredentialError(f"could not revoke encrypted credential: {kind}") from exc
        removed.append(path)
    if kind == "review-attestation":
        for path in _rotation_paths():
            path.unlink(missing_ok=True)
        (encrypted_credential_dir() / CREDENTIAL_GENERATION).unlink(missing_ok=True)
        (encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT).unlink(
            missing_ok=True
        )
    if not removed:
        raise CredentialError(f"encrypted credential is not provisioned: {kind}")
    return removed


def _decode_mountinfo_path(value: str) -> str:
    for encoded, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(encoded, decoded)
    return value


def _systemd_creds_mount_identity(
    mountinfo: str, metadata: os.stat_result
) -> None:
    target = "/usr/bin/systemd-creds"
    candidates: list[tuple[int, str, set[str]]] = []
    for line in mountinfo.splitlines():
        before, separator, _ = line.partition(" - ")
        fields = before.split()
        if not separator or len(fields) < 6:
            raise CredentialError("systemd-creds mount provenance is invalid")
        mountpoint = _decode_mountinfo_path(fields[4])
        if target == mountpoint or target.startswith(mountpoint.rstrip("/") + "/"):
            candidates.append((len(mountpoint), fields[2], set(fields[5].split(","))))
    if not candidates:
        raise CredentialError("systemd-creds mount provenance is missing")
    longest = max(length for length, _, _ in candidates)
    effective = [
        (device, options)
        for length, device, options in candidates
        if length == longest
    ]
    expected_device = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    if len(effective) != 1:
        raise CredentialError("systemd-creds mount provenance is ambiguous")
    device, options = effective[0]
    if device != expected_device or "ro" not in options or "rw" in options:
        raise CredentialError("systemd-creds mount provenance is unsafe")


def _validate_systemd_creds_namespace(
    parent_metadata: list[os.stat_result],
    metadata: os.stat_result,
    mountinfo: str,
    expected_device: int,
    expected_inode: int,
    expected_mode: int,
) -> None:
    namespace_root_uid = parent_metadata[0].st_uid
    if (
        namespace_root_uid not in {0, 65534}
        or any(
            not stat.S_ISDIR(value.st_mode)
            or value.st_uid != namespace_root_uid
            or value.st_mode & 0o022
            for value in parent_metadata
        )
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != namespace_root_uid
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or metadata.st_dev != expected_device
        or metadata.st_ino != expected_inode
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        raise CredentialError("systemd-creds namespace identity is unsafe")
    _systemd_creds_mount_identity(mountinfo, metadata)


def _sealed_systemd_creds() -> int:
    expected_digest = os.environ.get("SATURNIN_SYSTEMD_CREDS_SHA256", "")
    expected_device = os.environ.get("SATURNIN_SYSTEMD_CREDS_DEVICE", "")
    expected_inode = os.environ.get("SATURNIN_SYSTEMD_CREDS_INODE", "")
    expected_mode = os.environ.get("SATURNIN_SYSTEMD_CREDS_MODE", "")
    if (
        len(expected_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_digest)
        or not expected_device.isdigit()
        or not expected_inode.isdigit()
        or not expected_mode.isdigit()
    ):
        raise CredentialError("systemd-creds host identity is invalid")

    descriptors: list[int] = []
    helper_fd = -1
    try:
        parent_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent_fd)
        parent_metadata = [os.fstat(parent_fd)]
        for component in ("usr", "bin"):
            parent_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            descriptors.append(parent_fd)
            parent_metadata.append(os.fstat(parent_fd))
        source_fd = os.open(
            "systemd-creds",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        descriptors.append(source_fd)
        before = os.fstat(source_fd)
        _validate_systemd_creds_namespace(
            parent_metadata,
            before,
            Path("/proc/self/mountinfo").read_text(encoding="utf-8"),
            int(expected_device),
            int(expected_inode),
            int(expected_mode),
        )

        helper_fd = os.memfd_create(
            "saturnin-systemd-creds",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        os.fchmod(helper_fd, 0o500)
        digest = hashlib.sha256()
        while chunk := os.read(source_fd, 65536):
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(helper_fd, view) :]
        after = os.fstat(source_fd)
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
        ) or digest.hexdigest() != expected_digest:
            raise CredentialError("systemd-creds changed after host validation")
        fcntl.fcntl(
            helper_fd,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        return helper_fd
    except (OSError, ValueError) as exc:
        raise CredentialError("could not seal host-validated systemd-creds") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        if helper_fd >= 0 and not fcntl.fcntl(
            helper_fd, fcntl.F_GET_SEALS
        ) & fcntl.F_SEAL_SEAL:
            os.close(helper_fd)


def systemd_credential(name: str) -> str:
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not directory:
        ciphertext_env = {
            ATTESTATION_CREDENTIAL: "SATURNIN_CURRENT_CREDENTIAL_CIPHERTEXT",
            PREVIOUS_ATTESTATION_CREDENTIAL: (
                "SATURNIN_PREVIOUS_CREDENTIAL_CIPHERTEXT"
            ),
        }.get(name)
        ciphertext = os.environ.get(ciphertext_env, "") if ciphertext_env else ""
        if not ciphertext:
            return ""
        _validate_encryption_model(ciphertext.encode("utf-8"))
        tool_fd = _sealed_systemd_creds()
        try:
            plaintext_fd = os.memfd_create(
                "saturnin-decrypted-credential",
                os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
            )
            os.fchmod(plaintext_fd, 0)
        except OSError as exc:
            os.close(tool_fd)
            raise CredentialError(
                f"could not prepare inline systemd credential {name}"
            ) from exc
        try:
            result = subprocess.run(
                [
                    f"/proc/self/fd/{tool_fd}",
                    "decrypt",
                    "--user",
                    f"--name={name}",
                    "-",
                    "-",
                ],
                check=False,
                input=ciphertext.encode("utf-8"),
                stdout=plaintext_fd,
                stderr=subprocess.DEVNULL,
                env={"XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"},
                pass_fds=(tool_fd,),
            )
        except OSError as exc:
            os.close(plaintext_fd)
            os.close(tool_fd)
            raise CredentialError(
                f"could not decrypt inline systemd credential {name}"
            ) from exc
        try:
            fcntl.fcntl(
                plaintext_fd,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_SEAL,
            )
            value = os.pread(plaintext_fd, MAX_CREDENTIAL_BYTES + 1, 0)
            if (
                result.returncode != 0
                or not value
                or len(value) > MAX_CREDENTIAL_BYTES
                or b"\x00" in value
            ):
                raise CredentialError(
                    f"could not decrypt inline systemd credential {name}"
                )
            try:
                return value.decode("utf-8").rstrip("\n")
            except UnicodeDecodeError as exc:
                raise CredentialError(
                    f"inline systemd credential {name} is not text"
                ) from exc
        finally:
            os.close(plaintext_fd)
            os.close(tool_fd)
    path = Path(directory) / name
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise CredentialError(f"could not open systemd credential {name}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise CredentialError(f"systemd credential {name} is not an owner-controlled file")
        if metadata.st_mode & 0o077:
            raise CredentialError(f"systemd credential {name} has unsafe permissions")
        value = os.read(descriptor, MAX_CREDENTIAL_BYTES + 1)
    finally:
        os.close(descriptor)
    if not value or len(value) > MAX_CREDENTIAL_BYTES or b"\x00" in value:
        raise CredentialError(f"systemd credential {name} is invalid")
    try:
        return value.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise CredentialError(f"systemd credential {name} is not text") from exc


def credential_value(env_name: str, credential_name: str) -> str:
    return os.environ.get(env_name, "") or systemd_credential(credential_name)


def _decrypt_encrypted_credential(kind: str) -> str:
    path = encrypted_credential_path(kind)
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise CredentialError(f"encrypted credential is not provisioned: {kind}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        raise CredentialError(f"encrypted credential has unsafe ownership or mode: {kind}")
    _validate_encryption_model(_read_private_file(path).encode("utf-8"))
    try:
        result = subprocess.run(
            [
                "systemd-creds",
                "decrypt",
                "--user",
                f"--name={KNOWN_CREDENTIALS[kind]}",
                str(path),
                "-",
            ],
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        raise CredentialError(
            f"encrypted credential cannot be decrypted: {kind}"
        ) from exc
    if result.returncode != 0 or not result.stdout:
        raise CredentialError(f"encrypted credential cannot be decrypted: {kind}")
    if len(result.stdout) > MAX_CREDENTIAL_BYTES or b"\x00" in result.stdout:
        raise CredentialError(f"encrypted credential cannot be decrypted: {kind}")
    try:
        value = result.stdout.decode("utf-8").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise CredentialError(
            f"encrypted credential cannot be decrypted: {kind}"
        ) from exc
    if not value:
        raise CredentialError(f"encrypted credential cannot be decrypted: {kind}")
    return value


def validate_encrypted_credential(kind: str) -> Path:
    with _lifecycle_lock(exclusive=False):
        return _validate_encrypted_credential(kind)


def _validate_encrypted_credential(kind: str) -> Path:
    _decrypt_encrypted_credential(kind)
    if kind == "review-attestation":
        _decrypt_encrypted_credential("review-attestation-previous")
        credential_generation()
    return encrypted_credential_path(kind)


def credential_status(kind: str) -> dict[str, str]:
    with _lifecycle_lock(exclusive=False):
        path = _validate_encrypted_credential(kind)
        status = {
            "status": "valid",
            "path": str(path),
            "encryption": "host-key-only-user-scoped",
        }
        if kind == "review-attestation":
            status["rotation"] = _rotation_state()
            status["signer"] = (
                "ready" if execution_signer_ready() else "rotation-required"
            )
        return status
