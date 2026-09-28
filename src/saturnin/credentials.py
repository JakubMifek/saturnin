"""Systemd encrypted credential provisioning and runtime access."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pwd
import secrets
import shutil
import stat
import subprocess
from contextvars import ContextVar
from pathlib import Path
from contextlib import contextmanager
from typing import Callable

import fcntl

from .jsonlines import PRIVATE_FILE_MODE

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
CREDENTIAL_GENERATION = ".saturnin-attestation-generation"
EXECUTION_SIGNER_ENABLEMENT = ".saturnin-execution-signer-enabled"
HOST_SCOPED_CREDENTIAL_ID = bytes.fromhex("55b9ed1d38594d43a8319d2ebb332ac6")
_ACTIVE_CREDENTIAL_DIRECTORY: ContextVar[int | None] = ContextVar(
    "active_credential_directory", default=None
)


class CredentialError(RuntimeError):
    pass


@contextmanager
def _lifecycle_lock(
    *,
    exclusive: bool,
    validate_credentials: bool = True,
    startup: bool = False,
) -> object:
    gate_descriptor = _runtime_gate_descriptor()
    gate_locked = False
    directory_descriptor: int | None = None
    directory_token = None
    try:
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if startup:
            if exclusive or not validate_credentials:
                raise CredentialError("credential startup lock request is invalid")
            directory_descriptor = _credential_directory_descriptor()
            fcntl.flock(directory_descriptor, fcntl.LOCK_SH)
            _revalidate_credential_directory(directory_descriptor)
            directory_token = _ACTIVE_CREDENTIAL_DIRECTORY.set(directory_descriptor)
            try:
                fcntl.flock(gate_descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                gate_locked = True
            except BlockingIOError:
                pass
        else:
            fcntl.flock(gate_descriptor, operation)
            gate_locked = True
            if validate_credentials:
                directory_descriptor = _credential_directory_descriptor()
                fcntl.flock(directory_descriptor, operation)
                _revalidate_credential_directory(directory_descriptor)
                directory_token = _ACTIVE_CREDENTIAL_DIRECTORY.set(
                    directory_descriptor
                )
        metadata = (
            os.fstat(directory_descriptor) if directory_descriptor is not None else None
        )
        yield (
            (metadata.st_dev, metadata.st_ino) if metadata is not None else None
        )
    finally:
        if directory_token is not None:
            _ACTIVE_CREDENTIAL_DIRECTORY.reset(directory_token)
        if directory_descriptor is not None:
            fcntl.flock(directory_descriptor, fcntl.LOCK_UN)
            os.close(directory_descriptor)
        if gate_locked:
            fcntl.flock(gate_descriptor, fcntl.LOCK_UN)
        os.close(gate_descriptor)


def _runtime_gate_descriptor() -> int:
    runtime = _runtime_gate_path()
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
    metadata = os.fstat(runtime_descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_nlink < 2
    ):
        os.close(runtime_descriptor)
        raise CredentialError("credential lifecycle runtime directory is unsafe")
    return runtime_descriptor


def _runtime_gate_path() -> Path:
    return Path(f"/run/user/{os.getuid()}")


def encrypted_credential_dir() -> Path:
    return _credential_namespace_path()


def _credential_namespace_path() -> Path:
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def encrypted_credential_path(kind: str) -> Path:
    try:
        name = KNOWN_CREDENTIALS[kind]
    except KeyError as exc:
        raise CredentialError(f"unknown credential kind: {kind}") from exc
    return encrypted_credential_dir() / f"{name}.cred"


def _credential_directory_descriptor() -> int:
    directory = encrypted_credential_dir()
    parent = directory.parent
    if (
        directory.resolve(strict=True) != directory
        or parent.resolve(strict=True) != parent
    ):
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
        root_descriptor = os.open(
            "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            root_metadata = os.fstat(root_descriptor)
        finally:
            os.close(root_descriptor)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or not _credential_namespace_parent_is_trusted(
                parent_metadata, root_metadata
            )
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


def _credential_namespace_parent_is_trusted(
    metadata: os.stat_result, root_metadata: os.stat_result
) -> bool:
    return (
        stat.S_ISDIR(root_metadata.st_mode)
        and root_metadata.st_uid in {0, 65534}
        and metadata.st_uid == root_metadata.st_uid
        and not root_metadata.st_mode & 0o022
        and not metadata.st_mode & 0o022
    )


def _ensure_credential_directory() -> None:
    descriptor = _credential_directory_descriptor()
    os.close(descriptor)


@contextmanager
def _credential_operation_descriptor() -> object:
    active = _ACTIVE_CREDENTIAL_DIRECTORY.get()
    if active is not None:
        yield active
        return
    descriptor = _credential_directory_descriptor()
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def _credential_entry_name(path: Path) -> str:
    if path.parent != encrypted_credential_dir() or path.name in {"", ".", ".."}:
        raise CredentialError("credential path is outside the protected directory")
    return path.name


def _revalidate_credential_directory(descriptor: int) -> None:
    current = _credential_directory_descriptor()
    try:
        expected = os.fstat(descriptor)
        observed = os.fstat(current)
        if (expected.st_dev, expected.st_ino) != (observed.st_dev, observed.st_ino):
            raise CredentialError("credential directory identity changed")
    finally:
        os.close(current)


@contextmanager
def _credential_directory_lock(*, exclusive: bool) -> object:
    descriptor = _credential_directory_descriptor()
    token = None
    try:
        fcntl.flock(
            descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        )
        _revalidate_credential_directory(descriptor)
        token = _ACTIVE_CREDENTIAL_DIRECTORY.set(descriptor)
        metadata = os.fstat(descriptor)
        yield (metadata.st_dev, metadata.st_ino)
    finally:
        if token is not None:
            _ACTIVE_CREDENTIAL_DIRECTORY.reset(token)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _entry_exists(path: Path) -> bool:
    name = _credential_entry_name(path)
    with _credential_operation_descriptor() as descriptor:
        try:
            os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True


def _unlink_credential_entry(path: Path, *, missing_ok: bool = False) -> None:
    name = _credential_entry_name(path)
    with _credential_operation_descriptor() as descriptor:
        _revalidate_credential_directory(descriptor)
        try:
            os.unlink(name, dir_fd=descriptor)
        except FileNotFoundError:
            if not missing_ok:
                raise


def _atomic_replace_private(path: Path, value: str) -> None:
    name = _credential_entry_name(path)
    data = value.encode("utf-8")
    temporary = f".{name}.{secrets.token_urlsafe(24)}.tmp"
    with _credential_operation_descriptor() as directory_descriptor:
        file_descriptor = -1
        try:
            file_descriptor = os.open(
                temporary,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                PRIVATE_FILE_MODE,
                dir_fd=directory_descriptor,
            )
            os.fchmod(file_descriptor, PRIVATE_FILE_MODE)
            view = memoryview(data)
            while view:
                view = view[os.write(file_descriptor, view) :]
            os.fsync(file_descriptor)
            written_metadata = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(written_metadata.st_mode)
                or written_metadata.st_uid != os.getuid()
                or stat.S_IMODE(written_metadata.st_mode) != PRIVATE_FILE_MODE
                or written_metadata.st_nlink != 1
                or written_metadata.st_size != len(data)
            ):
                raise CredentialError(
                    f"credential staging artifact changed before publication: {name}"
                )
            _revalidate_credential_directory(directory_descriptor)
            staged_metadata = os.stat(
                temporary,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if (
                staged_metadata.st_dev != written_metadata.st_dev
                or staged_metadata.st_ino != written_metadata.st_ino
                or staged_metadata.st_mode != written_metadata.st_mode
                or staged_metadata.st_uid != written_metadata.st_uid
                or staged_metadata.st_gid != written_metadata.st_gid
                or staged_metadata.st_nlink != written_metadata.st_nlink
                or staged_metadata.st_size != written_metadata.st_size
            ):
                raise CredentialError(
                    f"credential staging artifact changed before publication: {name}"
                )
            os.rename(
                temporary,
                name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            published_metadata = os.stat(
                name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            retained_metadata = os.fstat(file_descriptor)
            if (
                published_metadata.st_dev != written_metadata.st_dev
                or published_metadata.st_ino != written_metadata.st_ino
                or published_metadata.st_mode != written_metadata.st_mode
                or published_metadata.st_uid != written_metadata.st_uid
                or published_metadata.st_gid != written_metadata.st_gid
                or published_metadata.st_nlink != 1
                or published_metadata.st_size != len(data)
                or retained_metadata.st_dev != written_metadata.st_dev
                or retained_metadata.st_ino != written_metadata.st_ino
                or retained_metadata.st_nlink != 1
                or retained_metadata.st_size != len(data)
            ):
                raise CredentialError(
                    f"credential artifact changed during publication: {name}"
                )
            os.fsync(directory_descriptor)
        except CredentialError:
            raise
        except OSError as exc:
            raise CredentialError(
                f"credential artifact could not be replaced safely: {name}"
            ) from exc
        finally:
            if file_descriptor >= 0:
                os.close(file_descriptor)
            try:
                os.unlink(temporary, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass


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
    _atomic_replace_private(destination, encrypted)


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
    _atomic_replace_private(
        encrypted_credential_dir() / CREDENTIAL_GENERATION,
        secrets.token_bytes(32).hex() + "\n",
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
    _atomic_replace_private(
        encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT,
        credential_generation() + "\n",
    )


def _read_private_file(path: Path) -> str:
    name = _credential_entry_name(path)
    with _credential_operation_descriptor() as directory_descriptor:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_descriptor,
            )
        except OSError as exc:
            raise CredentialError(
                f"credential recovery artifact is unavailable: {path.name}"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
                or metadata.st_nlink != 1
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
    artifacts = [
        _entry_exists(path) for path in (state_path, current_backup, previous_backup)
    ]
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
        with _credential_directory_lock(exclusive=True):
            return _provision_attestation_key()


def _provision_attestation_key() -> Path:
    destination = encrypted_credential_path("review-attestation")
    _unlink_credential_entry(
        encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT, missing_ok=True
    )
    if _entry_exists(destination):
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
    _unlink_credential_entry(
        encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT, missing_ok=True
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
    _atomic_replace_private(
        current_backup,
        _read_private_file(encrypted_credential_path("review-attestation")),
    )
    _atomic_replace_private(
        previous_backup,
        _read_private_file(encrypted_credential_path("review-attestation-previous")),
    )
    _atomic_replace_private(
        state_path,
        json.dumps({"version": 1, "state": "pending-seal"}) + "\n",
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
        _atomic_replace_private(
            state_path,
            json.dumps({"version": 1, "state": "sealed-cleanup"}) + "\n",
        )
    _enable_execution_signer()
    for path in (current_backup, previous_backup, state_path):
        try:
            _unlink_credential_entry(path, missing_ok=True)
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
    if not _entry_exists(current_backup) or not _entry_exists(previous_backup):
        raise CredentialError("attestation rotation recovery data is incomplete")
    current = encrypted_credential_path("review-attestation")
    previous = encrypted_credential_path("review-attestation-previous")
    _atomic_replace_private(current, _read_private_file(current_backup))
    _atomic_replace_private(previous, _read_private_file(previous_backup))
    _decrypt_encrypted_credential("review-attestation")
    _decrypt_encrypted_credential("review-attestation-previous")
    _advance_generation()
    _unlink_credential_entry(
        encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT, missing_ok=True
    )
    for path in (state_path, current_backup, previous_backup):
        _unlink_credential_entry(path, missing_ok=True)
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
            _unlink_credential_entry(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise CredentialError(f"could not revoke encrypted credential: {kind}") from exc
        removed.append(path)
    if kind == "review-attestation":
        for path in _rotation_paths():
            _unlink_credential_entry(path, missing_ok=True)
        generation_path = encrypted_credential_dir() / CREDENTIAL_GENERATION
        _unlink_credential_entry(generation_path, missing_ok=True)
        _unlink_credential_entry(
            encrypted_credential_dir() / EXECUTION_SIGNER_ENABLEMENT, missing_ok=True
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
    name = _credential_entry_name(path)
    with _credential_operation_descriptor() as directory_descriptor:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_descriptor,
            )
        except FileNotFoundError as exc:
            raise CredentialError(
                f"encrypted credential is not provisioned: {kind}"
            ) from exc
        except OSError as exc:
            raise CredentialError(
                f"encrypted credential cannot be opened: {kind}"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
                or metadata.st_nlink != 1
            ):
                raise CredentialError(
                    f"encrypted credential has unsafe ownership or mode: {kind}"
                )
            ciphertext = os.pread(descriptor, MAX_CREDENTIAL_BYTES + 1, 0)
            if not ciphertext or len(ciphertext) > MAX_CREDENTIAL_BYTES:
                raise CredentialError(
                    f"encrypted credential cannot be decrypted: {kind}"
                )
            _validate_encryption_model(ciphertext)
            try:
                result = subprocess.run(
                    [
                        "systemd-creds",
                        "decrypt",
                        "--user",
                        f"--name={KNOWN_CREDENTIALS[kind]}",
                        f"/proc/self/fd/{descriptor}",
                        "-",
                    ],
                    check=False,
                    capture_output=True,
                    pass_fds=(descriptor,),
                )
            except OSError as exc:
                raise CredentialError(
                    f"encrypted credential cannot be decrypted: {kind}"
                ) from exc
        finally:
            os.close(descriptor)
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
