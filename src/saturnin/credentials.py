"""Systemd encrypted credential provisioning and runtime access."""

from __future__ import annotations

import getpass
import base64
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
GITHUB_MCP_CREDENTIAL = "saturnin-github-mcp-token"
KNOWN_CREDENTIALS = {
    "review-attestation": ATTESTATION_CREDENTIAL,
    "review-attestation-previous": PREVIOUS_ATTESTATION_CREDENTIAL,
    "github-mcp": GITHUB_MCP_CREDENTIAL,
}
MAX_CREDENTIAL_BYTES = 16 * 1024
MINIMUM_SYSTEMD_CREDS_VERSION = 256
HOST_CREDENTIAL_SECRET = Path("/var/lib/systemd/credential.secret")
ROTATION_STATE = ".attestation-rotation.json"
ROTATION_CURRENT_BACKUP = ".saturnin-review-attestation-key.rollback.cred"
ROTATION_PREVIOUS_BACKUP = ".saturnin-review-attestation-previous-key.rollback.cred"
LIFECYCLE_LOCK = ".lifecycle"
HOST_SCOPED_CREDENTIAL_ID = bytes.fromhex("55b9ed1d38594d43a8319d2ebb332ac6")


class CredentialError(RuntimeError):
    pass


@contextmanager
def _lifecycle_lock(*, exclusive: bool) -> object:
    directory = encrypted_credential_dir()
    _secure_directory(directory)
    path = directory / LIFECYCLE_LOCK
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
        ):
            raise CredentialError("credential lifecycle lock is unsafe")
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        fcntl.flock(
            descriptor,
            fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
        )
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


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


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise CredentialError(
            "credential directory is not an owner-controlled directory"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.getuid():
            raise CredentialError(
                "credential directory is not an owner-controlled directory"
            )
        os.fchmod(descriptor, 0o700)
        if os.fstat(descriptor).st_mode & 0o077:
            raise CredentialError(
                "credential directory is accessible by group or other users"
            )
    finally:
        os.close(descriptor)


def _encrypt(name: str, value: str, destination: Path) -> None:
    if not value or "\x00" in value:
        raise CredentialError("credential value must be non-empty text")
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_CREDENTIAL_BYTES:
        raise CredentialError("credential value is too large")
    _secure_directory(destination.parent)
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
    with _lifecycle_lock(exclusive=True):
        return _provision_attestation_key()


def _provision_attestation_key() -> Path:
    destination = encrypted_credential_path("review-attestation")
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
    if not removed:
        raise CredentialError(f"encrypted credential is not provisioned: {kind}")
    return removed


def store_github_mcp_token() -> Path:
    token = getpass.getpass("Dedicated fine-grained GitHub token: ")
    confirmation = getpass.getpass("Confirm token: ")
    if not token or not secrets.compare_digest(token, confirmation):
        raise CredentialError("credential entries did not match")
    with _lifecycle_lock(exclusive=True):
        destination = encrypted_credential_path("github-mcp")
        _encrypt(GITHUB_MCP_CREDENTIAL, token, destination)
        return destination


def systemd_credential(name: str) -> str:
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not directory:
        return ""
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
        return status
