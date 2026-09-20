"""Systemd encrypted credential provisioning and runtime access."""

from __future__ import annotations

import getpass
import os
import secrets
import stat
import subprocess
from pathlib import Path

from .jsonlines import PRIVATE_FILE_MODE, atomic_replace_text

ATTESTATION_CREDENTIAL = "saturnin-review-attestation-key"
GITHUB_MCP_CREDENTIAL = "saturnin-github-mcp-token"
KNOWN_CREDENTIALS = {
    "review-attestation": ATTESTATION_CREDENTIAL,
    "github-mcp": GITHUB_MCP_CREDENTIAL,
}
MAX_CREDENTIAL_BYTES = 16 * 1024


class CredentialError(RuntimeError):
    pass


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
    path.chmod(0o700)
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise CredentialError("credential directory is not an owner-controlled directory")
    if metadata.st_mode & 0o077:
        raise CredentialError("credential directory is accessible by group or other users")


def _encrypt(name: str, value: str, destination: Path) -> None:
    if not value or "\x00" in value:
        raise CredentialError("credential value must be non-empty text")
    _secure_directory(destination.parent)
    staging = destination.parent / f".{name}.input.{os.getpid()}"
    descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_FILE_MODE)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        result = subprocess.run(
            [
                "systemd-creds",
                "encrypt",
                "--user",
                f"--name={name}",
                str(staging),
                "-",
            ],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0 or not result.stdout:
            raise CredentialError("systemd-creds could not encrypt the credential")
        try:
            encrypted = result.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CredentialError("systemd-creds returned an invalid encrypted credential") from exc
        atomic_replace_text(destination, encrypted, mode=PRIVATE_FILE_MODE)
    finally:
        try:
            staging.unlink()
        except FileNotFoundError:
            pass


def provision_attestation_key() -> Path:
    destination = encrypted_credential_path("review-attestation")
    _encrypt(ATTESTATION_CREDENTIAL, secrets.token_hex(32), destination)
    return destination


def store_github_mcp_token() -> Path:
    token = getpass.getpass("Dedicated fine-grained GitHub token: ")
    confirmation = getpass.getpass("Confirm token: ")
    if not token or not secrets.compare_digest(token, confirmation):
        raise CredentialError("credential entries did not match")
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


def validate_encrypted_credential(kind: str) -> Path:
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
    if result.returncode != 0 or not result.stdout:
        raise CredentialError(f"encrypted credential cannot be decrypted: {kind}")
    return path
