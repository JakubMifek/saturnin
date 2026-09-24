from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from saturnin.credentials import (
    ATTESTATION_CREDENTIAL,
    PREVIOUS_ATTESTATION_CREDENTIAL,
    CredentialError,
    provision_attestation_key,
    revoke_credential,
    rotate_attestation_key,
    systemd_credential,
    validate_encrypted_credential,
)


def test_provision_attestation_encrypts_without_secret_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr("saturnin.credentials.secrets.token_hex", lambda _: "private-value")
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(command)
        assert kwargs["input"] == b"private-value"
        return SimpleNamespace(returncode=0, stdout=b"encrypted-payload\n")

    monkeypatch.setattr("saturnin.credentials.subprocess.run", fake_run)

    destination = provision_attestation_key()

    assert destination.read_text(encoding="utf-8") == "encrypted-payload\n"
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.parent.stat().st_mode & 0o777 == 0o700
    assert "private-value" not in " ".join(calls[0])
    assert all(command[-2:] == ["-", "-"] for command in calls)


def test_systemd_credential_requires_private_owner_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "credentials"
    directory.mkdir()
    credential = directory / ATTESTATION_CREDENTIAL
    credential.write_text("role-master\n", encoding="utf-8")
    credential.chmod(0o640)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(directory))

    with pytest.raises(CredentialError, match="unsafe permissions"):
        systemd_credential(ATTESTATION_CREDENTIAL)

    credential.chmod(0o600)
    assert systemd_credential(ATTESTATION_CREDENTIAL) == "role-master"


def test_validate_encrypted_credential_reports_only_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    credential_dir.mkdir(parents=True, mode=0o700)
    path = credential_dir / f"{ATTESTATION_CREDENTIAL}.cred"
    path.write_text("encrypted\n", encoding="utf-8")
    path.chmod(0o600)
    previous = credential_dir / f"{PREVIOUS_ATTESTATION_CREDENTIAL}.cred"
    previous.write_text("encrypted\n", encoding="utf-8")
    previous.chmod(0o600)
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"secret"),
    )

    assert validate_encrypted_credential("review-attestation") == path


def test_failed_encryption_removes_exact_staging_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=b""),
    )

    with pytest.raises(CredentialError, match="could not encrypt"):
        provision_attestation_key()

    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    assert not list(credential_dir.glob(".*.input.*"))


def test_provision_rejects_symlinked_credential_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    controlled = tmp_path / "controlled"
    controlled.mkdir()
    credential_dir = config / "systemd" / "user" / "saturnin-credentials"
    credential_dir.parent.mkdir(parents=True)
    credential_dir.symlink_to(controlled, target_is_directory=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))

    with pytest.raises(CredentialError, match="owner-controlled directory"):
        provision_attestation_key()


def test_systemd_creds_execution_error_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

    def unavailable(*args: object, **kwargs: object) -> SimpleNamespace:
        raise FileNotFoundError("systemd-creds")

    monkeypatch.setattr("saturnin.credentials.subprocess.run", unavailable)

    with pytest.raises(CredentialError, match="could not encrypt"):
        provision_attestation_key()


def test_rotation_reencrypts_old_key_without_exposing_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    credential_dir.mkdir(parents=True, mode=0o700)
    current = credential_dir / f"{ATTESTATION_CREDENTIAL}.cred"
    current.write_text("encrypted-old\n", encoding="utf-8")
    current.chmod(0o600)
    calls: list[tuple[list[str], bytes | None]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        value = kwargs.get("input")
        calls.append((command, value if isinstance(value, bytes) else None))
        if command[1] == "decrypt":
            return SimpleNamespace(returncode=0, stdout=b"old-master")
        return SimpleNamespace(returncode=0, stdout=b"encrypted-new\n")

    monkeypatch.setattr("saturnin.credentials.subprocess.run", fake_run)
    monkeypatch.setattr("saturnin.credentials.secrets.token_hex", lambda _: "new-master")

    assert rotate_attestation_key() == current
    assert calls[1][1] == b"old-master"
    assert calls[2][1] == b"new-master"
    assert all("old-master" not in " ".join(command) for command, _ in calls)


def test_revoke_attestation_removes_current_and_previous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    credential_dir.mkdir(parents=True, mode=0o700)
    paths = [
        credential_dir / f"{ATTESTATION_CREDENTIAL}.cred",
        credential_dir / f"{PREVIOUS_ATTESTATION_CREDENTIAL}.cred",
    ]
    for path in paths:
        path.write_text("encrypted\n", encoding="utf-8")
        path.chmod(0o600)

    assert revoke_credential("review-attestation") == paths
    assert all(not path.exists() for path in paths)
