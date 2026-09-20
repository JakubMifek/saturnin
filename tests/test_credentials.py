from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from saturnin.credentials import (
    ATTESTATION_CREDENTIAL,
    CredentialError,
    provision_attestation_key,
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
        staging = Path(command[-2])
        assert staging.read_text(encoding="utf-8") == "private-value"
        assert staging.stat().st_mode & 0o777 == 0o600
        return SimpleNamespace(returncode=0, stdout=b"encrypted-payload\n")

    monkeypatch.setattr("saturnin.credentials.subprocess.run", fake_run)

    destination = provision_attestation_key()

    assert destination.read_text(encoding="utf-8") == "encrypted-payload\n"
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.parent.stat().st_mode & 0o777 == 0o700
    assert "private-value" not in " ".join(calls[0])
    assert not list(destination.parent.glob(f".{ATTESTATION_CREDENTIAL}.input.*"))


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
