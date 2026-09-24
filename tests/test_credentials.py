from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from saturnin.credentials import (
    ATTESTATION_CREDENTIAL,
    PREVIOUS_ATTESTATION_CREDENTIAL,
    CredentialError,
    attestation_rotation_values,
    complete_attestation_rotation,
    credential_prerequisites,
    credential_status,
    provision_attestation_key,
    revoke_credential,
    rollback_attestation_rotation,
    rotate_attestation_key,
    systemd_credential,
    validate_encrypted_credential,
)


def _write_attestation_credentials(credential_dir: Path) -> tuple[Path, Path]:
    credential_dir.mkdir(parents=True, mode=0o700)
    current = credential_dir / f"{ATTESTATION_CREDENTIAL}.cred"
    previous = credential_dir / f"{PREVIOUS_ATTESTATION_CREDENTIAL}.cred"
    current.write_text("encrypted-current\n", encoding="utf-8")
    previous.write_text("encrypted-previous\n", encoding="utf-8")
    current.chmod(0o600)
    previous.chmod(0o600)
    return current, previous


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
    path, _ = _write_attestation_credentials(credential_dir)
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
    current, _ = _write_attestation_credentials(credential_dir)
    calls: list[tuple[list[str], bytes | None]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        value = kwargs.get("input")
        calls.append((command, value if isinstance(value, bytes) else None))
        if command[1] == "decrypt" and command[-2].endswith(
            f"{ATTESTATION_CREDENTIAL}.cred"
        ):
            return SimpleNamespace(returncode=0, stdout=b"old-master")
        if command[1] == "decrypt":
            return SimpleNamespace(returncode=0, stdout=b"older-master")
        return SimpleNamespace(returncode=0, stdout=b"encrypted-new\n")

    monkeypatch.setattr("saturnin.credentials.subprocess.run", fake_run)
    monkeypatch.setattr("saturnin.credentials.secrets.token_hex", lambda _: "new-master")

    assert rotate_attestation_key(previous_key_in_use=lambda _: False) == current
    assert calls[2][1] == b"old-master"
    assert calls[3][1] == b"new-master"
    assert all("old-master" not in " ".join(command) for command, _ in calls)
    assert credential_status("review-attestation")["rotation"] == "pending-seal"
    assert attestation_rotation_values() == ("old-master", "older-master")

    complete_attestation_rotation()

    assert credential_status("review-attestation")["rotation"] == "ready"


def test_failed_rotation_can_restore_both_encrypted_slots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    current, previous = _write_attestation_credentials(credential_dir)
    original_current = current.read_text(encoding="utf-8")
    original_previous = previous.read_text(encoding="utf-8")
    encryptions = 0

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        nonlocal encryptions
        if command[1] == "decrypt":
            return SimpleNamespace(returncode=0, stdout=b"master")
        encryptions += 1
        if encryptions == 2:
            return SimpleNamespace(returncode=1, stdout=b"")
        return SimpleNamespace(returncode=0, stdout=b"changed-previous\n")

    monkeypatch.setattr("saturnin.credentials.subprocess.run", fake_run)

    with pytest.raises(CredentialError, match="could not encrypt"):
        rotate_attestation_key(previous_key_in_use=lambda _: False)

    assert credential_status("review-attestation")["rotation"] == "pending-seal"
    assert rollback_attestation_rotation() == current
    assert current.read_text(encoding="utf-8") == original_current
    assert previous.read_text(encoding="utf-8") == original_previous
    assert credential_status("review-attestation")["rotation"] == "ready"


def test_rotation_refuses_to_replace_pending_previous_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    _write_attestation_credentials(credential_dir)
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                b"master"
                if command[1] == "decrypt"
                else b"encrypted-new\n"
            ),
        ),
    )
    rotate_attestation_key(previous_key_in_use=lambda _: False)

    with pytest.raises(CredentialError, match="already pending"):
        rotate_attestation_key(previous_key_in_use=lambda _: False)


def test_rotation_refuses_to_discard_key_used_by_review_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    _write_attestation_credentials(credential_dir)
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"master"),
    )

    with pytest.raises(CredentialError, match="still protects review records"):
        rotate_attestation_key(previous_key_in_use=lambda _: True)

    assert credential_status("review-attestation")["rotation"] == "ready"


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


def test_prerequisites_reports_status_without_secret_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "run"
    socket = runtime / "systemd" / "private"
    socket.parent.mkdir(parents=True)
    socket.touch()
    host_key = tmp_path / "credential.secret"
    host_key.write_text("not-read", encoding="utf-8")
    host_key.chmod(0o400)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.setattr("saturnin.credentials.shutil.which", lambda _: "/bin/systemd-creds")
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="systemd 257\n", stderr=""
        ),
    )
    monkeypatch.setattr("saturnin.credentials.HOST_CREDENTIAL_SECRET", host_key)
    real_stat = Path.stat

    def fake_stat(path: Path, *args: object, **kwargs: object) -> os.stat_result:
        metadata = real_stat(path, *args, **kwargs)
        if path == socket:
            values = list(metadata)
            values[0] = stat.S_IFSOCK | 0o600
            return os.stat_result(values)
        if path == host_key:
            values = list(metadata)
            values[4] = 0
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(Path, "stat", fake_stat)

    assert credential_prerequisites() == {
        "systemd_creds_version": 257,
        "user_manager": "available",
        "host_key": "initialized",
    }
