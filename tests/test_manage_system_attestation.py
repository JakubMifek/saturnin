from __future__ import annotations

import os
import subprocess
import hashlib
import importlib.util
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ADMIN = ROOT / "scripts" / "manage_system_attestation.py"
SPEC = importlib.util.spec_from_file_location("manage_system_attestation", ADMIN)
assert SPEC and SPEC.loader
admin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = admin
SPEC.loader.exec_module(admin)


def run(root: Path, action: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(ADMIN), action, "--root", str(root)],
        text=True, capture_output=True, check=check,
    )


def test_fake_root_transaction_install_status_rotate_rollback_uninstall(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    run(root, "install")
    run(root, "status")
    assert (root / "usr/sbin/saturnin-attestation-admin").stat().st_mode & 0o777 == 0o755
    current = root / "etc/saturnin-attestation/current.key.cred"
    original = current.read_bytes()
    original_previous = (current.parent / "previous.key.cred").read_bytes()
    codec = admin.FakeRunner()
    original_plain = codec.decrypt(original, "current.key")
    original_previous_plain = codec.decrypt(original_previous, "previous.key")
    run(root, "rotate")
    assert codec.decrypt(
        (current.parent / "previous.key.cred").read_bytes(), "previous.key"
    ) == original_plain
    run(root, "rollback")
    assert codec.decrypt(current.read_bytes(), "current.key") == original_plain
    assert codec.decrypt(
        (current.parent / "previous.key.cred").read_bytes(), "previous.key"
    ) == original_previous_plain
    run(root, "uninstall")
    assert not (root / "usr/lib/saturnin-attestation/system_attestation.py").exists()
    assert not (root / "usr/sbin/saturnin-attestation-admin").exists()
    assert current.exists()


def test_installer_rejects_target_alias_and_cleans_transaction(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "usr").symlink_to(tmp_path)
    result = run(root, "install", check=False)
    assert result.returncode == 1
    assert "unsafe target parent" in result.stderr
    assert not list(root.glob(".saturnin-attestation-stage-*"))


def test_installer_rejects_hardlinked_existing_target(tmp_path: Path) -> None:
    root = tmp_path / "root"
    target = root / "usr/lib/saturnin-attestation/system_attestation.py"
    target.parent.mkdir(parents=True)
    target.write_text("old", encoding="utf-8")
    os.link(target, root / "alias")
    result = run(root, "install", check=False)
    assert result.returncode == 1
    assert "unsafe target" in result.stderr


def test_transaction_failure_restores_replaced_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "root"
    runtime = root / "usr/lib/saturnin-attestation/system_attestation.py"
    config = root / "etc/saturnin-attestation/config.json"
    runtime.parent.mkdir(parents=True)
    config.parent.mkdir(parents=True)
    runtime.write_text("old runtime", encoding="utf-8")
    config.write_text("old config", encoding="utf-8")
    (root / "usr/lib/systemd").symlink_to(tmp_path)

    result = run(root, "install", check=False)

    assert result.returncode == 1
    assert runtime.read_text(encoding="utf-8") == "old runtime"
    assert config.read_text(encoding="utf-8") == "old config"
    assert not list(root.glob(".saturnin-attestation-stage-*"))


def test_admin_interface_has_fixed_action_grammar(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    result = subprocess.run(
        [str(ADMIN), "install", "--root", str(root), "--unit", "evil.service"],
        text=True, capture_output=True,
    )
    assert result.returncode == 2


def test_concurrent_rotations_are_serialized(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    run(root, "install")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(root, "rotate"), range(2)))
    assert all(result.returncode == 0 for result in results)
    codec = admin.FakeRunner()
    current = root / "etc/saturnin-attestation/current.key.cred"
    previous = current.with_name("previous.key.cred")
    assert codec.decrypt(current.read_bytes(), "current.key") != codec.decrypt(
        previous.read_bytes(), "previous.key"
    )


def test_rotation_health_failure_restores_both_generations(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    admin.install(root, True)
    current, previous = admin._credential_paths(root)
    before = current.read_bytes(), previous.read_bytes()

    class FailingHealth(admin.FakeRunner):
        def command(self, argv):
            if "is-active" in argv:
                raise subprocess.CalledProcessError(1, argv)

    with pytest.raises(subprocess.CalledProcessError):
        admin.rotate(root, False, FailingHealth())
    assert (current.read_bytes(), previous.read_bytes()) == before


def test_rollback_health_failure_restores_all_generations(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    codec = admin.FakeRunner()
    admin.install(root, True, codec)
    admin.rotate(root, True, codec)
    current, previous = admin._credential_paths(root)
    rollback = current.with_name("rollback.key.cred")
    before = current.read_bytes(), previous.read_bytes(), rollback.read_bytes()

    class FailingHealth(admin.FakeRunner):
        def command(self, argv):
            if "is-active" in argv:
                raise subprocess.CalledProcessError(1, argv)

    with pytest.raises(subprocess.CalledProcessError):
        admin.rollback(root, False, FailingHealth())
    assert (current.read_bytes(), previous.read_bytes(), rollback.read_bytes()) == before


def test_status_rejects_credential_target_alias(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    admin.install(root, True)
    current, _previous = admin._credential_paths(root)
    ciphertext = current.read_bytes()
    current.unlink()
    alias = root / "alias.cred"
    alias.write_bytes(ciphertext)
    alias.chmod(0o600)
    current.symlink_to(alias)
    with pytest.raises(admin.InstallError, match="unsafe target"):
        admin.status(root)


def test_authorized_legacy_migration_reencrypts_reviewed_plaintext(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    source = root / admin.LEGACY_ROOT.relative_to("/")
    source.mkdir(parents=True, mode=0o700)
    for parent in [source, *source.parents[:5]]:
        if parent != root:
            parent.chmod(0o700)
    current_plain = b"legacy-current-" + b"c" * 40
    previous_plain = b"legacy-previous-" + b"p" * 40
    legacy = (
        ("current.cred", "legacy-current", hashlib.sha256(current_plain).hexdigest(),
         "current.key"),
        ("previous.cred", "legacy-previous",
         hashlib.sha256(previous_plain).hexdigest(), "previous.key"),
    )
    monkeypatch.setattr(admin, "LEGACY", legacy)
    codec = admin.FakeRunner()
    for (filename, name, _digest, _target), plaintext in zip(
        legacy, (current_plain, previous_plain)
    ):
        path = source / filename
        path.write_bytes(codec.encrypt(plaintext, name))
        path.chmod(0o600)

    admin.install(root, True, codec)

    current, previous = admin._credential_paths(root)
    assert codec.decrypt(current.read_bytes(), "current.key") == current_plain
    assert codec.decrypt(previous.read_bytes(), "previous.key") == previous_plain


def test_source_descriptor_rejects_links_and_mutation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"reviewed")
    source.chmod(0o600)
    symlink = tmp_path / "symlink"
    symlink.symlink_to(source)
    with pytest.raises(OSError):
        admin._open_source(symlink, os.getuid())
    hardlink = tmp_path / "hardlink"
    os.link(source, hardlink)
    with pytest.raises(admin.InstallError, match="unsafe source"):
        admin._open_source(source, os.getuid())
    hardlink.unlink()
    opened = admin._open_source(source, os.getuid())
    source.write_bytes(b"mutated")
    try:
        with pytest.raises(admin.InstallError, match="changed"):
            admin._revalidate(opened)
    finally:
        opened.close()


def test_system_units_sysusers_and_tmpfiles_are_consistent() -> None:
    unit_root = ROOT / "systemd/system"
    service = (unit_root / "saturnin-attestation.service").read_text()
    socket_unit = (unit_root / "saturnin-attestation.socket").read_text()
    sysusers = (unit_root / "saturnin-attestation.sysusers").read_text()
    tmpfiles = (unit_root / "saturnin-attestation.tmpfiles").read_text()
    assert "User=saturnin-signer" in service
    assert "Group=saturnin-signer" in service
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in service
    assert "SocketBindDeny=any" in service
    assert "ListenStream=/run/saturnin-attestation/sign.sock" in socket_unit
    assert "SocketUser=saturnin-signer" in socket_unit
    assert "SocketGroup=saturnin" in socket_unit
    assert "g saturnin - -" in sysusers
    assert "m jakubmifek saturnin" in sysusers
    assert "/usr/sbin/nologin" in sysusers
    assert "d /run/saturnin-attestation 0750 saturnin-signer saturnin -" in tmpfiles
