from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADMIN = ROOT / "scripts" / "manage_system_attestation.py"


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
    run(root, "rotate")
    assert (current.parent / "previous.key.cred").read_bytes() == original
    run(root, "rollback")
    assert current.read_bytes() == original
    assert (current.parent / "previous.key.cred").read_bytes() == original_previous
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
