from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_install_user_units_rejects_unsupported_checkout_path(tmp_path: Path) -> None:
    saturnin_home = tmp_path / "checkout with spaces"
    shutil.copytree(REPO_ROOT / "systemd", saturnin_home / "systemd")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "systemd-analyze").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    for command in ("id", "systemctl", "systemd-analyze"):
        (fake_bin / command).chmod(0o755)

    config_home = tmp_path / "config"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "SATURNIN_HOME": str(saturnin_home),
        "XDG_CONFIG_HOME": str(config_home),
    }
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/install_user_units.sh")],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 1
    assert "Use a checkout path containing only [A-Za-z0-9/._-]." in result.stderr


def test_install_user_units_installs_safe_checkout_path(tmp_path: Path) -> None:
    saturnin_home = tmp_path / "checkout-safe_path"
    shutil.copytree(REPO_ROOT / "systemd", saturnin_home / "systemd")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "systemd-analyze").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    for command in ("id", "systemctl", "systemd-analyze"):
        (fake_bin / command).chmod(0o755)

    config_home = tmp_path / "config"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "SATURNIN_HOME": str(saturnin_home),
        "XDG_CONFIG_HOME": str(config_home),
    }
    subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/install_user_units.sh")],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    installed_dir = config_home / "systemd" / "user"
    for installed in installed_dir.glob("saturnin-*.service"):
        text = installed.read_text(encoding="utf-8")
        working_directory = next(
            line.removeprefix("WorkingDirectory=")
            for line in text.splitlines()
            if line.startswith("WorkingDirectory=")
        )
        environment = next(
            line.removeprefix('Environment=SATURNIN_HOME="').removesuffix('"')
            for line in text.splitlines()
            if line.startswith("Environment=SATURNIN_HOME=")
        )
        assert working_directory == str(saturnin_home)
        assert environment == str(saturnin_home)
        assert "EnvironmentFile=-" not in text


def test_install_does_not_enable_unaccepted_mirror_timer(tmp_path: Path) -> None:
    saturnin_home = tmp_path / "checkout"
    shutil.copytree(REPO_ROOT / "systemd", saturnin_home / "systemd")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "systemctl-calls"
    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemd-analyze").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{calls}'\n", encoding="utf-8"
    )
    for command in ("id", "systemctl", "systemd-analyze"):
        (fake_bin / command).chmod(0o755)

    subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/install_user_units.sh")],
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "SATURNIN_HOME": str(saturnin_home),
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
        },
    )

    assert "saturnin-mirror.timer" not in calls.read_text(encoding="utf-8")


def test_install_stops_before_enable_when_verification_fails(tmp_path: Path) -> None:
    saturnin_home = tmp_path / "checkout"
    shutil.copytree(REPO_ROOT / "systemd", saturnin_home / "systemd")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "systemctl-calls"
    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemd-analyze").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{calls}'\n", encoding="utf-8"
    )
    for command in ("id", "systemctl", "systemd-analyze"):
        (fake_bin / command).chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "SATURNIN_HOME": str(saturnin_home),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
    }

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/install_user_units.sh")],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 1
    assert "refusing to enable invalid units" in result.stderr
    assert not calls.exists()
    installed_dir = tmp_path / "config" / "systemd" / "user"
    assert not any(installed_dir.glob("saturnin-*"))


def test_failed_verification_preserves_existing_unit_installation(tmp_path: Path) -> None:
    saturnin_home = tmp_path / "checkout"
    shutil.copytree(REPO_ROOT / "systemd", saturnin_home / "systemd")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemd-analyze").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    for command in ("id", "systemctl", "systemd-analyze"):
        (fake_bin / command).chmod(0o755)
    config_home = tmp_path / "config"
    installed_dir = config_home / "systemd" / "user"
    installed_dir.mkdir(parents=True)
    existing = installed_dir / "saturnin-janitor.service"
    existing.write_text("previous valid unit\n", encoding="utf-8")

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/install_user_units.sh")],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "SATURNIN_HOME": str(saturnin_home),
            "XDG_CONFIG_HOME": str(config_home),
        },
    )

    assert result.returncode == 1
    assert existing.read_text(encoding="utf-8") == "previous valid unit\n"


def test_failed_enable_rolls_back_replaced_units(tmp_path: Path) -> None:
    saturnin_home = tmp_path / "checkout"
    shutil.copytree(REPO_ROOT / "systemd", saturnin_home / "systemd")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemd-analyze").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = '--user' ] && [ \"$2\" = 'enable' ]; then exit 1; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    for command in ("id", "systemctl", "systemd-analyze"):
        (fake_bin / command).chmod(0o755)
    config_home = tmp_path / "config"
    installed_dir = config_home / "systemd" / "user"
    installed_dir.mkdir(parents=True)
    existing = installed_dir / "saturnin-janitor.service"
    existing.write_text("previous valid unit\n", encoding="utf-8")

    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts/install_user_units.sh")],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "SATURNIN_HOME": str(saturnin_home),
            "XDG_CONFIG_HOME": str(config_home),
        },
    )

    assert result.returncode == 1
    assert existing.read_text(encoding="utf-8") == "previous valid unit\n"
