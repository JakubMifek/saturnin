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

    enable_call = next(
        call
        for call in calls.read_text(encoding="utf-8").splitlines()
        if call.startswith("--user enable --now")
    )
    assert "saturnin-mirror.timer" not in enable_call


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
    calls = tmp_path / "systemctl-calls"
    state = tmp_path / "systemctl-state"
    enabled = state / "enabled"
    active = state / "active"
    enabled.mkdir(parents=True)
    active.mkdir()
    (enabled / "saturnin-janitor.timer").touch()
    (active / "saturnin-improve.timer").touch()
    (active / "saturnin-janitor.service").touch()
    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemd-analyze").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> '{calls}'\n"
        f"state='{state}'\n"
        "case \"$2\" in\n"
        "  is-enabled) [ -e \"$state/enabled/$4\" ] || exit 1 ;;\n"
        "  is-active) [ -e \"$state/active/$4\" ] || exit 1 ;;\n"
        "  enable)\n"
        "    if [ \"$3\" = '--now' ]; then\n"
        "      shift 3\n"
        "      for unit in \"$@\"; do touch \"$state/enabled/$unit\" \"$state/active/$unit\"; done\n"
        "      exit 1\n"
        "    fi\n"
        "    touch \"$state/enabled/$3\"\n"
        "    ;;\n"
        "  disable) rm -f \"$state/enabled/$3\" ;;\n"
        "  start) touch \"$state/active/$3\" ;;\n"
        "  stop) rm -f \"$state/active/$3\" ;;\n"
        "esac\n"
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
    linked_target = tmp_path / "linked-janitor.timer"
    linked_target.write_text("previous linked timer\n", encoding="utf-8")
    linked_timer = installed_dir / "saturnin-janitor.timer"
    linked_timer.symlink_to(linked_target)
    masked_timer = installed_dir / "saturnin-improve.timer"
    masked_timer.symlink_to("/dev/null")

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
    installed = {path.name for path in installed_dir.glob("saturnin-*")}
    assert installed == {
        "saturnin-janitor.service",
        "saturnin-janitor.timer",
        "saturnin-improve.timer",
    }
    assert linked_timer.is_symlink()
    assert os.readlink(linked_timer) == str(linked_target)
    assert masked_timer.is_symlink()
    assert os.readlink(masked_timer) == "/dev/null"
    systemctl_calls = calls.read_text(encoding="utf-8").splitlines()
    failed_enable = next(
        index for index, call in enumerate(systemctl_calls) if call.startswith("--user enable --now")
    )
    assert systemctl_calls[failed_enable + 1] == "--user daemon-reload"
    rollback_calls = systemctl_calls[failed_enable + 2 :]
    assert "--user start saturnin-janitor.service" in rollback_calls
    assert "--user disable saturnin-mirror.timer" in rollback_calls
    assert {path.name for path in enabled.iterdir()} == {"saturnin-janitor.timer"}
    assert {path.name for path in active.iterdir()} == {
        "saturnin-improve.timer",
        "saturnin-janitor.service",
    }
