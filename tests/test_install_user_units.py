from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _filesystem_topology(root: Path) -> list[tuple[str, str, str | bytes]]:
    entries: list[tuple[str, str, str | bytes]] = []
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            entries.append(("symlink", relative, os.readlink(path)))
        elif path.is_dir():
            entries.append(("directory", relative, ""))
        else:
            entries.append(("file", relative, path.read_bytes()))
    return entries


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
    for unit in (
        "saturnin-improve.service",
        "saturnin-resume.service",
        "saturnin-discovery.service",
    ):
        text = (installed_dir / unit).read_text(encoding="utf-8")
        assert "PrivateMounts=yes" in text
        assert "LoadCredentialEncrypted=" not in text


def test_install_user_units_rejects_incomplete_attestation_pair_before_replacement(
    tmp_path: Path,
) -> None:
    saturnin_home = tmp_path / "checkout"
    shutil.copytree(REPO_ROOT / "systemd", saturnin_home / "systemd")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "systemd-analyze").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    for command in ("id", "systemctl", "systemd-analyze"):
        (fake_bin / command).chmod(0o755)
    config_home = tmp_path / "config"
    unit_dir = config_home / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    previous = unit_dir / "saturnin-improve.service"
    previous.write_text("existing installation\n", encoding="utf-8")
    credential_dir = unit_dir / "saturnin-credentials"
    credential_dir.mkdir(mode=0o700)
    (credential_dir / "saturnin-review-attestation-key.cred").write_text(
        "ciphertext\n", encoding="utf-8"
    )

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
    assert "pair is incomplete or unsafe" in result.stderr
    assert previous.read_text(encoding="utf-8") == "existing installation\n"


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
    config_home = tmp_path / "config"
    installed_dir = config_home / "systemd" / "user"
    installed_dir.mkdir(parents=True)
    state = tmp_path / "systemctl-state"
    active = state / "active"
    wants = installed_dir / "default.target.wants"
    active.mkdir(parents=True)
    wants.mkdir()
    (active / "saturnin-janitor.service").touch()
    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemd-analyze").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> '{calls}'\n"
        f"state='{state}'\n"
        f"unit_dir='{installed_dir}'\n"
        "case \"$2\" in\n"
        "  is-active) [ -e \"$state/active/$4\" ] || exit 1 ;;\n"
        "  enable)\n"
        "    if [ \"$3\" = '--now' ]; then\n"
        "      shift 3\n"
        "      mkdir -p \"$unit_dir/timers.target.wants\"\n"
        "      for unit in \"$@\"; do\n"
        "        touch \"$state/active/$unit\"\n"
        "        ln -sf \"../$unit\" \"$unit_dir/timers.target.wants/$unit\"\n"
        "      done\n"
        "      exit 1\n"
        "    fi\n"
        "    ln -sf \"../$3\" \"$unit_dir/default.target.wants/$3\"\n"
        "    ;;\n"
        "  start) touch \"$state/active/$3\" ;;\n"
        "  stop) rm -f \"$state/active/$3\" ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    for command in ("id", "systemctl", "systemd-analyze"):
        (fake_bin / command).chmod(0o755)
    existing = installed_dir / "saturnin-janitor.service"
    existing.write_text("previous valid unit\n", encoding="utf-8")
    linked_target = tmp_path / "linked-janitor.timer"
    linked_target.write_text("previous linked timer\n", encoding="utf-8")
    linked_timer = installed_dir / "saturnin-janitor.timer"
    linked_timer.symlink_to(linked_target)
    masked_timer = installed_dir / "saturnin-improve.timer"
    masked_timer.symlink_to("/dev/null")
    dangling_timer = installed_dir / "saturnin-poller.timer"
    dangling_timer.symlink_to(tmp_path / "missing-poller.timer")
    enabled_timer = installed_dir / "saturnin-resume.timer"
    enabled_timer.write_text("previous enabled timer\n", encoding="utf-8")
    (wants / "saturnin-resume.timer").symlink_to("../saturnin-resume.timer")
    static_wants = installed_dir / "custom.target.wants"
    static_wants.mkdir()
    (static_wants / "saturnin-janitor.service").symlink_to("../saturnin-janitor.service")
    previous_topology = _filesystem_topology(installed_dir)

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
    assert _filesystem_topology(installed_dir) == previous_topology
    assert existing.read_text(encoding="utf-8") == "previous valid unit\n"
    installed = {path.name for path in installed_dir.glob("saturnin-*")}
    assert installed == {
        "saturnin-janitor.service",
        "saturnin-janitor.timer",
        "saturnin-improve.timer",
        "saturnin-poller.timer",
        "saturnin-resume.timer",
    }
    assert linked_timer.is_symlink()
    assert os.readlink(linked_timer) == str(linked_target)
    assert masked_timer.is_symlink()
    assert os.readlink(masked_timer) == "/dev/null"
    assert dangling_timer.is_symlink()
    assert os.readlink(dangling_timer) == str(tmp_path / "missing-poller.timer")
    assert enabled_timer.read_text(encoding="utf-8") == "previous enabled timer\n"
    systemctl_calls = calls.read_text(encoding="utf-8").splitlines()
    failed_enable = next(
        index for index, call in enumerate(systemctl_calls) if call.startswith("--user enable --now")
    )
    rollback_calls = systemctl_calls[failed_enable + 1 :]
    daemon_reload = rollback_calls.index("--user daemon-reload")
    assert all(
        call.startswith("--user stop ")
        for call in rollback_calls[:daemon_reload]
    )
    assert "--user stop saturnin-janitor.service" not in rollback_calls
    assert not any(call.startswith("--user disable ") for call in rollback_calls)
    assert not any(call.startswith("--user start ") for call in rollback_calls)
    assert {path.name for path in active.iterdir()} == {"saturnin-janitor.service"}
    assert {path.name for path in wants.iterdir()} == {"saturnin-resume.timer"}
    assert {path.name for path in static_wants.iterdir()} == {"saturnin-janitor.service"}
    assert not (installed_dir / "timers.target.wants").exists()


def test_early_install_failure_preserves_all_later_unit_entries(tmp_path: Path) -> None:
    saturnin_home = tmp_path / "checkout"
    shutil.copytree(REPO_ROOT / "systemd", saturnin_home / "systemd")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    config_home = tmp_path / "config"
    installed_dir = config_home / "systemd" / "user"
    installed_dir.mkdir(parents=True)
    install_count = tmp_path / "install-count"

    linked_target = tmp_path / "linked-resume.timer"
    linked_target.write_text("linked\n", encoding="utf-8")
    entries = {
        "saturnin-resume.timer": str(linked_target),
        "saturnin-poller.timer": "/dev/null",
        "saturnin-mirror.timer": str(tmp_path / "missing-mirror.timer"),
    }
    for name, target in entries.items():
        (installed_dir / name).symlink_to(target)
    previous = installed_dir / "saturnin-discovery.service"
    previous.write_text("previous discovery service\n", encoding="utf-8")
    previous_topology = _filesystem_topology(installed_dir)

    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemd-analyze").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "install").write_text(
        "#!/bin/sh\n"
        f"count_file='{install_count}'\n"
        "count=0\n"
        "[ ! -e \"$count_file\" ] || count=$(cat \"$count_file\")\n"
        "count=$((count + 1))\n"
        "printf '%s\\n' \"$count\" > \"$count_file\"\n"
        "[ \"$count\" -ne 2 ] || exit 1\n"
        "exec /usr/bin/install \"$@\"\n",
        encoding="utf-8",
    )
    (fake_bin / "systemctl").write_text(
        "#!/bin/sh\n"
        f"unit_dir='{installed_dir}'\n"
        "case \"$2\" in\n"
        "  is-active) exit 1 ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    for command in ("id", "install", "systemctl", "systemd-analyze"):
        (fake_bin / command).chmod(0o755)

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
    assert install_count.read_text(encoding="utf-8").strip() == "2"
    assert _filesystem_topology(installed_dir) == previous_topology
    assert previous.read_text(encoding="utf-8") == "previous discovery service\n"
    for name, target in entries.items():
        entry = installed_dir / name
        assert entry.is_symlink()
        assert os.readlink(entry) == target
