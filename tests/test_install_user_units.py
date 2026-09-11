from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_install_user_units_escapes_checkout_path(tmp_path: Path) -> None:
    saturnin_home = tmp_path / r"checkout with spaces%&pipe|slash\home"
    shutil.copytree(REPO_ROOT / "systemd", saturnin_home / "systemd")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "id").write_text("#!/bin/sh\nprintf '1000\\n'\n", encoding="utf-8")
    (fake_bin / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    for command in ("id", "systemctl"):
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
    def decode(value: str) -> str:
        value = value.replace("%%", "%")
        return re.sub(
            r"\\x([0-9a-fA-F]{2})",
            lambda match: chr(int(match.group(1), 16)),
            value,
        )

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
        assert decode(working_directory) == str(saturnin_home)
        assert decode(environment) == str(saturnin_home)
