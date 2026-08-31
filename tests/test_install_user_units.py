from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_install_user_units_escapes_checkout_path(tmp_path: Path) -> None:
    saturnin_home = tmp_path / r"checkout&pipe|slash\home"
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
    for template in (saturnin_home / "systemd").glob("saturnin-*"):
        installed = installed_dir / template.name
        expected = template.read_text(encoding="utf-8").replace(
            "@SATURNIN_HOME@", str(saturnin_home)
        )
        assert installed.read_text(encoding="utf-8") == expected
