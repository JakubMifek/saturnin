from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from saturnin.worker_callbacks import (
    WorkerCallbackError,
    _open_governed_executable,
    _open_governed_runtime,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _topology(root: Path) -> list[tuple[str, str, str | bytes]]:
    result: list[tuple[str, str, str | bytes]] = []
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            result.append(("link", relative, os.readlink(path)))
        elif path.is_dir():
            result.append(("dir", relative, ""))
        else:
            result.append(("file", relative, path.read_bytes()))
    return result


@pytest.fixture()
def signer_install(tmp_path: Path) -> tuple[Path, dict[str, str], Path, Path]:
    checkout = tmp_path / "checkout"
    (checkout / "scripts" / "lib").mkdir(parents=True)
    (checkout / "systemd").mkdir()
    (checkout / ".venv" / "bin").mkdir(parents=True)
    shutil.copytree(REPO_ROOT / "src" / "saturnin", checkout / "src" / "saturnin")
    yaml_destination = (
        checkout
        / ".venv"
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
        / "yaml"
    )
    shutil.copytree(Path(yaml.__file__).parent, yaml_destination)
    for directory in (
        checkout / "src" / "saturnin",
        yaml_destination,
    ):
        directory.chmod(0o755)
        for path in directory.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
            elif path.suffix == ".py":
                path.chmod(0o644)
    shutil.copy2(
        REPO_ROOT / "scripts" / "install_attestation_unit.sh",
        checkout / "scripts" / "install_attestation_unit.sh",
    )
    shutil.copy2(
        REPO_ROOT / "scripts" / "lib" / "user_unit_install.sh",
        checkout / "scripts" / "lib" / "user_unit_install.sh",
    )
    (checkout / "scripts" / "lib" / "user_unit_install.sh").chmod(0o755)
    shutil.copy2(
        REPO_ROOT / "systemd" / "saturnin-attestation.service",
        checkout / "systemd" / "saturnin-attestation.service",
    )
    (checkout / "systemd" / "saturnin-attestation.service").chmod(0o644)
    runtime = checkout / ".venv" / "bin" / "saturnin"
    runtime.write_text(
        "#!/bin/sh\nprintf '%s\\n' 'rotation=ready; signer=ready'\n",
        encoding="utf-8",
    )
    runtime.chmod(0o755)

    home = tmp_path / "home"
    unit_dir = home / ".config" / "systemd" / "user"
    credentials = unit_dir / "saturnin-credentials"
    credentials.mkdir(parents=True, mode=0o700)
    unit_dir.chmod(0o700)
    for name in (
        "saturnin-review-attestation-key.cred",
        "saturnin-review-attestation-previous-key.cred",
    ):
        credential = credentials / name
        credential.write_text("TOP-SECRET-CIPHERTEXT\n", encoding="utf-8")
        credential.chmod(0o600)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_stat = fake_bin / "stat"
    fake_stat.write_text("#!/bin/sh\nexec /usr/bin/stat \"$@\"\n", encoding="utf-8")
    fake_stat.chmod(0o755)
    fake_cp = fake_bin / "cp"
    fake_cp.write_text(
        "#!/bin/sh\n"
        "if [ -n \"${MUTATE_RUNTIME_IN_PLACE:-}\" ] "
        "&& [ \"${2##*/}\" = saturnin ]; then\n"
        "  printf '%s\\n' '#!/bin/sh' "
        "'/usr/bin/cat \"$HOME/.config/systemd/user/saturnin-credentials/"
        "saturnin-review-attestation-key.cred\" > \"$HOME/credential-leak\"' "
        "> \"${RUNTIME_TO_REPLACE}\"\n"
        "  chmod 0755 \"${RUNTIME_TO_REPLACE}\"\n"
        "fi\n"
        "if [ -n \"${MUTATE_TEMPLATE_IN_PLACE:-}\" ] "
        "&& [ \"${2##*/}\" = saturnin-attestation.service.template ]; then\n"
        "  printf '%s\\n' '[Unit]' 'Description=mutated' "
        "> \"${TEMPLATE_TO_REPLACE}\"\n"
        "  chmod 0644 \"${TEMPLATE_TO_REPLACE}\"\n"
        "fi\n"
        "exec /usr/bin/cp \"$@\"\n",
        encoding="utf-8",
    )
    fake_cp.chmod(0o755)
    fake_python = fake_bin / "python3"
    fake_python.write_text(
        "#!/bin/sh\n"
        "if [ \"${1:-}\" = -P ] && [ \"${2:-}\" = -m ] "
        "&& [ \"${3:-}\" = saturnin ] && [ \"${4:-}\" = credential ]; then\n"
        "  if [ -n \"${RACE_RUNTIME_ARCHIVE:-}\" ]; then\n"
        "    archive=$(/usr/bin/find \"$HOME/.config/systemd/user\" "
        "-name saturnin-attestation-runtime.pyz -type f -print -quit)\n"
        "    printf malicious > \"$archive.replacement\"\n"
        "    chmod 0400 \"$archive.replacement\"\n"
        "    mv -f \"$archive.replacement\" \"$archive\"\n"
        "  fi\n"
        "  printf '%s\\n' 'rotation=ready; signer=ready'\n"
        "  exit 0\n"
        "fi\n"
        "exec /usr/bin/python3 \"$@\"\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    calls = tmp_path / "systemctl-calls"
    state = tmp_path / "state"
    state.mkdir()
    systemctl = fake_bin / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\n"
        f"calls='{calls}'\n"
        f"state='{state}'\n"
        f"unit_dir='{unit_dir}'\n"
        "printf '%s\\n' \"$*\" >> \"$calls\"\n"
        "sub=$2\n"
        "unit=${5:-${4:-${3:-}}}\n"
        "case \"$sub\" in\n"
        "  is-active) [ -e \"$state/active\" ] ;;\n"
        "  daemon-reload)\n"
        "    if [ -n \"${REPLACE_WANTS_DIR:-}\" ] "
        "&& [ ! -e \"$state/wants-dir-replaced\" ]; then\n"
        "      touch \"$state/wants-dir-replaced\"\n"
        "      mv \"$unit_dir/default.target.wants\" "
        "\"$unit_dir/default.target.wants.replaced\"\n"
        "      ln -s \"${REPLACE_WANTS_DIR}\" "
        "\"$unit_dir/default.target.wants\"\n"
        "    fi\n"
        "    if [ -n \"${REPLACE_UNIT_DIR:-}\" ] "
        "&& [ ! -e \"$state/unit-dir-replaced\" ]; then\n"
        "      touch \"$state/unit-dir-replaced\"\n"
        "      mv \"$unit_dir\" \"$unit_dir.replaced\"\n"
        "      mkdir -m 0700 \"$unit_dir\"\n"
        "    fi\n"
        "    if [ -n \"${REPLACE_AFTER_MOVE:-}\" ] "
        "&& [ ! -e \"$state/replaced\" ]; then\n"
        "      touch \"$state/replaced\"\n"
        "      printf '%s\\n' '[Unit]' 'Description=replaced' > "
        "\"$unit_dir/saturnin-attestation.service\"\n"
        "      chmod 0644 \"$unit_dir/saturnin-attestation.service\"\n"
        "    fi\n"
        "    if [ -n \"${HOLD_DAEMON:-}\" ]; then\n"
        "      touch \"${HOLD_ENTERED}\"\n"
        "      while [ -e \"${HOLD_DAEMON}\" ]; do /usr/bin/sleep 0.01; done\n"
        "    fi\n"
        "    [ \"${FAIL_ON:-}\" != daemon-reload ]\n"
        "    ;;\n"
        "  cat)\n"
        "    if [ -n \"${MANAGER_MISMATCH:-}\" ]; then\n"
        "      printf '%s\\n' '# unexpected' '[Unit]' 'Description=mismatch'\n"
        "    else\n"
        "      printf '# %s\\n' \"$unit_dir/saturnin-attestation.service\"\n"
        "      /usr/bin/cat \"$unit_dir/saturnin-attestation.service\"\n"
        "    fi\n"
        "    ;;\n"
        "  enable)\n"
        "    if [ -n \"${RACE_ROLLBACK:-}\" ]; then\n"
        "      backup=$(/usr/bin/find \"$unit_dir\" "
        "-path '*/backup/unit' -type f -print -quit)\n"
        "      printf '%s\\n' '[Unit]' 'Description=raced rollback' > \"$backup\"\n"
        "      chmod 0644 \"$backup\"\n"
        "      rm -f \"$state/active\"\n"
        "      exit 1\n"
        "    fi\n"
        "    mkdir -p \"$unit_dir/default.target.wants\"\n"
        "    ln -sf \"../saturnin-attestation.service\" "
        "\"$unit_dir/default.target.wants/saturnin-attestation.service\"\n"
        "    [ \"${FAIL_ON:-}\" != enable ]\n"
        "    ;;\n"
        "  start)\n"
        "    if [ -n \"${RACE_ROLLBACK:-}\" ]; then\n"
        "      backup=$(/usr/bin/find \"$unit_dir\" "
        "-path '*/backup/unit' -type f -print -quit)\n"
        "      printf '%s\\n' '[Unit]' 'Description=raced rollback' > \"$backup\"\n"
        "      chmod 0644 \"$backup\"\n"
        "      rm -f \"$state/active\"\n"
        "      exit 1\n"
        "    fi\n"
        "    touch \"$state/active\"\n"
        "    [ \"${FAIL_ON:-}\" != start ]\n"
        "    ;;\n"
        "  stop) rm -f \"$state/active\" ;;\n"
        "  status) printf '%s\\n' 'signer status only' ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    systemctl.chmod(0o755)
    analyzer = fake_bin / "systemd-analyze"
    analyzer.write_text(
        "#!/bin/sh\n"
        "if [ -n \"${RACE_SOURCES:-}\" ]; then\n"
        "  printf '%s\\n' '#!/bin/sh' 'touch \"$HOME/runtime-reopened\"' "
        "> \"${RUNTIME_TO_REPLACE}\"\n"
        "  chmod 0755 \"${RUNTIME_TO_REPLACE}\"\n"
        "  printf '%s\\n' '[Unit]' 'Description=replaced' "
        "> \"${TEMPLATE_TO_REPLACE}\"\n"
        "  chmod 0644 \"${TEMPLATE_TO_REPLACE}\"\n"
        "  if [ -n \"${SOURCE_TO_REPLACE:-}\" ]; then\n"
        "    printf '%s\\n' 'raise RuntimeError(\"reopened source\")' "
        "> \"${SOURCE_TO_REPLACE}\"\n"
        "    chmod 0644 \"${SOURCE_TO_REPLACE}\"\n"
        "  fi\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    analyzer.chmod(0o755)
    installer = checkout / "scripts" / "install_attestation_unit.sh"
    installer.write_text(
        installer.read_text(encoding="utf-8")
        .replace("readonly STAT=/usr/bin/stat", f"readonly STAT={fake_stat}")
        .replace("readonly CP=/usr/bin/cp", f"readonly CP={fake_cp}")
        .replace(
            'PYTHON="$("$REALPATH" /usr/bin/python3)"',
            f"PYTHON={fake_python}",
        )
        .replace(
            "readonly SYSTEMCTL=/usr/bin/systemctl",
            f"readonly SYSTEMCTL={systemctl}",
        )
        .replace(
            "readonly SYSTEMD_ANALYZE=/usr/bin/systemd-analyze",
            f"readonly SYSTEMD_ANALYZE={analyzer}",
        )
        .replace(
            '[[ "$("$STAT" -c %u "$tool")" -ne 0 ]]',
            '[[ "$("$STAT" -c %u "$tool")" -ne 0 '
            '&& "$("$STAT" -c %u "$tool")" -ne "$CURRENT_UID" ]]',
        ),
        encoding="utf-8",
    )
    installer.chmod(0o755)
    env = {
        **os.environ,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "SATURNIN_HOME": str(checkout),
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
    }
    return checkout, env, unit_dir, calls


def _authorized_fds(
    checkout: Path, action: str
) -> tuple[int, int | None]:
    executable = checkout / "scripts" / "install_attestation_unit.sh"
    operation = {
        "executable": "scripts/install_attestation_unit.sh",
        "sha256": __import__("hashlib").sha256(executable.read_bytes()).hexdigest(),
        "runtime_sources": [],
    }
    for source, archive in (
        ("src/saturnin", "saturnin"),
        (".venv/lib/{python_version}/site-packages/yaml", "yaml"),
    ):
        package = checkout / source.replace(
            "{python_version}",
            f"python{sys.version_info.major}.{sys.version_info.minor}",
        )
        operation["runtime_sources"].append(
            {
                "source": source,
                "archive": archive,
                "files": [
                    str(path.relative_to(package))
                    for path in sorted(package.rglob("*.py"))
                ],
            }
        )
    config = SimpleNamespace(
        data_root=checkout,
        server_scope={"operations": {"signer_user_unit": operation}},
    )
    parts = [str(executable), action]
    executable_fd = _open_governed_executable(config, parts)
    assert executable_fd is not None
    runtime_fd = _open_governed_runtime(config, parts) if action == "install" else None
    return executable_fd, runtime_fd


def _run(
    setup: tuple[Path, dict[str, str], Path, Path],
    action: str,
    **environment: str,
) -> subprocess.CompletedProcess[str]:
    checkout, env, _, _ = setup
    executable_fd = None
    runtime_fd = None
    try:
        executable_fd, runtime_fd = _authorized_fds(checkout, action)
        command_env = {
            **env,
            **environment,
            "SATURNIN_GOVERNED_EXECUTION": "sealed-memfd",
        }
        pass_fds = (executable_fd,)
        if runtime_fd is not None:
            command_env["SATURNIN_GOVERNED_RUNTIME_FD"] = str(runtime_fd)
            pass_fds = (executable_fd, runtime_fd)
        return subprocess.run(
            [f"/proc/self/fd/{executable_fd}", action],
            check=False,
            capture_output=True,
            text=True,
            env=command_env,
            pass_fds=pass_fds,
        )
    except WorkerCallbackError as exc:
        return subprocess.CompletedProcess([str(checkout), action], 1, "", str(exc))
    finally:
        if executable_fd is not None:
            os.close(executable_fd)
        if runtime_fd is not None:
            os.close(runtime_fd)


def test_install_is_selective_idempotent_and_does_not_disclose_credentials(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, calls = signer_install
    unrelated = unit_dir / "saturnin-improve.timer"
    unrelated.write_text("unchanged\n", encoding="utf-8")

    first = _run(signer_install, "install")
    second = _run(signer_install, "install")

    assert first.returncode == second.returncode == 0
    assert unrelated.read_text(encoding="utf-8") == "unchanged\n"
    assert (unit_dir / "saturnin-attestation.service").is_file()
    assert "TOP-SECRET-CIPHERTEXT" not in first.stdout + first.stderr
    assert all(
        "saturnin-improve" not in call
        for call in calls.read_text(encoding="utf-8").splitlines()
    )


def test_install_rejects_execution_without_governed_runtime_descriptor(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    checkout, env, unit_dir, calls = signer_install

    result = subprocess.run(
        [str(checkout / "scripts" / "install_attestation_unit.sh"), "install"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode != 0
    assert "governed sealed runtime descriptor" in result.stderr
    assert not (unit_dir / "saturnin-attestation.service").exists()
    assert not calls.exists()


def test_start_failure_restores_preexisting_entries(
    signer_install: tuple[Path, dict[str, str], Path, Path]
) -> None:
    _, _, unit_dir, _ = signer_install
    installed = unit_dir / "saturnin-attestation.service"
    installed.write_text("old unit\n", encoding="utf-8")
    wants_dir = unit_dir / "default.target.wants"
    wants_dir.mkdir()
    old_target = unit_dir / "old-attestation.service"
    old_target.write_text("old target\n", encoding="utf-8")
    wants = wants_dir / "saturnin-attestation.service"
    wants.symlink_to("../old-attestation.service")
    before = _topology(unit_dir)

    result = _run(signer_install, "install", FAIL_ON="start")

    assert result.returncode != 0
    assert _topology(unit_dir) == before


def test_replaced_wants_directory_cannot_escape_unit_tree(
    signer_install: tuple[Path, dict[str, str], Path, Path],
    tmp_path: Path,
) -> None:
    _, _, unit_dir, calls = signer_install
    wants_dir = unit_dir / "default.target.wants"
    wants_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "saturnin-attestation.service"
    victim.write_text("unrelated\n", encoding="utf-8")

    result = _run(
        signer_install,
        "install",
        REPLACE_WANTS_DIR=str(outside),
    )

    assert result.returncode != 0
    assert victim.read_text(encoding="utf-8") == "unrelated\n"
    assert "start saturnin-attestation.service" not in calls.read_text(
        encoding="utf-8"
    )


def test_symlinked_wants_directory_blocks_uninstall_without_escape(
    signer_install: tuple[Path, dict[str, str], Path, Path],
    tmp_path: Path,
) -> None:
    _, _, unit_dir, calls = signer_install
    installed = unit_dir / "saturnin-attestation.service"
    installed.write_text("old unit\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "saturnin-attestation.service"
    victim.write_text("unrelated\n", encoding="utf-8")
    (unit_dir / "default.target.wants").symlink_to(outside, target_is_directory=True)

    result = _run(signer_install, "uninstall")

    assert result.returncode != 0
    assert installed.read_text(encoding="utf-8") == "old unit\n"
    assert victim.read_text(encoding="utf-8") == "unrelated\n"
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "--user is-active --quiet saturnin-attestation.service"
    ]


def test_failed_initial_reload_never_changes_existing_installation(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, _ = signer_install
    installed = unit_dir / "saturnin-attestation.service"
    installed.write_text("old unit\n", encoding="utf-8")
    before = _topology(unit_dir)

    result = _run(signer_install, "install", FAIL_ON="daemon-reload")

    assert result.returncode != 0
    assert _topology(unit_dir) == before


def test_post_move_replacement_is_detected_and_rolled_back(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, _ = signer_install
    installed = unit_dir / "saturnin-attestation.service"
    installed.write_text("old unit\n", encoding="utf-8")
    before = _topology(unit_dir)

    result = _run(signer_install, "install", REPLACE_AFTER_MOVE="1")

    assert result.returncode != 0
    assert _topology(unit_dir) == before


def test_manager_loaded_mismatch_is_detected_and_rolled_back(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, _ = signer_install
    installed = unit_dir / "saturnin-attestation.service"
    installed.write_text("old unit\n", encoding="utf-8")
    before = _topology(unit_dir)

    result = _run(signer_install, "install", MANAGER_MISMATCH="1")

    assert result.returncode != 0
    assert _topology(unit_dir) == before


def test_replaced_unit_directory_fails_closed_without_pathname_rollback(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, calls = signer_install
    installed = unit_dir / "saturnin-attestation.service"
    installed.write_text("old unit\n", encoding="utf-8")

    result = _run(signer_install, "install", REPLACE_UNIT_DIR="1")

    assert result.returncode != 0
    assert "start saturnin-attestation.service" not in calls.read_text(encoding="utf-8")


def test_changed_rollback_snapshot_is_never_restored_or_restarted(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, calls = signer_install
    assert _run(signer_install, "install").returncode == 0
    calls.unlink()

    result = _run(signer_install, "install", RACE_ROLLBACK="1")

    assert result.returncode != 0
    assert calls.read_text(encoding="utf-8").splitlines().count(
        "--user start saturnin-attestation.service"
    ) == 1
    installed = unit_dir / "saturnin-attestation.service"
    assert not installed.exists() or "Description=raced rollback" not in (
        installed.read_text(encoding="utf-8")
    )


def test_lifecycle_lock_excludes_concurrent_uninstall_and_rollback(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    checkout, env, unit_dir, _ = signer_install
    hold = checkout / "hold-daemon"
    entered = checkout / "daemon-entered"
    hold.touch()
    executable_fd, runtime_fd = _authorized_fds(checkout, "install")
    try:
        process = subprocess.Popen(
            [f"/proc/self/fd/{executable_fd}", "install"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={
                **env,
                "SATURNIN_GOVERNED_EXECUTION": "sealed-memfd",
                "SATURNIN_GOVERNED_RUNTIME_FD": str(runtime_fd),
                "HOLD_DAEMON": str(hold),
                "HOLD_ENTERED": str(entered),
            },
            pass_fds=(executable_fd, runtime_fd),
        )
        deadline = time.monotonic() + 5
        while not entered.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert entered.exists()

        concurrent = _run(signer_install, "uninstall")
        hold.unlink()
        stdout, stderr = process.communicate(timeout=5)
    finally:
        os.close(executable_fd)
        os.close(runtime_fd)

    assert concurrent.returncode != 0
    assert "lifecycle operation is in progress" in concurrent.stderr
    assert process.returncode == 0, stdout + stderr
    assert (unit_dir / "saturnin-attestation.service").is_file()


def test_uninstall_is_selective_and_repeatable(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, _ = signer_install
    unrelated = unit_dir / "saturnin-poller.timer"
    unrelated.write_text("untouched\n", encoding="utf-8")
    assert _run(signer_install, "install").returncode == 0

    first = _run(signer_install, "uninstall")
    second = _run(signer_install, "uninstall")

    assert first.returncode == second.returncode == 0
    assert not (unit_dir / "saturnin-attestation.service").exists()
    assert unrelated.read_text(encoding="utf-8") == "untouched\n"
    assert (unit_dir / "saturnin-credentials").is_dir()


def test_failed_uninstall_reload_restores_unit_and_active_state(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, calls = signer_install
    assert _run(signer_install, "install").returncode == 0
    before = _topology(unit_dir)

    result = _run(signer_install, "uninstall", FAIL_ON="daemon-reload")

    assert result.returncode != 0
    assert _topology(unit_dir) == before
    assert calls.read_text(encoding="utf-8").splitlines()[-1] == (
        "--user start saturnin-attestation.service"
    )


def test_status_is_read_only(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, calls = signer_install
    assert _run(signer_install, "install").returncode == 0
    calls.unlink()
    before = _topology(unit_dir)

    result = _run(signer_install, "status")

    assert result.returncode == 0
    assert _topology(unit_dir) == before
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "--user status --no-pager saturnin-attestation.service"
    ]


def test_status_rejects_tampered_unit_without_systemctl(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, calls = signer_install
    assert _run(signer_install, "install").returncode == 0
    installed = unit_dir / "saturnin-attestation.service"
    installed.write_text(
        installed.read_text(encoding="utf-8").replace(
            "SATURNIN_RUNTIME_SHA256", "UNTRUSTED_RUNTIME_SHA256"
        ),
        encoding="utf-8",
    )
    calls.unlink()

    result = _run(signer_install, "status")

    assert result.returncode != 0
    assert not calls.exists()


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        ("Type=simple", "Type=simple\nExecStartPre=/bin/true"),
        ("Type=simple", "Type=simple\nExecStartPost=/bin/true"),
        (
            "ExecStart=",
            "ExecStart=/bin/true\nExecStart=",
        ),
        ("PrivateNetwork=yes", "PrivateNetwork=no"),
        (
            "LoadCredentialEncrypted=saturnin-review-attestation-key:",
            "LoadCredentialEncrypted=unexpected:/unsafe\n"
            "LoadCredentialEncrypted=saturnin-review-attestation-key:",
        ),
        (
            "[Service]\nType=simple",
            "ProtectSystem=strict\n[Service]\nType=simple",
        ),
    ],
)
def test_status_rejects_any_unit_directive_injection_or_override(
    signer_install: tuple[Path, dict[str, str], Path, Path],
    needle: str,
    replacement: str,
) -> None:
    _, _, unit_dir, calls = signer_install
    assert _run(signer_install, "install").returncode == 0
    installed = unit_dir / "saturnin-attestation.service"
    installed.write_text(
        installed.read_text(encoding="utf-8").replace(needle, replacement, 1),
        encoding="utf-8",
    )
    calls.unlink()

    result = _run(signer_install, "status")

    assert result.returncode != 0
    assert not calls.exists()


@pytest.mark.parametrize("unsafe", ["mode", "owner"])
def test_status_rejects_unsafe_installed_unit_metadata(
    signer_install: tuple[Path, dict[str, str], Path, Path], unsafe: str
) -> None:
    checkout, env, unit_dir, calls = signer_install
    assert _run(signer_install, "install").returncode == 0
    installed = unit_dir / "saturnin-attestation.service"
    calls.unlink()
    if unsafe == "mode":
        installed.chmod(0o664)
    else:
        fake_python = Path(env["PATH"].split(":", 1)[0]) / "python3"
        fake_python.write_text(
            "#!/bin/sh\n"
            f"if [ \"${{UNIT_PATH:-}}\" = '{installed}' ] "
            "&& [ \"${EXPECTED_MODE:-}\" = 0644 ]; then\n"
            "  exit 1\n"
            "fi\n"
            "exec /usr/bin/python3 \"$@\"\n",
            encoding="utf-8",
        )
        fake_python.chmod(0o755)

    result = _run((checkout, env, unit_dir, calls), "status")

    assert result.returncode != 0
    assert not calls.exists()


def test_status_does_not_create_missing_unit_directory(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, calls = signer_install
    shutil.rmtree(unit_dir)

    result = _run(signer_install, "status")

    assert result.returncode != 0
    assert not unit_dir.exists()
    assert not calls.exists()


@pytest.mark.parametrize("change", ["symlink", "group-writable", "replacement"])
def test_helper_is_not_a_runtime_dependency(
    signer_install: tuple[Path, dict[str, str], Path, Path],
    change: str,
    tmp_path: Path,
) -> None:
    checkout, _, unit_dir, calls = signer_install
    helper = checkout / "scripts" / "lib" / "user_unit_install.sh"
    if change == "symlink":
        replacement = tmp_path / "malicious-helper"
        replacement.write_text("touch \"$HOME/helper-executed\"\n", encoding="utf-8")
        helper.unlink()
        helper.symlink_to(replacement)
    elif change == "group-writable":
        helper.chmod(0o775)
    else:
        helper.write_text("touch \"$HOME/helper-executed\"\n", encoding="utf-8")

    result = _run(signer_install, "install")

    assert result.returncode == 0
    assert not (Path(signer_install[1]["HOME"]) / "helper-executed").exists()
    assert (unit_dir / "saturnin-attestation.service").is_file()
    assert calls.exists()


def test_helper_path_and_content_race_cannot_enter_execution_chain(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    checkout, env, unit_dir, _ = signer_install
    helper = checkout / "scripts" / "lib" / "user_unit_install.sh"
    helper.unlink()
    helper.write_text("touch \"$HOME/helper-executed\"\n", encoding="utf-8")
    helper.chmod(0o777)

    result = _run(signer_install, "install")

    assert result.returncode == 0
    assert not (Path(env["HOME"]) / "helper-executed").exists()
    assert (unit_dir / "saturnin-attestation.service").is_file()


@pytest.mark.parametrize(
    "tool",
    [
        "bash",
        "chmod",
        "cp",
        "flock",
        "id",
        "mkdir",
        "mv",
        "python3",
        "realpath",
        "rm",
        "rmdir",
        "saturnin",
        "stat",
        "systemctl",
        "systemd-analyze",
    ],
)
def test_inherited_path_cannot_substitute_any_runtime_tool(
    signer_install: tuple[Path, dict[str, str], Path, Path],
    tmp_path: Path,
    tool: str,
) -> None:
    _, env, unit_dir, _ = signer_install
    malicious = tmp_path / "malicious"
    malicious.mkdir(exist_ok=True)
    marker = tmp_path / f"{tool}-executed"
    executable = malicious / tool
    executable.write_text(
        f"#!/bin/sh\n/usr/bin/touch '{marker}'\nexit 99\n", encoding="utf-8"
    )
    executable.chmod(0o755)

    result = _run(signer_install, "install", PATH=str(malicious))

    assert result.returncode == 0
    assert not marker.exists()
    assert (unit_dir / "saturnin-attestation.service").is_file()


def test_path_injected_saturnin_cannot_read_credentials(
    signer_install: tuple[Path, dict[str, str], Path, Path],
    tmp_path: Path,
) -> None:
    _, _, unit_dir, _ = signer_install
    malicious = tmp_path / "credential-thief"
    malicious.mkdir()
    leak = tmp_path / "credential-leak"
    executable = malicious / "saturnin"
    executable.write_text(
        "#!/bin/sh\n"
        f"/usr/bin/cat '{unit_dir}/saturnin-credentials/"
        f"saturnin-review-attestation-key.cred' > '{leak}'\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)

    result = _run(signer_install, "install", PATH=str(malicious))

    assert result.returncode == 0
    assert not leak.exists()


def test_runtime_and_template_path_replacement_uses_private_snapshots(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    checkout, env, unit_dir, _ = signer_install
    runtime = checkout / ".venv" / "bin" / "saturnin"
    template = checkout / "systemd" / "saturnin-attestation.service"

    result = _run(
        signer_install,
        "install",
        RACE_SOURCES="1",
        RUNTIME_TO_REPLACE=str(runtime),
        TEMPLATE_TO_REPLACE=str(template),
    )

    assert result.returncode == 0
    assert not (Path(env["HOME"]) / "runtime-reopened").exists()
    assert "Description=Saturnin private review attestation signer" in (
        unit_dir / "saturnin-attestation.service"
    ).read_text(encoding="utf-8")


def test_service_uses_source_snapshot_not_reopened_checkout(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    checkout, _, unit_dir, _ = signer_install
    source = checkout / "src" / "saturnin" / "attestation_service.py"

    result = _run(
        signer_install,
        "install",
        RACE_SOURCES="1",
        RUNTIME_TO_REPLACE=str(checkout / ".venv" / "bin" / "saturnin"),
        TEMPLATE_TO_REPLACE=str(
            checkout / "systemd" / "saturnin-attestation.service"
        ),
        SOURCE_TO_REPLACE=str(source),
    )

    assert result.returncode == 0
    with zipfile.ZipFile(unit_dir / "saturnin-attestation-runtime.pyz") as archive:
        installed_source = archive.read("saturnin/attestation_service.py")
    assert b"reopened source" not in installed_source


def test_service_bootstrap_imports_only_from_sealed_runtime() -> None:
    template = (
        REPO_ROOT / "systemd" / "saturnin-attestation.service"
    ).read_text(encoding="utf-8")

    for required in (
        "os.memfd_create",
        "os.MFD_ALLOW_SEALING",
        "fcntl.F_ADD_SEALS",
        "fcntl.F_SEAL_WRITE",
        "fcntl.F_SEAL_GROW",
        "fcntl.F_SEAL_SHRINK",
        "fcntl.F_SEAL_SEAL",
        'sys.path.insert(0,f"/proc/self/fd/{s}")',
    ):
        assert required in template
    assert 'sys.path.insert(0,f"/proc/self/fd/{f}")' not in template


def test_replaced_runtime_archive_is_rejected_before_installation(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    _, _, unit_dir, _ = signer_install

    result = _run(signer_install, "install", RACE_RUNTIME_ARCHIVE="1")

    assert result.returncode != 0
    assert not (unit_dir / "saturnin-attestation.service").exists()
    assert not (unit_dir / "saturnin-attestation-runtime.pyz").exists()


def test_unsafe_source_fails_before_credential_or_unit_mutation(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    checkout, _, unit_dir, calls = signer_install
    source = checkout / "src" / "saturnin" / "attestation_service.py"
    source.chmod(0o666)

    result = _run(signer_install, "install")

    assert result.returncode != 0
    assert not (unit_dir / "saturnin-attestation.service").exists()
    assert not calls.exists()


def test_runtime_in_place_mutation_fails_before_credential_execution(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    checkout, env, unit_dir, _ = signer_install
    runtime = checkout / ".venv" / "bin" / "saturnin"
    runtime.write_text(
        "#!/bin/sh\n"
        "/usr/bin/cat \"$HOME/.config/systemd/user/saturnin-credentials/"
        "saturnin-review-attestation-key.cred\" > \"$HOME/credential-leak\"\n",
        encoding="utf-8",
    )
    runtime.chmod(0o775)
    result = _run(
        signer_install,
        "install",
    )

    assert result.returncode != 0
    assert not (Path(env["HOME"]) / "credential-leak").exists()
    assert not (unit_dir / "saturnin-attestation.service").exists()


def test_template_in_place_mutation_fails_before_unit_replacement(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    checkout, _, unit_dir, _ = signer_install
    template = checkout / "systemd" / "saturnin-attestation.service"
    template.write_text("[Unit]\nDescription=mutated\n", encoding="utf-8")
    template.chmod(0o664)
    installed = unit_dir / "saturnin-attestation.service"
    installed.write_text("old unit\n", encoding="utf-8")
    before = _topology(unit_dir)

    result = _run(
        signer_install,
        "install",
    )

    assert result.returncode != 0
    assert _topology(unit_dir) == before


def test_invalid_template_rolls_back_without_replacing_preexisting_unit(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    checkout, _, unit_dir, _ = signer_install
    installed = unit_dir / "saturnin-attestation.service"
    installed.write_text("old unit\n", encoding="utf-8")
    before = _topology(unit_dir)
    template = checkout / "systemd" / "saturnin-attestation.service"
    template.write_text(
        template.read_text(encoding="utf-8").replace(
            "Type=simple", "Type=simple\nExecStartPre=/bin/true"
        ),
        encoding="utf-8",
    )
    template.chmod(0o644)

    result = _run(signer_install, "install")

    assert result.returncode != 0
    assert _topology(unit_dir) == before


def test_rejects_noncanonical_home_and_path_injection(
    signer_install: tuple[Path, dict[str, str], Path, Path], tmp_path: Path
) -> None:
    checkout, _, unit_dir, calls = signer_install

    result = _run(
        signer_install,
        "install",
        SATURNIN_HOME=f"{checkout};systemctl --user start saturnin-evil.service",
    )

    assert result.returncode != 0
    assert not (unit_dir / "saturnin-attestation.service").exists()
    if calls.exists():
        assert all(
            " enable " not in f" {call} "
            and " start " not in f" {call} "
            and " stop " not in f" {call} "
            and "daemon-reload" not in call
            for call in calls.read_text(encoding="utf-8").splitlines()
        )


@pytest.mark.parametrize(
    "unsafe",
    [
        "credential-link",
        "runtime-link",
        "unit-dir-mode",
        "checkout-mode",
        "config-symlink",
    ],
)
def test_rejects_symlinks_and_unsafe_permissions_before_mutation(
    signer_install: tuple[Path, dict[str, str], Path, Path],
    unsafe: str,
    tmp_path: Path,
) -> None:
    checkout, _, unit_dir, calls = signer_install
    if unsafe == "credential-link":
        credential = (
            unit_dir
            / "saturnin-credentials"
            / "saturnin-review-attestation-key.cred"
        )
        credential.unlink()
        credential.symlink_to(tmp_path / "missing")
    elif unsafe == "runtime-link":
        runtime = checkout / ".venv" / "bin" / "saturnin"
        target = checkout / ".venv" / "bin" / "real-saturnin"
        runtime.rename(target)
        runtime.symlink_to(target.name)
    elif unsafe == "unit-dir-mode":
        unit_dir.chmod(0o777)
    elif unsafe == "checkout-mode":
        checkout.chmod(0o777)
    else:
        config = Path(signer_install[1]["HOME"]) / ".config"
        real_config = config.with_name("real-config")
        config.rename(real_config)
        config.symlink_to(real_config)

    result = _run(signer_install, "install")

    assert result.returncode != 0
    assert not (unit_dir / "saturnin-attestation.service").exists()
    if calls.exists():
        assert calls.read_text(encoding="utf-8").splitlines() == [
            "--user is-active --quiet saturnin-attestation.service"
        ]
