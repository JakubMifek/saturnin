from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

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
        "  daemon-reload) [ \"${FAIL_ON:-}\" != daemon-reload ] ;;\n"
        "  enable)\n"
        "    mkdir -p \"$unit_dir/default.target.wants\"\n"
        "    ln -sf \"../saturnin-attestation.service\" "
        "\"$unit_dir/default.target.wants/saturnin-attestation.service\"\n"
        "    [ \"${FAIL_ON:-}\" != enable ]\n"
        "    ;;\n"
        "  start)\n"
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
    analyzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    analyzer.chmod(0o755)
    env = {
        **os.environ,
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "SATURNIN_HOME": str(checkout),
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
    }
    return checkout, env, unit_dir, calls


def _run(
    setup: tuple[Path, dict[str, str], Path, Path],
    action: str,
    **environment: str,
) -> subprocess.CompletedProcess[str]:
    checkout, env, _, _ = setup
    return subprocess.run(
        [str(checkout / "scripts" / "install_attestation_unit.sh"), action],
        check=False,
        capture_output=True,
        text=True,
        env={**env, **environment},
    )


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


@pytest.mark.parametrize("failure", ["enable", "start"])
def test_partial_service_failure_restores_preexisting_entries(
    signer_install: tuple[Path, dict[str, str], Path, Path], failure: str
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

    result = _run(signer_install, "install", FAIL_ON=failure)

    assert result.returncode != 0
    assert _topology(unit_dir) == before


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
            "saturnin.attestation_service serve", "saturnin.cli doctor"
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
        fake_stat = Path(env["PATH"].split(":", 1)[0]) / "stat"
        fake_stat.write_text(
            "#!/bin/sh\n"
            f"if [ \"$1\" = -c ] && [ \"$2\" = %u ] && [ \"$3\" = '{installed}' ]; then\n"
            "  printf '0\\n'\n"
            "  exit 0\n"
            "fi\n"
            "exec /usr/bin/stat \"$@\"\n",
            encoding="utf-8",
        )
        fake_stat.chmod(0o755)

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


@pytest.mark.parametrize("unsafe", ["symlink", "group-writable", "owner"])
def test_rejects_unsafe_helper_before_sourcing_or_systemctl(
    signer_install: tuple[Path, dict[str, str], Path, Path],
    unsafe: str,
    tmp_path: Path,
) -> None:
    checkout, _, unit_dir, calls = signer_install
    helper = checkout / "scripts" / "lib" / "user_unit_install.sh"
    if unsafe == "symlink":
        replacement = tmp_path / "malicious-helper"
        replacement.write_text("touch \"$HOME/helper-executed\"\n", encoding="utf-8")
        helper.unlink()
        helper.symlink_to(replacement)
    elif unsafe == "group-writable":
        helper.chmod(0o775)
    else:
        fake_stat = Path(signer_install[1]["PATH"].split(":", 1)[0]) / "stat"
        fake_stat.write_text(
            "#!/bin/sh\n"
            f"if [ \"$1\" = -c ] && [ \"$2\" = %u ] && [ \"$3\" = '{helper}' ]; then\n"
            "  printf '0\\n'\n"
            "  exit 0\n"
            "fi\n"
            "exec /usr/bin/stat \"$@\"\n",
            encoding="utf-8",
        )
        fake_stat.chmod(0o755)

    result = _run(signer_install, "install")

    assert result.returncode != 0
    assert not (Path(signer_install[1]["HOME"]) / "helper-executed").exists()
    assert not (unit_dir / "saturnin-attestation.service").exists()
    assert not calls.exists()


def test_helper_path_replacement_after_open_cannot_change_sourced_identity(
    signer_install: tuple[Path, dict[str, str], Path, Path],
) -> None:
    checkout, env, unit_dir, calls = signer_install
    helper = checkout / "scripts" / "lib" / "user_unit_install.sh"
    marker = checkout / "helper-replaced"
    fake_stat = Path(env["PATH"].split(":", 1)[0]) / "stat"
    fake_stat.write_text(
        "#!/bin/sh\n"
        f"helper='{helper}'\n"
        f"marker='{marker}'\n"
        "if [ \"$1\" = -Lc ] && [ \"$2\" = %u ] && [ ! -e \"$marker\" ]; then\n"
        "  mv \"$helper\" \"$helper.original\"\n"
        "  printf '%s\\n' 'touch \"$HOME/helper-executed\"' > \"$helper\"\n"
        "  chmod 0755 \"$helper\"\n"
        "  touch \"$marker\"\n"
        "fi\n"
        "exec /usr/bin/stat \"$@\"\n",
        encoding="utf-8",
    )
    fake_stat.chmod(0o755)

    result = _run(signer_install, "install")

    assert result.returncode == 0
    assert marker.exists()
    assert not (Path(env["HOME"]) / "helper-executed").exists()
    assert (unit_dir / "saturnin-attestation.service").is_file()
    assert not any(
        "saturnin-improve" in call
        for call in calls.read_text(encoding="utf-8").splitlines()
    )


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


@pytest.mark.parametrize("unsafe", ["credential-link", "runtime-link", "unit-dir-mode"])
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
    else:
        unit_dir.chmod(0o777)

    result = _run(signer_install, "install")

    assert result.returncode != 0
    assert not (unit_dir / "saturnin-attestation.service").exists()
    if calls.exists():
        assert calls.read_text(encoding="utf-8").splitlines() == [
            "--user is-active --quiet saturnin-attestation.service"
        ]
