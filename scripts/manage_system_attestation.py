#!/usr/bin/python3
"""Transactional fixed-action installer for the dedicated signer.

Normal operation requires uid 0.  ``--root`` is solely a filesystem test mode:
it never invokes systemctl, sysusers, tmpfiles, or systemd-creds.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
ADMIN_SOURCE = Path(__file__).resolve()
ADMIN_TARGET = "usr/sbin/saturnin-attestation-admin"
FILES = {
    "src/saturnin/system_attestation.py": "usr/lib/saturnin-attestation/system_attestation.py",
    "config/attestation.json": "etc/saturnin-attestation/config.json",
    "systemd/system/saturnin-attestation.service": "usr/lib/systemd/system/saturnin-attestation.service",
    "systemd/system/saturnin-attestation.socket": "usr/lib/systemd/system/saturnin-attestation.socket",
    "systemd/system/saturnin-attestation.sysusers": "usr/lib/sysusers.d/saturnin-attestation.conf",
    "systemd/system/saturnin-attestation.tmpfiles": "usr/lib/tmpfiles.d/saturnin-attestation.conf",
}
EXPECTED_SHA256 = {
    "src/saturnin/system_attestation.py": "8e427b58be499e65a6aafa7378d90642a2680a72f77569d2d4cf91e06f95905c",
    "config/attestation.json": "8f861363e8ac6c893a6d8e3d22f771a5c65b9f2bfacea2993a6c5b79cbcb1f1b",
    "systemd/system/saturnin-attestation.service": "825b0f555cf685445fa5706955b0bd97afc89f3738efb48a2f19d4b7fe5ae7dd",
    "systemd/system/saturnin-attestation.socket": "607ca78353de34badb46a03e366b00859638dba057a7e08e25ded311d0f0855f",
    "systemd/system/saturnin-attestation.sysusers": "0059e8a1ead80a9b47399f04a1430a1cecf7b70479b224dc8efe084e27fa2187",
    "systemd/system/saturnin-attestation.tmpfiles": "db85221548cb33ab108fbb2ded0e4b4508414507ddc4b190da23e62ae9c47222",
}
ROOT_ONLY = {
    "etc/saturnin-attestation": 0o750,
    "var/lib/saturnin-attestation": 0o700,
    "run/saturnin-attestation": 0o750,
}


class InstallError(RuntimeError):
    pass


def _safe_regular(path: Path, uid: int) -> os.stat_result:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o002
    ):
        raise InstallError(f"unsafe source: {path}")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise InstallError(f"source alias is forbidden: {path}")
    return metadata


def _safe_target(root: Path, relative: str) -> Path:
    if not root.is_absolute() or root.is_symlink():
        raise InstallError("installation root must be an absolute real directory")
    target = root / relative
    current = root
    for component in Path(relative).parts[:-1]:
        current /= component
        if current.exists() and (current.is_symlink() or not current.is_dir()):
            raise InstallError(f"unsafe target parent: {current}")
    if target.exists() and (target.is_symlink() or target.stat().st_nlink != 1):
        raise InstallError(f"unsafe target: {target}")
    return target


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def status(root: Path) -> None:
    uid = 0 if root == Path("/") else os.getuid()
    for source_name, target_name in FILES.items():
        if PROJECT != Path("/usr"):
            source = PROJECT / source_name
            _safe_regular(source, uid)
            if _digest(source) != EXPECTED_SHA256[source_name]:
                raise InstallError(f"reviewed source digest mismatch: {source}")
        target = _safe_target(root, target_name)
        if not target.is_file() or _digest(target) != EXPECTED_SHA256[source_name]:
            raise InstallError(f"installed artifact differs: /{target_name}")
        metadata = target.stat()
        if root == Path("/") and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
            raise InstallError(f"installed artifact is not root-controlled: /{target_name}")


def install(root: Path, test_mode: bool) -> None:
    if PROJECT == Path("/usr"):
        status(root)
        return
    uid = os.getuid()
    sources: list[tuple[Path, str]] = []
    for source_name, target_name in FILES.items():
        source = PROJECT / source_name
        _safe_regular(source, uid)
        if _digest(source) != EXPECTED_SHA256[source_name]:
            raise InstallError(f"reviewed source digest mismatch: {source}")
        sources.append((source, target_name))
    stage = root / f".saturnin-attestation-stage-{os.getpid()}"
    if stage.exists() or stage.is_symlink():
        raise InstallError("transaction stage already exists")
    installed: list[Path] = []
    backups: list[tuple[Path, Path]] = []
    try:
        stage.mkdir(mode=0o700)
        for source, target_name in sources:
            staged = stage / target_name
            staged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, staged, follow_symlinks=False)
            staged.chmod(0o755 if target_name.endswith(".py") else 0o644)
            if _digest(staged) != _digest(source):
                raise InstallError("staged artifact digest mismatch")
        staged_admin = stage / ADMIN_TARGET
        staged_admin.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ADMIN_SOURCE, staged_admin, follow_symlinks=False)
        staged_admin.chmod(0o755)
        for relative, mode in ROOT_ONLY.items():
            target = _safe_target(root, relative + "/.sentinel").parent
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(mode)
        for target_name in [*(name for _, name in sources), ADMIN_TARGET]:
            target = _safe_target(root, target_name)
            target.parent.mkdir(parents=True, exist_ok=True)
            staged = stage / target_name
            if target.exists():
                backup = stage / "backups" / target_name
                backup.parent.mkdir(parents=True, exist_ok=True)
                os.replace(target, backup)
                backups.append((target, backup))
            os.replace(staged, target)
            installed.append(target)
        credential = _safe_target(root, "etc/saturnin-attestation/current.key.cred")
        if not credential.exists():
            _provision_credential(credential, test_mode)
        previous = _safe_target(root, "etc/saturnin-attestation/previous.key.cred")
        if not previous.exists():
            _provision_credential(previous, test_mode, name="previous.key")
        if not test_mode:
            for command in (
                ["/usr/bin/systemd-sysusers", "/usr/lib/sysusers.d/saturnin-attestation.conf"],
                ["/usr/bin/systemd-tmpfiles", "--create", "/usr/lib/tmpfiles.d/saturnin-attestation.conf"],
                ["/usr/bin/systemctl", "daemon-reload"],
                ["/usr/bin/systemctl", "enable", "--now", "saturnin-attestation.socket"],
            ):
                subprocess.run(command, check=True, timeout=30)
        status(root)
    except Exception:
        for target in reversed(installed):
            target.unlink(missing_ok=True)
        for target, backup in reversed(backups):
            if backup.exists():
                os.replace(backup, target)
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _provision_credential(
    path: Path, test_mode: bool, *, name: str = "current.key"
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    if temporary.exists() or temporary.is_symlink():
        raise InstallError("credential staging path already exists")
    if test_mode:
        temporary.write_bytes(b"TEST-ENCRYPTED-CREDENTIAL-" + secrets.token_bytes(32))
    else:
        secret = secrets.token_bytes(48)
        try:
            subprocess.run(
                ["/usr/bin/systemd-creds", "encrypt", f"--name={name}", "-", str(temporary)],
                input=secret, check=True, timeout=30,
            )
        finally:
            secret = b""
    temporary.chmod(0o600)
    os.replace(temporary, path)


def rotate(root: Path, test_mode: bool) -> None:
    status(root)
    directory = _safe_target(root, "etc/saturnin-attestation/.sentinel").parent
    current = directory / "current.key.cred"
    previous = directory / "previous.key.cred"
    rollback = directory / "current.key.rollback"
    if rollback.exists():
        raise InstallError("an uncommitted rotation already exists")
    if previous.exists():
        os.replace(previous, rollback)
    os.replace(current, previous)
    try:
        _provision_credential(current, test_mode)
        if not test_mode:
            subprocess.run(
                ["/usr/bin/systemctl", "restart", "saturnin-attestation.service"],
                check=True, timeout=30,
            )
    except Exception:
        current.unlink(missing_ok=True)
        os.replace(previous, current)
        if rollback.exists():
            os.replace(rollback, previous)
        raise


def rollback(root: Path, test_mode: bool) -> None:
    directory = _safe_target(root, "etc/saturnin-attestation/.sentinel").parent
    current, previous = directory / "current.key.cred", directory / "previous.key.cred"
    if not current.is_file() or not previous.is_file():
        raise InstallError("rotation rollback requires current and previous credentials")
    failed = directory / "current.key.failed"
    os.replace(current, failed)
    os.replace(previous, current)
    rollback_key = directory / "current.key.rollback"
    if rollback_key.exists():
        os.replace(rollback_key, previous)
    else:
        os.replace(failed, previous)
    failed.unlink(missing_ok=True)
    if not test_mode:
        subprocess.run(
            ["/usr/bin/systemctl", "restart", "saturnin-attestation.service"],
            check=True, timeout=30,
        )


def uninstall(root: Path, test_mode: bool) -> None:
    if not test_mode:
        subprocess.run(
            ["/usr/bin/systemctl", "disable", "--now", "saturnin-attestation.socket"],
            check=True, timeout=30,
        )
    for target_name in FILES.values():
        _safe_target(root, target_name).unlink(missing_ok=True)
    _safe_target(root, ADMIN_TARGET).unlink(missing_ok=True)
    if not test_mode:
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True, timeout=30)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["install", "status", "uninstall", "rotate", "rollback"])
    parser.add_argument("--root", type=Path, default=Path("/"))
    args = parser.parse_args(argv)
    root = args.root.resolve(strict=True)
    test_mode = root != Path("/")
    if not test_mode and os.geteuid() != 0:
        raise InstallError("system installation requires the human administrator")
    state = _safe_target(root, "var/lib/saturnin-attestation/.admin.lock")
    state.parent.mkdir(parents=True, exist_ok=True)
    with state.open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH if args.action == "status" else fcntl.LOCK_EX)
        {"install": install, "status": lambda r, t: status(r), "uninstall": uninstall,
         "rotate": rotate, "rollback": rollback}[args.action](root, test_mode)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (InstallError, OSError, subprocess.SubprocessError) as exc:
        print(f"saturnin-attestation-admin: {exc}", file=sys.stderr)
        sys.exit(1)
