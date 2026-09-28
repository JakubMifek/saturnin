#!/usr/bin/python3
"""Transactional fixed-action administration for the dedicated signer."""

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
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

PROJECT = Path(__file__).resolve().parents[1]
ADMIN_SOURCE = Path(__file__).resolve()
ADMIN_TARGET = "usr/sbin/saturnin-attestation-admin"
SYSTEMD_CREDS = "/usr/bin/systemd-creds"
LEGACY_UID = 1000
LEGACY_ROOT = Path("/home/jakubmifek/.config/systemd/user/saturnin-credentials")
LEGACY = (
    (
        "saturnin-review-attestation-key.cred",
        "saturnin-review-attestation-key",
        "375e3d3378f472f503dc5d0622fb87ae66d4b3fa47b260b0cb5a19ec5b7dc2a1",
        "current.key",
    ),
    (
        "saturnin-review-attestation-previous-key.cred",
        "saturnin-review-attestation-previous-key",
        "7c48788075e222129f49d8955299c790278eafea901d728fc1ec0398e5687ff8",
        "previous.key",
    ),
)
FILES = {
    "src/saturnin/system_attestation.py":
        "usr/lib/saturnin-attestation/system_attestation.py",
    "config/attestation.json": "etc/saturnin-attestation/config.json",
    "systemd/system/saturnin-attestation.service":
        "usr/lib/systemd/system/saturnin-attestation.service",
    "systemd/system/saturnin-attestation.socket":
        "usr/lib/systemd/system/saturnin-attestation.socket",
    "systemd/system/saturnin-attestation.sysusers":
        "usr/lib/sysusers.d/saturnin-attestation.conf",
    "systemd/system/saturnin-attestation.tmpfiles":
        "usr/lib/tmpfiles.d/saturnin-attestation.conf",
}
EXPECTED_SHA256 = {
    "src/saturnin/system_attestation.py":
        "99b67e0f67f5ae49a8e6beacce55095299ed5628875a0e72e4f00bde7ad22ee0",
    "config/attestation.json":
        "203d56027f000b87c4a14e972e97655151986969c6d8c0e96fa8ac4c6416a2d1",
    "systemd/system/saturnin-attestation.service":
        "c2cb3f16079e8d15adf9950eacbad554cbec82578feed1e7b24c30c2fac3ef96",
    "systemd/system/saturnin-attestation.socket":
        "607ca78353de34badb46a03e366b00859638dba057a7e08e25ded311d0f0855f",
    "systemd/system/saturnin-attestation.sysusers":
        "40a7f9eb62eb5544932db64bd459077547a52f38f18a2a62ee5f3da5e5960e08",
    "systemd/system/saturnin-attestation.tmpfiles":
        "db85221548cb33ab108fbb2ded0e4b4508414507ddc4b190da23e62ae9c47222",
}
ADMIN_REVIEWED_SHA256 = "47fcb8a3fe5f58c5662e1ad3710f837a61a5df2a8fe4648bc46082131a456ed9"
ADMIN_DIGEST_MARKER = b'ADMIN_REVIEWED_SHA256 = "'
ROOT_ONLY = {
    "etc/saturnin-attestation": 0o750,
    "var/lib/saturnin-attestation": 0o700,
    "run/saturnin-attestation": 0o750,
}


class InstallError(RuntimeError):
    pass


class Runner(Protocol):
    def encrypt(self, plaintext: bytes, name: str) -> bytes: ...
    def decrypt(self, ciphertext: bytes, name: str, uid: int | None = None) -> bytes: ...
    def command(self, argv: list[str]) -> None: ...


class SystemRunner:
    def encrypt(self, plaintext: bytes, name: str) -> bytes:
        return subprocess.run(
            [SYSTEMD_CREDS, "encrypt", f"--name={name}", "-", "-"],
            input=plaintext, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=True, timeout=30,
        ).stdout

    def decrypt(self, ciphertext: bytes, name: str, uid: int | None = None) -> bytes:
        uid_option = [] if uid is None else [f"--uid={uid}"]
        return subprocess.run(
            [SYSTEMD_CREDS, "decrypt", *uid_option, f"--name={name}", "-", "-"],
            input=ciphertext, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=True, timeout=30,
        ).stdout

    def command(self, argv: list[str]) -> None:
        subprocess.run(argv, check=True, timeout=30)


class FakeRunner:
    """Deterministic fake-root credential codec; never used for system installs."""

    PREFIX = b"SATURNIN-TEST-CREDENTIAL\0"

    def encrypt(self, plaintext: bytes, name: str) -> bytes:
        return self.PREFIX + name.encode() + b"\0" + plaintext

    def decrypt(self, ciphertext: bytes, name: str, uid: int | None = None) -> bytes:
        prefix = self.PREFIX + name.encode() + b"\0"
        if not ciphertext.startswith(prefix):
            raise InstallError("encrypted credential name does not match")
        return ciphertext[len(prefix):]

    def command(self, argv: list[str]) -> None:
        return None


@dataclass
class Source:
    path: Path
    fd: int
    identity: tuple[int, int, int, int, int, int]
    mount_identity: tuple[str, str, str]
    content: bytes

    def close(self) -> None:
        os.close(self.fd)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
        metadata.st_gid, metadata.st_nlink,
    )


def _open_source(path: Path, uid: int, *, mode: int | None = None) -> Source:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or before.st_nlink != 1
            or before.st_mode & (0o002 if mode is None else 0o022)
            or (mode is not None and stat.S_IMODE(before.st_mode) != mode)
        ):
            raise InstallError(f"unsafe source: {path}")
        if path.resolve(strict=True) != path:
            raise InstallError(f"source alias is forbidden: {path}")
        content = _read_fd(fd)
        after = os.fstat(fd)
        if _identity(before) != _identity(after):
            raise InstallError(f"source changed while reading: {path}")
        return Source(path, fd, _identity(before), _mount_identity(path), content)
    except Exception:
        os.close(fd)
        raise


def _read_fd(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _revalidate(source: Source) -> None:
    try:
        path_metadata = source.path.lstat()
    except OSError as exc:
        raise InstallError(f"source disappeared: {source.path}") from exc
    if (
        _identity(os.fstat(source.fd)) != source.identity
        or _identity(path_metadata) != source.identity
        or _mount_identity(source.path) != source.mount_identity
        or _read_fd(source.fd) != source.content
    ):
        raise InstallError(f"source changed during transaction: {source.path}")


def _safe_target(root: Path, relative: str) -> Path:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise InstallError("installation root must be an absolute real directory")
    target = root / relative
    current = root
    for component in Path(relative).parts[:-1]:
        current /= component
        if current.exists() and (current.is_symlink() or not current.is_dir()):
            raise InstallError(f"unsafe target parent: {current}")
    if target.exists():
        metadata = target.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise InstallError(f"unsafe target: {target}")
    return target


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _admin_digest(value: bytes) -> str:
    start = value.find(ADMIN_DIGEST_MARKER)
    if start < 0:
        raise InstallError("administrator digest marker is missing")
    start += len(ADMIN_DIGEST_MARKER)
    end = value.find(b'"', start)
    if end < 0:
        raise InstallError("administrator digest marker is malformed")
    return _digest_bytes(value[:start] + b"0" * 64 + value[end:])


def _credential_paths(root: Path) -> tuple[Path, Path]:
    directory = _safe_target(root, "etc/saturnin-attestation/.sentinel").parent
    return directory / "current.key.cred", directory / "previous.key.cred"


def _read_credential(root: Path, path: Path) -> bytes:
    source = _open_source(
        _safe_target(root, str(path.relative_to(root))),
        0 if root == Path("/") else os.getuid(),
        mode=0o600,
    )
    try:
        return source.content
    finally:
        source.close()


def _validate_key(value: bytes, label: str) -> None:
    if len(value) < 32 or len(value) > 4096 or b"\0" in value:
        raise InstallError(f"{label} signing credential identity is invalid")


def _new_key() -> bytes:
    return secrets.token_hex(48).encode()


def _encode_checked(runner: Runner, plaintext: bytes, name: str) -> bytes:
    _validate_key(plaintext, name)
    ciphertext = runner.encrypt(plaintext, name)
    if not ciphertext or runner.decrypt(ciphertext, name) != plaintext:
        raise InstallError(f"{name} credential round-trip failed")
    return ciphertext


def _atomic_credentials(
    root: Path, values: dict[Path, bytes], runner: Runner, *, restart: bool
) -> None:
    staged: list[Path] = []
    backups: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        for target, ciphertext in values.items():
            _safe_target(root, str(target.relative_to(root)))
            temporary = target.with_name(f".{target.name}.{os.getpid()}.new")
            if temporary.exists() or temporary.is_symlink():
                raise InstallError("credential staging path already exists")
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            try:
                os.write(fd, ciphertext)
                os.fsync(fd)
            finally:
                os.close(fd)
            staged.append(temporary)
        for target in values:
            if target.exists():
                backup = target.with_name(f".{target.name}.{os.getpid()}.backup")
                if backup.exists() or backup.is_symlink():
                    raise InstallError("credential backup path already exists")
                os.replace(target, backup)
                backups.append((target, backup))
            temporary = target.with_name(f".{target.name}.{os.getpid()}.new")
            os.replace(temporary, target)
            published.append(target)
        directory_fd = os.open(next(iter(values)).parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        if restart:
            _restart_and_verify(runner)
    except Exception:
        for target in reversed(published):
            target.unlink(missing_ok=True)
        for target, backup in reversed(backups):
            if backup.exists():
                os.replace(backup, target)
        if restart:
            try:
                _restart_and_verify(runner)
            except Exception:
                pass
        raise
    finally:
        for temporary in staged:
            temporary.unlink(missing_ok=True)
        for _target, backup in backups:
            backup.unlink(missing_ok=True)


def _restart_and_verify(runner: Runner) -> None:
    runner.command(["/usr/bin/systemctl", "restart", "saturnin-attestation.service"])
    runner.command(
        ["/usr/bin/systemctl", "is-active", "--quiet", "saturnin-attestation.service"]
    )


def _mount_identity(path: Path) -> tuple[str, str, str]:
    resolved = str(path.resolve(strict=True))
    selected: tuple[str, str, str] | None = None
    selected_length = -1
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        mountpoint = fields[4].replace("\\040", " ")
        if (
            resolved == mountpoint or resolved.startswith(mountpoint.rstrip("/") + "/")
        ) and len(mountpoint) > selected_length:
            selected = fields[0], fields[2], mountpoint
            selected_length = len(mountpoint)
    if selected is None:
        raise InstallError(f"mount identity unavailable: {path}")
    return selected


def _legacy_root(root: Path) -> Path:
    return LEGACY_ROOT if root == Path("/") else root / LEGACY_ROOT.relative_to("/")


def _open_legacy(root: Path) -> list[Source] | None:
    source_root = _legacy_root(root)
    if not source_root.exists():
        return None
    owner_uid = LEGACY_UID if root == Path("/") else os.getuid()
    checks = (
        (source_root.parents[4], 0 if root == Path("/") else os.getuid()),  # /home
        (source_root.parents[3], owner_uid),  # /home/jakubmifek
        (source_root.parents[2], owner_uid),  # .config
        (source_root.parents[1], owner_uid),  # systemd
        (source_root.parent, owner_uid),  # user
        (source_root, owner_uid),
    )
    directory_identity: list[tuple[Path, tuple[int, int, int, int, int, int]]] = []
    for path, uid in checks:
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_mode & 0o022
            or path.resolve(strict=True) != path
        ):
            raise InstallError(f"unsafe legacy directory: {path}")
        directory_identity.append((path, _identity(metadata)))
    mount_before = tuple(_mount_identity(path) for path, _uid in checks)
    if len(set(mount_before)) != 1:
        raise InstallError("legacy source crosses a mount boundary")
    opened = [
        _open_source(source_root / filename, owner_uid, mode=0o600)
        for filename, _name, _digest, _target in LEGACY
    ]
    if any(source.mount_identity != mount_before[-1] for source in opened):
        for source in opened:
            source.close()
        raise InstallError("legacy credential is a mounted alias")
    for path, identity in directory_identity:
        if _identity(path.lstat()) != identity:
            for source in opened:
                source.close()
            raise InstallError("legacy directory changed during inspection")
    if tuple(_mount_identity(path) for path, _uid in checks) != mount_before:
        for source in opened:
            source.close()
        raise InstallError("legacy mount identity changed during inspection")
    return opened


def _migrate_or_provision(root: Path, runner: Runner) -> bool:
    current, previous = _credential_paths(root)
    existing = (current.exists(), previous.exists())
    if any(existing):
        if not all(existing):
            raise InstallError("partial system credential state is forbidden")
        return False
    opened = _open_legacy(root)
    if opened is None:
        current_plain = _new_key()
        previous_plain = _new_key()
    else:
        try:
            plaintexts = []
            for source, (_filename, legacy_name, expected, _target) in zip(opened, LEGACY):
                plaintext = runner.decrypt(source.content, legacy_name, LEGACY_UID)
                if _digest_bytes(plaintext) != expected:
                    raise InstallError("legacy credential plaintext identity mismatch")
                _validate_key(plaintext, legacy_name)
                plaintexts.append(plaintext)
            for source in opened:
                _revalidate(source)
            current_plain, previous_plain = plaintexts
        finally:
            for source in opened:
                source.close()
    if current_plain == previous_plain:
        raise InstallError("current and previous credentials must differ")
    values = {
        current: _encode_checked(runner, current_plain, "current.key"),
        previous: _encode_checked(runner, previous_plain, "previous.key"),
    }
    _atomic_credentials(root, values, runner, restart=False)
    current_plain = previous_plain = b""
    return True


def status(root: Path, runner: Runner | None = None) -> None:
    uid = 0 if root == Path("/") else os.getuid()
    for source_name, target_name in FILES.items():
        if PROJECT != Path("/usr"):
            source = _open_source(PROJECT / source_name, uid)
            try:
                if _digest_bytes(source.content) != EXPECTED_SHA256[source_name]:
                    raise InstallError(f"reviewed source digest mismatch: {source.path}")
            finally:
                source.close()
        target = _safe_target(root, target_name)
        if (
            not target.is_file()
            or _digest_bytes(target.read_bytes()) != EXPECTED_SHA256[source_name]
        ):
            raise InstallError(f"installed artifact differs: /{target_name}")
        metadata = target.stat()
        if root == Path("/") and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
            raise InstallError(f"installed artifact is not root-controlled: /{target_name}")
    admin = _safe_target(root, ADMIN_TARGET)
    if not admin.is_file() or _admin_digest(admin.read_bytes()) != ADMIN_REVIEWED_SHA256:
        raise InstallError("installed administrator differs")
    current, previous = _credential_paths(root)
    codec = runner or (SystemRunner() if root == Path("/") else FakeRunner())
    current_plain = codec.decrypt(_read_credential(root, current), "current.key")
    previous_plain = codec.decrypt(_read_credential(root, previous), "previous.key")
    _validate_key(current_plain, "current.key")
    _validate_key(previous_plain, "previous.key")
    if current_plain == previous_plain:
        raise InstallError("current and previous credentials must differ")


def install(root: Path, test_mode: bool, runner: Runner | None = None) -> None:
    codec = runner or (FakeRunner() if test_mode else SystemRunner())
    if PROJECT == Path("/usr"):
        status(root, codec)
        return
    uid = os.getuid()
    sources: list[tuple[Source, str]] = []
    admin_source: Source | None = None
    for source_name, target_name in FILES.items():
        source = _open_source(PROJECT / source_name, uid)
        if _digest_bytes(source.content) != EXPECTED_SHA256[source_name]:
            source.close()
            raise InstallError(f"reviewed source digest mismatch: {source.path}")
        sources.append((source, target_name))
    admin_source = _open_source(ADMIN_SOURCE, uid)
    if _admin_digest(admin_source.content) != ADMIN_REVIEWED_SHA256:
        raise InstallError("reviewed administrator digest mismatch")
    stage = root / f".saturnin-attestation-stage-{os.getpid()}"
    if stage.exists() or stage.is_symlink():
        raise InstallError("transaction stage already exists")
    installed: list[Path] = []
    backups: list[tuple[Path, Path]] = []
    credentials_created = False
    try:
        stage.mkdir(mode=0o700)
        for source, target_name in [*sources, (admin_source, ADMIN_TARGET)]:
            staged = stage / target_name
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(source.content)
            staged.chmod(0o755 if target_name.endswith((".py", "admin")) else 0o644)
        for relative, mode in ROOT_ONLY.items():
            target = _safe_target(root, relative + "/.sentinel").parent
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(mode)
        for source, _target_name in [*sources, (admin_source, ADMIN_TARGET)]:
            _revalidate(source)
        for _source, target_name in [*sources, (admin_source, ADMIN_TARGET)]:
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
        credentials_created = _migrate_or_provision(root, codec)
        if not test_mode:
            for command in (
                ["/usr/bin/systemd-sysusers",
                 "/usr/lib/sysusers.d/saturnin-attestation.conf"],
                ["/usr/bin/systemd-tmpfiles", "--create",
                 "/usr/lib/tmpfiles.d/saturnin-attestation.conf"],
                ["/usr/bin/systemctl", "daemon-reload"],
                ["/usr/bin/systemctl", "enable", "--now",
                 "saturnin-attestation.socket"],
            ):
                codec.command(command)
            _restart_and_verify(codec)
        status(root, codec)
    except Exception:
        if credentials_created:
            for credential in _credential_paths(root):
                credential.unlink(missing_ok=True)
        for target in reversed(installed):
            target.unlink(missing_ok=True)
        for target, backup in reversed(backups):
            if backup.exists():
                os.replace(backup, target)
        raise
    finally:
        for source, _target in sources:
            source.close()
        if admin_source is not None:
            admin_source.close()
        shutil.rmtree(stage, ignore_errors=True)


def rotate(root: Path, test_mode: bool, runner: Runner | None = None) -> None:
    codec = runner or (FakeRunner() if test_mode else SystemRunner())
    status(root, codec)
    current, previous = _credential_paths(root)
    old_current = codec.decrypt(_read_credential(root, current), "current.key")
    old_previous = codec.decrypt(_read_credential(root, previous), "previous.key")
    _validate_key(old_current, "current.key")
    _validate_key(old_previous, "previous.key")
    rollback_key = current.with_name("rollback.key.cred")
    new_current = _new_key()
    values = {
        current: _encode_checked(codec, new_current, "current.key"),
        previous: _encode_checked(codec, old_current, "previous.key"),
        rollback_key: _encode_checked(codec, old_previous, "rollback.key"),
    }
    _atomic_credentials(root, values, codec, restart=not test_mode)


def rollback(root: Path, test_mode: bool, runner: Runner | None = None) -> None:
    codec = runner or (FakeRunner() if test_mode else SystemRunner())
    status(root, codec)
    current, previous = _credential_paths(root)
    rollback_key = current.with_name("rollback.key.cred")
    if not rollback_key.exists():
        raise InstallError("rollback requires a completed rotation")
    current_plain = codec.decrypt(_read_credential(root, current), "current.key")
    previous_plain = codec.decrypt(_read_credential(root, previous), "previous.key")
    rollback_plain = codec.decrypt(
        _read_credential(root, rollback_key), "rollback.key"
    )
    values = {
        current: _encode_checked(codec, previous_plain, "current.key"),
        previous: _encode_checked(codec, rollback_plain, "previous.key"),
        rollback_key: _encode_checked(codec, current_plain, "rollback.key"),
    }
    _atomic_credentials(root, values, codec, restart=not test_mode)


def uninstall(root: Path, test_mode: bool, runner: Runner | None = None) -> None:
    codec = runner or (FakeRunner() if test_mode else SystemRunner())
    if not test_mode:
        codec.command(
            ["/usr/bin/systemctl", "disable", "--now", "saturnin-attestation.socket"]
        )
    for target_name in FILES.values():
        _safe_target(root, target_name).unlink(missing_ok=True)
    _safe_target(root, ADMIN_TARGET).unlink(missing_ok=True)
    if not test_mode:
        codec.command(["/usr/bin/systemctl", "daemon-reload"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action", choices=["install", "status", "uninstall", "rotate", "rollback"]
    )
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
        actions = {
            "install": install,
            "status": lambda r, t: status(r),
            "uninstall": uninstall,
            "rotate": rotate,
            "rollback": rollback,
        }
        actions[args.action](root, test_mode)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (InstallError, OSError, subprocess.SubprocessError) as exc:
        print(f"saturnin-attestation-admin: {exc}", file=sys.stderr)
        sys.exit(1)
