#!/usr/bin/python3
"""Transactional fixed-action administration for the dedicated signer."""

from __future__ import annotations

import argparse
import base64
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

ADMIN_SOURCE = Path(__file__).resolve()
ADMIN_STAGE = Path(
    "/run/saturnin-attestation-bootstrap/saturnin-attestation-admin.py"
)
ADMIN_INSTALLED = Path("/usr/sbin/saturnin-attestation-admin")
PROJECT = Path("/usr") if ADMIN_SOURCE == ADMIN_INSTALLED else Path.cwd().resolve()
ADMIN_TARGET = "usr/sbin/saturnin-attestation-admin"
SYSTEMD_CREDS = "/usr/bin/systemd-creds"
LEGACY_UID = 1000
OPERATOR_NAME = "jakubmifek"
OPERATOR_UID = 1000
OPERATOR_GID = 1000
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
    "systemd/system/saturnin-attestation.sysusers":
        "usr/lib/sysusers.d/saturnin-attestation.conf",
    "systemd/system/saturnin-attestation.tmpfiles":
        "usr/lib/tmpfiles.d/saturnin-attestation.conf",
}
OBSOLETE_FILES = ("usr/lib/systemd/system/saturnin-attestation.socket",)
EXPECTED_SHA256 = {
    "src/saturnin/system_attestation.py":
        "3646e2588dd0e49cf6a811f84b29f1614e432565818de6d1c0879acab30c84be",
    "config/attestation.json":
        "abce4e29a1c5e20f7bf76381356129e0ee09d178a50f0c05764f61b92d1176d6",
    "systemd/system/saturnin-attestation.service":
        "6b009c048a031b4e3047e8a55ab1848b5d97e051f6608f58b3d2b1f6ef68903c",
    "systemd/system/saturnin-attestation.sysusers":
        "0059e8a1ead80a9b47399f04a1430a1cecf7b70479b224dc8efe084e27fa2187",
    "systemd/system/saturnin-attestation.tmpfiles":
        "3e4885148836f41ab17f2b790d326c10af050160ea602a9660712bb677f65110",
}
ARCHIVE_VERSION = 1
ARCHIVE_MAX_KEYS = 16
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


def _validate_operator_identity() -> None:
    try:
        account = pwd.getpwnam(OPERATOR_NAME)
        primary_group = grp.getgrnam(OPERATOR_NAME)
        uid_account = pwd.getpwuid(OPERATOR_UID)
        gid_group = grp.getgrgid(OPERATOR_GID)
    except KeyError as exc:
        raise InstallError("fixed socket operator identity is missing") from exc
    if (
        account.pw_name != OPERATOR_NAME
        or account.pw_uid != OPERATOR_UID
        or account.pw_gid != OPERATOR_GID
        or uid_account.pw_name != OPERATOR_NAME
        or primary_group.gr_name != OPERATOR_NAME
        or primary_group.gr_gid != OPERATOR_GID
        or gid_group.gr_name != OPERATOR_NAME
    ):
        raise InstallError("fixed socket operator identity does not match reviewed UID/GID")


def _reviewed_source_uid(root: Path) -> int:
    return OPERATOR_UID if root == Path("/") else os.getuid()


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


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_file_durable(path: Path, value: bytes, mode: int) -> None:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
    )
    try:
        view = memoryview(value)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while staging installed artifact")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def _mkdir_tracked(path: Path, root: Path, created: list[Path]) -> None:
    missing: list[Path] = []
    current = path
    while current != root and not current.exists():
        missing.append(current)
        current = current.parent
    if current != root and (current.is_symlink() or not current.is_dir()):
        raise InstallError(f"unsafe target parent: {current}")
    for directory in reversed(missing):
        directory.mkdir()
        created.append(directory)


def _cleanup_created_directories(created: list[Path], preserve: set[Path]) -> None:
    for directory in reversed(created):
        if directory in preserve:
            continue
        try:
            directory.rmdir()
            _fsync_directory(directory.parent)
        except OSError:
            pass


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _credential_paths(root: Path) -> tuple[Path, Path]:
    directory = _safe_target(root, "etc/saturnin-attestation/.sentinel").parent
    return directory / "current.key.cred", directory / "previous.key.cred"


def _archive_path(root: Path) -> Path:
    return _credential_paths(root)[0].with_name("archive.keys.cred")


def _github_token_path(root: Path) -> Path:
    return _credential_paths(root)[0].with_name("github.token.cred")


def _policy_credential_path(root: Path) -> Path:
    return _credential_paths(root)[0].with_name("github.policy.cred")


def _publisher_credential_path(root: Path) -> Path:
    return _credential_paths(root)[0].with_name("github.publisher.cred")


def _validate_github_token(value: bytes) -> None:
    if (
        not 20 <= len(value) <= 512
        or not value.isascii()
        or any(character in b" \t\r\n\v\f" for character in value)
    ):
        raise InstallError("protected GitHub credential is invalid")


def _validate_publisher_credential(value: bytes) -> None:
    try:
        payload = json.loads(value)
        app_id = payload["app_id"]
        private_key = payload["private_key"].encode("ascii")
    except (KeyError, TypeError, UnicodeEncodeError, json.JSONDecodeError) as exc:
        raise InstallError("publisher App credential is invalid") from exc
    if (
        set(payload) != {"app_id", "private_key"}
        or type(app_id) is not int
        or app_id < 1
        or len(private_key) > 32 * 1024
        or not re.fullmatch(
            rb"-----BEGIN (?:RSA )?PRIVATE KEY-----\n"
            rb"[A-Za-z0-9+/=\r\n]+"
            rb"-----END (?:RSA )?PRIVATE KEY-----\n?",
            private_key,
        )
    ):
        raise InstallError("publisher App credential is invalid")


def _rollback_path(root: Path) -> Path:
    return _credential_paths(root)[0].with_name("rollback.state.cred")


def _read_credential(root: Path, path: Path) -> bytes:
    try:
        source = _open_source(
            _safe_target(root, str(path.relative_to(root))),
            0 if root == Path("/") else os.getuid(),
            mode=0o600,
        )
    except FileNotFoundError as exc:
        raise InstallError(f"required credential is unavailable: {path.name}") from exc
    try:
        return source.content
    finally:
        source.close()


def _validate_key(value: bytes, label: str) -> None:
    if len(value) < 32 or len(value) > 4096 or b"\0" in value:
        raise InstallError(f"{label} signing credential identity is invalid")


def _encode_archive(keys: list[bytes]) -> bytes:
    if len(keys) > ARCHIVE_MAX_KEYS:
        raise InstallError(
            f"retired key archive limit ({ARCHIVE_MAX_KEYS}) is reached"
        )
    for key in keys:
        _validate_key(key, "archive.keys")
    if len({_digest_bytes(key) for key in keys}) != len(keys):
        raise InstallError("retired key archive contains duplicate credentials")
    return json.dumps(
        {
            "version": ARCHIVE_VERSION,
            "keys": [base64.b64encode(key).decode("ascii") for key in keys],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _decode_archive(value: bytes) -> list[bytes]:
    try:
        payload = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("retired key archive is malformed") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "keys"}
        or payload["version"] != ARCHIVE_VERSION
        or not isinstance(payload["keys"], list)
        or len(payload["keys"]) > ARCHIVE_MAX_KEYS
    ):
        raise InstallError("retired key archive schema is invalid")
    keys: list[bytes] = []
    for encoded in payload["keys"]:
        if not isinstance(encoded, str):
            raise InstallError("retired key archive schema is invalid")
        try:
            key = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise InstallError("retired key archive contains an invalid key") from exc
        _validate_key(key, "archive.keys")
        keys.append(key)
    if len({_digest_bytes(key) for key in keys}) != len(keys):
        raise InstallError("retired key archive contains duplicate credentials")
    return keys


def _encode_rollback(current: bytes, previous: bytes, archive: list[bytes]) -> bytes:
    return json.dumps(
        {
            "version": 1,
            "current": base64.b64encode(current).decode("ascii"),
            "previous": base64.b64encode(previous).decode("ascii"),
            "archive": json.loads(_encode_archive(archive)),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _decode_rollback(value: bytes) -> tuple[bytes, bytes, list[bytes]]:
    try:
        payload = json.loads(value)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"version", "current", "previous", "archive"}
            or payload["version"] != 1
            or not isinstance(payload["current"], str)
            or not isinstance(payload["previous"], str)
        ):
            raise ValueError
        current = base64.b64decode(payload["current"], validate=True)
        previous = base64.b64decode(payload["previous"], validate=True)
        archive = _decode_archive(
            json.dumps(payload["archive"], separators=(",", ":")).encode()
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise InstallError("rollback state is malformed") from exc
    _validate_key(current, "rollback current")
    _validate_key(previous, "rollback previous")
    if current == previous:
        raise InstallError("rollback credentials must differ")
    return current, previous, archive


def _new_key() -> bytes:
    return secrets.token_hex(48).encode()


def _encode_checked(runner: Runner, plaintext: bytes, name: str) -> bytes:
    _validate_key(plaintext, name)
    return _encode_blob_checked(runner, plaintext, name)


def _encode_blob_checked(runner: Runner, plaintext: bytes, name: str) -> bytes:
    if not plaintext or len(plaintext) > 128 * 1024 or b"\0" in plaintext:
        raise InstallError(f"{name} credential payload is invalid")
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
        _fsync_directory(next(iter(values)).parent)
        if restart:
            try:
                _restart_and_verify(runner)
            except Exception as recovery:
                _record_install_failure(
                    root, "credential-activation", "service-recovery-failed"
                )
                raise InstallError(
                    "credentials were rolled back but service recovery failed"
                ) from recovery
            _record_install_failure(
                root, "credential-activation", "service-restarted-after-rollback"
            )
        raise
    finally:
        for temporary in staged:
            temporary.unlink(missing_ok=True)
        for _target, backup in backups:
            backup.unlink(missing_ok=True)
        _fsync_directory(next(iter(values)).parent)


def _restart_and_verify(runner: Runner) -> None:
    runner.command(["/usr/bin/systemctl", "restart", "saturnin-attestation.service"])
    runner.command(
        ["/usr/bin/systemctl", "is-active", "--quiet", "saturnin-attestation.service"]
    )


def _record_install_failure(root: Path, phase: str, recovery: str) -> Path:
    directory = _safe_target(
        root, "var/lib/saturnin-attestation/.failure"
    ).parent
    directory.mkdir(parents=True, exist_ok=True)
    marker = directory / "install-failure.json"
    temporary = marker.with_name(f".{marker.name}.{os.getpid()}.new")
    payload = json.dumps(
        {
            "version": 1,
            "phase": phase,
            "artifacts_restored": True,
            "credentials_restored": True,
            "service_recovery": recovery,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    _write_file_durable(temporary, payload, 0o600)
    os.replace(temporary, marker)
    _fsync_directory(directory)
    return marker


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


def _migrate_or_provision(root: Path, runner: Runner) -> list[Path]:
    current, previous = _credential_paths(root)
    archive = _archive_path(root)
    github_token = _github_token_path(root)
    policy_credential = _policy_credential_path(root)
    publisher_credential = _publisher_credential_path(root)
    created: list[Path] = []
    if root != Path("/") and not github_token.exists():
        github_token.parent.mkdir(parents=True, exist_ok=True)
        _atomic_credentials(
            root,
            {
                github_token: _encode_blob_checked(
                    runner, b"production-shape-test-token", "github.token"
                )
            },
            runner,
            restart=False,
        )
        created.append(github_token)
    if root != Path("/") and not policy_credential.exists():
        _atomic_credentials(
            root,
            {
                policy_credential: _encode_blob_checked(
                    runner, b"production-shape-test-policy-token", "github.policy"
                )
            },
            runner,
            restart=False,
        )
        created.append(policy_credential)
    if root != Path("/") and not publisher_credential.exists():
        _atomic_credentials(
            root,
            {
                publisher_credential: _encode_blob_checked(
                    runner,
                    json.dumps({
                        "app_id": 1,
                        "private_key": (
                            "-----BEGIN " + "PRIVATE KEY-----\n"
                            "QUJDRA==\n"
                            "-----END " + "PRIVATE KEY-----\n"
                        ),
                    }).encode(),
                    "github.publisher",
                )
            },
            runner,
            restart=False,
        )
        created.append(publisher_credential)
    if not github_token.is_file() or github_token.is_symlink():
        raise InstallError(
            "root-provisioned protected GitHub credential is required"
        )
    token_metadata = github_token.lstat()
    if (
        not stat.S_ISREG(token_metadata.st_mode)
        or token_metadata.st_nlink != 1
        or stat.S_IMODE(token_metadata.st_mode) != 0o600
        or (root == Path("/") and token_metadata.st_uid != 0)
    ):
        raise InstallError("protected GitHub credential file is unsafe")
    merge_plaintext = runner.decrypt(
        _read_credential(root, github_token), "github.token"
    )
    _validate_github_token(merge_plaintext)
    if not policy_credential.is_file() or policy_credential.is_symlink():
        raise InstallError(
            "root-provisioned policy GitHub credential is required"
        )
    policy_metadata = policy_credential.lstat()
    if (
        not stat.S_ISREG(policy_metadata.st_mode)
        or policy_metadata.st_nlink != 1
        or stat.S_IMODE(policy_metadata.st_mode) != 0o600
        or (root == Path("/") and policy_metadata.st_uid != 0)
    ):
        raise InstallError("policy GitHub credential file is unsafe")
    policy_plaintext = runner.decrypt(
        _read_credential(root, policy_credential), "github.policy"
    )
    _validate_github_token(policy_plaintext)
    if secrets.compare_digest(merge_plaintext, policy_plaintext):
        raise InstallError("merge and policy GitHub credentials must differ")
    if not publisher_credential.is_file() or publisher_credential.is_symlink():
        raise InstallError(
            "root-provisioned publisher App credential is required"
        )
    publisher_metadata = publisher_credential.lstat()
    if (
        not stat.S_ISREG(publisher_metadata.st_mode)
        or publisher_metadata.st_nlink != 1
        or stat.S_IMODE(publisher_metadata.st_mode) != 0o600
        or (root == Path("/") and publisher_metadata.st_uid != 0)
    ):
        raise InstallError("publisher App credential file is unsafe")
    _validate_publisher_credential(
        runner.decrypt(
            _read_credential(root, publisher_credential), "github.publisher"
        )
    )
    existing = (current.exists(), previous.exists())
    if any(existing):
        if not all(existing):
            raise InstallError("partial system credential state is forbidden")
        if archive.exists():
            return created
        values = {
            archive: _encode_blob_checked(
                runner, _encode_archive([]), "archive.keys"
            ),
        }
        _atomic_credentials(root, values, runner, restart=False)
        return [*created, archive]
    if archive.exists():
        raise InstallError("partial system credential state is forbidden")
    opened = _open_legacy(root)
    legacy_plaintexts: list[bytes] = []
    if opened is not None:
        try:
            for source, (_filename, legacy_name, expected, _target) in zip(opened, LEGACY):
                plaintext = runner.decrypt(source.content, legacy_name, LEGACY_UID)
                if _digest_bytes(plaintext) != expected:
                    raise InstallError("legacy credential plaintext identity mismatch")
                _validate_key(plaintext, legacy_name)
                legacy_plaintexts.append(plaintext)
            for source in opened:
                _revalidate(source)
        finally:
            for source in opened:
                source.close()
    current_plain = _new_key()
    previous_plain = _new_key()
    if current_plain == previous_plain:
        raise InstallError("current and previous credentials must differ")
    values = {
        current: _encode_checked(runner, current_plain, "current.key"),
        previous: _encode_checked(runner, previous_plain, "previous.key"),
        archive: _encode_blob_checked(
            runner, _encode_archive(legacy_plaintexts), "archive.keys"
        ),
    }
    _atomic_credentials(root, values, runner, restart=False)
    current_plain = previous_plain = b""
    return [*created, current, previous, archive]


def status(root: Path, runner: Runner | None = None) -> None:
    source_uid = _reviewed_source_uid(root)
    for source_name, target_name in FILES.items():
        if PROJECT != Path("/usr"):
            source = _open_source(PROJECT / source_name, source_uid)
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
    for target_name in OBSOLETE_FILES:
        if _safe_target(root, target_name).exists():
            raise InstallError(f"obsolete socket activation artifact remains: /{target_name}")
    admin = _safe_target(root, ADMIN_TARGET)
    admin_metadata = admin.lstat()
    if (
        not stat.S_ISREG(admin_metadata.st_mode)
        or admin_metadata.st_nlink != 1
        or stat.S_IMODE(admin_metadata.st_mode) != 0o755
        or (root == Path("/") and admin_metadata.st_uid != 0)
    ):
        raise InstallError("installed administrator identity is unsafe")
    current, previous = _credential_paths(root)
    archive = _archive_path(root)
    codec = runner or (SystemRunner() if root == Path("/") else FakeRunner())
    merge_plaintext = codec.decrypt(
        _read_credential(root, _github_token_path(root)), "github.token"
    )
    _validate_github_token(merge_plaintext)
    policy_plaintext = codec.decrypt(
        _read_credential(root, _policy_credential_path(root)), "github.policy"
    )
    _validate_github_token(policy_plaintext)
    if secrets.compare_digest(merge_plaintext, policy_plaintext):
        raise InstallError("merge and policy GitHub credentials must differ")
    _validate_publisher_credential(
        codec.decrypt(
            _read_credential(root, _publisher_credential_path(root)),
            "github.publisher",
        )
    )
    current_plain = codec.decrypt(_read_credential(root, current), "current.key")
    previous_plain = codec.decrypt(_read_credential(root, previous), "previous.key")
    archive_plain = _decode_archive(
        codec.decrypt(_read_credential(root, archive), "archive.keys")
    )
    _validate_key(current_plain, "current.key")
    _validate_key(previous_plain, "previous.key")
    if current_plain == previous_plain:
        raise InstallError("current and previous credentials must differ")
    all_keys = [current_plain, previous_plain, *archive_plain]
    if len({_digest_bytes(key) for key in all_keys}) != len(all_keys):
        raise InstallError("active and retired credentials must be duplicate-free")
    rollback = _rollback_path(root)
    if rollback.exists():
        _decode_rollback(
            codec.decrypt(_read_credential(root, rollback), "rollback.state")
        )
    if root == Path("/"):
        codec.command(
            ["/usr/bin/systemctl", "is-enabled", "--quiet",
             "saturnin-attestation.service"]
        )
        codec.command(
            ["/usr/bin/systemctl", "is-active", "--quiet",
             "saturnin-attestation.service"]
        )


def install(root: Path, test_mode: bool, runner: Runner | None = None) -> None:
    codec = runner or (FakeRunner() if test_mode else SystemRunner())
    if PROJECT == Path("/usr"):
        status(root, codec)
        return
    source_uid = _reviewed_source_uid(root)
    sources: list[tuple[Source, str]] = []
    admin_source: Source | None = None
    for source_name, target_name in FILES.items():
        source = _open_source(PROJECT / source_name, source_uid)
        if _digest_bytes(source.content) != EXPECTED_SHA256[source_name]:
            source.close()
            raise InstallError(f"reviewed source digest mismatch: {source.path}")
        sources.append((source, target_name))
    admin_source = _open_source(
        ADMIN_SOURCE, 0 if root == Path("/") else os.getuid()
    )
    stage = root / f".saturnin-attestation-stage-{os.getpid()}"
    if stage.exists() or stage.is_symlink():
        raise InstallError("transaction stage already exists")
    installed: list[Path] = []
    backups: list[tuple[Path, Path]] = []
    credentials_created: list[Path] = []
    created_directories: list[Path] = []
    service_phase = ""
    retired_socket = False
    preserve_directories: set[Path] = set()
    try:
        stage.mkdir(mode=0o700)
        for source, target_name in [*sources, (admin_source, ADMIN_TARGET)]:
            staged = stage / target_name
            staged.parent.mkdir(parents=True, exist_ok=True)
            _write_file_durable(
                staged,
                source.content,
                0o755 if target_name.endswith((".py", "admin")) else 0o644,
            )
        for directory in sorted(
            {path.parent for path in stage.rglob("*")}, key=lambda path: len(path.parts),
            reverse=True,
        ):
            _fsync_directory(directory)
        for relative, mode in ROOT_ONLY.items():
            target = _safe_target(root, relative + "/.sentinel").parent
            _mkdir_tracked(target, root, created_directories)
            target.chmod(mode)
            _fsync_directory(target.parent)
        for source, _target_name in [*sources, (admin_source, ADMIN_TARGET)]:
            _revalidate(source)
        for target_name in OBSOLETE_FILES:
            target = _safe_target(root, target_name)
            if target.exists():
                retired_socket = True
                backup = stage / "backups" / target_name
                backup.parent.mkdir(parents=True, exist_ok=True)
                os.replace(target, backup)
                backups.append((target, backup))
                _fsync_directory(target.parent)
                _fsync_directory(backup.parent)
        for _source, target_name in [*sources, (admin_source, ADMIN_TARGET)]:
            target = _safe_target(root, target_name)
            _mkdir_tracked(target.parent, root, created_directories)
            staged = stage / target_name
            if target.exists():
                backup = stage / "backups" / target_name
                backup.parent.mkdir(parents=True, exist_ok=True)
                os.replace(target, backup)
                backups.append((target, backup))
                _fsync_directory(target.parent)
                _fsync_directory(backup.parent)
            os.replace(staged, target)
            installed.append(target)
            _fsync_directory(target.parent)
        credentials_created = _migrate_or_provision(root, codec)
        if not test_mode:
            commands = [
                (
                    "sysusers",
                    ["/usr/bin/systemd-sysusers",
                     "/usr/lib/sysusers.d/saturnin-attestation.conf"],
                ),
                (
                    "tmpfiles",
                    ["/usr/bin/systemd-tmpfiles", "--create",
                     "/usr/lib/tmpfiles.d/saturnin-attestation.conf"],
                ),
            ]
            if retired_socket:
                commands.append((
                    "socket-deactivation",
                    ["/usr/bin/systemctl", "disable", "--now",
                     "saturnin-attestation.socket"],
                ))
            commands.extend((
                ("daemon-reload", ["/usr/bin/systemctl", "daemon-reload"]),
                (
                    "service-enable",
                    ["/usr/bin/systemctl", "enable", "--now",
                     "saturnin-attestation.service"],
                ),
            ))
            for phase, command in commands:
                service_phase = phase
                codec.command(command)
            service_phase = "service-health"
            _restart_and_verify(codec)
        status(root, codec)
        (_safe_target(
            root, "var/lib/saturnin-attestation/install-failure.json"
        )).unlink(missing_ok=True)
    except Exception:
        for credential in credentials_created:
            credential.unlink(missing_ok=True)
            _fsync_directory(credential.parent)
        for target in reversed(installed):
            target.unlink(missing_ok=True)
            _fsync_directory(target.parent)
        for target, backup in reversed(backups):
            if backup.exists():
                os.replace(backup, target)
                _fsync_directory(target.parent)
        if service_phase:
            recovery = "not-attempted"
            try:
                codec.command(
                    ["/usr/bin/systemctl", "disable", "--now",
                     "saturnin-attestation.service"]
                )
                codec.command(["/usr/bin/systemctl", "daemon-reload"])
                recovery = "service-disabled"
            except Exception:
                recovery = "service-disable-failed"
            marker = _record_install_failure(root, service_phase, recovery)
            preserve_directories.update({marker.parent})
        raise
    finally:
        for source, _target in sources:
            source.close()
        if admin_source is not None:
            admin_source.close()
        shutil.rmtree(stage, ignore_errors=True)
        _cleanup_created_directories(created_directories, preserve_directories)


def rotate(root: Path, test_mode: bool, runner: Runner | None = None) -> None:
    codec = runner or (FakeRunner() if test_mode else SystemRunner())
    status(root, codec)
    current, previous = _credential_paths(root)
    archive = _archive_path(root)
    old_current = codec.decrypt(_read_credential(root, current), "current.key")
    old_previous = codec.decrypt(_read_credential(root, previous), "previous.key")
    old_archive = _decode_archive(
        codec.decrypt(_read_credential(root, archive), "archive.keys")
    )
    _validate_key(old_current, "current.key")
    _validate_key(old_previous, "previous.key")
    if len(old_archive) >= ARCHIVE_MAX_KEYS:
        raise InstallError(
            "retired key archive is full; complete documented retirement before rotating"
        )
    rollback_state = _rollback_path(root)
    new_current = _new_key()
    values = {
        current: _encode_checked(codec, new_current, "current.key"),
        previous: _encode_checked(codec, old_current, "previous.key"),
        archive: _encode_blob_checked(
            codec, _encode_archive([*old_archive, old_previous]), "archive.keys"
        ),
        rollback_state: _encode_blob_checked(
            codec,
            _encode_rollback(old_current, old_previous, old_archive),
            "rollback.state",
        ),
    }
    _atomic_credentials(root, values, codec, restart=not test_mode)


def rollback(root: Path, test_mode: bool, runner: Runner | None = None) -> None:
    codec = runner or (FakeRunner() if test_mode else SystemRunner())
    status(root, codec)
    current, previous = _credential_paths(root)
    archive = _archive_path(root)
    rollback_state = _rollback_path(root)
    if not rollback_state.exists():
        raise InstallError("rollback requires a completed rotation")
    current_plain = codec.decrypt(_read_credential(root, current), "current.key")
    previous_plain = codec.decrypt(_read_credential(root, previous), "previous.key")
    archive_plain = _decode_archive(
        codec.decrypt(_read_credential(root, archive), "archive.keys")
    )
    restore_current, restore_previous, restore_archive = _decode_rollback(
        codec.decrypt(_read_credential(root, rollback_state), "rollback.state")
    )
    values = {
        current: _encode_checked(codec, restore_current, "current.key"),
        previous: _encode_checked(codec, restore_previous, "previous.key"),
        archive: _encode_blob_checked(
            codec, _encode_archive(restore_archive), "archive.keys"
        ),
        rollback_state: _encode_blob_checked(
            codec,
            _encode_rollback(current_plain, previous_plain, archive_plain),
            "rollback.state",
        ),
    }
    _atomic_credentials(root, values, codec, restart=not test_mode)


def uninstall(root: Path, test_mode: bool, runner: Runner | None = None) -> None:
    codec = runner or (FakeRunner() if test_mode else SystemRunner())
    if not test_mode:
        codec.command(
            ["/usr/bin/systemctl", "disable", "--now", "saturnin-attestation.service"]
        )
    for target_name in FILES.values():
        _safe_target(root, target_name).unlink(missing_ok=True)
    for target_name in OBSOLETE_FILES:
        _safe_target(root, target_name).unlink(missing_ok=True)
    _safe_target(root, ADMIN_TARGET).unlink(missing_ok=True)
    if not test_mode:
        codec.command(["/usr/bin/systemctl", "daemon-reload"])


def _validate_admin_execution() -> None:
    if ADMIN_SOURCE not in {ADMIN_STAGE, ADMIN_INSTALLED}:
        raise InstallError("administrator must run from the fixed root-owned path")
    source = ADMIN_SOURCE.lstat()
    parent = ADMIN_SOURCE.parent.lstat()
    if (
        not stat.S_ISREG(source.st_mode)
        or source.st_uid != 0
        or source.st_gid != 0
        or source.st_nlink != 1
        or source.st_mode & 0o022
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_gid != 0
        or parent.st_mode & 0o022
    ):
        raise InstallError("administrator executable is not root-controlled")


def _execute(action: str, root: Path) -> None:
    root = root.resolve(strict=True)
    test_mode = root != Path("/")
    if not test_mode and os.geteuid() != 0:
        raise InstallError("system installation requires the human administrator")
    if not test_mode:
        _validate_admin_execution()
        _validate_operator_identity()
    state = _safe_target(root, "var/lib/saturnin-attestation/.admin.lock")
    state.parent.mkdir(parents=True, exist_ok=True)
    with state.open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH if action == "status" else fcntl.LOCK_EX)
        actions = {
            "install": install,
            "status": lambda r, t: status(r),
            "uninstall": uninstall,
            "rotate": rotate,
            "rollback": rollback,
        }
        actions[action](root, test_mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action", choices=["install", "status", "uninstall", "rotate", "rollback"]
    )
    args = parser.parse_args(argv)
    _execute(args.action, Path("/"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (InstallError, OSError, subprocess.SubprocessError) as exc:
        print(f"saturnin-attestation-admin: {exc}", file=sys.stderr)
        sys.exit(1)
