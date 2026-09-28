from __future__ import annotations

import os
import pwd
import stat
import base64
import fcntl
import hashlib
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from saturnin.credentials import (
    ATTESTATION_CREDENTIAL,
    CREDENTIAL_GENERATION,
    HOST_SCOPED_CREDENTIAL_ID,
    PREVIOUS_ATTESTATION_CREDENTIAL,
    CredentialError,
    _advance_generation,
    _atomic_replace_private,
    _credential_namespace_parent_is_trusted,
    _credential_namespace_path,
    _lifecycle_lock,
    _sealed_systemd_creds,
    _validate_systemd_creds_namespace,
    attestation_rotation_values,
    complete_attestation_rotation,
    credential_generation,
    credential_prerequisites,
    credential_status,
    provision_attestation_key,
    revoke_credential,
    rollback_attestation_rotation,
    rotate_attestation_key,
    systemd_credential,
    validate_encrypted_credential,
)


@pytest.fixture(autouse=True)
def runtime_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    runtime = tmp_path / "canonical-runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setattr("saturnin.credentials._runtime_gate_path", lambda: runtime)
    namespace = tmp_path / "config/systemd/user/saturnin-credentials"
    namespace.mkdir(parents=True, mode=0o700)
    namespace.parent.chmod(0o700)
    monkeypatch.setattr(
        "saturnin.credentials._credential_namespace_path",
        lambda: Path(os.environ["XDG_CONFIG_HOME"])
        / "systemd/user/saturnin-credentials",
    )
    monkeypatch.setattr(
        "saturnin.credentials._credential_namespace_parent_is_trusted",
        lambda *_: True,
    )
    return runtime


def _ciphertext(payload: bytes = b"fixture") -> bytes:
    return base64.b64encode(HOST_SCOPED_CREDENTIAL_ID + payload) + b"\n"


def test_atomic_replace_rejects_staging_entry_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = (
        tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    )
    credential_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    destination = credential_dir / "state"
    original_rename = os.rename

    def substitute_then_rename(
        source: str,
        target: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
    ) -> None:
        os.unlink(source, dir_fd=src_dir_fd)
        replacement = os.open(
            source,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=src_dir_fd,
        )
        os.write(replacement, b"attacker")
        os.close(replacement)
        original_rename(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr("saturnin.credentials.os.rename", substitute_then_rename)

    with pytest.raises(CredentialError, match="changed during publication"):
        _atomic_replace_private(destination, "trusted")

    assert destination.read_text() == "attacker"


def test_production_credential_namespace_ignores_caller_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "saturnin.credentials._credential_namespace_path",
        _credential_namespace_path,
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    namespace = _credential_namespace_path()

    assert namespace == Path(pwd.getpwuid(os.getuid()).pw_dir)
    assert namespace != tmp_path
    root_metadata = Path("/").stat()
    assert _credential_namespace_parent_is_trusted(
        namespace.parent.stat(), root_metadata
    )
    assert not _credential_namespace_parent_is_trusted(
        tmp_path.stat(), root_metadata
    )


def _write_attestation_credentials(credential_dir: Path) -> tuple[Path, Path]:
    credential_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    credential_dir.parent.chmod(0o700)
    current = credential_dir / f"{ATTESTATION_CREDENTIAL}.cred"
    previous = credential_dir / f"{PREVIOUS_ATTESTATION_CREDENTIAL}.cred"
    current.write_bytes(_ciphertext(b"current"))
    previous.write_bytes(_ciphertext(b"previous"))
    generation = credential_dir / CREDENTIAL_GENERATION
    generation.write_text("fixture-generation\n", encoding="utf-8")
    current.chmod(0o600)
    previous.chmod(0o600)
    generation.chmod(0o600)
    return current, previous


def test_runtime_lock_serializes_service_and_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime_gate: Path
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    _write_attestation_credentials(
        tmp_path / "config/systemd/user/saturnin-credentials"
    )
    gate = os.open(
        runtime_gate,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    fcntl.flock(gate, fcntl.LOCK_EX)
    acquired = threading.Event()

    def rotation_status() -> None:
        with _lifecycle_lock(exclusive=False):
            acquired.set()

    thread = threading.Thread(target=rotation_status)
    thread.start()
    try:
        assert not acquired.wait(0.05)
    finally:
        fcntl.flock(gate, fcntl.LOCK_UN)
        os.close(gate)
    thread.join(timeout=2)
    assert acquired.is_set()


def test_startup_couples_to_credential_lock_while_rotation_gate_is_held(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runtime_gate: Path,
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_directory = (
        tmp_path / "config/systemd/user/saturnin-credentials"
    )
    _write_attestation_credentials(credential_directory)
    gate = os.open(
        runtime_gate,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    fcntl.flock(gate, fcntl.LOCK_EX)
    startup_acquired = threading.Event()
    release_startup = threading.Event()

    def start_service() -> None:
        with _lifecycle_lock(exclusive=False, startup=True):
            startup_acquired.set()
            release_startup.wait(2)

    thread = threading.Thread(target=start_service)
    thread.start()
    credential_descriptor = os.open(
        credential_directory,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        assert startup_acquired.wait(1)
        with pytest.raises(BlockingIOError):
            fcntl.flock(
                credential_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
            )
    finally:
        release_startup.set()
        thread.join(timeout=2)
        os.close(credential_descriptor)
        fcntl.flock(gate, fcntl.LOCK_UN)
        os.close(gate)
    assert not thread.is_alive()


def test_lifecycle_lock_validates_existing_directory_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    credential_dir = tmp_path / "config/systemd/user/saturnin-credentials"
    _write_attestation_credentials(credential_dir)
    before = credential_dir.stat()
    monkeypatch.setattr(
        "saturnin.credentials.os.fchmod",
        lambda *_: pytest.fail("runtime validation must not mutate directories"),
    )

    with _lifecycle_lock(exclusive=False):
        pass

    after = credential_dir.stat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    )


def test_lifecycle_transaction_stays_on_pinned_directory_and_rejects_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    directory = tmp_path / "config/systemd/user/saturnin-credentials"
    _write_attestation_credentials(directory)
    original = directory.with_name("saturnin-credentials.original")

    with _lifecycle_lock(exclusive=True):
        directory.rename(original)
        replacement = directory
        replacement.mkdir(mode=0o700)
        (replacement / CREDENTIAL_GENERATION).write_text(
            "attacker\n", encoding="utf-8"
        )
        (replacement / CREDENTIAL_GENERATION).chmod(0o600)

        assert credential_generation() == "fixture-generation"
        with pytest.raises(CredentialError, match="identity changed"):
            _advance_generation()

    assert (replacement / CREDENTIAL_GENERATION).read_text(
        encoding="utf-8"
    ) == "attacker\n"
    assert (original / CREDENTIAL_GENERATION).read_text(encoding="utf-8") == (
        "fixture-generation\n"
    )


@pytest.mark.parametrize("unsafe_kind", ["mode", "file", "symlink"])
def test_lifecycle_lock_rejects_unsafe_credential_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unsafe_kind: str
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    directory = tmp_path / "config/systemd/user/saturnin-credentials"
    _write_attestation_credentials(directory)
    if unsafe_kind == "mode":
        directory.chmod(0o755)
    else:
        for path in directory.iterdir():
            path.unlink()
        directory.rmdir()
        if unsafe_kind == "file":
            directory.write_text("not a directory", encoding="utf-8")
        else:
            target = tmp_path / "target"
            target.mkdir(mode=0o700)
            directory.symlink_to(target, target_is_directory=True)

    with pytest.raises(CredentialError, match="canonical|owner-controlled"):
        with _lifecycle_lock(exclusive=False):
            pass


def test_lifecycle_lock_ignores_alternate_runtime_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runtime_gate: Path
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    _write_attestation_credentials(
        tmp_path / "config/systemd/user/saturnin-credentials"
    )
    alternate = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fcntl.flock(alternate, fcntl.LOCK_EX)
    try:
        with _lifecycle_lock(exclusive=False):
            pass
    finally:
        fcntl.flock(alternate, fcntl.LOCK_UN)
        os.close(alternate)


def test_lifecycle_lock_rejects_wrong_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    directory = tmp_path / "config/systemd/user/saturnin-credentials"
    _write_attestation_credentials(directory)
    real_fstat = os.fstat

    def wrong_owner(descriptor: int) -> os.stat_result:
        metadata = real_fstat(descriptor)
        if os.readlink(f"/proc/self/fd/{descriptor}") == str(directory):
            fields = list(metadata)
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)
        return metadata

    monkeypatch.setattr("saturnin.credentials.os.fstat", wrong_owner)

    with pytest.raises(CredentialError, match="owner-controlled"):
        with _lifecycle_lock(exclusive=False):
            pass


def test_provision_attestation_encrypts_without_secret_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    generated = iter(("previous-value", "private-value"))
    monkeypatch.setattr(
        "saturnin.credentials.secrets.token_hex", lambda _: next(generated)
    )
    calls: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(command)
        assert kwargs["input"] in {b"private-value", b"previous-value"}
        return SimpleNamespace(returncode=0, stdout=_ciphertext())

    monkeypatch.setattr("saturnin.credentials.subprocess.run", fake_run)

    destination = provision_attestation_key()

    assert destination.read_bytes() == _ciphertext()
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.parent.stat().st_mode & 0o777 == 0o700
    assert "private-value" not in " ".join(calls[0])
    assert "--with-key=host" in calls[0]
    assert all(command[-2:] == ["-", "-"] for command in calls)


def test_parallel_provision_is_serialized_without_partial_ready_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

    def fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
        time.sleep(0.02)
        return SimpleNamespace(returncode=0, stdout=_ciphertext())

    monkeypatch.setattr("saturnin.credentials.subprocess.run", fake_run)
    destinations: list[Path] = []
    failures: list[CredentialError] = []

    def provision() -> None:
        try:
            destinations.append(provision_attestation_key())
        except CredentialError as exc:
            failures.append(exc)

    workers = [threading.Thread(target=provision) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=2)

    assert all(not worker.is_alive() for worker in workers)
    assert len(destinations) == 1
    assert len(failures) == 1
    assert "already provisioned" in str(failures[0])
    credential_dir = destinations[0].parent
    assert (credential_dir / f"{PREVIOUS_ATTESTATION_CREDENTIAL}.cred").is_file()
    assert credential_dir.stat().st_mode & 0o777 == 0o700


def test_systemd_credential_requires_private_owner_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "credentials"
    directory.mkdir()
    credential = directory / ATTESTATION_CREDENTIAL
    credential.write_text("role-master\n", encoding="utf-8")
    credential.chmod(0o640)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(directory))

    with pytest.raises(CredentialError, match="unsafe permissions"):
        systemd_credential(ATTESTATION_CREDENTIAL)

    credential.chmod(0o600)
    assert systemd_credential(ATTESTATION_CREDENTIAL) == "role-master"


def test_systemd_credential_decrypts_inline_ciphertext_without_secret_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ciphertext = base64.b64encode(
        HOST_SCOPED_CREDENTIAL_ID + b"encrypted-envelope"
    ).decode()
    observed: dict[str, object] = {}

    def decrypt(args: list[str], **kwargs: object) -> SimpleNamespace:
        observed["args"] = args
        observed["input"] = kwargs["input"]
        observed["env"] = kwargs["env"]
        observed["pass_fds"] = kwargs["pass_fds"]
        output = int(kwargs["stdout"])
        observed["mode"] = stat.S_IMODE(os.fstat(output).st_mode)
        with pytest.raises(PermissionError):
            os.open(f"/proc/self/fd/{output}", os.O_RDONLY)
        os.write(output, b"role-master\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.setenv("LD_PRELOAD", "/same-uid/attacker.so")
    monkeypatch.setenv("SATURNIN_CURRENT_CREDENTIAL_CIPHERTEXT", ciphertext)
    monkeypatch.setattr("saturnin.credentials.subprocess.run", decrypt)
    helper = os.memfd_create("test-systemd-creds", os.MFD_ALLOW_SEALING)
    os.fchmod(helper, 0o500)
    monkeypatch.setattr(
        "saturnin.credentials._sealed_systemd_creds", lambda: os.dup(helper)
    )

    try:
        assert systemd_credential(ATTESTATION_CREDENTIAL) == "role-master"
    finally:
        os.close(helper)
    arguments = observed["args"]
    assert isinstance(arguments, list)
    assert str(arguments[0]).startswith("/proc/self/fd/")
    assert arguments[1:] == [
        "decrypt",
        "--user",
        f"--name={ATTESTATION_CREDENTIAL}",
        "-",
        "-",
    ]
    assert observed["pass_fds"] == (int(str(arguments[0]).rsplit("/", 1)[-1]),)
    assert observed["env"] == {"XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"}
    assert observed["input"] == ciphertext.encode()
    assert observed["mode"] == 0
    assert "role-master" not in " ".join(observed["args"])


def _namespace_metadata(
    uid: int, *, tool_uid: int | None = None, nlink: int = 1
) -> tuple[list[SimpleNamespace], SimpleNamespace, str]:
    device = os.makedev(254, 1)
    parents = [
        SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=uid)
        for _ in range(3)
    ]
    tool = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o755,
        st_uid=uid if tool_uid is None else tool_uid,
        st_nlink=nlink,
        st_dev=device,
        st_ino=5509331,
    )
    mountinfo = "278 47 254:1 / / ro,nosuid,relatime - ext4 /dev/root rw\n"
    return parents, tool, mountinfo


@pytest.mark.parametrize("namespace_root_uid", [0, 65534])
def test_systemd_creds_namespace_accepts_bound_canonical_host_identity(
    namespace_root_uid: int,
) -> None:
    parents, tool, mountinfo = _namespace_metadata(namespace_root_uid)

    _validate_systemd_creds_namespace(
        parents, tool, mountinfo, tool.st_dev, tool.st_ino, 0o755
    )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"tool_uid": 65534}, "namespace identity"),
        ({"nlink": 2}, "namespace identity"),
    ],
)
def test_systemd_creds_namespace_rejects_nobody_lookalikes_and_aliases(
    change: dict[str, int], message: str
) -> None:
    parents, tool, mountinfo = _namespace_metadata(0, **change)

    with pytest.raises(CredentialError, match=message):
        _validate_systemd_creds_namespace(
            parents, tool, mountinfo, tool.st_dev, tool.st_ino, 0o755
        )


def test_systemd_creds_namespace_rejects_wrong_or_writable_mount() -> None:
    parents, tool, _ = _namespace_metadata(65534)
    for mountinfo in (
        "278 47 254:2 / / ro,nosuid - ext4 /dev/other rw\n",
        "278 47 254:1 / / rw,nosuid - ext4 /dev/root rw\n",
        "278 47 254:1 / / ro - ext4 /dev/root rw\n"
        "279 278 254:1 /systemd-creds /usr/bin/systemd-creds "
        "rw - ext4 /dev/root rw\n",
        "278 47 254:1 / / ro - ext4 /dev/root rw\n"
        "279 47 254:1 / / ro - ext4 /dev/root rw\n",
    ):
        with pytest.raises(CredentialError, match="mount provenance"):
            _validate_systemd_creds_namespace(
                parents, tool, mountinfo, tool.st_dev, tool.st_ino, 0o755
            )


@pytest.mark.parametrize(
    ("device_delta", "inode_delta", "mode"),
    [(1, 0, 0o755), (0, 1, 0o755), (0, 0, 0o775)],
)
def test_systemd_creds_namespace_rejects_changed_host_identity(
    device_delta: int, inode_delta: int, mode: int
) -> None:
    parents, tool, mountinfo = _namespace_metadata(65534)

    with pytest.raises(CredentialError, match="namespace identity"):
        _validate_systemd_creds_namespace(
            parents,
            tool,
            mountinfo,
            tool.st_dev + device_delta,
            tool.st_ino + inode_delta,
            mode,
        )


def test_systemd_creds_is_copied_to_exact_sealed_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = Path("/usr/bin/systemd-creds")
    metadata = tool.stat(follow_symlinks=False)
    digest = hashlib.sha256(tool.read_bytes()).hexdigest()
    monkeypatch.setenv("SATURNIN_SYSTEMD_CREDS_SHA256", digest)
    monkeypatch.setenv("SATURNIN_SYSTEMD_CREDS_DEVICE", str(metadata.st_dev))
    monkeypatch.setenv("SATURNIN_SYSTEMD_CREDS_INODE", str(metadata.st_ino))
    monkeypatch.setenv(
        "SATURNIN_SYSTEMD_CREDS_MODE", str(stat.S_IMODE(metadata.st_mode))
    )
    original_read_text = Path.read_text

    def read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == Path("/proc/self/mountinfo"):
            device = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
            return f"1 0 {device} / / ro - ext4 /dev/root rw\n"
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)

    descriptor = _sealed_systemd_creds()
    try:
        assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o500
        assert fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) == (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        assert hashlib.sha256(
            os.pread(descriptor, metadata.st_size, 0)
        ).hexdigest() == digest
    finally:
        os.close(descriptor)


def test_systemd_creds_sealing_rejects_byte_digest_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = Path("/usr/bin/systemd-creds")
    metadata = tool.stat(follow_symlinks=False)
    monkeypatch.setenv("SATURNIN_SYSTEMD_CREDS_SHA256", "0" * 64)
    monkeypatch.setenv("SATURNIN_SYSTEMD_CREDS_DEVICE", str(metadata.st_dev))
    monkeypatch.setenv("SATURNIN_SYSTEMD_CREDS_INODE", str(metadata.st_ino))
    monkeypatch.setenv(
        "SATURNIN_SYSTEMD_CREDS_MODE", str(stat.S_IMODE(metadata.st_mode))
    )
    device = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *_args, **_kwargs: (
            f"1 0 {device} / / ro - ext4 /dev/root rw\n"
        ),
    )

    with pytest.raises(CredentialError, match="changed after host validation"):
        _sealed_systemd_creds()


def test_validate_encrypted_credential_reports_only_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    path, _ = _write_attestation_credentials(credential_dir)
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"secret"),
    )

    assert validate_encrypted_credential("review-attestation") == path


def test_status_rejects_non_host_scoped_credential_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    current, previous = _write_attestation_credentials(credential_dir)
    current.write_bytes(base64.b64encode(b"\0" * 16 + b"auto-envelope") + b"\n")

    with pytest.raises(CredentialError, match="not host-key-only"):
        credential_status("review-attestation")

    assert previous.is_file()


def test_restored_ciphertext_requires_matching_host_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "restored-host"))
    credential_dir = (
        tmp_path
        / "restored-host"
        / "systemd"
        / "user"
        / "saturnin-credentials"
    )
    _write_attestation_credentials(credential_dir)
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"restored-value"),
    )
    assert credential_status("review-attestation")["status"] == "valid"

    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=b"identity mismatch"),
    )
    with pytest.raises(CredentialError, match="cannot be decrypted"):
        credential_status("review-attestation")


def test_failed_encryption_removes_exact_staging_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=b""),
    )

    with pytest.raises(CredentialError, match="could not encrypt"):
        provision_attestation_key()

    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    assert not list(credential_dir.glob(".*.input.*"))


def test_provision_rejects_symlinked_credential_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    controlled = tmp_path / "controlled"
    controlled.mkdir()
    credential_dir = config / "systemd" / "user" / "saturnin-credentials"
    credential_dir.parent.mkdir(parents=True, exist_ok=True)
    credential_dir.rmdir()
    credential_dir.symlink_to(controlled, target_is_directory=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))

    with pytest.raises(CredentialError, match="canonical|owner-controlled directory"):
        provision_attestation_key()


def test_systemd_creds_execution_error_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))

    def unavailable(*args: object, **kwargs: object) -> SimpleNamespace:
        raise FileNotFoundError("systemd-creds")

    monkeypatch.setattr("saturnin.credentials.subprocess.run", unavailable)

    with pytest.raises(CredentialError, match="could not encrypt"):
        provision_attestation_key()


def test_rotation_reencrypts_old_key_without_exposing_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    current, _ = _write_attestation_credentials(credential_dir)
    calls: list[tuple[list[str], bytes | None]] = []

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        value = kwargs.get("input")
        calls.append((command, value if isinstance(value, bytes) else None))
        if command[1] == "decrypt" and f"--name={ATTESTATION_CREDENTIAL}" in command:
            return SimpleNamespace(returncode=0, stdout=b"old-master")
        if command[1] == "decrypt":
            return SimpleNamespace(returncode=0, stdout=b"older-master")
        return SimpleNamespace(returncode=0, stdout=_ciphertext(b"new"))

    monkeypatch.setattr("saturnin.credentials.subprocess.run", fake_run)
    monkeypatch.setattr("saturnin.credentials.secrets.token_hex", lambda _: "new-master")

    assert rotate_attestation_key(previous_key_in_use=lambda _: False) == current
    assert calls[2][1] == b"old-master"
    assert calls[3][1] == b"new-master"
    assert all("old-master" not in " ".join(command) for command, _ in calls)
    pending = credential_status("review-attestation")
    assert pending["rotation"] == "pending-seal"
    assert pending["signer"] == "rotation-required"
    assert attestation_rotation_values() == ("old-master", "older-master")

    complete_attestation_rotation()

    ready = credential_status("review-attestation")
    assert ready["rotation"] == "ready"
    assert ready["signer"] == "ready"


def test_failed_rotation_can_restore_both_encrypted_slots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    current, previous = _write_attestation_credentials(credential_dir)
    original_current = current.read_text(encoding="utf-8")
    original_previous = previous.read_text(encoding="utf-8")
    encryptions = 0

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        nonlocal encryptions
        if command[1] == "decrypt":
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    b"current-master"
                    if f"--name={ATTESTATION_CREDENTIAL}" in command
                    else b"previous-master"
                ),
            )
        encryptions += 1
        if encryptions == 2:
            return SimpleNamespace(returncode=1, stdout=b"")
        return SimpleNamespace(returncode=0, stdout=_ciphertext(b"changed"))

    monkeypatch.setattr("saturnin.credentials.subprocess.run", fake_run)

    with pytest.raises(CredentialError, match="could not encrypt"):
        rotate_attestation_key(previous_key_in_use=lambda _: False)

    assert credential_status("review-attestation")["rotation"] == "pending-seal"
    assert rollback_attestation_rotation() == current
    assert current.read_text(encoding="utf-8") == original_current
    assert previous.read_text(encoding="utf-8") == original_previous
    restored = credential_status("review-attestation")
    assert restored["rotation"] == "ready"
    assert restored["signer"] == "rotation-required"


def test_rotation_refuses_to_replace_pending_previous_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    _write_attestation_credentials(credential_dir)
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                (
                    b"current-master"
                    if f"--name={ATTESTATION_CREDENTIAL}" in command
                    else b"previous-master"
                )
                if command[1] == "decrypt"
                else _ciphertext(b"new")
            ),
        ),
    )
    rotate_attestation_key(previous_key_in_use=lambda _: False)

    with pytest.raises(CredentialError, match="already pending"):
        rotate_attestation_key(previous_key_in_use=lambda _: False)


def test_rotation_refuses_to_discard_key_used_by_review_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    _write_attestation_credentials(credential_dir)
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=(
                b"current-master"
                if f"--name={ATTESTATION_CREDENTIAL}" in command
                else b"previous-master"
            ),
        ),
    )

    with pytest.raises(CredentialError, match="still protects review records"):
        rotate_attestation_key(previous_key_in_use=lambda _: True)

    assert credential_status("review-attestation")["rotation"] == "ready"


def test_revoke_attestation_removes_current_and_previous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    credential_dir = tmp_path / "config" / "systemd" / "user" / "saturnin-credentials"
    credential_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    credential_dir.parent.chmod(0o700)
    paths = [
        credential_dir / f"{ATTESTATION_CREDENTIAL}.cred",
        credential_dir / f"{PREVIOUS_ATTESTATION_CREDENTIAL}.cred",
    ]
    for path in paths:
        path.write_bytes(_ciphertext())
        path.chmod(0o600)

    assert revoke_credential("review-attestation") == paths
    assert all(not path.exists() for path in paths)


def test_prerequisites_reports_status_without_secret_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "run"
    socket = runtime / "systemd" / "private"
    socket.parent.mkdir(parents=True)
    socket.touch()
    host_key = tmp_path / "credential.secret"
    host_key.write_text("not-read", encoding="utf-8")
    host_key.chmod(0o400)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    monkeypatch.setattr("saturnin.credentials.shutil.which", lambda _: "/bin/systemd-creds")
    monkeypatch.setattr(
        "saturnin.credentials.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="systemd 257\n", stderr=""
        ),
    )
    monkeypatch.setattr("saturnin.credentials.HOST_CREDENTIAL_SECRET", host_key)
    real_stat = Path.stat

    def fake_stat(path: Path, *args: object, **kwargs: object) -> os.stat_result:
        metadata = real_stat(path, *args, **kwargs)
        if path == socket:
            values = list(metadata)
            values[0] = stat.S_IFSOCK | 0o600
            return os.stat_result(values)
        if path == host_key:
            values = list(metadata)
            values[4] = 0
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(Path, "stat", fake_stat)

    assert credential_prerequisites() == {
        "systemd_creds_version": 257,
        "user_manager": "available",
        "host_key": "initialized",
    }
