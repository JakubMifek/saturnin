from __future__ import annotations

import os
import subprocess
import hashlib
import importlib.util
import json
import sys
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ADMIN = ROOT / "scripts" / "manage_system_attestation.py"
SPEC = importlib.util.spec_from_file_location("manage_system_attestation", ADMIN)
assert SPEC and SPEC.loader
admin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = admin
SPEC.loader.exec_module(admin)


def run(root: Path, action: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    args = [str(ADMIN), action]
    try:
        admin._execute(action, root)
    except (admin.InstallError, OSError, subprocess.SubprocessError) as exc:
        if check:
            raise
        return subprocess.CompletedProcess(args, 1, "", str(exc))
    return subprocess.CompletedProcess(args, 0, "", "")


def test_production_source_identity_is_operator_not_root(tmp_path: Path) -> None:
    assert admin._reviewed_source_uid(Path("/")) == admin.OPERATOR_UID
    assert admin._reviewed_source_uid(tmp_path) == os.getuid()


def test_fake_root_transaction_install_status_rotate_rollback_uninstall(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    obsolete = root / admin.OBSOLETE_FILES[0]
    obsolete.parent.mkdir(parents=True)
    obsolete.write_text("old socket unit", encoding="utf-8")
    run(root, "install")
    assert not obsolete.exists()
    run(root, "status")
    assert (root / "usr/sbin/saturnin-attestation-admin").stat().st_mode & 0o777 == 0o755
    current = root / "etc/saturnin-attestation/current.key.cred"
    original = current.read_bytes()
    original_previous = (current.parent / "previous.key.cred").read_bytes()
    archive = current.parent / "archive.keys.cred"
    original_archive = archive.read_bytes()
    codec = admin.FakeRunner()
    publisher = current.parent / "github.publisher.cred"
    policy = current.parent / "github.policy.cred"
    original_policy = policy.read_bytes()
    assert codec.decrypt(policy.read_bytes(), "github.policy") != codec.decrypt(
        (current.parent / "github.token.cred").read_bytes(), "github.token"
    )
    assert policy.stat().st_mode & 0o777 == 0o600
    publisher_payload = json.loads(
        codec.decrypt(publisher.read_bytes(), "github.publisher")
    )
    assert set(publisher_payload) == {"app_id", "private_key"}
    assert publisher.stat().st_mode & 0o777 == 0o600
    original_plain = codec.decrypt(original, "current.key")
    original_previous_plain = codec.decrypt(original_previous, "previous.key")
    run(root, "rotate")
    assert policy.read_bytes() == original_policy
    assert codec.decrypt(
        (current.parent / "previous.key.cred").read_bytes(), "previous.key"
    ) == original_plain
    run(root, "rollback")
    assert policy.read_bytes() == original_policy
    assert codec.decrypt(current.read_bytes(), "current.key") == original_plain
    assert codec.decrypt(
        (current.parent / "previous.key.cred").read_bytes(), "previous.key"
    ) == original_previous_plain
    assert archive.read_bytes() == original_archive
    run(root, "uninstall")
    assert not (root / "usr/lib/saturnin-attestation/system_attestation.py").exists()
    assert not (root / "usr/sbin/saturnin-attestation-admin").exists()
    assert current.exists()
    assert policy.exists()
    assert publisher.exists()


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"app_id":0,"private_key":"secret"}',
        b'{"app_id":1,"private_key":"secret","token":"leak"}',
    ],
)
def test_status_rejects_malformed_publisher_credential(
    tmp_path: Path, payload: bytes,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    run(root, "install")
    path = root / "etc/saturnin-attestation/github.publisher.cred"
    path.write_bytes(
        admin.FakeRunner().encrypt(payload, "github.publisher")
    )
    with pytest.raises(admin.InstallError, match="publisher App credential"):
        run(root, "status")


@pytest.mark.parametrize("payload", [b"", b"short", b"token with spaces"])
def test_status_rejects_malformed_policy_credential(
    tmp_path: Path, payload: bytes,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    run(root, "install")
    path = root / "etc/saturnin-attestation/github.policy.cred"
    path.write_bytes(admin.FakeRunner().encrypt(payload, "github.policy"))
    with pytest.raises(admin.InstallError, match="GitHub credential"):
        run(root, "status")


def test_status_rejects_credential_substitution(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    run(root, "install")
    directory = root / "etc/saturnin-attestation"
    codec = admin.FakeRunner()
    merge = codec.decrypt(
        (directory / "github.token.cred").read_bytes(), "github.token"
    )
    (directory / "github.policy.cred").write_bytes(
        codec.encrypt(merge, "github.policy")
    )

    with pytest.raises(admin.InstallError, match="must differ"):
        run(root, "status")


def test_install_requires_root_provisioned_policy_credential(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    run(root, "install")
    policy = root / "etc/saturnin-attestation/github.policy.cred"
    policy.unlink()
    with pytest.raises(admin.InstallError, match="github.policy.cred"):
        run(root, "status")


def test_installer_rejects_target_alias_and_cleans_transaction(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "usr").symlink_to(tmp_path)
    result = run(root, "install", check=False)
    assert result.returncode == 1
    assert "unsafe target parent" in result.stderr
    assert not list(root.glob(".saturnin-attestation-stage-*"))


def test_installer_rejects_hardlinked_existing_target(tmp_path: Path) -> None:
    root = tmp_path / "root"
    target = root / "usr/lib/saturnin-attestation/system_attestation.py"
    target.parent.mkdir(parents=True)
    target.write_text("old", encoding="utf-8")
    os.link(target, root / "alias")
    result = run(root, "install", check=False)
    assert result.returncode == 1
    assert "unsafe target" in result.stderr


def test_transaction_failure_restores_replaced_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "root"
    runtime = root / "usr/lib/saturnin-attestation/system_attestation.py"
    config = root / "etc/saturnin-attestation/config.json"
    runtime.parent.mkdir(parents=True)
    config.parent.mkdir(parents=True)
    runtime.write_text("old runtime", encoding="utf-8")
    config.write_text("old config", encoding="utf-8")
    (root / "usr/lib/systemd").symlink_to(tmp_path)

    result = run(root, "install", check=False)

    assert result.returncode == 1
    assert runtime.read_text(encoding="utf-8") == "old runtime"
    assert config.read_text(encoding="utf-8") == "old config"
    assert not list(root.glob(".saturnin-attestation-stage-*"))
    assert not (root / "run/saturnin-attestation").exists()


def test_late_install_failure_restores_files_and_records_fail_closed_state(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()

    class FailingSysusers(admin.FakeRunner):
        def __init__(self) -> None:
            self.commands: list[list[str]] = []

        def command(self, argv):
            self.commands.append(argv)
            if argv[0] == "/usr/bin/systemd-sysusers":
                raise subprocess.CalledProcessError(1, argv)

    runner = FailingSysusers()
    with pytest.raises(subprocess.CalledProcessError):
        admin.install(root, False, runner)

    assert not (root / "usr/lib/saturnin-attestation").exists()
    assert not (root / "etc/saturnin-attestation").exists()
    assert not (root / "run/saturnin-attestation").exists()
    marker = root / "var/lib/saturnin-attestation/install-failure.json"
    assert json.loads(marker.read_text()) == {
        "version": 1,
        "phase": "sysusers",
        "artifacts_restored": True,
        "credentials_restored": True,
        "service_recovery": "service-disabled",
    }
    assert not any("userdel" in argument for command in runner.commands for argument in command)


def test_upgrade_deactivates_socket_before_enabling_service(tmp_path: Path) -> None:
    root = tmp_path / "root"
    obsolete = root / admin.OBSOLETE_FILES[0]
    obsolete.parent.mkdir(parents=True)
    obsolete.write_text("old socket unit", encoding="utf-8")

    class RecordingRunner(admin.FakeRunner):
        def __init__(self) -> None:
            self.commands: list[list[str]] = []

        def command(self, argv):
            self.commands.append(argv)

    runner = RecordingRunner()
    admin.install(root, False, runner)

    assert not obsolete.exists()
    disable = [
        "/usr/bin/systemctl", "disable", "--now",
        "saturnin-attestation.socket",
    ]
    enable = [
        "/usr/bin/systemctl", "enable", "--now",
        "saturnin-attestation.service",
    ]
    assert disable in runner.commands
    assert enable in runner.commands
    assert runner.commands.index(disable) < runner.commands.index(enable)


@pytest.mark.parametrize(
    "extra", [["--unit", "evil.service"], ["--root", "/tmp/fake-root"]]
)
def test_admin_interface_has_fixed_action_grammar(
    extra: list[str],
) -> None:
    result = subprocess.run(
        [str(ADMIN), "install", *extra],
        text=True, capture_output=True,
    )
    assert result.returncode == 2


def test_concurrent_rotations_are_serialized(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    run(root, "install")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(root, "rotate"), range(2)))
    assert all(result.returncode == 0 for result in results)
    codec = admin.FakeRunner()
    current = root / "etc/saturnin-attestation/current.key.cred"
    previous = current.with_name("previous.key.cred")
    archive = current.with_name("archive.keys.cred")
    assert codec.decrypt(current.read_bytes(), "current.key") != codec.decrypt(
        previous.read_bytes(), "previous.key"
    )
    assert len(admin._decode_archive(codec.decrypt(
        archive.read_bytes(), "archive.keys"
    ))) == 2


def test_archive_is_bounded_duplicate_free_and_verification_only(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    codec = admin.FakeRunner()
    admin.install(root, True, codec)
    for _ in range(admin.ARCHIVE_MAX_KEYS):
        admin.rotate(root, True, codec)
    with pytest.raises(admin.InstallError, match="archive is full"):
        admin.rotate(root, True, codec)

    duplicate = [b"k" * 48, b"k" * 48]
    with pytest.raises(admin.InstallError, match="duplicate"):
        admin._encode_archive(duplicate)
    with pytest.raises(admin.InstallError, match="schema"):
        admin._decode_archive(b'{"version":1,"keys":[],"unknown":true}')


def test_rotation_health_failure_restores_both_generations(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    admin.install(root, True)
    current, previous = admin._credential_paths(root)
    archive = admin._archive_path(root)
    before = current.read_bytes(), previous.read_bytes(), archive.read_bytes()

    class FailingHealth(admin.FakeRunner):
        def command(self, argv):
            if "is-active" in argv:
                raise subprocess.CalledProcessError(1, argv)

    with pytest.raises(admin.InstallError, match="service recovery failed"):
        admin.rotate(root, False, FailingHealth())
    assert (current.read_bytes(), previous.read_bytes(), archive.read_bytes()) == before
    assert json.loads(
        (root / "var/lib/saturnin-attestation/install-failure.json").read_text()
    )["phase"] == "credential-activation"


def test_rollback_health_failure_restores_all_generations(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    codec = admin.FakeRunner()
    admin.install(root, True, codec)
    admin.rotate(root, True, codec)
    current, previous = admin._credential_paths(root)
    archive = admin._archive_path(root)
    rollback = admin._rollback_path(root)
    before = (
        current.read_bytes(),
        previous.read_bytes(),
        archive.read_bytes(),
        rollback.read_bytes(),
    )

    class FailingHealth(admin.FakeRunner):
        def command(self, argv):
            if "is-active" in argv:
                raise subprocess.CalledProcessError(1, argv)

    with pytest.raises(admin.InstallError, match="service recovery failed"):
        admin.rollback(root, False, FailingHealth())
    assert (
        current.read_bytes(),
        previous.read_bytes(),
        archive.read_bytes(),
        rollback.read_bytes(),
    ) == before


def test_status_rejects_credential_target_alias(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    admin.install(root, True)
    current, _previous = admin._credential_paths(root)
    ciphertext = current.read_bytes()
    current.unlink()
    alias = root / "alias.cred"
    alias.write_bytes(ciphertext)
    alias.chmod(0o600)
    current.symlink_to(alias)
    with pytest.raises(admin.InstallError, match="unsafe target"):
        admin.status(root)


def test_authorized_legacy_migration_reencrypts_reviewed_plaintext(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    source = root / admin.LEGACY_ROOT.relative_to("/")
    source.mkdir(parents=True, mode=0o700)
    for parent in [source, *source.parents[:5]]:
        if parent != root:
            parent.chmod(0o700)
    current_plain = b"legacy-current-" + b"c" * 40
    previous_plain = b"legacy-previous-" + b"p" * 40
    legacy = (
        ("current.cred", "legacy-current", hashlib.sha256(current_plain).hexdigest(),
         "current.key"),
        ("previous.cred", "legacy-previous",
         hashlib.sha256(previous_plain).hexdigest(), "previous.key"),
    )
    monkeypatch.setattr(admin, "LEGACY", legacy)
    codec = admin.FakeRunner()
    for (filename, name, _digest, _target), plaintext in zip(
        legacy, (current_plain, previous_plain)
    ):
        path = source / filename
        path.write_bytes(codec.encrypt(plaintext, name))
        path.chmod(0o600)

    admin.install(root, True, codec)

    current, previous = admin._credential_paths(root)
    new_current = codec.decrypt(current.read_bytes(), "current.key")
    new_previous = codec.decrypt(previous.read_bytes(), "previous.key")
    assert new_current not in {current_plain, previous_plain}
    assert new_previous not in {current_plain, previous_plain, new_current}
    assert admin._decode_archive(
        codec.decrypt(admin._archive_path(root).read_bytes(), "archive.keys")
    ) == [current_plain, previous_plain]


def test_source_descriptor_rejects_links_and_mutation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"reviewed")
    source.chmod(0o600)
    symlink = tmp_path / "symlink"
    symlink.symlink_to(source)
    with pytest.raises(OSError):
        admin._open_source(symlink, os.getuid())
    hardlink = tmp_path / "hardlink"
    os.link(source, hardlink)
    with pytest.raises(admin.InstallError, match="unsafe source"):
        admin._open_source(source, os.getuid())
    hardlink.unlink()
    opened = admin._open_source(source, os.getuid())
    source.write_bytes(b"mutated")
    try:
        with pytest.raises(admin.InstallError, match="changed"):
            admin._revalidate(opened)
    finally:
        opened.close()


def test_bootstrap_copy_is_digest_pinned_and_source_mutation_safe(
    tmp_path: Path,
) -> None:
    source = tmp_path / "checkout" / "manage_system_attestation.py"
    stage = tmp_path / "root-stage" / "saturnin-attestation-admin.py"
    source.parent.mkdir()
    stage.parent.mkdir(mode=0o700)
    reviewed = ADMIN.read_bytes()
    source.write_bytes(reviewed)
    subprocess.run(
        ["/usr/bin/install", "-m", "0500", str(source), str(stage)],
        check=True,
    )
    source.write_bytes(b"mutated after root-owned copy")
    digest = hashlib.sha256(reviewed).hexdigest()
    evidence = tmp_path / "root-owned-evidence.sha256"
    evidence.write_text(f"{digest}  {stage}\n", encoding="ascii")
    evidence.chmod(0o400)
    verified = subprocess.run(
        ["/usr/bin/sha256sum", "--strict", "--check", str(evidence)],
        text=True,
        capture_output=True,
    )
    assert verified.returncode == 0
    assert stage.read_bytes() == reviewed
    assert stage.stat().st_mode & 0o777 == 0o500
    assert stage.stat().st_uid == os.getuid()


def test_bootstrap_rejects_wrong_external_digest(tmp_path: Path) -> None:
    stage = tmp_path / "saturnin-attestation-admin.py"
    stage.write_bytes(ADMIN.read_bytes())
    evidence = tmp_path / "root-owned-evidence.sha256"
    evidence.write_text(f"{'0' * 64}  {stage}\n", encoding="ascii")
    evidence.chmod(0o400)
    result = subprocess.run(
        ["/usr/bin/sha256sum", "--strict", "--check", str(evidence)],
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "FAILED" in result.stdout


def test_isolated_staged_invocation_ignores_checkout_module_shadow(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    sentinel = tmp_path / "shadow-imported"
    (checkout / "secrets.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('owned')\n",
        encoding="utf-8",
    )
    stage = tmp_path / "saturnin-attestation-admin.py"
    stage.write_bytes(ADMIN.read_bytes())
    stage.chmod(0o500)

    result = subprocess.run(
        ["/usr/bin/python3", "-I", str(stage), "--help"],
        cwd=checkout,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert not sentinel.exists()
    assert result.args[:2] == ["/usr/bin/python3", "-I"]


def test_system_units_sysusers_and_tmpfiles_are_consistent() -> None:
    unit_root = ROOT / "systemd/system"
    service = (unit_root / "saturnin-attestation.service").read_text()
    sysusers = (unit_root / "saturnin-attestation.sysusers").read_text()
    tmpfiles = (unit_root / "saturnin-attestation.tmpfiles").read_text()
    assert "User=saturnin-signer" in service
    assert "Group=saturnin-signer" in service
    assert "system_attestation.py preflight" in service
    assert "LoadCredentialEncrypted=archive.keys:" in service
    assert "LoadCredentialEncrypted=github.token" in service
    assert "LoadCredentialEncrypted=github.policy" in service
    assert "LoadCredentialEncrypted=github.publisher" in service
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in service
    assert "SocketBindDeny=any" in service
    assert "WantedBy=multi-user.target" in service
    assert "saturnin-attestation.socket" not in service
    assert not (unit_root / "saturnin-attestation.socket").exists()
    assert admin.OPERATOR_NAME == "jakubmifek"
    assert admin.OPERATOR_UID == 1000
    assert admin.OPERATOR_GID == 1000
    assert "RuntimeDirectory=" not in service
    assert "g saturnin " not in sysusers
    assert "m jakubmifek " not in sysusers
    assert admin.OPERATOR_NAME not in sysusers
    assert "/usr/sbin/nologin" in sysusers
    assert (
        "d /run/saturnin-attestation 2750 saturnin-signer "
        f"{admin.OPERATOR_NAME} -"
        in tmpfiles
    )
    assert "d /etc/saturnin-attestation 0750 root saturnin-signer -" in tmpfiles
    assert (
        "d /var/lib/saturnin-attestation 0700 "
        "saturnin-signer saturnin-signer -" in tmpfiles
    )


def test_fixed_socket_operator_identity_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    account = SimpleNamespace(
        pw_name=admin.OPERATOR_NAME,
        pw_uid=admin.OPERATOR_UID,
        pw_gid=admin.OPERATOR_GID,
    )
    group = SimpleNamespace(
        gr_name=admin.OPERATOR_NAME,
        gr_gid=admin.OPERATOR_GID,
    )
    monkeypatch.setattr(admin.pwd, "getpwnam", lambda _name: account)
    monkeypatch.setattr(admin.pwd, "getpwuid", lambda _uid: account)
    monkeypatch.setattr(admin.grp, "getgrnam", lambda _name: group)
    monkeypatch.setattr(admin.grp, "getgrgid", lambda _gid: group)
    admin._validate_operator_identity()

    mismatched = SimpleNamespace(
        pw_name=admin.OPERATOR_NAME,
        pw_uid=admin.OPERATOR_UID + 1,
        pw_gid=admin.OPERATOR_GID,
    )
    monkeypatch.setattr(admin.pwd, "getpwnam", lambda _name: mismatched)
    with pytest.raises(admin.InstallError, match="does not match"):
        admin._validate_operator_identity()

    monkeypatch.setattr(
        admin.pwd,
        "getpwnam",
        lambda _name: (_ for _ in ()).throw(KeyError(_name)),
    )
    with pytest.raises(admin.InstallError, match="missing"):
        admin._validate_operator_identity()


def test_live_identity_check_precedes_admin_lock_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_checked = False

    def reject_identity() -> None:
        raise admin.InstallError("identity rejected")

    def track_target(_root: Path, _relative: str) -> Path:
        nonlocal target_checked
        target_checked = True
        raise AssertionError("admin lock target must not be reached")

    monkeypatch.setattr(admin.os, "geteuid", lambda: 0)
    monkeypatch.setattr(admin, "_validate_admin_execution", lambda: None)
    monkeypatch.setattr(admin, "_validate_operator_identity", reject_identity)
    monkeypatch.setattr(admin, "_safe_target", track_target)

    with pytest.raises(admin.InstallError, match="identity rejected"):
        admin.main(["install"])
    assert not target_checked


def test_system_admin_rejects_checkout_execution_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(admin.os, "geteuid", lambda: 0)
    monkeypatch.setattr(admin, "ADMIN_SOURCE", ADMIN)
    with pytest.raises(admin.InstallError, match="fixed root-owned path"):
        admin.main(["install"])


def test_system_admin_accepts_only_root_controlled_staged_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = SimpleNamespace(
        st_mode=admin.stat.S_IFREG | 0o500,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
    )
    parent = SimpleNamespace(
        st_mode=admin.stat.S_IFDIR | 0o700,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
    )

    monkeypatch.setattr(admin, "ADMIN_SOURCE", admin.ADMIN_STAGE)
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda path: source if path == admin.ADMIN_STAGE else parent,
    )
    admin._validate_admin_execution()

    source.st_mode |= 0o020
    with pytest.raises(admin.InstallError, match="not root-controlled"):
        admin._validate_admin_execution()
