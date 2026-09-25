from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from saturnin.attestation_service import (
    AttestationServiceError,
    _ProcessIdentity,
    SigningService,
    _Session,
    _identity_is_live,
    _is_descendant,
    _peer_identity,
    _peer_matches_root,
    _process_identity,
    _process_start_time,
    _trusted_attestation_server,
    _trusted_supervisor,
    request,
    service_socket,
    sign_from_session,
    verify_manifest_with_service,
    verify_with_service,
)
from saturnin.config import Config


@pytest.fixture(autouse=True)
def stable_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "saturnin.attestation_service.credential_generation",
        lambda: "test-generation",
    )
    monkeypatch.setattr(
        "saturnin.attestation_service.execution_signer_ready",
        lambda: True,
    )


def _scope() -> dict[str, str]:
    return {
        "task_id": "T-20260924-review",
        "role": "pr-reviewer",
        "subject": "JakubMifek/saturnin#6",
        "kind": "pr",
        "author": "ops-worker",
        "head_sha": "a" * 40,
        "issue_digest": "",
        "destination_repo": "jakubmifek/saturnin",
        "nonce": "b" * 64,
    }


def _request(**changes: object) -> dict[str, object]:
    scope = _scope()
    request: dict[str, object] = {
        "nonce": scope["nonce"],
        "subject": scope["subject"],
        "kind": scope["kind"],
        "author": scope["author"],
        "reviewer": scope["role"],
        "verdict": "approved",
        "zero_context": True,
        "head_sha": scope["head_sha"],
        "issue_digest": scope["issue_digest"],
        "destination_repo": scope["destination_repo"],
    }
    request.update(changes)
    return request


def _service(config: Config) -> SigningService:
    service = SigningService.__new__(SigningService)
    service.config = config
    service.current = "current-test-master"
    service.previous = "previous-test-master"
    service.generation = "test-generation"
    service.sessions = {}
    service.lock = threading.Lock()
    return service


def _session(path: Path) -> _Session:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    return _Session(_scope(), path, listener, time.monotonic() + 60)


def test_one_shot_signing_binds_task_role_head_and_nonce(
    config: Config, tmp_path: Path
) -> None:
    service = _service(config)
    session = _session(tmp_path / "unused.sock")
    sender, receiver = socket.socketpair()
    try:
        service._sign(session, _request(), sender)
        response = json.loads(receiver.recv(128 * 1024))
        attestation = json.loads(response["attestation"])
        assert attestation["attestation_id"] == (
            "T-20260924-review:" + "b" * 64
        )
        assert attestation["head_sha"] == "a" * 40
        assert service._verify(
            {"action": "verify", "attestation": response["attestation"]}
        ) == {"status": "verified", "previous": False}
        with pytest.raises(AttestationServiceError, match="unavailable"):
            service._sign(session, _request(), sender)
    finally:
        sender.close()
        receiver.close()
        session.listener.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("reviewer", "issue-reviewer"),
        ("head_sha", "c" * 40),
        ("subject", "JakubMifek/saturnin#7"),
        ("nonce", "d" * 64),
    ],
)
def test_signing_scope_mismatch_fails_closed(
    config: Config, tmp_path: Path, field: str, value: str
) -> None:
    service = _service(config)
    session = _session(tmp_path / "unused.sock")
    sender, receiver = socket.socketpair()
    try:
        with pytest.raises(AttestationServiceError, match="match|scope"):
            service._sign(session, _request(**{field: value}), sender)
        with pytest.raises(AttestationServiceError, match="unavailable"):
            service._sign(session, _request(), sender)
    finally:
        sender.close()
        receiver.close()
        session.listener.close()


def test_ordinary_worker_without_private_session_cannot_sign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SATURNIN_REVIEW_SIGNING_SOCKET", raising=False)
    monkeypatch.delenv("SATURNIN_REVIEW_SIGNING_NONCE", raising=False)
    with pytest.raises(AttestationServiceError, match="unavailable"):
        sign_from_session(_request())


def test_same_uid_process_outside_supervisor_cgroup_is_not_trusted(
    config: Config,
) -> None:
    assert not _trusted_supervisor(__import__("os").getpid(), config)


def test_generation_change_invalidates_inflight_session(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(config)
    monkeypatch.setattr(
        "saturnin.attestation_service.credential_generation",
        lambda: "rotated-generation",
    )
    session = _session(tmp_path / "unused.sock")
    sender, receiver = socket.socketpair()
    try:
        with pytest.raises(AttestationServiceError, match="must restart"):
            service._sign(session, _request(), sender)
        with pytest.raises(AttestationServiceError, match="unavailable"):
            service._sign(session, _request(), sender)
    finally:
        sender.close()
        receiver.close()
        session.listener.close()


def test_signer_startup_requires_completed_rotation(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "saturnin.attestation_service.systemd_credential",
        lambda name: f"{name}-test-value",
    )
    monkeypatch.setattr(
        "saturnin.attestation_service.execution_signer_ready",
        lambda: False,
    )
    with pytest.raises(AttestationServiceError, match="rotation and migration"):
        SigningService(config)


def test_process_binding_uses_pid_and_start_identity() -> None:
    pid = os.getpid()
    started = _process_start_time(pid)
    assert started is not None
    assert _is_descendant(pid, pid, started)
    assert not _is_descendant(pid, pid, started + 1)


def test_crafted_process_name_cannot_spoof_unrelated_sibling_ancestry() -> None:
    root = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    attacker = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import ctypes,sys,time;"
                "ctypes.CDLL(None).prctl(15,sys.argv[1].encode(),0,0,0);"
                "print('ready',flush=True);time.sleep(30)"
            ),
            f") S {root.pid} x",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert attacker.stdout is not None
        assert attacker.stdout.readline().strip() == "ready"
        root_started = _process_start_time(root.pid)
        assert root_started is not None
        assert not _is_descendant(attacker.pid, root.pid, root_started)
    finally:
        attacker.terminate()
        root.terminate()
        attacker.wait(timeout=5)
        root.wait(timeout=5)


def test_process_identity_is_pidfd_bound_and_namespace_aware() -> None:
    identity = _process_identity(os.getpid())
    assert identity is not None
    try:
        assert _identity_is_live(identity)
        assert identity.namespace_pids[0] == os.getpid()
        assert identity.pid_namespace[0] > 0
        assert identity.pid_namespace[1] > 0
    finally:
        identity.close()
    assert not _identity_is_live(identity)


def test_peer_binding_rejects_sibling_namespace_and_cgroup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "saturnin.attestation_service._identity_is_live", lambda identity: True
    )
    monkeypatch.setattr(
        "saturnin.attestation_service._is_descendant",
        lambda pid, ancestor, started: True,
    )
    root = _ProcessIdentity(10, 100, -1, (1, 20), (10,), ("/trusted.service",))
    sibling_namespace = _ProcessIdentity(
        11, 101, -1, (1, 21), (11,), ("/trusted.service",)
    )
    nested_namespace = _ProcessIdentity(
        12, 102, -1, (1, 22), (12, 1), ("/trusted.service",)
    )
    wrong_cgroup = _ProcessIdentity(
        13, 103, -1, (1, 20), (13,), ("/attacker.service",)
    )

    assert not _peer_matches_root(sibling_namespace, root)
    assert _peer_matches_root(nested_namespace, root)
    assert not _peer_matches_root(wrong_cgroup, root)


def _fake_attestation_service(
    listener: socket.socket, response: dict[str, object]
) -> threading.Thread:
    def respond() -> None:
        connection, _ = listener.accept()
        with connection:
            try:
                connection.sendall(
                    json.dumps(response, separators=(",", ":")).encode() + b"\n"
                )
            except BrokenPipeError:
                pass

    thread = threading.Thread(target=respond)
    thread.start()
    return thread


def test_control_socket_replacement_cannot_forge_verification(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    config.governance["review"]["attestation"]["service_socket"] = "%t/s"
    path = service_socket(config)
    path.parent.mkdir(parents=True)
    original = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    original.bind(str(path))
    path.unlink()
    replacement.bind(str(path))
    replacement.listen(1)
    thread = _fake_attestation_service(
        replacement, {"status": "verified", "previous": False}
    )
    try:
        with pytest.raises(AttestationServiceError, match="identity is not trusted"):
            verify_with_service(config, '{"key_id":"forged","signature":"forged"}')
    finally:
        original.close()
        replacement.close()
        thread.join(timeout=5)


def test_fake_same_uid_responder_cannot_forge_manifest_verification(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    config.governance["review"]["attestation"]["service_socket"] = "%t/s"
    path = service_socket(config)
    path.parent.mkdir(parents=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    thread = _fake_attestation_service(listener, {"status": "verified"})
    try:
        with pytest.raises(AttestationServiceError, match="identity is not trusted"):
            verify_manifest_with_service(config, [], "cutoff", "digest", "signature")
    finally:
        listener.close()
        thread.join(timeout=5)


def test_attestation_server_requires_exact_executable_and_cgroup(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _ProcessIdentity(
        10,
        100,
        -1,
        (1, 20),
        (10,),
        ("/user.slice/saturnin-attestation.service",),
    )
    trusted_python = (config.root / ".venv" / "bin" / "python").resolve()
    monkeypatch.setattr(
        "saturnin.attestation_service._identity_is_live", lambda candidate: True
    )
    monkeypatch.setattr(
        "saturnin.attestation_service._process_executable",
        lambda candidate: trusted_python,
    )
    assert _trusted_attestation_server(identity, config)

    identity.cgroups = ("/user.slice/attacker.service",)
    assert not _trusted_attestation_server(identity, config)
    identity.cgroups = ("/user.slice/saturnin-attestation.service",)
    monkeypatch.setattr(
        "saturnin.attestation_service._process_executable",
        lambda candidate: Path("/usr/bin/not-saturnin"),
    )
    assert not _trusted_attestation_server(identity, config)


def test_attestation_server_pid_reuse_race_fails_closed(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _ProcessIdentity(
        10,
        100,
        -1,
        (1, 20),
        (10,),
        ("/user.slice/saturnin-attestation.service",),
    )
    checks = iter((True, False))
    monkeypatch.setattr(
        "saturnin.attestation_service._identity_is_live",
        lambda candidate: next(checks),
    )
    monkeypatch.setattr(
        "saturnin.attestation_service._process_executable",
        lambda candidate: (config.root / ".venv" / "bin" / "python").resolve(),
    )
    assert not _trusted_attestation_server(identity, config)


def test_attestation_server_missing_proc_identity_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, server = socket.socketpair()
    monkeypatch.setattr(
        "saturnin.attestation_service._process_identity", lambda pid: None
    )
    try:
        with pytest.raises(AttestationServiceError, match="identity is unavailable"):
            _peer_identity(client)
    finally:
        client.close()
        server.close()
