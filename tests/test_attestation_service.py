from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import pytest

from saturnin.attestation_service import (
    AttestationServiceError,
    SigningService,
    _Session,
    _is_descendant,
    _process_start_time,
    _trusted_supervisor,
    sign_from_session,
)
from saturnin.config import Config


@pytest.fixture(autouse=True)
def stable_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "saturnin.attestation_service.credential_generation",
        lambda: "test-generation",
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


def test_process_binding_uses_pid_and_start_identity() -> None:
    pid = __import__("os").getpid()
    started = _process_start_time(pid)
    assert started is not None
    assert _is_descendant(pid, pid, started)
    assert not _is_descendant(pid, pid, started + 1)
