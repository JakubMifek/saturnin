"""Private review-attestation signing service and scoped session client."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import json
import os
import secrets
import signal
import socket
import stat
import struct
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .board import Board, BoardError
from .config import Config, default_config
from .credentials import (
    ATTESTATION_CREDENTIAL,
    PREVIOUS_ATTESTATION_CREDENTIAL,
    CredentialError,
    _lifecycle_lock,
    _rotation_state,
    credential_generation,
    execution_signer_ready,
    systemd_credential,
)

MAX_MESSAGE = 128 * 1024
SESSION_TTL_SECONDS = 15 * 60
ENV_SESSION_SOCKET = "SATURNIN_REVIEW_SIGNING_SOCKET"
ENV_SESSION_NONCE = "SATURNIN_REVIEW_SIGNING_NONCE"


class AttestationServiceError(RuntimeError):
    pass


def _disable_process_dump() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:
        raise AttestationServiceError("could not protect attestation service process memory")


def service_socket(config: Config) -> Path:
    configured = (
        config.governance.get("review", {})
        .get("attestation", {})
        .get("service_socket", "%t/saturnin-attestation/control.sock")
    )
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    if not runtime or not Path(runtime).is_absolute():
        raise AttestationServiceError("XDG_RUNTIME_DIR is required for attestation service")
    return Path(str(configured).replace("%t", runtime))


def _send(connection: socket.socket, payload: dict[str, Any]) -> None:
    connection.sendall(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )


def _receive(connection: socket.socket) -> dict[str, Any]:
    data = bytearray()
    while len(data) <= MAX_MESSAGE:
        chunk = connection.recv(min(4096, MAX_MESSAGE + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if not data or len(data) > MAX_MESSAGE or b"\n" not in data:
        raise AttestationServiceError("invalid attestation service request")
    try:
        payload = json.loads(bytes(data).split(b"\n", 1)[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationServiceError("invalid attestation service request") from exc
    if not isinstance(payload, dict):
        raise AttestationServiceError("invalid attestation service request")
    return payload


def _peer_pid(connection: socket.socket) -> int:
    pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != os.getuid() or pid <= 1:
        raise AttestationServiceError("attestation service peer is not trusted")
    return pid


def _process_stat(pid: int) -> tuple[int, int] | None:
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    prefix, separator, suffix = value.rpartition(")")
    fields = suffix.split()
    if (
        not separator
        or not prefix.startswith(f"{pid} (")
        or len(fields) < 20
    ):
        return None
    try:
        parent = int(fields[1])
        started = int(fields[19])
    except ValueError:
        return None
    if parent < 0 or started < 0:
        return None
    return parent, started


def _process_start_time(pid: int) -> int | None:
    process = _process_stat(pid)
    return process[1] if process is not None else None


def _is_descendant(pid: int, ancestor: int, ancestor_start: int) -> bool:
    current = pid
    for _ in range(64):
        if current == ancestor:
            return _process_start_time(current) == ancestor_start
        process = _process_stat(current)
        if process is None:
            return False
        current = process[0]
        if current <= 1:
            return False
    return False


def _process_cgroups(pid: int) -> tuple[str, ...] | None:
    try:
        lines = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return None
    paths: list[str] = []
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) != 3 or not parts[2].startswith("/"):
            return None
        paths.append(parts[2])
    return tuple(sorted(paths)) if paths else None


def _process_namespace_pids(pid: int) -> tuple[int, ...] | None:
    try:
        lines = Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return None
    for line in lines:
        if not line.startswith("NSpid:"):
            continue
        try:
            values = tuple(int(value) for value in line.split()[1:])
        except ValueError:
            return None
        if values and values[0] == pid and all(value > 0 for value in values):
            return values
        return None
    return None


@dataclass
class _ProcessIdentity:
    pid: int
    started: int
    pidfd: int
    pid_namespace: tuple[int, int]
    namespace_pids: tuple[int, ...]
    cgroups: tuple[str, ...]

    def close(self) -> None:
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1


def _process_identity(pid: int) -> _ProcessIdentity | None:
    if pid <= 1 or not hasattr(os, "pidfd_open"):
        return None
    try:
        pidfd = os.pidfd_open(pid)
    except OSError:
        return None
    try:
        process = _process_stat(pid)
        namespace = os.stat(f"/proc/{pid}/ns/pid")
        namespace_pids = _process_namespace_pids(pid)
        cgroups = _process_cgroups(pid)
        if (
            process is None
            or namespace_pids is None
            or cgroups is None
            or _process_start_time(pid) != process[1]
        ):
            os.close(pidfd)
            return None
        return _ProcessIdentity(
            pid,
            process[1],
            pidfd,
            (namespace.st_dev, namespace.st_ino),
            namespace_pids,
            cgroups,
        )
    except OSError:
        os.close(pidfd)
        return None


def _identity_is_live(identity: _ProcessIdentity) -> bool:
    try:
        signal.pidfd_send_signal(identity.pidfd, 0)
    except OSError:
        return False
    return _process_start_time(identity.pid) == identity.started


def _peer_identity(connection: socket.socket) -> _ProcessIdentity:
    identity = _process_identity(_peer_pid(connection))
    if identity is None:
        raise AttestationServiceError("attestation service peer identity is unavailable")
    return identity


def _peer_matches_root(
    peer: _ProcessIdentity, root: _ProcessIdentity
) -> bool:
    return (
        _identity_is_live(peer)
        and _identity_is_live(root)
        and peer.cgroups == root.cgroups
        and len(peer.namespace_pids) >= len(root.namespace_pids)
        and (
            peer.pid_namespace == root.pid_namespace
            or len(peer.namespace_pids) > len(root.namespace_pids)
        )
        and _is_descendant(peer.pid, root.pid, root.started)
    )


def _cgroup_contains_unit(cgroups: tuple[str, ...], unit: str) -> bool:
    return any(unit in Path(path).parts for path in cgroups)


def _trusted_supervisor(pid: int | _ProcessIdentity, config: Config) -> bool:
    owned = not isinstance(pid, _ProcessIdentity)
    identity = pid if isinstance(pid, _ProcessIdentity) else _process_identity(pid)
    if identity is None:
        return False
    try:
        if not _identity_is_live(identity):
            return False
        executable = Path(f"/proc/{identity.pid}/exe").resolve()
        trusted_python = (config.root / ".venv" / "bin" / "python").resolve()
        units = (
            config.governance.get("review", {})
            .get("attestation", {})
            .get("supervisor_units", [])
        )
        return (
            executable == trusted_python
            and isinstance(units, list)
            and any(
                isinstance(unit, str)
                and _cgroup_contains_unit(identity.cgroups, unit)
                for unit in units
            )
            and _identity_is_live(identity)
        )
    except OSError:
        return False
    finally:
        if owned:
            identity.close()


def _execution_key(master: str, scope: dict[str, str]) -> str:
    from .review import execution_scoped_review_attestation_key

    return execution_scoped_review_attestation_key(
        master,
        scope["role"],
        scope["task_id"],
        scope["nonce"],
        scope["subject"],
        scope["head_sha"],
        scope["issue_digest"],
    )


@dataclass
class _Session:
    scope: dict[str, str]
    socket_path: Path
    listener: socket.socket
    expires_at: float
    root_pid: int = 0
    root_start: int = 0
    root_identity: _ProcessIdentity | None = None
    used: bool = False


class SigningService:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or default_config()
        self.current = systemd_credential(ATTESTATION_CREDENTIAL)
        self.previous = systemd_credential(PREVIOUS_ATTESTATION_CREDENTIAL)
        if not self.current or not self.previous:
            raise AttestationServiceError("attestation service credentials are unavailable")
        with _lifecycle_lock(exclusive=False):
            self.generation = credential_generation()
            if not execution_signer_ready():
                raise AttestationServiceError(
                    "master rotation and migration sealing are required before signer startup"
                )
        self.sessions: dict[str, _Session] = {}
        self.lock = threading.Lock()

    def _validate_scope(self, request: dict[str, Any]) -> dict[str, str]:
        required = {
            "task_id",
            "role",
            "subject",
            "kind",
            "author",
            "head_sha",
            "issue_digest",
            "destination_repo",
        }
        if set(request) != required | {"action"} or not all(
            isinstance(request[name], str) for name in required
        ):
            raise AttestationServiceError("invalid reviewer signing scope")
        try:
            task = Board(self.config).get(request["task_id"])
        except BoardError as exc:
            raise AttestationServiceError("reviewer signing task is unavailable") from exc
        role = request["role"].strip().lower()
        allowed: set[str] = set()
        review = self.config.governance.get("review", {})
        for kind in ("pr", "issue"):
            allowed.update(review.get(kind, {}).get("allowed_reviewer_roles", []))
        if (
            role not in allowed
            or task.role != role
            or task.kind != f"{request['kind']}-review"
            or task.review_subject != request["subject"]
            or task.review_author != request["author"]
            or task.review_head_sha != request["head_sha"]
            or task.review_issue_digest != (request["issue_digest"] or None)
            or (
                (task.review_destination_repo or task.repo or "")
                if request["kind"] == "issue"
                else ""
            )
            != request["destination_repo"]
            or not request["author"]
            or task.state not in {"routed", "in_progress"}
        ):
            raise AttestationServiceError("reviewer signing scope does not match routed task")
        scope = {name: request[name] for name in required}
        scope["role"] = role
        scope["nonce"] = secrets.token_hex(32)
        return scope

    def _open(self, request: dict[str, Any]) -> dict[str, Any]:
        scope = self._validate_scope(request)
        directory = service_socket(self.config).parent / "sessions"
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = directory / f"{scope['task_id']}-{scope['nonce']}.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(1)
        ttl = int(
            self.config.governance.get("review", {})
            .get("attestation", {})
            .get("session_ttl_seconds", SESSION_TTL_SECONDS)
        )
        session = _Session(scope, path, listener, time.monotonic() + ttl)
        with self.lock:
            self.sessions[scope["nonce"]] = session
        threading.Thread(target=self._serve_session, args=(session,), daemon=True).start()
        return {"status": "ready", "socket": str(path), "nonce": scope["nonce"]}

    def _activate(
        self, request: dict[str, Any], supervisor: _ProcessIdentity
    ) -> dict[str, Any]:
        nonce = request.get("nonce")
        pid = request.get("root_pid")
        started = request.get("root_start")
        if (
            not isinstance(nonce, str)
            or not isinstance(pid, int)
            or isinstance(pid, bool)
            or not isinstance(started, int)
            or isinstance(started, bool)
        ):
            raise AttestationServiceError("invalid reviewer process binding")
        root = _process_identity(pid)
        if root is None:
            raise AttestationServiceError("reviewer process identity does not match")
        with self.lock:
            session = self.sessions.get(nonce)
            if session is None or session.used or time.monotonic() >= session.expires_at:
                root.close()
                raise AttestationServiceError("reviewer signing session is unavailable")
            if (
                root.started != started
                or root.pid_namespace != supervisor.pid_namespace
                or root.cgroups != supervisor.cgroups
                or not _identity_is_live(supervisor)
                or not _is_descendant(pid, supervisor.pid, supervisor.started)
            ):
                root.close()
                raise AttestationServiceError("reviewer process identity does not match")
            if session.root_identity is not None:
                session.root_identity.close()
            session.root_pid = pid
            session.root_start = started
            session.root_identity = root
        return {"status": "activated"}

    def _cancel(self, request: dict[str, Any]) -> dict[str, Any]:
        nonce = request.get("nonce")
        if not isinstance(nonce, str):
            raise AttestationServiceError("invalid reviewer signing session")
        with self.lock:
            session = self.sessions.pop(nonce, None)
            if session is not None:
                session.used = True
        if session is not None:
            if session.root_identity is not None:
                session.root_identity.close()
                session.root_identity = None
            session.listener.close()
            session.socket_path.unlink(missing_ok=True)
        return {"status": "cancelled"}

    def _serve_session(self, session: _Session) -> None:
        try:
            session.listener.settimeout(
                max(1, session.expires_at - time.monotonic())
            )
            connection, _ = session.listener.accept()
            with connection:
                peer = _peer_identity(connection)
                try:
                    if (
                        session.root_identity is None
                        or not _peer_matches_root(peer, session.root_identity)
                        or time.monotonic() >= session.expires_at
                    ):
                        raise AttestationServiceError(
                            "reviewer signing peer does not match launch"
                        )
                    request = _receive(connection)
                    self._sign(session, request, connection)
                finally:
                    peer.close()
        except (OSError, AttestationServiceError):
            pass
        finally:
            with self.lock:
                session.used = True
                self.sessions.pop(session.scope["nonce"], None)
            if session.root_identity is not None:
                session.root_identity.close()
                session.root_identity = None
            session.listener.close()
            session.socket_path.unlink(missing_ok=True)

    def _sign(
        self, session: _Session, request: dict[str, Any], connection: socket.socket
    ) -> None:
        from .review import sign_review_attestation

        with self.lock:
            if session.used or time.monotonic() >= session.expires_at:
                raise AttestationServiceError("reviewer signing session is unavailable")
            session.used = True
        if request.get("nonce") != session.scope["nonce"]:
            raise AttestationServiceError("reviewer signing nonce does not match")
        for name in (
            "subject",
            "kind",
            "author",
            "reviewer",
            "head_sha",
            "issue_digest",
            "destination_repo",
        ):
            expected_name = "role" if name == "reviewer" else name
            if request.get(name) != session.scope[expected_name]:
                raise AttestationServiceError("reviewer signing request exceeds launch scope")
        if request.get("zero_context") is not True or request.get("verdict") not in {
            "approved",
            "changes_requested",
            "rejected",
            "dismissed",
        }:
            raise AttestationServiceError("reviewer signing request is invalid")
        with _lifecycle_lock(exclusive=False):
            if (
                _rotation_state() != "ready"
                or not execution_signer_ready()
                or not secrets.compare_digest(
                    self.generation, credential_generation()
                )
            ):
                raise AttestationServiceError(
                    "attestation service must restart after credential lifecycle change"
                )
            attestation_id = f"{session.scope['task_id']}:{session.scope['nonce']}"
            attestation = sign_review_attestation(
                key=_execution_key(self.current, session.scope),
                subject=session.scope["subject"],
                kind=session.scope["kind"],
                author=session.scope["author"],
                reviewer=session.scope["role"],
                verdict=request["verdict"],
                zero_context=True,
                head_sha=session.scope["head_sha"],
                issue_digest=session.scope["issue_digest"],
                destination_repo=session.scope["destination_repo"],
                attestation_id=attestation_id,
            )
        _send(connection, {"attestation": attestation})

    def handle(self, connection: socket.socket) -> None:
        peer = _peer_identity(connection)
        try:
            request = _receive(connection)
            action = request.get("action")
            if action in {"open", "activate", "cancel"} and not _trusted_supervisor(
                peer, self.config
            ):
                raise AttestationServiceError(
                    "attestation service caller is not trusted supervisor"
                )
            if action == "open":
                response = self._open(request)
            elif action == "activate":
                response = self._activate(request, peer)
            elif action == "cancel":
                response = self._cancel(request)
            elif action == "verify":
                response = self._verify(request)
            elif action == "verify_manifest":
                response = self._verify_manifest(request)
            else:
                raise AttestationServiceError("unknown attestation service action")
            _send(connection, response)
        finally:
            peer.close()

    def _verify(self, request: dict[str, Any]) -> dict[str, Any]:
        from .review import (
            _canonical_attestation_payload,
            _execution_key_for_payload,
        )

        encoded = request.get("attestation")
        if not isinstance(encoded, str):
            raise AttestationServiceError("invalid attestation verification request")
        try:
            payload = json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise AttestationServiceError("invalid review attestation") from exc
        if not isinstance(payload, dict):
            raise AttestationServiceError("invalid review attestation")
        signature = payload.get("signature")
        key_id = payload.get("key_id")
        for previous, master in ((False, self.current), (True, self.previous)):
            try:
                key = _execution_key_for_payload(master, payload)
                expected_id = hashlib.sha256(key.encode()).hexdigest()
                expected = hmac.new(
                    key.encode(),
                    _canonical_attestation_payload(payload),
                    hashlib.sha256,
                ).hexdigest()
            except (KeyError, TypeError, ValueError):
                continue
            if (
                isinstance(key_id, str)
                and isinstance(signature, str)
                and hmac.compare_digest(key_id, expected_id)
                and hmac.compare_digest(signature, expected)
            ):
                return {"status": "verified", "previous": previous}
        raise AttestationServiceError("review attestation signature does not match")

    def _verify_manifest(self, request: dict[str, Any]) -> dict[str, Any]:
        from .review import _manifest_payload, _rotation_manifest_key

        entries = request.get("entries")
        cutoff = request.get("migration_cutoff")
        ledger_digest = request.get("ledger_digest")
        signature = request.get("signature")
        if (
            not isinstance(entries, list)
            or not isinstance(cutoff, str)
            or not isinstance(ledger_digest, str)
            or not isinstance(signature, str)
        ):
            raise AttestationServiceError("invalid rotation manifest request")
        expected = hmac.new(
            _rotation_manifest_key(self.current),
            _manifest_payload(entries, cutoff, ledger_digest),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise AttestationServiceError(
                "previous-key rotation manifest signature does not match"
            )
        return {"status": "verified"}

    def serve(self) -> None:
        path = service_socket(self.config)
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        sessions = path.parent / "sessions"
        sessions.mkdir(mode=0o700, exist_ok=True)
        for stale in sessions.iterdir():
            try:
                metadata = stale.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.getuid():
                stale.unlink(missing_ok=True)
        path.unlink(missing_ok=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(16)
            while True:
                connection, _ = listener.accept()
                with connection:
                    try:
                        self.handle(connection)
                    except AttestationServiceError as exc:
                        _send(connection, {"error": str(exc)})
        finally:
            listener.close()
            path.unlink(missing_ok=True)


def request(config: Config, payload: dict[str, Any]) -> dict[str, Any]:
    path = service_socket(config)
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise AttestationServiceError("attestation service socket is unsafe")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with connection:
        connection.connect(str(path))
        _send(connection, payload)
        response = _receive(connection)
    if "error" in response:
        raise AttestationServiceError(str(response["error"]))
    return response


def sign_from_session(payload: dict[str, Any]) -> str:
    path = os.environ.get(ENV_SESSION_SOCKET, "")
    nonce = os.environ.get(ENV_SESSION_NONCE, "")
    if not path or not nonce:
        raise AttestationServiceError("reviewer signing session is unavailable")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with connection:
        connection.connect(path)
        _send(connection, {**payload, "nonce": nonce})
        response = _receive(connection)
    attestation = response.get("attestation")
    if not isinstance(attestation, str):
        raise AttestationServiceError("reviewer signing session failed")
    return attestation


def verify_with_service(config: Config, attestation: str) -> dict[str, Any]:
    response = request(
        config, {"action": "verify", "attestation": attestation}
    )
    if response.get("status") != "verified":
        raise AttestationServiceError("review attestation verification failed")
    return response


def verify_manifest_with_service(
    config: Config,
    entries: list[dict[str, str]],
    migration_cutoff: str,
    ledger_digest: str,
    signature: str,
) -> None:
    response = request(
        config,
        {
            "action": "verify_manifest",
            "entries": entries,
            "migration_cutoff": migration_cutoff,
            "ledger_digest": ledger_digest,
            "signature": signature,
        },
    )
    if response.get("status") != "verified":
        raise AttestationServiceError("rotation manifest verification failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["serve"])
    args = parser.parse_args()
    try:
        if args.command == "serve":
            _disable_process_dump()
            SigningService().serve()
    except (AttestationServiceError, CredentialError, OSError) as exc:
        print(f"saturnin-attestation: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
