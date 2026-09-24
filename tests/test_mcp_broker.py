from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest

from saturnin.mcp_broker import BrokerError, serve


def _connect_when_ready(path: Path) -> socket.socket:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(str(path))
            return connection
        except (FileNotFoundError, ConnectionRefusedError):
            connection.close()
            time.sleep(0.01)
    pytest.fail("broker did not create its socket")


def _serve_in_thread(path: Path, capability: str) -> tuple[threading.Thread, list[BaseException]]:
    read_fd, write_fd = os.pipe()
    failures: list[BaseException] = []

    def target() -> None:
        try:
            serve(path, capability, read_fd, ["/bin/cat"])
        except BaseException as exc:
            failures.append(exc)

    thread = threading.Thread(target=target)
    thread.start()
    os.write(write_fd, b"public-test-token")
    os.close(write_fd)
    return thread, failures


def test_broker_authenticates_before_starting_relay(tmp_path: Path) -> None:
    path = tmp_path / "broker.sock"
    thread, failures = _serve_in_thread(path, "expected-capability")
    with _connect_when_ready(path) as connection:
        connection.sendall(
            json.dumps({"capability": "wrong-capability"}).encode() + b"\n"
        )
        assert connection.recv(16) == b""
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], BrokerError)
    assert str(failures[0]) == "broker authentication failed"
    assert not path.exists()


def test_broker_socket_is_private_and_relays_after_authentication(tmp_path: Path) -> None:
    path = tmp_path / "broker.sock"
    thread, failures = _serve_in_thread(path, "task-capability")
    with _connect_when_ready(path) as connection:
        assert path.stat().st_mode & 0o777 == 0o600
        connection.sendall(
            json.dumps({"capability": "task-capability"}).encode() + b"\n"
        )
        assert connection.recv(3) == b"OK\n"
        connection.sendall(b"bounded request\n")
        assert connection.recv(16) == b"bounded request\n"
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert failures == []
    assert not path.exists()
