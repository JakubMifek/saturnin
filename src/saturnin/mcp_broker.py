"""Authenticated Unix-socket relay for host-side MCP processes."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import selectors
import socket
import stat
import subprocess
import sys
from pathlib import Path

MAX_HANDSHAKE_BYTES = 4096


class BrokerError(RuntimeError):
    pass


def _relay(left_read: int, left_write: int, right_read: int, right_write: int) -> None:
    selector = selectors.DefaultSelector()
    selector.register(left_read, selectors.EVENT_READ, right_write)
    selector.register(right_read, selectors.EVENT_READ, left_write)
    open_reads = {left_read, right_read}
    try:
        while open_reads:
            for key, _ in selector.select():
                data = os.read(key.fd, 64 * 1024)
                if not data:
                    return
                view = memoryview(data)
                while view:
                    written = os.write(key.data, view)
                    view = view[written:]
    finally:
        selector.close()


def _read_handshake(connection: socket.socket) -> str:
    data = bytearray()
    while len(data) <= MAX_HANDSHAKE_BYTES:
        chunk = connection.recv(1)
        if not chunk:
            break
        if chunk == b"\n":
            break
        data.extend(chunk)
    if not data or len(data) > MAX_HANDSHAKE_BYTES:
        raise BrokerError("invalid broker handshake")
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerError("invalid broker handshake") from exc
    capability = payload.get("capability") if isinstance(payload, dict) else None
    if not isinstance(capability, str) or not capability:
        raise BrokerError("invalid broker handshake")
    return capability


def serve(
    socket_path: Path,
    capability: str,
    token_fd: int,
    command: list[str],
) -> int:
    token = os.read(token_fd, 64 * 1024)
    os.close(token_fd)
    if not token or b"\x00" in token:
        raise BrokerError("invalid broker credential")
    socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    socket_path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    child: subprocess.Popen[bytes] | None = None
    try:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(1)
        listener.settimeout(30)
        connection, _ = listener.accept()
        with connection:
            supplied = _read_handshake(connection)
            if not hmac.compare_digest(supplied, capability):
                raise BrokerError("broker authentication failed")
            connection.sendall(b"OK\n")
            environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "GITHUB_PERSONAL_ACCESS_TOKEN": token.decode("utf-8"),
            }
            child = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=environment,
            )
            assert child.stdin is not None
            assert child.stdout is not None
            _relay(
                connection.fileno(),
                connection.fileno(),
                child.stdout.fileno(),
                child.stdin.fileno(),
            )
            child.stdin.close()
        return child.wait(timeout=5)
    finally:
        token = b""
        listener.close()
        socket_path.unlink(missing_ok=True)
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def client(socket_path: Path, capability: str) -> int:
    metadata = socket_path.stat(follow_symlinks=False)
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        raise BrokerError("unsafe broker socket")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    with connection:
        connection.connect(str(socket_path))
        handshake = json.dumps({"capability": capability}, separators=(",", ":"))
        connection.sendall(handshake.encode("utf-8") + b"\n")
        response = bytearray()
        while len(response) < 16:
            chunk = connection.recv(1)
            if not chunk or chunk == b"\n":
                break
            response.extend(chunk)
        if response != b"OK":
            raise BrokerError("broker authentication failed")
        _relay(sys.stdin.fileno(), sys.stdout.fileno(), connection.fileno(), connection.fileno())
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    server = subparsers.add_parser("serve")
    server.add_argument("--socket", type=Path, required=True)
    server.add_argument("--capability", required=True)
    server.add_argument("--token-fd", type=int, required=True)
    server.add_argument("command", nargs=argparse.REMAINDER)
    client_parser = subparsers.add_parser("client")
    client_parser.add_argument("--socket", type=Path, required=True)
    client_parser.add_argument("--capability", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.mode == "serve":
            if not args.command:
                raise BrokerError("broker server command is required")
            return serve(args.socket, args.capability, args.token_fd, args.command)
        return client(args.socket, args.capability)
    except (BrokerError, OSError, subprocess.SubprocessError) as exc:
        print(f"mcp-broker: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
