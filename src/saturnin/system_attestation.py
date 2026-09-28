"""Client and dedicated-system-service implementation for review attestations.

The service is deliberately independent of the checkout.  Its installed copy,
configuration, credentials, and replay database are administrator-owned.  A
caller supplies only an object identifier; every authorization field is
obtained again from GitHub.
"""

from __future__ import annotations

import argparse
from collections import defaultdict, deque
import hashlib
import hmac
import json
import os
import pwd
import re
import signal
import socket
import sqlite3
import stat
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

MAX_REQUEST = 16 * 1024
MAX_RESPONSE = 128 * 1024
SOCKET_PATH = Path("/run/saturnin-attestation/sign.sock")
CONFIG_PATH = Path("/etc/saturnin-attestation/config.json")
STATE_PATH = Path("/var/lib/saturnin-attestation/authorizations.sqlite3")
ISSUE_MARKER = "saturnin-attestation:v1 "
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32,64}")
_ATTESTATION_FIELDS = {
    "schema", "kind", "repository", "subject", "author", "author_role",
    "reviewer", "reviewer_identity", "verdict", "zero_context", "head_sha",
    "issue_digest", "destination_repo", "authorization_evidence_id", "nonce",
    "expires_at", "attestation_id", "key_id", "signature",
}


class SystemAttestationError(RuntimeError):
    """A fail-closed request, authorization, or service identity error."""


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _repo(value: object) -> str:
    if not isinstance(value, str) or not _REPO.fullmatch(value):
        raise SystemAttestationError("repository must be an owner/repository slug")
    return value.casefold()


def _subject(repo: str, number: object) -> str:
    if type(number) is not int or not 0 < number <= 2_147_483_647:
        raise SystemAttestationError("subject number is invalid")
    return f"{repo}#{number}"


def _iso(value: object) -> datetime:
    if not isinstance(value, str):
        raise SystemAttestationError("expiry must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemAttestationError("expiry is invalid") from exc
    if parsed.tzinfo is None:
        raise SystemAttestationError("expiry must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class ServiceConfig:
    repositories: frozenset[str]
    pr_reviewers: frozenset[str]
    issue_reviewers: frozenset[str]
    allowed_verdicts: frozenset[str]
    github_api: str = "https://api.github.com"
    request_timeout_seconds: float = 10
    maximum_issue_marker_ttl_seconds: int = 3600
    authorization_limit: int = 30
    authorization_window_seconds: int = 60

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> "ServiceConfig":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemAttestationError("service configuration is unavailable") from exc
        if not isinstance(raw, dict) or set(raw) - {
            "repositories", "pr_reviewers", "issue_reviewers", "allowed_verdicts",
            "github_api", "request_timeout_seconds", "maximum_issue_marker_ttl_seconds",
            "authorization_limit", "authorization_window_seconds",
        }:
            raise SystemAttestationError("service configuration schema is invalid")
        api = raw.get("github_api", "https://api.github.com")
        parsed = urllib.parse.urlsplit(api)
        if parsed != urllib.parse.SplitResult("https", "api.github.com", "", "", ""):
            raise SystemAttestationError("github_api must be exactly https://api.github.com")
        try:
            repositories = frozenset(_repo(item) for item in raw["repositories"])
            pr_reviewers = frozenset(str(item).casefold() for item in raw["pr_reviewers"])
            issue_reviewers = frozenset(
                str(item).casefold() for item in raw["issue_reviewers"]
            )
            verdicts = frozenset(str(item).casefold() for item in raw["allowed_verdicts"])
        except (KeyError, TypeError) as exc:
            raise SystemAttestationError("service configuration lists are invalid") from exc
        if not repositories or not pr_reviewers or not issue_reviewers:
            raise SystemAttestationError("service allowlists must not be empty")
        if not verdicts or not verdicts <= {"approved", "changes_requested", "rejected"}:
            raise SystemAttestationError("allowed verdicts are invalid")
        try:
            timeout = float(raw.get("request_timeout_seconds", 10))
            marker_ttl = int(raw.get("maximum_issue_marker_ttl_seconds", 3600))
            authorization_limit = int(raw.get("authorization_limit", 30))
            authorization_window = int(raw.get("authorization_window_seconds", 60))
        except (TypeError, ValueError) as exc:
            raise SystemAttestationError("service configuration bounds are invalid") from exc
        if (
            not 0 < timeout <= 30
            or not 0 < marker_ttl <= 3600
            or not 0 < authorization_limit <= 1000
            or not 0 < authorization_window <= 3600
        ):
            raise SystemAttestationError("service configuration bounds are invalid")
        return cls(
            repositories, pr_reviewers, issue_reviewers, verdicts,
            request_timeout_seconds=timeout,
            maximum_issue_marker_ttl_seconds=marker_ttl,
            authorization_limit=authorization_limit,
            authorization_window_seconds=authorization_window,
        )


class GitHub:
    """Small fixed-origin GitHub API client with bounded pagination."""

    def __init__(
        self,
        config: ServiceConfig,
        token: str = "",
        transport: Callable[[str], Any] | None = None,
        request_transport: Callable[[urllib.request.Request, float], Any] | None = None,
    ) -> None:
        self.config = config
        self.token = token
        self.transport = transport
        self.request_transport = request_transport or _open_without_redirects

    def get(self, path: str) -> Any:
        if not re.fullmatch(r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9?&=._/-]+", path):
            raise SystemAttestationError("GitHub API path is invalid")
        if ".." in path or "//" in path or "\\" in path:
            raise SystemAttestationError("GitHub API path is invalid")
        if self.transport:
            return self.transport(path)
        request = urllib.request.Request(
            self.config.github_api + path,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "saturnin-dedicated-attestation/1",
                **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
            },
        )
        try:
            with self.request_transport(
                request, self.config.request_timeout_seconds
            ) as response:
                if response.geturl().split("?", 1)[0] != (
                    self.config.github_api + path.split("?", 1)[0]
                ):
                    raise SystemAttestationError("GitHub redirect was refused")
                body = response.read(MAX_RESPONSE + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise SystemAttestationError("GitHub authorization lookup failed") from exc
        if len(body) > MAX_RESPONSE:
            raise SystemAttestationError("GitHub response is oversized")
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise SystemAttestationError("GitHub response is malformed") from exc

    def pages(self, path: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for page in range(1, 11):
            values = self.get(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
            if not isinstance(values, list):
                raise SystemAttestationError("GitHub list response is malformed")
            if len(values) > 100:
                raise SystemAttestationError("GitHub page is oversized")
            result.extend(item for item in values if isinstance(item, dict))
            if len(values) < 100:
                return result
        raise SystemAttestationError("GitHub authorization pagination limit exceeded")


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _open_without_redirects(
    request: urllib.request.Request, timeout: float
) -> Any:
    return urllib.request.build_opener(_RejectRedirects).open(request, timeout=timeout)


class DedicatedSigner:
    def __init__(
        self,
        config: ServiceConfig,
        github: GitHub,
        current_key: bytes,
        previous_key: bytes | None,
        state_path: Path = STATE_PATH,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if len(current_key) < 32:
            raise SystemAttestationError("current signing credential is invalid")
        if previous_key is not None and (
            len(previous_key) < 32 or hmac.compare_digest(current_key, previous_key)
        ):
            raise SystemAttestationError("previous signing credential is invalid")
        self.config, self.github = config, github
        self.current_key, self.previous_key = current_key, previous_key
        self.state_path = state_path
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.lock = threading.Lock()
        state_path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS consumed ("
                "evidence_id TEXT PRIMARY KEY, scope_hash TEXT NOT NULL, "
                "attestation TEXT NOT NULL, created_at TEXT NOT NULL)"
            )

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.state_path, timeout=10, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def authorize(self, request: dict[str, Any]) -> str:
        if not isinstance(request, dict) or set(request) != {
            "action", "kind", "repository", "number", "destination_repo"
        } or request["action"] != "authorize":
            raise SystemAttestationError("request schema is invalid")
        repository = _repo(request["repository"])
        destination = _repo(request["destination_repo"])
        if repository not in self.config.repositories or destination not in self.config.repositories:
            raise SystemAttestationError("repository is not allowlisted")
        number = request["number"]
        subject = _subject(repository, number)
        if request["kind"] == "pr":
            evidence = self._pr(repository, number, subject, destination)
        elif request["kind"] == "issue":
            evidence = self._issue(repository, number, subject, destination)
        else:
            raise SystemAttestationError("review kind is invalid")
        scope_hash = hashlib.sha256(_canonical(evidence)).hexdigest()
        evidence_id = evidence["authorization_evidence_id"]
        with self.lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT scope_hash, attestation FROM consumed WHERE evidence_id=?",
                (evidence_id,),
            ).fetchone()
            if row:
                db.execute("COMMIT")
                if hmac.compare_digest(row[0], scope_hash):
                    return str(row[1])
                raise SystemAttestationError("authorization evidence was already consumed")
            evidence["attestation_id"] = (
                "T-00000000-github:" + evidence["nonce"].ljust(64, "0")[:64]
            )
            evidence["key_id"] = hashlib.sha256(self.current_key).hexdigest()
            evidence["signature"] = hmac.new(
                self.current_key, _canonical_signed(evidence), hashlib.sha256
            ).hexdigest()
            attestation = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
            db.execute(
                "INSERT INTO consumed VALUES (?, ?, ?, ?)",
                (evidence_id, scope_hash, attestation, self.now().isoformat()),
            )
            db.execute("COMMIT")
            return attestation

    def verify(self, attestation: str) -> dict[str, Any]:
        if not isinstance(attestation, str) or len(attestation) > MAX_RESPONSE:
            raise SystemAttestationError("attestation is invalid")
        try:
            payload = json.loads(attestation)
        except json.JSONDecodeError as exc:
            raise SystemAttestationError("attestation is malformed") from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != _ATTESTATION_FIELDS
            or payload.get("schema") != "saturnin-attestation-v2"
        ):
            raise SystemAttestationError("attestation schema is invalid")
        if _iso(payload.get("expires_at")) <= self.now():
            raise SystemAttestationError("attestation is expired")
        signature = payload.get("signature")
        key_id = payload.get("key_id")
        if not isinstance(signature, str) or not _DIGEST.fullmatch(signature):
            raise SystemAttestationError("attestation signature is invalid")
        unsigned = {key: value for key, value in payload.items() if key != "signature"}
        keys = [self.current_key] + ([self.previous_key] if self.previous_key else [])
        for index, key in enumerate(keys):
            assert key is not None
            if (
                hmac.compare_digest(hashlib.sha256(key).hexdigest(), str(key_id))
                and hmac.compare_digest(
                    hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest(),
                    signature,
                )
            ):
                return {"status": "verified", "previous": index == 1}
        raise SystemAttestationError("attestation signature does not match")

    def _pr(
        self, repo: str, number: int, subject: str, destination: str
    ) -> dict[str, Any]:
        pull = self.github.get(f"/repos/{repo}/pulls/{number}")
        if not isinstance(pull, dict):
            raise SystemAttestationError("pull request response is malformed")
        head = (pull.get("head") or {}).get("sha")
        author = (pull.get("user") or {}).get("login")
        if not isinstance(head, str) or not _SHA.fullmatch(head.casefold()):
            raise SystemAttestationError("pull request head is invalid")
        if not isinstance(author, str) or not author:
            raise SystemAttestationError("pull request author is invalid")
        latest: dict[str, dict[str, Any]] = {}
        for review in self.github.pages(f"/repos/{repo}/pulls/{number}/reviews"):
            user = review.get("user") or {}
            login = str(user.get("login", "")).casefold()
            review_id = review.get("id")
            if (
                type(review_id) is not int
                or
                login not in self.config.pr_reviewers
                or user.get("type") != "Bot"
                or review.get("commit_id", "").casefold() != head.casefold()
            ):
                continue
            state = str(review.get("state", "")).casefold()
            if state not in {"approved", "changes_requested", "rejected", "dismissed"}:
                continue
            old = latest.get(login)
            order = (str(review.get("submitted_at", "")), review_id)
            old_order = (
                str(old.get("submitted_at", "")), int(old.get("id", 0))
            ) if old else ("", -1)
            if order >= old_order:
                latest[login] = review
        blocking = [
            value for value in latest.values()
            if str(value.get("state", "")).casefold()
            in {"changes_requested", "rejected", "dismissed"}
        ]
        approved = [
            value for value in latest.values()
            if str(value.get("state", "")).casefold() == "approved"
        ]
        if blocking or not approved:
            raise SystemAttestationError("exact head has no current allowed approval")
        review = max(approved, key=lambda value: (
            str(value.get("submitted_at", "")), int(value.get("id", 0))
        ))
        verdict = str(review["state"]).casefold()
        if verdict not in self.config.allowed_verdicts:
            raise SystemAttestationError("review verdict is not allowed")
        reviewer = str((review.get("user") or {}).get("login", "")).casefold()
        nonce = hashlib.sha256(f"pr:{repo}:{review['id']}:{head}".encode()).hexdigest()
        return self._evidence(
            "pr", repo, subject, author, "pr-reviewer", verdict, head.casefold(), "",
            destination, f"github:review:{review['id']}", nonce, reviewer,
            self.now().timestamp() + 300,
        )

    def _issue(
        self, repo: str, number: int, subject: str, destination: str
    ) -> dict[str, Any]:
        issue = self.github.get(f"/repos/{repo}/issues/{number}")
        if not isinstance(issue, dict) or "pull_request" in issue:
            raise SystemAttestationError("issue response is malformed")
        author = str((issue.get("user") or {}).get("login", ""))
        if not author:
            raise SystemAttestationError("issue author is invalid")
        digest = hashlib.sha256(_canonical({
            "title": str(issue.get("title", "")), "body": str(issue.get("body") or "")
        })).hexdigest()
        candidates: list[tuple[int, dict[str, Any], str, datetime]] = []
        for comment in self.github.pages(f"/repos/{repo}/issues/{number}/comments"):
            body = comment.get("body")
            user = comment.get("user") or {}
            login = str(user.get("login", "")).casefold()
            comment_id = comment.get("id")
            if (
                not isinstance(body, str) or not body.startswith(ISSUE_MARKER)
                or type(comment_id) is not int
                or login not in self.config.issue_reviewers or user.get("type") != "Bot"
            ):
                continue
            try:
                marker = json.loads(body[len(ISSUE_MARKER):])
                created = _iso(comment.get("created_at"))
                updated = _iso(comment.get("updated_at"))
            except json.JSONDecodeError:
                continue
            except SystemAttestationError:
                continue
            if isinstance(marker, dict) and created == updated:
                candidates.append((comment_id, marker, login, created))
        if not candidates:
            raise SystemAttestationError("issue has no valid review marker")
        comment_id, marker, reviewer_identity, comment_created = max(
            candidates, key=lambda item: item[0]
        )
        required = {
            "repository", "issue", "digest", "author", "reviewer_role", "verdict",
            "zero_context", "destination_repo", "expiry", "nonce",
        }
        if set(marker) != required:
            raise SystemAttestationError("issue review marker schema is invalid")
        if not all(
            isinstance(marker[name], str)
            for name in (
                "repository", "digest", "author", "reviewer_role", "verdict",
                "destination_repo", "expiry", "nonce",
            )
        ) or type(marker["issue"]) is not int or type(marker["zero_context"]) is not bool:
            raise SystemAttestationError("issue review marker types are invalid")
        expiry = _iso(marker["expiry"])
        now = self.now()
        if (
            expiry <= now
            or expiry <= comment_created
            or (expiry - comment_created).total_seconds()
            > self.config.maximum_issue_marker_ttl_seconds
        ):
            raise SystemAttestationError("issue review marker is expired or overlong")
        if (
            _repo(marker["repository"]) != repo
            or marker["issue"] != number
            or marker["digest"] != digest
            or marker["author"].casefold() != author.casefold()
            or marker["reviewer_role"] != "issue-reviewer"
            or marker["verdict"] not in self.config.allowed_verdicts
            or marker["zero_context"] is not True
            or _repo(marker["destination_repo"]) != destination
            or not isinstance(marker["nonce"], str)
            or not _NONCE.fullmatch(marker["nonce"])
        ):
            raise SystemAttestationError("issue review marker scope does not match")
        return self._evidence(
            "issue", repo, subject, author, "issue-reviewer", marker["verdict"], "",
            digest, destination, f"github:comment:{comment_id}", marker["nonce"],
            reviewer_identity, expiry.timestamp(),
        )

    @staticmethod
    def _evidence(
        kind: str, repository: str, subject: str, author: str, reviewer_role: str,
        verdict: str, head: str, digest: str, destination: str, evidence_id: str,
        nonce: str, reviewer_identity: str, expiry: float,
    ) -> dict[str, Any]:
        return {
            "schema": "saturnin-attestation-v2", "kind": kind,
            "repository": repository, "subject": subject,
            "author": f"github:{author}", "author_role": "github-user",
            "reviewer": reviewer_role, "reviewer_identity": reviewer_identity,
            "verdict": verdict, "zero_context": True, "head_sha": head,
            "issue_digest": digest, "destination_repo": destination,
            "authorization_evidence_id": evidence_id, "nonce": nonce,
            "expires_at": datetime.fromtimestamp(expiry, timezone.utc).isoformat(),
        }


def _canonical_signed(payload: dict[str, Any]) -> bytes:
    return _canonical({key: value for key, value in payload.items() if key != "signature"})


def request_attestation(
    *, kind: str, repository: str, number: int, destination_repo: str,
    socket_path: Path = SOCKET_PATH, expected_uid: int | None = None,
) -> str:
    request = {
        "action": "authorize", "kind": kind, "repository": repository,
        "number": number, "destination_repo": destination_repo,
    }
    encoded = _canonical(request) + b"\n"
    if len(encoded) > MAX_REQUEST:
        raise SystemAttestationError("request is oversized")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    try:
        client.connect(str(socket_path))
        pid, uid, _ = struct.unpack("3i", client.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        ))
        trusted_uid = (
            pwd.getpwnam("saturnin-signer").pw_uid
            if expected_uid is None else expected_uid
        )
        if uid != trusted_uid or pid <= 1 or not _trusted_service_process(pid):
            raise SystemAttestationError("dedicated signer identity is not trusted")
        client.sendall(encoded)
        body = bytearray()
        while b"\n" not in body and len(body) <= MAX_RESPONSE:
            chunk = client.recv(4096)
            if not chunk:
                break
            body.extend(chunk)
    finally:
        client.close()
    if len(body) > MAX_RESPONSE or b"\n" not in body:
        raise SystemAttestationError("dedicated signer response is invalid")
    try:
        response = json.loads(bytes(body).split(b"\n", 1)[0])
    except json.JSONDecodeError as exc:
        raise SystemAttestationError("dedicated signer response is malformed") from exc
    if not isinstance(response, dict) or set(response) not in ({"attestation"}, {"error"}):
        raise SystemAttestationError("dedicated signer response schema is invalid")
    if "error" in response:
        raise SystemAttestationError(str(response["error"]))
    if not isinstance(response["attestation"], str):
        raise SystemAttestationError("dedicated signer response is malformed")
    return response["attestation"]


def verify_attestation(
    attestation: str, *, socket_path: Path = SOCKET_PATH, expected_uid: int | None = None
) -> dict[str, Any]:
    response = _socket_request(
        {"action": "verify", "attestation": attestation},
        socket_path=socket_path,
        expected_uid=expected_uid,
    )
    if set(response) == {"error"}:
        raise SystemAttestationError(str(response["error"]))
    if set(response) != {"status", "previous"} or response["status"] != "verified":
        raise SystemAttestationError("dedicated signer verification failed")
    return response


def _socket_request(
    request: dict[str, Any], *, socket_path: Path, expected_uid: int | None
) -> dict[str, Any]:
    encoded = _canonical(request) + b"\n"
    if len(encoded) > MAX_REQUEST:
        raise SystemAttestationError("request is oversized")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    try:
        client.connect(str(socket_path))
        pid, uid, _ = struct.unpack(
            "3i",
            client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
        )
        trusted_uid = (
            pwd.getpwnam("saturnin-signer").pw_uid
            if expected_uid is None else expected_uid
        )
        if uid != trusted_uid or pid <= 1 or not _trusted_service_process(pid):
            raise SystemAttestationError("dedicated signer identity is not trusted")
        client.sendall(encoded)
        body = bytearray()
        while b"\n" not in body and len(body) <= MAX_RESPONSE:
            chunk = client.recv(4096)
            if not chunk:
                break
            body.extend(chunk)
    finally:
        client.close()
    if len(body) > MAX_RESPONSE or b"\n" not in body:
        raise SystemAttestationError("dedicated signer response is invalid")
    try:
        response = json.loads(bytes(body).split(b"\n", 1)[0])
    except json.JSONDecodeError as exc:
        raise SystemAttestationError("dedicated signer response is malformed") from exc
    if not isinstance(response, dict):
        raise SystemAttestationError("dedicated signer response schema is invalid")
    return response


def _trusted_service_process(pid: int) -> bool:
    """Bind the peer to the installed executable and system service cgroup."""
    try:
        executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        metadata = executable.stat()
        cgroup = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8")
        command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        runtime = Path("/usr/lib/saturnin-attestation/system_attestation.py")
        runtime_metadata = runtime.lstat()
    except OSError:
        return False
    return (
        executable.parent in {Path("/usr/bin"), Path("/bin")}
        and executable.name.startswith("python3")
        and metadata.st_uid == 0
        and not metadata.st_mode & 0o022
        and any(
            part == b"/usr/lib/saturnin-attestation/system_attestation.py"
            for part in command
        )
        and stat.S_ISREG(runtime_metadata.st_mode)
        and runtime_metadata.st_uid == 0
        and runtime_metadata.st_nlink == 1
        and not runtime_metadata.st_mode & 0o022
        and "saturnin-attestation.service" in cgroup
    )


def _credential(name: str, *, optional: bool = False) -> bytes:
    directory = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
    path = directory / name
    try:
        value = path.read_bytes()
    except OSError:
        if optional:
            return b""
        raise SystemAttestationError(f"required credential {name} is unavailable") from None
    if b"\0" in value or len(value) > 4096:
        raise SystemAttestationError(f"credential {name} is invalid")
    return value.rstrip(b"\n")


class AuthorizationLimiter:
    def __init__(
        self, limit: int, window: int, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.limit, self.window, self.clock = limit, window, clock
        self._events: dict[int, deque[float]] = defaultdict(deque)

    def allow(self, uid: int) -> bool:
        now = self.clock()
        events = self._events[uid]
        while events and events[0] <= now - self.window:
            events.popleft()
        if len(events) >= self.limit:
            return False
        events.append(now)
        return True


def _audit(outcome: str, evidence_hash: str = "", scope_hash: str = "") -> None:
    print(
        json.dumps(
            {
                "event": "attestation_authorization",
                "outcome": outcome,
                "evidence_hash": evidence_hash,
                "scope_hash": scope_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        file=sys.stderr,
        flush=True,
    )


def serve() -> None:
    config = ServiceConfig.load()
    current = _credential("current.key")
    previous = _credential("previous.key", optional=True) or None
    token = _credential("github.token", optional=True).decode()
    signer = DedicatedSigner(config, GitHub(config, token), current, previous)
    listener = socket.socket(fileno=3)
    if listener.family != socket.AF_UNIX:
        listener.close()
        raise SystemAttestationError("socket activation listener must be AF_UNIX")
    listener.settimeout(1)
    stopping = threading.Event()
    limiter = AuthorizationLimiter(
        config.authorization_limit, config.authorization_window_seconds
    )
    old_handlers = {
        signum: signal.signal(signum, lambda _signum, _frame: stopping.set())
        for signum in (signal.SIGTERM, signal.SIGINT)
    }
    while not stopping.is_set():
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            continue
        with connection:
            connection.settimeout(10)
            outcome = "denied"
            evidence_hash = ""
            scope_hash = ""
            try:
                _pid, peer_uid, _gid = struct.unpack(
                    "3i",
                    connection.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                    ),
                )
                data = bytearray()
                while b"\n" not in data and len(data) <= MAX_REQUEST:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    data.extend(chunk)
                if len(data) > MAX_REQUEST or b"\n" not in data:
                    raise SystemAttestationError("request is malformed or oversized")
                request = json.loads(bytes(data).split(b"\n", 1)[0])
                if not isinstance(request, dict):
                    raise SystemAttestationError("request schema is invalid")
                if request.get("action") == "authorize":
                    if not limiter.allow(peer_uid):
                        outcome = "rate_limited"
                        raise SystemAttestationError("authorization rate limit exceeded")
                    attestation = signer.authorize(request)
                    payload = json.loads(attestation)
                    evidence_hash = hashlib.sha256(
                        str(payload["authorization_evidence_id"]).encode()
                    ).hexdigest()
                    scope_hash = hashlib.sha256(
                        _canonical(
                            {
                                key: payload[key]
                                for key in (
                                    "kind", "repository", "subject",
                                    "destination_repo", "head_sha", "issue_digest",
                                )
                            }
                        )
                    ).hexdigest()
                    outcome = "authorized"
                    response = {"attestation": attestation}
                elif set(request) == {"action", "attestation"} and request["action"] == "verify":
                    outcome = "verified"
                    response = signer.verify(request["attestation"])
                else:
                    raise SystemAttestationError("request schema is invalid")
            except (SystemAttestationError, json.JSONDecodeError, TimeoutError) as exc:
                response = {"error": str(exc)}
            except Exception:
                response = {"error": "internal authorization failure"}
            if outcome != "verified":
                _audit(outcome, evidence_hash, scope_hash)
            connection.sendall(_canonical(response) + b"\n")
    listener.close()
    for signum, handler in old_handlers.items():
        signal.signal(signum, handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["serve"])
    args = parser.parse_args(argv)
    if args.action == "serve":
        serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
