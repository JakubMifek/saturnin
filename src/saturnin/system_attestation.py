"""Client and dedicated-system-service implementation for review attestations.

The service is deliberately independent of the checkout.  Its installed copy,
configuration, credentials, and replay database are administrator-owned.  A
caller supplies only an object identifier; every authorization field is
obtained again from GitHub.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from collections import defaultdict, deque
from contextlib import closing
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

MAX_REQUEST = 16 * 1024
MAX_RESPONSE = 128 * 1024
SOCKET_PATH = Path("/run/saturnin-attestation/sign.sock")
SOCKET_GROUP_GID = 1000
CONFIG_PATH = Path("/etc/saturnin-attestation/config.json")
STATE_PATH = Path("/var/lib/saturnin-attestation/authorizations.sqlite3")
ISSUE_MARKER = "saturnin-attestation:v1 "
ISSUE_SUBMISSION_MARKER = "<!-- saturnin-protected-submission:v1 {} -->"
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32,64}")
_EXECUTION_ATTESTATION_ID = re.compile(
    r"T-[0-9]{8}-[a-z0-9]+:[0-9a-f]{64}"
)
_ROLE_ATTESTATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_ATTESTATION_FIELDS = {
    "schema", "kind", "repository", "subject", "author", "author_role",
    "reviewer", "reviewer_identity", "verdict", "zero_context", "head_sha",
    "issue_digest", "destination_repo", "authorization_evidence_id", "nonce",
    "expires_at", "attestation_id", "key_id", "signature",
}
_LEGACY_ATTESTED_FIELDS = {
    "subject", "kind", "author", "reviewer", "verdict", "zero_context",
    "head_sha", "issue_digest", "destination_repo",
}
_LEGACY_REQUIRED_FIELDS = _LEGACY_ATTESTED_FIELDS | {
    "attestation_id", "signature",
}
ROLE_SCOPED_KEY_CONTEXT = "saturnin-review-attestation"
EXECUTION_SCOPED_KEY_CONTEXT = "saturnin-review-attestation-execution:v1"
ARCHIVE_VERSION = 1
ARCHIVE_MAX_KEYS = 16
MAX_CREDENTIAL = 128 * 1024


class SystemAttestationError(RuntimeError):
    """A fail-closed request, authorization, or service identity error."""


class GitHubMutationError(SystemAttestationError):
    def __init__(self, message: str, *, safe_to_retry: bool = False):
        super().__init__(message)
        self.safe_to_retry = safe_to_retry


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _repo(value: object) -> str:
    if not isinstance(value, str) or not _REPO.fullmatch(value):
        raise SystemAttestationError("repository must be an owner/repository slug")
    if any(component in {".", ".."} for component in value.split("/")):
        raise SystemAttestationError("repository must be an owner/repository slug")
    return value.casefold()


def _github_issue_url(value: object, repo: str, number: object) -> bool:
    if not isinstance(value, str) or type(number) is not int:
        return False
    parsed = urllib.parse.urlsplit(value)
    return (
        parsed.scheme == "https"
        and parsed.netloc == "github.com"
        and not parsed.query
        and not parsed.fragment
        and parsed.path.casefold() == f"/{repo.casefold()}/issues/{number}"
    )


def current_pr_review(
    config: ServiceConfig,
    github: GitHub,
    repo: str,
    number: int,
    *,
    now: datetime,
) -> dict[str, Any]:
    pull = github.get(f"/repos/{repo}/pulls/{number}")
    if not isinstance(pull, dict):
        raise SystemAttestationError("pull request response is malformed")
    head = (pull.get("head") or {}).get("sha")
    author = (pull.get("user") or {}).get("login")
    if not isinstance(head, str) or not _SHA.fullmatch(head.casefold()):
        raise SystemAttestationError("pull request head is invalid")
    if not isinstance(author, str) or not author:
        raise SystemAttestationError("pull request author is invalid")
    latest: dict[str, tuple[datetime, int, dict[str, Any]]] = {}
    for review in github.pages(f"/repos/{repo}/pulls/{number}/reviews"):
        user = review.get("user") or {}
        login = str(user.get("login", "")).casefold()
        review_id = review.get("id")
        if (
            type(review_id) is not int
            or login not in config.pr_reviewers
            or user.get("type") != "Bot"
            or review.get("commit_id", "").casefold() != head.casefold()
        ):
            continue
        state = str(review.get("state", "")).casefold()
        if state not in {
            "approved", "changes_requested", "rejected", "dismissed"
        }:
            continue
        try:
            submitted = _iso(review.get("submitted_at"))
        except SystemAttestationError:
            continue
        if submitted > now:
            continue
        order = (submitted, review_id)
        old = latest.get(login)
        if old is None or order >= old[:2]:
            latest[login] = (submitted, review_id, review)
    reviews = [item[2] for item in latest.values()]
    blocking = [
        value for value in reviews
        if str(value.get("state", "")).casefold()
        in {"changes_requested", "rejected", "dismissed"}
    ]
    approved = [
        value for value in reviews
        if str(value.get("state", "")).casefold() == "approved"
    ]
    if blocking or len(approved) != 1:
        raise SystemAttestationError("exact head has no current allowed approval")
    review = approved[0]
    reviewer = str((review.get("user") or {}).get("login", "")).casefold()
    if author.casefold() == reviewer:
        raise SystemAttestationError("reviewer is not independent")
    return {
        "repository": repo,
        "number": number,
        "head_sha": head.casefold(),
        "base_ref": str((pull.get("base") or {}).get("ref", "")),
        "base_repository": str(
            ((pull.get("base") or {}).get("repo") or {}).get("full_name", "")
        ).casefold(),
        "pull_state": str(pull.get("state", "")).casefold(),
        "draft": pull.get("draft"),
        "author": author,
        "reviewer_identity": reviewer,
        "review_id": int(review["id"]),
        "review_state": str(review["state"]).casefold(),
        "submitted_at": _iso(review["submitted_at"]).isoformat(),
    }


def read_only_pr_gate(
    config: ServiceConfig,
    github: GitHub,
    repo: str,
    number: int,
    expected_head: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    repo = _repo(repo)
    if (
        repo not in config.repositories
        or type(number) is not int
        or number < 1
        or not isinstance(expected_head, str)
        or not _SHA.fullmatch(expected_head)
    ):
        raise SystemAttestationError("read-only review scope is invalid")
    current_time = now or datetime.now(timezone.utc)
    first = current_pr_review(config, github, repo, number, now=current_time)
    second = current_pr_review(config, github, repo, number, now=current_time)
    if first != second:
        raise SystemAttestationError(
            "GitHub state changed during read-only review authorization"
        )
    if (
        first["head_sha"] != expected_head.casefold()
        or first["base_repository"] != repo
        or first["base_ref"] not in config.pr_base_refs
        or first["pull_state"] != "open"
        or first["draft"] is not False
        or first["review_state"] not in config.allowed_verdicts
    ):
        raise SystemAttestationError("pull request live scope changed")
    return first


def publish_issue_review(
    config: ServiceConfig,
    github: GitHub,
    repository: str,
    number: int,
    destination_repo: str,
    labels: list[str],
    expected_digest: str,
    *,
    now: datetime | None = None,
    ttl_seconds: int = 600,
    nonce: str | None = None,
) -> dict[str, Any]:
    repo = _repo(repository)
    destination = _repo(destination_repo)
    current_time = now or datetime.now(timezone.utc)
    destinations = config.issue_destinations or config.repositories
    if repo not in config.repositories or destination not in destinations:
        raise SystemAttestationError("protected issue repository is not allowed")
    if (
        type(number) is not int
        or number < 1
        or type(ttl_seconds) is not int
        or ttl_seconds < 60
        or ttl_seconds > config.maximum_issue_marker_ttl_seconds
        or len(labels) > 20
        or any(
            not isinstance(label, str)
            or not re.fullmatch(r"[A-Za-z0-9:_. -]{1,50}", label)
            for label in labels
        )
        or len(set(labels)) != len(labels)
        or not isinstance(expected_digest, str)
        or not _DIGEST.fullmatch(expected_digest)
    ):
        raise SystemAttestationError("issue review publication scope is invalid")
    issue = github.get(f"/repos/{repo}/issues/{number}")
    if not isinstance(issue, dict) or "pull_request" in issue:
        raise SystemAttestationError("issue response is malformed")
    if str(issue.get("state", "")).casefold() != "open":
        raise SystemAttestationError("source issue is not open")
    title = issue.get("title")
    body = issue.get("body") or ""
    author = str((issue.get("user") or {}).get("login", ""))
    if not isinstance(title, str) or not isinstance(body, str) or not author:
        raise SystemAttestationError("issue response is malformed")
    if author.casefold() in config.issue_reviewers:
        raise SystemAttestationError("issue reviewer cannot approve its own issue")
    existing = [
        comment for comment in github.pages(
            f"/repos/{repo}/issues/{number}/comments"
        )
        if (
            isinstance(comment.get("body"), str)
            and comment["body"].startswith(ISSUE_MARKER)
            and str((comment.get("user") or {}).get("login", "")).casefold()
            in config.issue_reviewers
        )
    ]
    if existing:
        raise SystemAttestationError(
            "issue already has protected review marker evidence"
        )
    marker_nonce = nonce or secrets.token_hex(32)
    if not _NONCE.fullmatch(marker_nonce):
        raise SystemAttestationError("issue review nonce is invalid")
    digest = hashlib.sha256(_canonical({"title": title, "body": body})).hexdigest()
    if digest != expected_digest:
        raise SystemAttestationError(
            "source issue content changed after review approval"
        )
    marker = {
        "repository": repo,
        "issue": number,
        "digest": digest,
        "author": author,
        "reviewer_role": "issue-reviewer",
        "verdict": "approved",
        "zero_context": True,
        "destination_repo": destination,
        "labels": sorted(labels),
        "expiry": (current_time + timedelta(seconds=ttl_seconds)).isoformat(),
        "nonce": marker_nonce,
    }
    marker_body = ISSUE_MARKER + json.dumps(
        marker, sort_keys=True, separators=(",", ":")
    )
    response = github.post_issue_comment(repo, number, marker_body)
    response_user = response.get("user") or {}
    created = _iso(response.get("created_at"))
    updated = _iso(response.get("updated_at"))
    if (
        type(response.get("id")) is not int
        or response.get("body") != marker_body
        or str(response_user.get("login", "")).casefold()
        not in config.issue_reviewers
        or response_user.get("type") != "Bot"
        or created != updated
        or created < current_time - timedelta(seconds=30)
        or created > current_time + timedelta(seconds=30)
    ):
        raise SystemAttestationError(
            "GitHub issue reviewer identity or marker response is invalid"
        )
    return {
        "comment_id": response["id"],
        "reviewer_identity": str(response_user["login"]).casefold(),
        "issue_digest": digest,
        "expiry": marker["expiry"],
        "nonce": marker_nonce,
        "marker": marker_body,
    }


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
    issue_destinations: frozenset[str] = frozenset()
    github_api: str = "https://api.github.com"
    request_timeout_seconds: float = 10
    maximum_issue_marker_ttl_seconds: int = 3600
    authorization_limit: int = 30
    authorization_window_seconds: int = 60
    pr_base_refs: tuple[str, ...] = ("main",)
    required_check_runs: tuple[str, ...] = ("test",)
    action_ttl_seconds: int = 60
    protected_actor_login: str = "saturnin-merge-bot"
    publisher_actor_login: str = "saturnin-issue-publisher[bot]"

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
            "pr_base_refs", "required_check_runs", "action_ttl_seconds",
            "protected_actor_login",
            "publisher_actor_login",
            "issue_destinations",
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
            issue_destinations = frozenset(
                _repo(item) for item in raw.get("issue_destinations", [])
            )
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
            action_ttl = int(raw.get("action_ttl_seconds", 60))
        except (TypeError, ValueError) as exc:
            raise SystemAttestationError("service configuration bounds are invalid") from exc
        if (
            not 0 < timeout <= 30
            or not 0 < marker_ttl <= 3600
            or not 0 < authorization_limit <= 1000
            or not 0 < authorization_window <= 3600
            or not 5 <= action_ttl <= 300
        ):
            raise SystemAttestationError("service configuration bounds are invalid")
        base_refs = raw.get("pr_base_refs", ["main"])
        check_runs = raw.get("required_check_runs", ["test"])
        protected_actor = str(
            raw.get("protected_actor_login", "saturnin-merge-bot")
        ).casefold()
        publisher_actor = str(
            raw.get("publisher_actor_login", "saturnin-issue-publisher[bot]")
        ).casefold()
        if (
            not isinstance(base_refs, list)
            or not isinstance(check_runs, list)
            or not base_refs
            or not check_runs
            or any(
                not isinstance(value, str)
                or not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", value)
                for value in [*base_refs, *check_runs]
            )
            or len(set(base_refs)) != len(base_refs)
            or len(set(check_runs)) != len(check_runs)
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})", protected_actor)
            or protected_actor in pr_reviewers
            or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})\[bot\]",
                publisher_actor,
            )
            or publisher_actor in pr_reviewers
            or publisher_actor in issue_reviewers
        ):
            raise SystemAttestationError("protected action policy is invalid")
        return cls(
            repositories, pr_reviewers, issue_reviewers, verdicts,
            issue_destinations=issue_destinations,
            request_timeout_seconds=timeout,
            maximum_issue_marker_ttl_seconds=marker_ttl,
            authorization_limit=authorization_limit,
            authorization_window_seconds=authorization_window,
            pr_base_refs=tuple(base_refs),
            required_check_runs=tuple(check_runs),
            action_ttl_seconds=action_ttl,
            protected_actor_login=protected_actor,
            publisher_actor_login=publisher_actor,
        )


class GitHub:
    """Small fixed-origin GitHub API client with bounded pagination."""

    def __init__(
        self,
        config: ServiceConfig,
        token: str = "",
        transport: Callable[[str], Any] | None = None,
        request_transport: Callable[[urllib.request.Request, float], Any] | None = None,
        mutation_transport: Callable[[str, str, dict[str, Any]], Any] | None = None,
    ) -> None:
        self.config = config
        self.token = token
        self.transport = transport
        self.request_transport = request_transport or _open_without_redirects
        self.mutation_transport = mutation_transport

    def get(self, path: str) -> Any:
        if not (
            path == "/user"
            or re.fullmatch(
                r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9?&=._/-]+)?",
                path,
            )
        ):
            raise SystemAttestationError("GitHub API path is invalid")
        if ".." in path or "//" in path or "\\" in path:
            raise SystemAttestationError("GitHub API path is invalid")
        if self.transport:
            return self.transport(path)
        request = urllib.request.Request(
            self.config.github_api + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Cache-Control": "no-cache",
                "X-GitHub-Api-Version": "2022-11-28",
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
        except (OSError, urllib.error.URLError):
            raise SystemAttestationError("GitHub authorization lookup failed") from None
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

    def check_runs(self, repo: str, head: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for page in range(1, 11):
            value = self.get(
                f"/repos/{repo}/commits/{head}/check-runs?per_page=100&page={page}"
            )
            if (
                not isinstance(value, dict)
                or type(value.get("total_count")) is not int
                or not isinstance(value.get("check_runs"), list)
                or len(value["check_runs"]) > 100
                or any(not isinstance(item, dict) for item in value["check_runs"])
            ):
                raise SystemAttestationError("GitHub check-runs response is malformed")
            result.extend(value["check_runs"])
            if len(value["check_runs"]) < 100:
                if len(result) != value["total_count"]:
                    raise SystemAttestationError(
                        "GitHub check-runs pagination is inconsistent"
                    )
                return result
        raise SystemAttestationError("GitHub check-runs pagination limit exceeded")

    def put(self, path: str, payload: dict[str, Any]) -> Any:
        if not re.fullmatch(
            r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pulls/[1-9][0-9]*/merge",
            path,
        ):
            raise SystemAttestationError("GitHub mutation path is invalid")
        if self.mutation_transport:
            return self.mutation_transport("PUT", path, payload)
        encoded = _canonical(payload)
        request = urllib.request.Request(
            self.config.github_api + path,
            data=encoded,
            method="PUT",
            headers={
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "saturnin-protected-merge/1",
                "Authorization": f"Bearer {self.token}",
            },
        )
        if not self.token:
            raise SystemAttestationError("protected GitHub credential is unavailable")
        try:
            with self.request_transport(
                request, self.config.request_timeout_seconds
            ) as response:
                if response.geturl() != self.config.github_api + path:
                    raise SystemAttestationError("GitHub redirect was refused")
                body = response.read(MAX_RESPONSE + 1)
        except (OSError, urllib.error.URLError):
            raise SystemAttestationError("GitHub protected merge failed") from None
        if len(body) > MAX_RESPONSE:
            raise SystemAttestationError("GitHub response is oversized")
        try:
            value = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SystemAttestationError("GitHub response is malformed") from exc
        if not isinstance(value, dict):
            raise SystemAttestationError("GitHub response is malformed")
        return value

    def post_issue(
        self, repo: str, title: str, body: str, labels: list[str]
    ) -> Any:
        path = f"/repos/{repo}/issues"
        if self.mutation_transport:
            return self.mutation_transport(
                "POST", path, {"title": title, "body": body, "labels": labels}
            )
        if not self.token:
            raise SystemAttestationError("protected GitHub credential is unavailable")
        encoded = _canonical({"title": title, "body": body, "labels": labels})
        request = urllib.request.Request(
            self.config.github_api + path,
            data=encoded,
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "saturnin-protected-issue/1",
                "Authorization": f"Bearer {self.token}",
            },
        )
        try:
            with self.request_transport(
                request, self.config.request_timeout_seconds
            ) as response:
                if response.geturl() != self.config.github_api + path:
                    raise SystemAttestationError("GitHub redirect was refused")
                response_body = response.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            safe = 400 <= exc.code < 500 and exc.code != 408
            raise GitHubMutationError(
                "GitHub protected issue submission failed", safe_to_retry=safe
            ) from None
        except urllib.error.URLError as exc:
            safe = isinstance(exc.reason, (socket.gaierror, ConnectionRefusedError))
            raise GitHubMutationError(
                "GitHub protected issue submission failed", safe_to_retry=safe
            ) from None
        except OSError:
            raise GitHubMutationError(
                "GitHub protected issue submission failed"
            ) from None
        if len(response_body) > MAX_RESPONSE:
            raise SystemAttestationError("GitHub response is oversized")
        try:
            value = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise SystemAttestationError("GitHub response is malformed") from exc
        if not isinstance(value, dict):
            raise SystemAttestationError("GitHub response is malformed")
        return value

    def post_issue_comment(self, repo: str, number: int, body: str) -> Any:
        path = f"/repos/{repo}/issues/{number}/comments"
        if self.mutation_transport:
            return self.mutation_transport("POST", path, {"body": body})
        if not self.token:
            raise SystemAttestationError("protected GitHub credential is unavailable")
        request = urllib.request.Request(
            self.config.github_api + path,
            data=_canonical({"body": body}),
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "saturnin-issue-reviewer/1",
                "Authorization": f"Bearer {self.token}",
            },
        )
        try:
            with self.request_transport(
                request, self.config.request_timeout_seconds
            ) as response:
                if response.geturl() != self.config.github_api + path:
                    raise SystemAttestationError("GitHub redirect was refused")
                response_body = response.read(MAX_RESPONSE + 1)
        except (OSError, urllib.error.URLError):
            raise SystemAttestationError(
                "GitHub issue review publication failed"
            ) from None
        if len(response_body) > MAX_RESPONSE:
            raise SystemAttestationError("GitHub response is oversized")
        try:
            value = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise SystemAttestationError("GitHub response is malformed") from exc
        if not isinstance(value, dict):
            raise SystemAttestationError("GitHub response is malformed")
        return value

    def create_installation_token(
        self, installation_id: int, repository_name: str,
    ) -> Any:
        if (
            type(installation_id) is not int
            or installation_id < 1
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", repository_name)
        ):
            raise SystemAttestationError("publisher installation scope is invalid")
        path = f"/app/installations/{installation_id}/access_tokens"
        payload = {
            "repositories": [repository_name],
            "permissions": {"issues": "write", "metadata": "read"},
        }
        if self.mutation_transport:
            return self.mutation_transport("POST", path, payload)
        if not self.token:
            raise SystemAttestationError("publisher App JWT is unavailable")
        request = urllib.request.Request(
            self.config.github_api + path,
            data=_canonical(payload),
            method="POST",
            headers={
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "saturnin-issue-publisher/1",
                "Authorization": f"Bearer {self.token}",
            },
        )
        try:
            with self.request_transport(
                request, self.config.request_timeout_seconds
            ) as response:
                if response.geturl() != self.config.github_api + path:
                    raise SystemAttestationError("GitHub redirect was refused")
                body = response.read(MAX_RESPONSE + 1)
        except (OSError, urllib.error.URLError):
            raise SystemAttestationError(
                "publisher installation token request failed"
            ) from None
        if len(body) > MAX_RESPONSE:
            raise SystemAttestationError("GitHub response is oversized")
        try:
            value = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SystemAttestationError("GitHub response is malformed") from exc
        if not isinstance(value, dict):
            raise SystemAttestationError("GitHub response is malformed")
        return value

    def close_issue(self, repo: str, number: int) -> Any:
        path = f"/repos/{repo}/issues/{number}"
        payload = {"state": "closed", "state_reason": "not_planned"}
        if self.mutation_transport:
            return self.mutation_transport("PATCH", path, payload)
        if not self.token:
            raise SystemAttestationError("publisher installation token is unavailable")
        request = urllib.request.Request(
            self.config.github_api + path,
            data=_canonical(payload),
            method="PATCH",
            headers={
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "saturnin-issue-publisher/1",
                "Authorization": f"Bearer {self.token}",
            },
        )
        try:
            with self.request_transport(
                request, self.config.request_timeout_seconds
            ) as response:
                if response.geturl() != self.config.github_api + path:
                    raise SystemAttestationError("GitHub redirect was refused")
                body = response.read(MAX_RESPONSE + 1)
        except (OSError, urllib.error.URLError):
            raise SystemAttestationError("publisher containment failed") from None
        if len(body) > MAX_RESPONSE:
            raise SystemAttestationError("GitHub response is oversized")
        try:
            value = json.loads(body)
        except json.JSONDecodeError as exc:
            raise SystemAttestationError("GitHub response is malformed") from exc
        if not isinstance(value, dict):
            raise SystemAttestationError("GitHub response is malformed")
        return value


@dataclass(frozen=True)
class PublisherCredential:
    app_id: int
    private_key: bytes

    @classmethod
    def load(cls, value: bytes) -> "PublisherCredential":
        try:
            raw = json.loads(value)
            app_id = raw["app_id"]
            private_key = raw["private_key"].encode("ascii")
        except (KeyError, TypeError, UnicodeEncodeError, json.JSONDecodeError) as exc:
            raise SystemAttestationError(
                "publisher App credential is malformed"
            ) from exc
        if (
            set(raw) != {"app_id", "private_key"}
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
            raise SystemAttestationError("publisher App credential is malformed")
        return cls(app_id, private_key)


class GitHubAppPublisher:
    def __init__(
        self,
        config: ServiceConfig,
        credential: PublisherCredential,
        *,
        now: Callable[[], datetime] | None = None,
        jwt_signer: Callable[[bytes, bytes], bytes] | None = None,
        transport: Callable[[str], Any] | None = None,
        mutation_transport: Callable[[str, str, dict[str, Any]], Any] | None = None,
        request_transport: Callable[[urllib.request.Request, float], Any] | None = None,
    ) -> None:
        self.config = config
        self.credential = credential
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.jwt_signer = jwt_signer or self._openssl_sign
        self.transport = transport
        self.mutation_transport = mutation_transport
        self.request_transport = request_transport

    @staticmethod
    def _b64url(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    @staticmethod
    def _openssl_sign(private_key: bytes, message: bytes) -> bytes:
        if not hasattr(os, "memfd_create"):
            raise SystemAttestationError("memory-only App signing is unavailable")
        descriptor = os.memfd_create("saturnin-publisher-key", os.MFD_CLOEXEC)
        try:
            os.write(descriptor, private_key)
            os.lseek(descriptor, 0, os.SEEK_SET)
            result = subprocess.run(
                [
                    "/usr/bin/openssl",
                    "dgst",
                    "-sha256",
                    "-sign",
                    f"/proc/self/fd/{descriptor}",
                ],
                input=message,
                capture_output=True,
                check=False,
                close_fds=True,
                pass_fds=(descriptor,),
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            raise SystemAttestationError("publisher App signing failed") from None
        finally:
            os.close(descriptor)
        if result.returncode != 0 or not result.stdout:
            raise SystemAttestationError("publisher App signing failed")
        return result.stdout

    def _jwt(self) -> str:
        current = int(self.now().timestamp())
        header = self._b64url(_canonical({"alg": "RS256", "typ": "JWT"}))
        payload = self._b64url(_canonical({
            "iat": current - 30,
            "exp": current + 540,
            "iss": str(self.credential.app_id),
        }))
        unsigned = f"{header}.{payload}".encode()
        return f"{unsigned.decode()}.{self._b64url(self.jwt_signer(self.credential.private_key, unsigned))}"

    def client(self, destination: str) -> GitHub:
        repo = _repo(destination)
        if repo not in self.config.issue_destinations:
            raise SystemAttestationError("publisher destination is not allowlisted")
        app = GitHub(
            self.config,
            self._jwt(),
            transport=self.transport,
            request_transport=self.request_transport,
            mutation_transport=self.mutation_transport,
        )
        installation = app.get(f"/repos/{repo}/installation")
        permissions = (
            installation.get("permissions")
            if isinstance(installation, dict) else None
        )
        installation_id = (
            installation.get("id") if isinstance(installation, dict) else None
        )
        if (
            type(installation_id) is not int
            or installation.get("app_id") != self.credential.app_id
            or str(installation.get("app_slug", "")).casefold() + "[bot]"
            != self.config.publisher_actor_login
            or installation.get("repository_selection") != "selected"
            or permissions != {"issues": "write", "metadata": "read"}
        ):
            raise SystemAttestationError(
                "publisher App installation scope is invalid"
            )
        repository_name = repo.split("/", 1)[1]
        response = app.create_installation_token(installation_id, repository_name)
        token = response.get("token") if isinstance(response, dict) else None
        repositories = (
            response.get("repositories") if isinstance(response, dict) else None
        )
        expiry = _iso(response.get("expires_at")) if isinstance(response, dict) else None
        if (
            not isinstance(token, str)
            or not token
            or response.get("repository_selection") != "selected"
            or response.get("permissions")
            != {"issues": "write", "metadata": "read"}
            or not isinstance(repositories, list)
            or len(repositories) != 1
            or not isinstance(repositories[0], dict)
            or str(repositories[0].get("full_name", "")).casefold() != repo
            or expiry is None
            or expiry <= self.now() + timedelta(seconds=30)
            or expiry > self.now() + timedelta(minutes=61)
        ):
            raise SystemAttestationError(
                "publisher installation token scope is invalid"
            )
        client = GitHub(
            self.config,
            token,
            transport=self.transport,
            request_transport=self.request_transport,
            mutation_transport=self.mutation_transport,
        )
        repository = client.get(f"/repos/{repo}")
        if (
            not isinstance(repository, dict)
            or str(repository.get("full_name", "")).casefold() != repo
        ):
            raise SystemAttestationError("publisher destination lookup is invalid")
        return client


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
        archive_keys: tuple[bytes, ...] = (),
        publisher_client: Callable[[str], GitHub] | None = None,
    ) -> None:
        if len(current_key) < 32:
            raise SystemAttestationError("current signing credential is invalid")
        if previous_key is not None and (
            len(previous_key) < 32 or hmac.compare_digest(current_key, previous_key)
        ):
            raise SystemAttestationError("previous signing credential is invalid")
        if len(archive_keys) > ARCHIVE_MAX_KEYS:
            raise SystemAttestationError("retired signing credential archive is oversized")
        all_keys = [current_key] + ([previous_key] if previous_key else []) + list(archive_keys)
        if any(
            key is None or len(key) < 32 or len(key) > 4096 or b"\0" in key
            for key in all_keys
        ):
            raise SystemAttestationError("retired signing credential archive is invalid")
        if len({hashlib.sha256(key).digest() for key in all_keys}) != len(all_keys):
            raise SystemAttestationError("signing credentials must be duplicate-free")
        self.config, self.github = config, github
        self.current_key, self.previous_key = current_key, previous_key
        self.archive_keys = archive_keys
        self.publisher_client = publisher_client
        self.state_path = state_path
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.lock = threading.Lock()
        state_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._db()) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS consumed ("
                "evidence_id TEXT PRIMARY KEY, scope_hash TEXT NOT NULL, "
                "attestation TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS actions ("
                "nonce TEXT PRIMARY KEY, scope_hash TEXT NOT NULL, "
                "result TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS issue_claims ("
                "claim_hash TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL, "
                "created_at TEXT NOT NULL)"
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
        number = request["number"]
        subject = _subject(repository, number)
        if request["kind"] == "pr":
            if (
                repository not in self.config.repositories
                or destination != repository
            ):
                raise SystemAttestationError("repository is not allowlisted")
            evidence = self._pr(repository, number, subject, destination)
        elif request["kind"] == "issue":
            destinations = (
                self.config.issue_destinations or self.config.repositories
            )
            if (
                repository not in self.config.repositories
                or destination not in destinations
            ):
                raise SystemAttestationError("repository is not allowlisted")
            evidence = self._issue(repository, number, subject, destination)
        else:
            raise SystemAttestationError("review kind is invalid")
        authorization_current = bool(evidence.pop("_authorization_current", True))
        evidence.pop("_approved_labels", None)
        scope_hash = hashlib.sha256(_canonical(evidence)).hexdigest()
        evidence_id = evidence["authorization_evidence_id"]
        with self.lock, closing(self._db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT scope_hash, attestation FROM consumed WHERE evidence_id=?",
                (evidence_id,),
            ).fetchone()
            if row:
                db.execute("COMMIT")
                if not authorization_current:
                    raise SystemAttestationError("authorization evidence is expired")
                if hmac.compare_digest(row[0], scope_hash):
                    return str(row[1])
                raise SystemAttestationError("authorization evidence was already consumed")
            if not authorization_current:
                raise SystemAttestationError("authorization evidence is expired")
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

    def verify(self, attestation: str, *, historical: bool = False) -> dict[str, Any]:
        if not isinstance(attestation, str) or len(attestation) > MAX_RESPONSE:
            raise SystemAttestationError("attestation is invalid")
        try:
            payload = json.loads(attestation)
        except json.JSONDecodeError as exc:
            raise SystemAttestationError("attestation is malformed") from exc
        if not isinstance(payload, dict):
            raise SystemAttestationError("attestation schema is invalid")
        if payload.get("schema") == "saturnin-attestation-v2":
            if set(payload) != _ATTESTATION_FIELDS:
                raise SystemAttestationError("attestation schema is invalid")
            unsigned = self._v2_unsigned(payload)
        else:
            if not historical:
                raise SystemAttestationError(
                    "legacy attestation cannot authorize a new review record"
                )
            unsigned = self._legacy_unsigned(payload)
        signature = payload.get("signature")
        key_id = payload.get("key_id")
        if not isinstance(signature, str) or not _DIGEST.fullmatch(signature):
            raise SystemAttestationError("attestation signature is invalid")
        keys: list[tuple[str, bytes]] = [("current", self.current_key)]
        if self.previous_key:
            keys.append(("previous", self.previous_key))
        keys.extend(("archive", key) for key in self.archive_keys)
        for key_state, master in keys:
            key = (
                master
                if payload.get("schema") == "saturnin-attestation-v2"
                else self._legacy_key(master, payload)
            )
            if (
                (
                    key_id is None
                    or hmac.compare_digest(
                        hashlib.sha256(key).hexdigest(), str(key_id)
                    )
                )
                and hmac.compare_digest(
                    hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest(),
                    signature,
                )
            ):
                if (
                    payload.get("schema") == "saturnin-attestation-v2"
                    and not historical
                ):
                    with closing(self._db()) as db:
                        issued = db.execute(
                            "SELECT attestation FROM consumed WHERE evidence_id=?",
                            (payload["authorization_evidence_id"],),
                        ).fetchone()
                    if issued is None or not hmac.compare_digest(
                        str(issued[0]), attestation
                    ):
                        raise SystemAttestationError(
                            "attestation was not issued by the protected signer"
                        )
                return {"status": "verified", "key_state": key_state}
        raise SystemAttestationError("attestation signature does not match")

    def action(self, request: dict[str, Any]) -> dict[str, Any]:
        required = {
            "action", "operation", "repository", "number", "destination_repo",
            "expected_head", "merge_method", "nonce",
        }
        if (
            not isinstance(request, dict)
            or set(request) != required
            or request["action"] != "decide"
            or request["operation"] not in {"gate", "merge"}
            or not _NONCE.fullmatch(str(request["nonce"]))
            or request["merge_method"] not in {"merge", "squash", "rebase"}
        ):
            raise SystemAttestationError("protected action request schema is invalid")
        repo = _repo(request["repository"])
        destination = _repo(request["destination_repo"])
        number = request["number"]
        _subject(repo, number)
        if repo not in self.config.repositories or destination != repo:
            raise SystemAttestationError("protected action repository is not allowed")
        expected_head = str(request["expected_head"]).casefold()
        if not _SHA.fullmatch(expected_head):
            raise SystemAttestationError("protected action head is invalid")
        scope = {
            "operation": request["operation"],
            "repository": repo,
            "number": number,
            "destination_repo": destination,
            "expected_head": expected_head,
            "merge_method": request["merge_method"],
            "nonce": request["nonce"],
        }
        scope_hash = hashlib.sha256(_canonical(scope)).hexdigest()
        with self.lock, closing(self._db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT scope_hash, result FROM actions WHERE nonce=?",
                (request["nonce"],),
            ).fetchone()
            if old:
                db.execute("COMMIT")
                if hmac.compare_digest(old[0], scope_hash):
                    prior = json.loads(old[1])
                    if (
                        prior.get("operation") == "gate"
                        and _iso(prior.get("expires_at")) <= self.now()
                    ):
                        raise SystemAttestationError(
                            "protected action decision is expired"
                        )
                    return prior
                raise SystemAttestationError("protected action nonce was already consumed")
            evidence = self._live_pr_action(repo, number, destination, expected_head)
            decision = {
                "allowed": True,
                **scope,
                **evidence,
                "expires_at": (
                    self.now() + timedelta(seconds=self.config.action_ttl_seconds)
                ).isoformat(),
            }
            if request["operation"] == "merge":
                repeated = self._live_pr_action(
                    repo, number, destination, expected_head
                )
                if repeated != evidence:
                    raise SystemAttestationError(
                        "GitHub state changed during protected merge authorization"
                    )
                merged = self.github.put(
                    f"/repos/{repo}/pulls/{number}/merge",
                    {"sha": expected_head, "merge_method": request["merge_method"]},
                )
                decision.update({
                    "merged": merged.get("merged") is True,
                    "message": str(merged.get("message", "")),
                    "sha": str(merged.get("sha", "")),
                })
                if not decision["merged"]:
                    raise SystemAttestationError("GitHub rejected protected merge")
            signed = dict(decision)
            signed["signature"] = hmac.new(
                self.current_key, _canonical(decision), hashlib.sha256
            ).hexdigest()
            serialized = json.dumps(signed, sort_keys=True, separators=(",", ":"))
            db.execute(
                "INSERT INTO actions VALUES (?, ?, ?, ?)",
                (request["nonce"], scope_hash, serialized, self.now().isoformat()),
            )
            db.execute("COMMIT")
            return signed

    def _current_issue_authorization(
        self, repo: str, number: int, subject: str, destination: str,
    ) -> tuple[dict[str, Any], list[str]]:
        evidence = self._issue(repo, number, subject, destination)
        if not evidence.pop("_authorization_current", False):
            raise SystemAttestationError(
                "issue has no current matching authorization"
            )
        labels = sorted(evidence.pop("_approved_labels"))
        return evidence, labels

    def _publisher(self, destination: str) -> GitHub:
        if self.publisher_client is None:
            raise SystemAttestationError(
                "protected issue publisher is not provisioned"
            )
        publisher = self.publisher_client(destination)
        if not isinstance(publisher, GitHub):
            raise SystemAttestationError("protected issue publisher is invalid")
        return publisher

    def issue_action(self, request: dict[str, Any]) -> dict[str, Any]:
        required = {
            "action", "operation", "repository", "number", "destination_repo",
            "issue_digest", "title", "body", "labels", "nonce",
        }
        if (
            not isinstance(request, dict)
            or set(request) != required
            or request["action"] != "decide_issue"
            or request["operation"] not in {"issue_gate", "issue_submit"}
            or not _NONCE.fullmatch(str(request["nonce"]))
            or not _DIGEST.fullmatch(str(request["issue_digest"]))
            or not isinstance(request["title"], str)
            or not isinstance(request["body"], str)
            or not isinstance(request["labels"], list)
            or any(
                not isinstance(label, str)
                or not re.fullmatch(r"[A-Za-z0-9:_. -]{1,50}", label)
                for label in request["labels"]
            )
            or len(request["labels"]) > 20
            or len(request["title"]) > 256
            or len(request["body"].encode()) > (
                64 * 1024
                - len(("\n\n" + ISSUE_SUBMISSION_MARKER.format("f" * 64)).encode())
            )
        ):
            raise SystemAttestationError("protected issue request schema is invalid")
        repo = _repo(request["repository"])
        destination = _repo(request["destination_repo"])
        number = request["number"]
        subject = _subject(repo, number)
        destinations = self.config.issue_destinations or self.config.repositories
        if repo not in self.config.repositories or destination not in destinations:
            raise SystemAttestationError("protected issue repository is not allowed")
        if request["operation"] == "issue_submit":
            digest = hashlib.sha256(_canonical({
                "title": request["title"], "body": request["body"],
            })).hexdigest()
            if digest != request["issue_digest"]:
                raise SystemAttestationError("protected issue content digest changed")
        elif request["title"] or request["body"] or request["labels"]:
            raise SystemAttestationError("issue gate accepts no submission content")
        scope = {
            key: request[key]
            for key in (
                "operation", "repository", "number", "destination_repo",
                "issue_digest", "title", "body", "labels", "nonce",
            )
        }
        scope["repository"] = repo
        scope["destination_repo"] = destination
        scope_hash = hashlib.sha256(_canonical(scope)).hexdigest()
        with self.lock, closing(self._db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT scope_hash, result FROM actions WHERE nonce=?",
                (request["nonce"],),
            ).fetchone()
            if old:
                db.execute("COMMIT")
                prior = json.loads(old[1])
                if not hmac.compare_digest(old[0], scope_hash):
                    raise SystemAttestationError(
                        "protected action nonce was already consumed"
                    )
                if (
                    prior.get("operation") == "issue_submit"
                    and not prior.get("submitted")
                ):
                    if prior.get("contained") or prior.get("containment_failed"):
                        raise SystemAttestationError(
                            "protected issue publication was revoked after creation"
                        )
                    publisher = self._publisher(destination)
                    found = self._find_issue_submission(
                        publisher, destination, prior["title"], prior["body"],
                        prior["labels"], prior["nonce"],
                    )
                    if found is None:
                        raise SystemAttestationError(
                            "protected issue submission requires reconciliation"
                        )
                    return self._complete_issue_submission(
                        db, prior, found, scope_hash
                    )
                if (
                    prior.get("operation") == "issue_gate"
                    and _iso(prior.get("expires_at")) <= self.now()
                ):
                    raise SystemAttestationError(
                        "protected action decision is expired"
                    )
                return prior
            publisher = (
                self._publisher(destination)
                if request["operation"] == "issue_submit" else None
            )
            evidence, approved_labels = self._current_issue_authorization(
                repo, number, subject, destination
            )
            if evidence["issue_digest"] != request["issue_digest"]:
                raise SystemAttestationError(
                    "issue has no current matching authorization"
                )
            repeated, repeated_labels = self._current_issue_authorization(
                repo, number, subject, destination
            )
            if repeated != evidence or repeated_labels != approved_labels:
                raise SystemAttestationError(
                    "GitHub state changed during protected issue authorization"
                )
            if (
                request["operation"] == "issue_submit"
                and sorted(request["labels"]) != approved_labels
            ):
                raise SystemAttestationError(
                    "protected issue labels were not approved"
                )
            expiry = min(
                _iso(evidence["expires_at"]),
                self.now() + timedelta(seconds=self.config.action_ttl_seconds),
            )
            decision: dict[str, Any] = {
                "allowed": True, **scope,
                "reviewer_identity": evidence["reviewer_identity"],
                "comment_id": int(
                    evidence["authorization_evidence_id"].rsplit(":", 1)[1]
                ),
                "review_state": evidence["verdict"],
                "approved_labels": approved_labels,
                "expires_at": expiry.isoformat(),
            }
            signed = dict(decision)
            signed["signature"] = hmac.new(
                self.current_key, _canonical(decision), hashlib.sha256
            ).hexdigest()
            serialized = json.dumps(signed, sort_keys=True, separators=(",", ":"))
            found = None
            if request["operation"] == "issue_submit":
                assert publisher is not None
                found = self._find_issue_submission(
                    publisher, destination, request["title"], request["body"],
                    request["labels"], request["nonce"],
                )
                claim_hash = hashlib.sha256(_canonical({
                    "repository": repo,
                    "number": number,
                    "destination_repo": destination,
                    "issue_digest": request["issue_digest"],
                })).hexdigest()
                try:
                    db.execute(
                        "INSERT INTO issue_claims VALUES (?, ?, ?)",
                        (claim_hash, request["nonce"], self.now().isoformat()),
                    )
                except sqlite3.IntegrityError:
                    raise SystemAttestationError(
                        "protected issue publication is already claimed"
                    ) from None
            db.execute(
                "INSERT INTO actions VALUES (?, ?, ?, ?)",
                (request["nonce"], scope_hash, serialized, self.now().isoformat()),
            )
            db.execute("COMMIT")
            if request["operation"] == "issue_gate":
                return signed

            assert publisher is not None
            try:
                final_evidence, final_labels = self._current_issue_authorization(
                    repo, number, subject, destination
                )
                final_current = (
                    final_evidence == evidence
                    and final_labels == approved_labels
                    and _iso(decision["expires_at"]) > self.now()
                )
            except SystemAttestationError:
                final_current = False
            if not final_current:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "DELETE FROM actions WHERE nonce=? AND scope_hash=?",
                    (request["nonce"], scope_hash),
                )
                db.execute(
                    "DELETE FROM issue_claims WHERE nonce=?",
                    (request["nonce"],),
                )
                db.execute("COMMIT")
                raise SystemAttestationError(
                    "source authorization changed before issue publication"
                )
            if found is None:
                submission_body = self._issue_submission_body(
                    request["body"], request["nonce"]
                )
                try:
                    response = publisher.post_issue(
                        destination, request["title"], submission_body,
                        request["labels"],
                    )
                except GitHubMutationError as exc:
                    if exc.safe_to_retry:
                        db.execute("BEGIN IMMEDIATE")
                        db.execute(
                            "DELETE FROM actions WHERE nonce=? AND scope_hash=?",
                            (request["nonce"], scope_hash),
                        )
                        db.execute(
                            "DELETE FROM issue_claims WHERE nonce=?",
                            (request["nonce"],),
                        )
                        db.execute("COMMIT")
                    raise
                found = self._matching_issue_submission(
                    response, destination, request["title"], submission_body,
                    request["labels"],
                )
            if found is None:
                raise SystemAttestationError(
                    "GitHub protected issue response is invalid"
                )
            try:
                post_evidence, post_labels = self._current_issue_authorization(
                    repo, number, subject, destination
                )
                post_current = (
                    post_evidence == evidence
                    and post_labels == approved_labels
                    and _iso(decision["expires_at"]) > self.now()
                )
            except SystemAttestationError:
                post_current = False
            if not post_current:
                self._contain_issue_submission(
                    db, publisher, decision, found, scope_hash
                )
                raise SystemAttestationError(
                    "source authorization was revoked after issue publication"
                )
            return self._complete_issue_submission(db, decision, found, scope_hash)

    @staticmethod
    def _issue_submission_body(body: str, nonce: str) -> str:
        return f"{body}\n\n{ISSUE_SUBMISSION_MARKER.format(nonce)}"

    def _matching_issue_submission(
        self, value: Any, destination: str, title: str, body: str,
        labels: list[str],
    ) -> dict[str, Any] | None:
        if not isinstance(value, dict) or "pull_request" in value:
            return None
        issue_labels = value.get("labels")
        issue_user = value.get("user") or {}
        issue_url = value.get("html_url")
        if (
            type(value.get("number")) is not int
            or value.get("title") != title
            or value.get("body") != body
            or value.get("state") != "open"
            or str(issue_user.get("login", "")).casefold()
            != self.config.publisher_actor_login
            or issue_user.get("type") != "Bot"
            or value.get("created_at") != value.get("updated_at")
            or not isinstance(value.get("created_at"), str)
            or _iso(value["created_at"]) > self.now()
            or not isinstance(issue_labels, list)
            or any(
                not isinstance(label, dict)
                or not isinstance(label.get("name"), str)
                for label in issue_labels
            )
            or sorted(label["name"] for label in issue_labels) != sorted(labels)
            or not _github_issue_url(
                issue_url, destination, value.get("number")
            )
        ):
            return None
        return {"number": value["number"], "url": issue_url}

    def _find_issue_submission(
        self, github: GitHub, destination: str, title: str, body: str,
        labels: list[str], nonce: str,
    ) -> dict[str, Any] | None:
        marked_body = self._issue_submission_body(body, nonce)
        matches = [
            match
            for value in github.pages(
                f"/repos/{destination}/issues?state=all"
            )
            if (
                ISSUE_SUBMISSION_MARKER.format(nonce)
                in str(value.get("body") or "")
                and (
                    match := self._matching_issue_submission(
                        value, destination, title, marked_body, labels
                    )
                ) is not None
            )
        ]
        if len(matches) > 1:
            raise SystemAttestationError(
                "multiple protected issue submissions require reconciliation"
            )
        return matches[0] if matches else None

    def _contain_issue_submission(
        self,
        db: sqlite3.Connection,
        publisher: GitHub,
        decision: dict[str, Any],
        submission: dict[str, Any],
        scope_hash: str,
    ) -> None:
        contained = False
        try:
            response = publisher.close_issue(
                decision["destination_repo"], submission["number"]
            )
            user = response.get("user") if isinstance(response, dict) else None
            contained = (
                isinstance(response, dict)
                and response.get("number") == submission["number"]
                and response.get("state") == "closed"
                and response.get("state_reason") == "not_planned"
                and response.get("title") == decision["title"]
                and response.get("body") == self._issue_submission_body(
                    decision["body"], decision["nonce"]
                )
                and isinstance(user, dict)
                and str(user.get("login", "")).casefold()
                == self.config.publisher_actor_login
                and user.get("type") == "Bot"
                and _github_issue_url(
                    response.get("html_url"),
                    decision["destination_repo"],
                    submission["number"],
                )
                and ISSUE_SUBMISSION_MARKER.format(decision["nonce"])
                in str(response.get("body") or "")
                and isinstance(response.get("labels"), list)
                and all(
                    isinstance(label, dict)
                    and isinstance(label.get("name"), str)
                    for label in response["labels"]
                )
                and sorted(label["name"] for label in response["labels"])
                == sorted(decision["labels"])
            )
        except SystemAttestationError:
            contained = False
        terminal = {
            **decision,
            "submitted": False,
            "issue_number": submission["number"],
            "url": submission["url"],
            "contained": contained,
            "containment_failed": not contained,
        }
        signed = dict(terminal)
        signed["signature"] = hmac.new(
            self.current_key, _canonical(terminal), hashlib.sha256
        ).hexdigest()
        db.execute("BEGIN IMMEDIATE")
        changed = db.execute(
            "UPDATE actions SET result=? WHERE nonce=? AND scope_hash=?",
            (
                json.dumps(signed, sort_keys=True, separators=(",", ":")),
                decision["nonce"],
                scope_hash,
            ),
        ).rowcount
        db.execute("COMMIT")
        if changed != 1:
            raise SystemAttestationError("protected issue reservation was lost")
        _audit(
            "contained" if contained else "containment-failed",
            hashlib.sha256(
                f"{decision['destination_repo']}#{submission['number']}".encode()
            ).hexdigest(),
            scope_hash,
        )

    def _complete_issue_submission(
        self, db: sqlite3.Connection, decision: dict[str, Any],
        submission: dict[str, Any], scope_hash: str,
    ) -> dict[str, Any]:
        decision = {
            **decision, "submitted": True,
            "issue_number": submission["number"], "url": submission["url"],
        }
        signed = dict(decision)
        signed["signature"] = hmac.new(
            self.current_key, _canonical(decision), hashlib.sha256
        ).hexdigest()
        serialized = json.dumps(signed, sort_keys=True, separators=(",", ":"))
        db.execute("BEGIN IMMEDIATE")
        changed = db.execute(
            "UPDATE actions SET result=? WHERE nonce=? AND scope_hash=?",
            (serialized, decision["nonce"], scope_hash),
        ).rowcount
        db.execute("COMMIT")
        if changed != 1:
            raise SystemAttestationError("protected issue reservation was lost")
        return signed

    def _live_pr_action(
        self, repo: str, number: int, destination: str, expected_head: str
    ) -> dict[str, Any]:
        actor = self._protected_actor(repo)
        evidence = self._pr(repo, number, _subject(repo, number), destination)
        if evidence["head_sha"] != expected_head:
            raise SystemAttestationError("pull request head changed")
        pull = self.github.get(f"/repos/{repo}/pulls/{number}")
        snapshot = self._pull_snapshot(
            pull, repo, number, destination, expected_head
        )
        base_ref = snapshot["base_ref"]
        base_sha = snapshot["base_sha"]
        protection = self.github.get(
            f"/repos/{repo}/branches/{base_ref}/protection"
        )
        if not isinstance(protection, dict):
            raise SystemAttestationError("branch protection response is malformed")
        review_rule = protection.get("required_pull_request_reviews")
        status_rule = protection.get("required_status_checks")
        bypass = (
            review_rule.get("bypass_pull_request_allowances")
            if isinstance(review_rule, dict) else None
        )
        contexts = set()
        if isinstance(status_rule, dict):
            contexts.update(
                value for value in status_rule.get("contexts", [])
                if isinstance(value, str)
            )
            contexts.update(
                value.get("context") for value in status_rule.get("checks", [])
                if isinstance(value, dict) and isinstance(value.get("context"), str)
            )
        if (
            not isinstance(review_rule, dict)
            or review_rule.get("dismiss_stale_reviews") is not True
            or type(review_rule.get("required_approving_review_count")) is not int
            or review_rule["required_approving_review_count"] < 1
            or not isinstance(bypass, dict)
            or any(bypass.get(kind) for kind in ("users", "teams", "apps"))
            or not isinstance(protection.get("enforce_admins"), dict)
            or protection["enforce_admins"].get("enabled") is not True
            or not isinstance(status_rule, dict)
            or status_rule.get("strict") is not True
            or not set(self.config.required_check_runs) <= contexts
        ):
            raise SystemAttestationError(
                "branch protection does not enforce the protected action contract"
            )
        if evidence["author"].casefold() == (
            "github:" + evidence["reviewer_identity"]
        ).casefold() or evidence["reviewer_identity"] == actor:
            raise SystemAttestationError("reviewer is not independent")
        checks = self.github.check_runs(repo, expected_head)
        accepted: list[dict[str, Any]] = []
        check_ids: set[int] = set()
        for check in checks:
            name = check.get("name")
            if name not in self.config.required_check_runs:
                continue
            check_id = check.get("id")
            if type(check_id) is not int or check_id in check_ids:
                raise SystemAttestationError("required check result is ambiguous")
            check_ids.add(check_id)
            accepted.append(check)
        if (
            {str(value.get("name")) for value in accepted}
            != set(self.config.required_check_runs)
            or any(
            value.get("status") != "completed" or value.get("conclusion") != "success"
                for value in accepted
            )
        ):
            raise SystemAttestationError("required checks are not green")
        final_evidence = self._pr(
            repo, number, _subject(repo, number), destination
        )
        final_protection = self.github.get(
            f"/repos/{repo}/branches/{base_ref}/protection"
        )
        final_checks = self.github.check_runs(repo, expected_head)
        final_snapshot = self._pull_snapshot(
            self.github.get(f"/repos/{repo}/pulls/{number}"),
            repo, number, destination, expected_head,
        )
        if (
            final_evidence != evidence
            or final_snapshot != snapshot
            or final_protection != protection
            or sorted(final_checks, key=lambda value: int(value.get("id", 0)))
            != sorted(checks, key=lambda value: int(value.get("id", 0)))
        ):
            raise SystemAttestationError(
                "GitHub state changed during protected action authorization"
            )
        return {
            "head_sha": evidence["head_sha"],
            "base_ref": base_ref,
            "base_sha": base_sha,
            "reviewer_identity": evidence["reviewer_identity"],
            "review_id": int(evidence["authorization_evidence_id"].rsplit(":", 1)[1]),
            "review_state": evidence["verdict"],
            "check_runs": sorted(
                f"{value['name']}:{value['id']}" for value in accepted
            ),
            "protected_actor": actor,
            "protection_hash": hashlib.sha256(_canonical(protection)).hexdigest(),
        }

    def _pull_snapshot(
        self, pull: Any, repo: str, number: int, destination: str,
        expected_head: str,
    ) -> dict[str, str]:
        if not isinstance(pull, dict):
            raise SystemAttestationError("pull request response is malformed")
        base = pull.get("base") or {}
        base_repo = base.get("repo") or {}
        head = pull.get("head") or {}
        head_sha = str(head.get("sha", "")).casefold()
        base_sha = str(base.get("sha", "")).casefold()
        if (
            pull.get("number", number) != number
            or head_sha != expected_head
            or str(base_repo.get("full_name", "")).casefold() != destination
            or base.get("ref") not in self.config.pr_base_refs
            or not _SHA.fullmatch(base_sha)
            or pull.get("state") != "open"
            or pull.get("draft") is not False
            or pull.get("mergeable") is not True
            or pull.get("mergeable_state") not in {"clean", "has_hooks"}
        ):
            raise SystemAttestationError("pull request is not currently mergeable")
        return {
            "repository": repo,
            "number": str(number),
            "head_sha": head_sha,
            "base_ref": str(base["ref"]),
            "base_sha": base_sha,
        }

    def _protected_actor(self, repo: str) -> str:
        if not self.github.token:
            raise SystemAttestationError("protected GitHub credential is unavailable")
        actor = self.github.get("/user")
        repository = self.github.get(f"/repos/{repo}")
        permissions = repository.get("permissions") if isinstance(repository, dict) else None
        if (
            not isinstance(actor, dict)
            or str(actor.get("login", "")).casefold()
            != self.config.protected_actor_login
            or actor.get("type") != "User"
            or not isinstance(repository, dict)
            or str(repository.get("full_name", "")).casefold() != repo
            or not isinstance(permissions, dict)
            or permissions.get("push") is not True
            or permissions.get("admin") is not False
        ):
            raise SystemAttestationError(
                "protected GitHub credential identity or permissions are invalid"
            )
        return self.config.protected_actor_login

    def _verify_protected_access(self) -> None:
        for repo in sorted(self.config.repositories):
            self._protected_actor(repo)
            for base_ref in self.config.pr_base_refs:
                protection = self.github.get(
                    f"/repos/{repo}/branches/{base_ref}/protection"
                )
                if not isinstance(protection, dict):
                    raise SystemAttestationError(
                        "branch protection response is malformed"
                    )
                self.github.check_runs(repo, base_ref)
        for destination in sorted(self.config.issue_destinations):
            self._publisher(destination)

    @staticmethod
    def _v2_unsigned(payload: dict[str, Any]) -> dict[str, Any]:
        string_fields = _ATTESTATION_FIELDS - {"zero_context"}
        if (
            type(payload["zero_context"]) is not bool
            or any(not isinstance(payload[field], str) for field in string_fields)
            or payload["schema"] != "saturnin-attestation-v2"
        ):
            raise SystemAttestationError("attestation types are invalid")
        repository = _repo(payload["repository"])
        _repo(payload["destination_repo"])
        if (
            not re.fullmatch(re.escape(repository) + r"#[1-9][0-9]*", payload["subject"])
            or not payload["author"].startswith("github:")
            or payload["author"] == "github:"
            or not payload["reviewer_identity"]
            or payload["author_role"] != "github-user"
            or payload["verdict"] not in {
                "approved", "changes_requested", "rejected"
            }
            or payload["zero_context"] is not True
            or not _NONCE.fullmatch(payload["nonce"])
            or not _EXECUTION_ATTESTATION_ID.fullmatch(payload["attestation_id"])
            or not _DIGEST.fullmatch(payload["key_id"])
        ):
            raise SystemAttestationError("attestation scope is invalid")
        _iso(payload["expires_at"])
        if payload["kind"] == "pr":
            if (
                payload["reviewer"] != "pr-reviewer"
                or not _SHA.fullmatch(payload["head_sha"])
                or payload["issue_digest"]
                or not re.fullmatch(
                    r"github:review:[1-9][0-9]*",
                    payload["authorization_evidence_id"],
                )
            ):
                raise SystemAttestationError("attestation scope is invalid")
        elif payload["kind"] == "issue":
            if (
                payload["reviewer"] != "issue-reviewer"
                or payload["head_sha"]
                or not _DIGEST.fullmatch(payload["issue_digest"])
                or not re.fullmatch(
                    r"github:comment:[1-9][0-9]*",
                    payload["authorization_evidence_id"],
                )
            ):
                raise SystemAttestationError("attestation scope is invalid")
        else:
            raise SystemAttestationError("attestation scope is invalid")
        return {key: value for key, value in payload.items() if key != "signature"}

    @staticmethod
    def _legacy_unsigned(payload: dict[str, Any]) -> dict[str, Any]:
        fields = set(payload)
        if fields not in (
            _LEGACY_REQUIRED_FIELDS,
            _LEGACY_REQUIRED_FIELDS | {"key_id"},
        ):
            raise SystemAttestationError("legacy attestation schema is invalid")
        if any(
            type(payload[field]) is not (bool if field == "zero_context" else str)
            for field in fields
        ):
            raise SystemAttestationError("legacy attestation types are invalid")
        if payload["kind"] not in {"pr", "issue"}:
            raise SystemAttestationError("legacy attestation kind is invalid")
        if (
            not payload["subject"]
            or len(payload["subject"]) > 512
            or not payload["author"]
            or not payload["reviewer"]
            or payload["zero_context"] is not True
            or payload["verdict"] not in {
                "approved", "changes_requested", "rejected", "dismissed"
            }
        ):
            raise SystemAttestationError("legacy attestation scope is invalid")
        if payload["kind"] == "pr":
            if (
                payload["reviewer"].strip().lower() != "pr-reviewer"
                or not _SHA.fullmatch(payload["head_sha"])
                or payload["issue_digest"]
                or payload["destination_repo"]
            ):
                raise SystemAttestationError("legacy attestation scope is invalid")
        elif (
            payload["reviewer"].strip().lower() != "issue-reviewer"
            or not _DIGEST.fullmatch(payload["issue_digest"])
            or payload["head_sha"]
            or not _REPO.fullmatch(payload["destination_repo"])
        ):
            raise SystemAttestationError("legacy attestation scope is invalid")
        attestation_id = payload["attestation_id"]
        if not (
            _EXECUTION_ATTESTATION_ID.fullmatch(attestation_id)
            or _ROLE_ATTESTATION_ID.fullmatch(attestation_id)
        ):
            raise SystemAttestationError("legacy attestation id is invalid")
        if "key_id" in payload and not _DIGEST.fullmatch(payload["key_id"]):
            raise SystemAttestationError("legacy attestation key id is invalid")
        return {
            key: payload[key]
            for key in (
                *sorted(_LEGACY_ATTESTED_FIELDS),
                "attestation_id",
                *(("key_id",) if "key_id" in payload else ()),
            )
        }

    @staticmethod
    def _legacy_key(master: bytes, payload: dict[str, Any]) -> bytes:
        reviewer = payload["reviewer"].strip().lower()
        if not reviewer:
            raise SystemAttestationError("legacy attestation reviewer is invalid")
        attestation_id = payload["attestation_id"]
        if _EXECUTION_ATTESTATION_ID.fullmatch(attestation_id):
            task_id, nonce = attestation_id.split(":", 1)
            scope = _canonical({
                "context": EXECUTION_SCOPED_KEY_CONTEXT,
                "reviewer": reviewer,
                "task_id": task_id,
                "nonce": nonce,
                "subject": payload["subject"],
                "head_sha": payload["head_sha"],
                "issue_digest": payload["issue_digest"],
            })
            return hmac.new(master, scope, hashlib.sha256).hexdigest().encode()
        return hmac.new(
            master,
            f"{ROLE_SCOPED_KEY_CONTEXT}:{reviewer}".encode(),
            hashlib.sha256,
        ).hexdigest().encode()

    def _pr(
        self, repo: str, number: int, subject: str, destination: str
    ) -> dict[str, Any]:
        review = current_pr_review(
            self.config, self.github, repo, number, now=self.now()
        )
        verdict = str(review["review_state"]).casefold()
        if verdict not in self.config.allowed_verdicts:
            raise SystemAttestationError("review verdict is not allowed")
        head = str(review["head_sha"])
        reviewer = str(review["reviewer_identity"])
        review_id = int(review["review_id"])
        nonce = hashlib.sha256(f"pr:{repo}:{review_id}:{head}".encode()).hexdigest()
        return self._evidence(
            "pr", repo, subject, str(review["author"]), "pr-reviewer", verdict,
            head, "", destination, f"github:review:{review_id}", nonce, reviewer,
            _iso(review["submitted_at"]).timestamp(),
        )

    def _issue(
        self, repo: str, number: int, subject: str, destination: str
    ) -> dict[str, Any]:
        issue = self.github.get(f"/repos/{repo}/issues/{number}")
        if not isinstance(issue, dict) or "pull_request" in issue:
            raise SystemAttestationError("issue response is malformed")
        if str(issue.get("state", "")).casefold() != "open":
            raise SystemAttestationError("source issue is not open")
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
        if len(candidates) != 1:
            raise SystemAttestationError(
                "issue must have exactly one valid review marker"
            )
        comment_id, marker, reviewer_identity, comment_created = max(
            candidates, key=lambda item: item[0]
        )
        if author.casefold() == reviewer_identity:
            raise SystemAttestationError("issue author cannot approve their own issue")
        required = {
            "repository", "issue", "digest", "author", "reviewer_role", "verdict",
            "zero_context", "destination_repo", "labels", "expiry", "nonce",
        }
        if set(marker) != required:
            raise SystemAttestationError("issue review marker schema is invalid")
        if not all(
            isinstance(marker[name], str)
            for name in (
                "repository", "digest", "author", "reviewer_role", "verdict",
                "destination_repo", "expiry", "nonce",
            )
        ) or (
            type(marker["issue"]) is not int
            or type(marker["zero_context"]) is not bool
            or not isinstance(marker["labels"], list)
            or len(marker["labels"]) > 20
            or any(
                not isinstance(label, str)
                or not re.fullmatch(r"[A-Za-z0-9:_. -]{1,50}", label)
                for label in marker["labels"]
            )
            or len(set(marker["labels"])) != len(marker["labels"])
        ):
            raise SystemAttestationError("issue review marker types are invalid")
        expiry = _iso(marker["expiry"])
        now = self.now()
        if (
            comment_created > now
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
        evidence = self._evidence(
            "issue", repo, subject, author, "issue-reviewer", marker["verdict"], "",
            digest, destination, f"github:comment:{comment_id}", marker["nonce"],
            reviewer_identity, expiry.timestamp(),
        )
        evidence["_authorization_current"] = expiry > now
        evidence["_approved_labels"] = sorted(marker["labels"])
        return evidence

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
    expected_gid: int = SOCKET_GROUP_GID,
) -> str:
    response = _socket_request(
        {
            "action": "authorize", "kind": kind, "repository": repository,
            "number": number, "destination_repo": destination_repo,
        },
        socket_path=socket_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if not isinstance(response, dict) or set(response) not in ({"attestation"}, {"error"}):
        raise SystemAttestationError("dedicated signer response schema is invalid")
    if "error" in response:
        raise SystemAttestationError(str(response["error"]))
    if not isinstance(response["attestation"], str):
        raise SystemAttestationError("dedicated signer response is malformed")
    return response["attestation"]


def request_action(
    *, operation: str, repository: str, number: int, destination_repo: str,
    expected_head: str, merge_method: str = "squash", nonce: str | None = None,
    socket_path: Path = SOCKET_PATH, expected_uid: int | None = None,
    expected_gid: int = SOCKET_GROUP_GID,
) -> dict[str, Any]:
    action_nonce = nonce or secrets.token_hex(32)
    response = _socket_request(
        {
            "action": "decide", "operation": operation,
            "repository": repository, "number": number,
            "destination_repo": destination_repo, "expected_head": expected_head,
            "merge_method": merge_method, "nonce": action_nonce,
        },
        socket_path=socket_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if set(response) == {"error"}:
        raise SystemAttestationError(str(response["error"]))
    required = {
        "allowed", "operation", "repository", "number", "destination_repo",
        "expected_head", "merge_method", "nonce", "head_sha", "base_ref",
        "base_sha",
        "reviewer_identity", "review_id", "review_state", "check_runs",
        "expires_at", "signature",
    }
    if not isinstance(response, dict) or not required <= set(response):
        raise SystemAttestationError("protected signer decision is malformed")
    if (
        response["allowed"] is not True
        or response["operation"] != operation
        or response["repository"] != repository.casefold()
        or response["destination_repo"] != destination_repo.casefold()
        or response["number"] != number
        or response["expected_head"] != expected_head.casefold()
        or response["head_sha"] != expected_head.casefold()
        or response["merge_method"] != merge_method
        or response["nonce"] != action_nonce
        or _iso(response["expires_at"]) <= datetime.now(timezone.utc)
    ):
        raise SystemAttestationError("protected signer denied the action")
    return response


def request_issue_action(
    *, operation: str, repository: str, number: int, destination_repo: str,
    issue_digest: str, title: str = "", body: str = "",
    labels: list[str] | None = None, nonce: str | None = None,
    socket_path: Path = SOCKET_PATH, expected_uid: int | None = None,
    expected_gid: int = SOCKET_GROUP_GID,
) -> dict[str, Any]:
    action_nonce = nonce or secrets.token_hex(32)
    response = _socket_request(
        {
            "action": "decide_issue", "operation": operation,
            "repository": repository, "number": number,
            "destination_repo": destination_repo,
            "issue_digest": issue_digest, "title": title, "body": body,
            "labels": labels or [], "nonce": action_nonce,
        },
        socket_path=socket_path, expected_uid=expected_uid, expected_gid=expected_gid,
    )
    if set(response) == {"error"}:
        raise SystemAttestationError(str(response["error"]))
    required = {
        "allowed", "operation", "repository", "number", "destination_repo",
        "issue_digest", "title", "body", "labels", "nonce",
        "reviewer_identity", "comment_id", "review_state", "expires_at",
        "approved_labels", "signature",
    }
    if (
        not isinstance(response, dict)
        or not required <= set(response)
        or response["allowed"] is not True
        or response["operation"] != operation
        or response["repository"] != repository.casefold()
        or response["destination_repo"] != destination_repo.casefold()
        or response["number"] != number
        or response["issue_digest"] != issue_digest
        or response["title"] != title
        or response["body"] != body
        or response["labels"] != (labels or [])
        or response["nonce"] != action_nonce
        or _iso(response["expires_at"]) <= datetime.now(timezone.utc)
        or (
            operation == "issue_submit"
            and (
                response.get("submitted") is not True
                or type(response.get("issue_number")) is not int
                or not _github_issue_url(
                    response.get("url"), destination_repo,
                    response.get("issue_number"),
                )
            )
        )
    ):
        raise SystemAttestationError("protected signer denied the issue action")
    return response


def verify_attestation(
    attestation: str,
    *,
    historical: bool = False,
    socket_path: Path = SOCKET_PATH,
    expected_uid: int | None = None,
    expected_gid: int = SOCKET_GROUP_GID,
) -> dict[str, Any]:
    response = _socket_request(
        {
            "action": "verify",
            "attestation": attestation,
            "historical": historical,
        },
        socket_path=socket_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if set(response) == {"error"}:
        raise SystemAttestationError(str(response["error"]))
    if (
        set(response) != {"status", "key_state"}
        or response["status"] != "verified"
        or response["key_state"] not in {"current", "previous", "archive"}
    ):
        raise SystemAttestationError("dedicated signer verification failed")
    return response


def _socket_request(
    request: dict[str, Any], *, socket_path: Path, expected_uid: int | None,
    expected_gid: int,
) -> dict[str, Any]:
    encoded = _canonical(request) + b"\n"
    if len(encoded) > MAX_REQUEST:
        raise SystemAttestationError("request is oversized")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    try:
        trusted_uid = (
            pwd.getpwnam("saturnin-signer").pw_uid
            if expected_uid is None else expected_uid
        )
        identity = _trusted_socket_identity(
            socket_path, trusted_uid, expected_gid
        )
        client.connect(str(socket_path))
        pid, uid, _ = struct.unpack(
            "3i",
            client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
        )
        if (
            uid != trusted_uid
            or pid <= 1
            or _trusted_socket_identity(
                socket_path, trusted_uid, expected_gid
            ) != identity
        ):
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


def _trusted_socket_identity(
    socket_path: Path, expected_uid: int, expected_gid: int
) -> tuple[int, int]:
    try:
        parent = socket_path.parent.lstat()
        endpoint = socket_path.lstat()
    except OSError:
        raise SystemAttestationError(
            "dedicated signer socket identity is unavailable"
        ) from None
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != expected_uid
        or parent.st_gid != expected_gid
        or stat.S_IMODE(parent.st_mode) != 0o2750
        or not stat.S_ISSOCK(endpoint.st_mode)
        or endpoint.st_uid != expected_uid
        or endpoint.st_gid != expected_gid
        or stat.S_IMODE(endpoint.st_mode) != 0o660
        or endpoint.st_nlink != 1
    ):
        raise SystemAttestationError("dedicated signer socket identity is not trusted")
    return endpoint.st_dev, endpoint.st_ino


def _credential(name: str, *, optional: bool = False) -> bytes:
    directory = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
    path = directory / name
    try:
        value = path.read_bytes()
    except OSError:
        if optional:
            return b""
        raise SystemAttestationError(f"required credential {name} is unavailable") from None
    if b"\0" in value or len(value) > MAX_CREDENTIAL:
        raise SystemAttestationError(f"credential {name} is invalid")
    return value.rstrip(b"\n")


def _archive_credential(value: bytes) -> tuple[bytes, ...]:
    try:
        payload = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemAttestationError(
            "retired signing credential archive is malformed"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "keys"}
        or payload["version"] != ARCHIVE_VERSION
        or not isinstance(payload["keys"], list)
        or len(payload["keys"]) > ARCHIVE_MAX_KEYS
    ):
        raise SystemAttestationError("retired signing credential archive schema is invalid")
    keys: list[bytes] = []
    for encoded in payload["keys"]:
        if not isinstance(encoded, str):
            raise SystemAttestationError(
                "retired signing credential archive schema is invalid"
            )
        try:
            key = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise SystemAttestationError(
                "retired signing credential archive key is invalid"
            ) from exc
        if len(key) < 32 or len(key) > 4096 or b"\0" in key:
            raise SystemAttestationError(
                "retired signing credential archive key is invalid"
            )
        keys.append(key)
    if len({hashlib.sha256(key).digest() for key in keys}) != len(keys):
        raise SystemAttestationError(
            "retired signing credential archive contains duplicates"
        )
    return tuple(keys)


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


def _create_listener(
    path: Path = SOCKET_PATH, expected_gid: int = SOCKET_GROUP_GID
) -> socket.socket:
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or parent.st_gid != expected_gid
        or stat.S_IMODE(parent.st_mode) != 0o2750
    ):
        raise SystemAttestationError("dedicated signer runtime directory is unsafe")
    try:
        existing = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISSOCK(existing.st_mode)
            or existing.st_uid != os.getuid()
            or existing.st_nlink != 1
        ):
            raise SystemAttestationError("dedicated signer socket path is unsafe")
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        os.chmod(path, 0o660, follow_symlinks=False)
        metadata = path.lstat()
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o660
            or metadata.st_nlink != 1
        ):
            raise SystemAttestationError("dedicated signer socket identity is unsafe")
        listener.listen(socket.SOMAXCONN)
        listener.settimeout(1)
        return listener
    except Exception:
        listener.close()
        try:
            if path.lstat().st_uid == os.getuid():
                path.unlink()
        except FileNotFoundError:
            pass
        raise


def _notify_ready() -> None:
    address = os.environ.get("NOTIFY_SOCKET", "")
    if not address:
        raise SystemAttestationError("systemd readiness socket is unavailable")
    if address.startswith("@"):
        address = "\0" + address[1:]
    if not address.startswith(("/", "\0")) or len(address.encode()) > 107:
        raise SystemAttestationError("systemd readiness socket is invalid")
    notification = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        notification.settimeout(5)
        notification.connect(address)
        notification.sendall(
            b"READY=1\nSTATUS=Protected GitHub access and listener verified"
        )
    except OSError:
        raise SystemAttestationError("systemd readiness notification failed") from None
    finally:
        notification.close()


def serve() -> None:
    config = ServiceConfig.load()
    current = _credential("current.key")
    previous = _credential("previous.key", optional=True) or None
    archive = _archive_credential(_credential("archive.keys"))
    token = _credential("github.token").decode()
    publisher_credential = PublisherCredential.load(
        _credential("github.publisher")
    )
    if (
        not 20 <= len(token) <= 512
        or not token.isascii()
        or any(character.isspace() for character in token)
    ):
        raise SystemAttestationError("protected GitHub credential is invalid")
    publisher = GitHubAppPublisher(config, publisher_credential)
    signer = DedicatedSigner(
        config,
        GitHub(config, token),
        current,
        previous,
        archive_keys=archive,
        publisher_client=publisher.client,
    )
    signer._verify_protected_access()
    listener = _create_listener()
    _notify_ready()
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
                elif request.get("action") == "decide":
                    if not limiter.allow(peer_uid):
                        outcome = "rate_limited"
                        raise SystemAttestationError("authorization rate limit exceeded")
                    response = signer.action(request)
                    evidence_hash = hashlib.sha256(
                        f"github:review:{response['review_id']}".encode()
                    ).hexdigest()
                    scope_hash = hashlib.sha256(
                        _canonical({
                            key: response[key]
                            for key in (
                                "operation", "repository", "number",
                                "destination_repo", "head_sha", "nonce",
                            )
                        })
                    ).hexdigest()
                    outcome = f"{response['operation']}_authorized"
                elif request.get("action") == "decide_issue":
                    if not limiter.allow(peer_uid):
                        outcome = "rate_limited"
                        raise SystemAttestationError("authorization rate limit exceeded")
                    response = signer.issue_action(request)
                    evidence_hash = hashlib.sha256(
                        f"github:comment:{response['comment_id']}".encode()
                    ).hexdigest()
                    scope_hash = hashlib.sha256(
                        _canonical({
                            key: response[key]
                            for key in (
                                "operation", "repository", "number",
                                "destination_repo", "issue_digest", "nonce",
                            )
                        })
                    ).hexdigest()
                    outcome = f"{response['operation']}_authorized"
                elif (
                    set(request) == {"action", "attestation", "historical"}
                    and request["action"] == "verify"
                    and type(request["historical"]) is bool
                ):
                    outcome = "verified"
                    response = signer.verify(
                        request["attestation"], historical=request["historical"]
                    )
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
    try:
        metadata = SOCKET_PATH.lstat()
        if stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.getuid():
            SOCKET_PATH.unlink()
    except FileNotFoundError:
        pass
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
