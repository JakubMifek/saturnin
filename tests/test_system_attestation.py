from __future__ import annotations

import json
import os
import socket
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from saturnin.system_attestation import (
    DedicatedSigner,
    GitHub,
    AuthorizationLimiter,
    ServiceConfig,
    SystemAttestationError,
    _RejectRedirects,
    _audit,
    _open_without_redirects,
    request_attestation,
    verify_attestation,
)
from saturnin.governance import Governance
from saturnin.review import ReviewLedger


NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)
HEAD = "a" * 40


def config() -> ServiceConfig:
    return ServiceConfig(
        frozenset({"acme/widget"}),
        frozenset({"review-bot"}),
        frozenset({"review-bot"}),
        frozenset({"approved"}),
    )


def pr_transport(*, state: str = "APPROVED", head: str = HEAD):
    def get(path: str):
        if path == "/repos/acme/widget/pulls/7":
            return {"head": {"sha": head}, "user": {"login": "author"}}
        if "/reviews?" in path:
            return [] if "page=2" in path else [{
                "id": 91, "commit_id": head, "state": state,
                "submitted_at": "2026-09-28T16:00:00Z",
                "user": {"login": "review-bot", "type": "Bot"},
            }]
        raise AssertionError(path)
    return get


def signer(tmp_path: Path, transport=pr_transport()) -> DedicatedSigner:
    cfg = config()
    return DedicatedSigner(
        cfg, GitHub(cfg, transport=transport), b"c" * 48, b"p" * 48,
        tmp_path / "state.sqlite3", now=lambda: NOW,
    )


def request(**changes):
    value = {
        "action": "authorize", "kind": "pr", "repository": "acme/widget",
        "number": 7, "destination_repo": "acme/widget",
    }
    value.update(changes)
    return value


def test_same_uid_direct_request_only_signs_live_github_approval(tmp_path: Path) -> None:
    value = signer(tmp_path).authorize(request())
    payload = json.loads(value)
    assert payload["head_sha"] == HEAD
    assert payload["author"] == "github:author"
    assert payload["reviewer_identity"] == "review-bot"
    assert payload["zero_context"] is True

    with pytest.raises(SystemAttestationError, match="no current allowed approval"):
        signer(tmp_path / "unapproved", pr_transport(state="CHANGES_REQUESTED")).authorize(
            request()
        )


@pytest.mark.parametrize("change", [
    {"repository": "evil/widget"}, {"destination_repo": "evil/widget"},
    {"number": "../7"}, {"kind": "unknown"}, {"extra": "claim"},
])
def test_forged_scope_and_malformed_requests_fail(tmp_path: Path, change: dict) -> None:
    with pytest.raises(SystemAttestationError):
        signer(tmp_path).authorize(request(**change))


def test_stale_or_wrong_commit_review_fails(tmp_path: Path) -> None:
    def transport(path: str):
        if path.endswith("/pulls/7"):
            return {"head": {"sha": HEAD}, "user": {"login": "author"}}
        return [{
            "id": 1, "commit_id": "b" * 40, "state": "APPROVED",
            "submitted_at": "2026-09-28T16:00:00Z",
            "user": {"login": "review-bot", "type": "Bot"},
        }]
    with pytest.raises(SystemAttestationError, match="exact head"):
        signer(tmp_path, transport).authorize(request())


def test_evidence_is_idempotent_but_altered_scope_is_replay(tmp_path: Path) -> None:
    service = signer(tmp_path)
    first = service.authorize(request())
    assert service.authorize(request()) == first
    service.config = ServiceConfig(
        frozenset({"acme/widget", "acme/other"}), service.config.pr_reviewers,
        service.config.issue_reviewers, service.config.allowed_verdicts,
    )
    with pytest.raises(SystemAttestationError, match="already consumed"):
        service.authorize(request(destination_repo="acme/other"))


def test_concurrent_request_has_one_exact_result(tmp_path: Path) -> None:
    service = signer(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda _: service.authorize(request()), range(16)))
    assert len(set(values)) == 1


def test_issue_marker_binds_every_field_and_consumes_comment(tmp_path: Path) -> None:
    digest_payload = json.dumps(
        {"body": "Body", "title": "Title"}, sort_keys=True, separators=(",", ":")
    ).encode()
    import hashlib
    digest = hashlib.sha256(digest_payload).hexdigest()
    marker = {
        "repository": "acme/widget", "issue": 9, "digest": digest,
        "author": "author", "reviewer_role": "issue-reviewer",
        "verdict": "approved", "zero_context": True,
        "destination_repo": "acme/widget",
        "expiry": (NOW + timedelta(minutes=5)).isoformat(), "nonce": "d" * 32,
    }

    def transport(path: str):
        if path.endswith("/issues/9"):
            return {"title": "Title", "body": "Body", "user": {"login": "author"}}
        return [{
            "id": 55, "body": "saturnin-attestation:v1 " + json.dumps(marker),
            "created_at": NOW.isoformat(),
            "updated_at": NOW.isoformat(),
            "user": {"login": "review-bot", "type": "Bot"},
        }]

    cfg = config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, transport=transport), b"k" * 48, None,
        tmp_path / "issue.sqlite3", now=lambda: NOW,
    )
    value = service.authorize(request(kind="issue", number=9))
    assert json.loads(value)["issue_digest"] == digest
    assert service.authorize(request(kind="issue", number=9)) == value
    marker["expiry"] = (NOW - timedelta(seconds=1)).isoformat()
    with pytest.raises(SystemAttestationError, match="expired"):
        service.authorize(request(kind="issue", number=9))
    marker["expiry"] = (NOW + timedelta(minutes=5)).isoformat()
    marker["author"] = 7
    with pytest.raises(SystemAttestationError, match="types"):
        service.authorize(request(kind="issue", number=9))


def test_current_and_previous_verification_no_downgrade(tmp_path: Path) -> None:
    cfg = config()
    with pytest.raises(SystemAttestationError, match="previous"):
        DedicatedSigner(
            cfg, GitHub(cfg, transport=pr_transport()), b"k" * 48, b"k" * 48,
            tmp_path / "bad.sqlite3",
        )
    service = signer(tmp_path)
    with pytest.raises(SystemAttestationError, match="malformed"):
        service.verify("{")
    value = service.authorize(request())
    assert service.verify(value) == {"status": "verified", "previous": False}
    altered = json.loads(value)
    altered["destination_repo"] = "acme/other"
    with pytest.raises(SystemAttestationError, match="does not match"):
        service.verify(json.dumps(altered))


def test_attestation_expiry_is_enforced(tmp_path: Path) -> None:
    current = [NOW]
    cfg = config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, transport=pr_transport()), b"c" * 48, b"p" * 48,
        tmp_path / "expiry.sqlite3", now=lambda: current[0],
    )
    value = service.authorize(request())
    current[0] += timedelta(seconds=301)
    with pytest.raises(SystemAttestationError, match="expired"):
        service.verify(value)


def test_mocked_production_approval_record_gate_and_unreviewed_rejection(
    tmp_path: Path, config, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = signer(tmp_path)
    attestation = service.authorize(request())
    monkeypatch.setattr(
        "saturnin.system_attestation.verify_attestation",
        lambda value: service.verify(value),
    )
    record = ReviewLedger(config).record(
        subject="acme/widget#7",
        kind="pr",
        author="github:author",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=HEAD,
        destination_repo="acme/widget",
        attestation=attestation,
        notes="mock GitHub production flow",
    )
    reloaded = ReviewLedger(config).for_subject("acme/widget#7", "pr")
    decision = Governance(config).merge_allowed(
        repo="JakubMifek/saturnin",
        author="github:author",
        records=reloaded,
        head_sha=HEAD,
    )
    assert decision.allowed
    rejected = Governance(config).merge_allowed(
        repo="JakubMifek/saturnin",
        author="github:author",
        records=[record],
        head_sha="b" * 40,
    )
    assert not rejected.allowed


def test_service_config_loads_only_fixed_github_origin(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "repositories": ["Acme/Widget"],
        "pr_reviewers": ["Review-Bot"],
        "issue_reviewers": ["Review-Bot"],
        "allowed_verdicts": ["approved"],
        "github_api": "https://api.github.com",
    }), encoding="utf-8")
    loaded = ServiceConfig.load(path)
    assert loaded.repositories == frozenset({"acme/widget"})
    assert loaded.pr_reviewers == frozenset({"review-bot"})

    data = json.loads(path.read_text())
    data["github_api"] = "https://github.example.invalid"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SystemAttestationError, match="exactly"):
        ServiceConfig.load(path)
    path.write_text("{", encoding="utf-8")
    with pytest.raises(SystemAttestationError, match="unavailable"):
        ServiceConfig.load(path)

    path.write_text(json.dumps({
        "repositories": [], "pr_reviewers": [], "issue_reviewers": [],
        "allowed_verdicts": ["approved"],
    }), encoding="utf-8")
    with pytest.raises(SystemAttestationError, match="must not be empty"):
        ServiceConfig.load(path)
    path.write_text(json.dumps({
        "repositories": ["acme/widget"], "pr_reviewers": ["bot"],
        "issue_reviewers": ["bot"], "allowed_verdicts": ["invented"],
    }), encoding="utf-8")
    with pytest.raises(SystemAttestationError, match="verdicts"):
        ServiceConfig.load(path)
    path.write_text(json.dumps({
        "repositories": ["acme/widget"], "pr_reviewers": ["bot"],
        "issue_reviewers": ["bot"], "allowed_verdicts": ["approved"],
        "unexpected": True,
    }), encoding="utf-8")
    with pytest.raises(SystemAttestationError, match="schema"):
        ServiceConfig.load(path)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("request_timeout_seconds", 0),
        ("maximum_issue_marker_ttl_seconds", 3601),
        ("authorization_limit", 0),
        ("authorization_window_seconds", 3601),
    ],
)
def test_service_config_rejects_unbounded_limits(
    tmp_path: Path, name: str, value: int
) -> None:
    data = {
        "repositories": ["acme/widget"], "pr_reviewers": ["bot"],
        "issue_reviewers": ["bot"], "allowed_verdicts": ["approved"],
        name: value,
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(SystemAttestationError, match="bounds"):
        ServiceConfig.load(path)


def test_service_config_rejects_missing_lists_and_non_numeric_bounds(
    tmp_path: Path,
) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "repositories": ["acme/widget"], "pr_reviewers": ["bot"],
        "issue_reviewers": ["bot"],
    }), encoding="utf-8")
    with pytest.raises(SystemAttestationError, match="lists"):
        ServiceConfig.load(path)
    path.write_text(json.dumps({
        "repositories": ["acme/widget"], "pr_reviewers": ["bot"],
        "issue_reviewers": ["bot"], "allowed_verdicts": ["approved"],
        "authorization_limit": "not-a-number",
    }), encoding="utf-8")
    with pytest.raises(SystemAttestationError, match="bounds"):
        ServiceConfig.load(path)


def _one_shot_server(path: Path, response: dict) -> threading.Thread:
    ready = threading.Event()

    def run() -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        ready.set()
        connection, _ = listener.accept()
        with connection:
            connection.recv(128 * 1024)
            connection.sendall(
                json.dumps(response, separators=(",", ":")).encode() + b"\n"
            )
        listener.close()

    thread = threading.Thread(target=run)
    thread.start()
    ready.wait(timeout=5)
    return thread


def test_socket_client_checks_peer_and_response_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "sign.sock"
    monkeypatch.setattr(
        "saturnin.system_attestation._trusted_service_process", lambda pid: True
    )
    thread = _one_shot_server(path, {"attestation": "signed"})
    assert request_attestation(
        kind="pr", repository="acme/widget", number=7,
        destination_repo="acme/widget", socket_path=path, expected_uid=os.getuid(),
    ) == "signed"
    thread.join(timeout=5)

    path.unlink()
    thread = _one_shot_server(path, {"status": "verified", "previous": False})
    assert verify_attestation(
        "signed", socket_path=path, expected_uid=os.getuid()
    ) == {"status": "verified", "previous": False}
    thread.join(timeout=5)

    path.unlink()
    thread = _one_shot_server(path, {"error": "denied"})
    with pytest.raises(SystemAttestationError, match="denied"):
        verify_attestation("signed", socket_path=path, expected_uid=os.getuid())
    thread.join(timeout=5)


def test_github_client_rejects_paths_and_bounds_pagination() -> None:
    cfg = config()
    client = GitHub(cfg, transport=lambda path: [])
    with pytest.raises(SystemAttestationError, match="path"):
        client.get("https://evil.invalid/repos/acme/widget")
    with pytest.raises(SystemAttestationError, match="path"):
        client.get("/repos/acme/widget/pulls/../secrets")
    assert client.pages("/repos/acme/widget/pulls/7/reviews") == []

    oversized = GitHub(cfg, transport=lambda path: [{}] * 101)
    with pytest.raises(SystemAttestationError, match="oversized"):
        oversized.pages("/repos/acme/widget/pulls/7/reviews")


def test_github_authorization_header_uses_token_without_disclosure(
) -> None:
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def geturl(self):
            return "https://api.github.com/repos/acme/widget/pulls/7"

        def read(self, _size):
            return b"{}"

    def open_request(request, timeout):
        seen["authorization"] = request.get_header("Authorization")
        seen["timeout"] = timeout
        return Response()

    token = "root-token-for-test"
    assert GitHub(
        config(), token=token, request_transport=open_request
    ).get("/repos/acme/widget/pulls/7") == {}
    assert seen == {"authorization": f"Bearer {token}", "timeout": 10}

    def fail_request(_request, timeout):
        raise urllib.error.URLError(f"transport failed with {token}")

    with pytest.raises(SystemAttestationError) as caught:
        GitHub(
            config(), token=token, request_transport=fail_request
        ).get("/repos/acme/widget/pulls/7")
    assert token not in str(caught.value)


def test_github_client_rejects_redirect_and_malformed_response(
) -> None:
    class Response:
        url = "https://evil.invalid/repos/acme/widget/pulls/7"
        body = b"{}"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def geturl(self):
            return self.url

        def read(self, _size):
            return self.body

    response = Response()
    client = GitHub(
        config(), request_transport=lambda request, timeout: response
    )
    with pytest.raises(SystemAttestationError, match="redirect"):
        client.get("/repos/acme/widget/pulls/7")
    response.url = "https://api.github.com/repos/acme/widget/pulls/7"
    response.body = b"{"
    with pytest.raises(SystemAttestationError, match="malformed"):
        client.get("/repos/acme/widget/pulls/7")


def test_default_github_transport_disables_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _RejectRedirects().redirect_request(None, None, 302, "", {}, "") is None
    seen = {}

    class Opener:
        def open(self, request, timeout):
            seen["request"] = request
            seen["timeout"] = timeout
            return "response"

    def build(handler):
        seen["handler"] = handler
        return Opener()

    monkeypatch.setattr("urllib.request.build_opener", build)
    request = urllib.request.Request("https://api.github.com/repos/acme/widget")
    assert _open_without_redirects(request, 3) == "response"
    assert seen["handler"] is _RejectRedirects
    assert seen["request"] is request
    assert seen["timeout"] == 3


def test_authorization_limiter_is_bounded_and_recovers() -> None:
    ticks = iter((0.0, 1.0, 2.0, 11.0, 12.0))
    limiter = AuthorizationLimiter(2, 10, clock=lambda: next(ticks))
    assert limiter.allow(1000)
    assert limiter.allow(1000)
    assert not limiter.allow(1000)
    assert limiter.allow(1000)
    assert limiter.allow(1001)


def test_audit_record_contains_only_hashes_and_outcome(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _audit("authorized", "e" * 64, "s" * 64)
    record = json.loads(capsys.readouterr().err)
    assert record == {
        "event": "attestation_authorization",
        "outcome": "authorized",
        "evidence_hash": "e" * 64,
        "scope_hash": "s" * 64,
    }
