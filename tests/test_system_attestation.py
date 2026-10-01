from __future__ import annotations

import json
import base64
import hashlib
import hmac
import os
import secrets
import socket
import struct
import subprocess
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import saturnin.system_attestation as system_attestation
from saturnin.system_attestation import (
    DedicatedSigner,
    GitHub,
    GitHubAppPublisher,
    GitHubMutationError,
    ISSUE_MARKER,
    ISSUE_SUBMISSION_MARKER,
    NOTES_REVIEW_MARKER,
    PublisherCredential,
    AuthorizationLimiter,
    ARCHIVE_MAX_KEYS,
    ServiceConfig,
    SystemAttestationError,
    _RejectRedirects,
    _archive_credential,
    _audit,
    _create_listener,
    _notify_ready,
    _credential,
    _open_without_redirects,
    publish_issue_review,
    read_only_pr_gate,
    request_attestation,
    request_action,
    request_issue_action,
    verify_attestation,
)
from saturnin.governance import Governance
from saturnin.review import ReviewLedger, ReviewRecord, slugify
from saturnin.review import (
    execution_scoped_review_attestation_key,
    role_scoped_review_attestation_key,
    sign_review_attestation,
    notes_review_settings,
)


NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)
HEAD = "a" * 40


def production_branch_protection() -> dict:
    return {
        "required_pull_request_reviews": {
            "url": "https://api.github.com/repos/acme/widget/branches/main/protection/required_pull_request_reviews",
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": False,
            "require_last_push_approval": True,
            "required_approving_review_count": 1,
        },
        "required_status_checks": {
            "url": "https://api.github.com/repos/acme/widget/branches/main/protection/required_status_checks",
            "strict": True,
            "contexts": ["test"],
            "checks": [{"context": "test", "app_id": None}],
        },
        "enforce_admins": {
            "enabled": True,
            "url": "https://api.github.com/repos/acme/widget/branches/main/protection/enforce_admins",
        },
        "restrictions": None,
    }


def service_config() -> ServiceConfig:
    return ServiceConfig(
        frozenset({"acme/widget"}),
        frozenset({"review-bot"}),
        frozenset({"review-bot"}),
        frozenset({"approved"}),
    )


def notes_service_config() -> ServiceConfig:
    return ServiceConfig(
        frozenset({"acme/widget"}),
        frozenset({"review-bot"}),
        frozenset({"review-bot"}),
        frozenset({"approved"}),
        notes_repository="acme/widget",
        notes_review_profile="notes-review",
        notes_review_method="rubber-duck",
        notes_review_checks=(
            "canonical_structure",
            "duplication",
            "factual_integrity",
            "links",
            "retrievability",
        ),
        notes_writer_logins=frozenset({"author"}),
        notes_delivery_check_run="saturnin-notes-delivery",
        notes_delivery_app_slug="saturnin-notes-writer",
    )


def notes_review_body(head: str = HEAD) -> str:
    return NOTES_REVIEW_MARKER + json.dumps(
        {
            "repository": "acme/widget",
            "head_sha": head,
            "profile": "notes-review",
            "method": "rubber-duck",
            "checks": [
                "canonical_structure",
                "duplication",
                "factual_integrity",
                "links",
                "retrievability",
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def pr_transport(*, state: str = "APPROVED", head: str = HEAD):
    def get(path: str):
        if path == "/user":
            return {"login": "saturnin-merge-bot", "type": "User"}
        if path == "/repos/acme/widget":
            return {
                "full_name": "acme/widget",
                "permissions": {"push": True, "admin": False},
            }
        if path == "/repos/acme/widget/branches/main/protection":
            return production_branch_protection()
        if path == "/repos/acme/widget/pulls/7":
            return {
                "head": {"sha": head},
                "base": {
                    "ref": "main",
                    "repo": {"full_name": "acme/widget"},
                },
                "user": {"login": "author"},
                "state": "open",
                "draft": False,
            }
        if "/reviews?" in path:
            return [] if "page=2" in path else [{
                "id": 91, "commit_id": head, "state": state,
                "submitted_at": "2026-09-27T16:00:00Z",
                "body": notes_review_body(head),
                "user": {"login": "review-bot", "type": "Bot"},
            }]
        if "/check-runs?" in path:
            return {
                "total_count": 1,
                "check_runs": [{
                    "id": 601,
                    "name": "saturnin-notes-delivery",
                    "status": "completed",
                    "conclusion": "success",
                    "external_id": (
                        "saturnin-notes-delivery:v1:"
                        f"acme/widget:{head}:author"
                    ),
                    "app": {"slug": "saturnin-notes-writer"},
                }],
            }
        raise AssertionError(path)
    return get


def action_transport(
    *, state: str = "APPROVED", head: str = HEAD,
    reviewer: str = "review-bot", reviewer_type: str = "Bot",
    check_conclusion: str = "success",
):
    def get(path: str):
        if path == "/user":
            return {"login": "saturnin-merge-bot", "type": "User"}
        if path == "/repos/acme/widget":
            return {
                "full_name": "acme/widget",
                "permissions": {"push": True, "admin": False},
            }
        if path == "/repos/acme/widget/branches/main/protection":
            return production_branch_protection()
        if path == "/repos/acme/widget/pulls/7":
            return {
                "head": {"sha": head},
                "base": {
                    "ref": "main",
                    "sha": "f" * 40,
                    "repo": {"full_name": "acme/widget"},
                },
                "user": {"login": "author"},
                "state": "open",
                "draft": False,
                "mergeable": True,
                "mergeable_state": "clean",
            }
        if "/reviews?" in path:
            return [] if "page=2" in path else [{
                "id": 91, "commit_id": head, "state": state,
                "submitted_at": "2026-09-27T16:00:00Z",
                "body": notes_review_body(head),
                "user": {"login": reviewer, "type": reviewer_type},
            }]
        if "/check-runs?" in path:
            return {
                "total_count": 2,
                "check_runs": [
                    {
                        "id": 501, "name": "test", "status": "completed",
                        "conclusion": check_conclusion,
                    },
                    {
                        "id": 601,
                        "name": "saturnin-notes-delivery",
                        "status": "completed",
                        "conclusion": "success",
                        "external_id": (
                            "saturnin-notes-delivery:v1:"
                            f"acme/widget:{head}:author"
                        ),
                        "app": {"slug": "saturnin-notes-writer"},
                    },
                ],
            }
        raise AssertionError(path)
    return get


def action_request(**changes):
    value = {
        "action": "decide", "operation": "gate",
        "repository": "acme/widget", "number": 7,
        "destination_repo": "acme/widget", "expected_head": HEAD,
        "merge_method": "squash", "nonce": "d" * 64,
    }
    value.update(changes)
    return value


def issue_action_fixture(*, expiry: datetime | None = None):
    title = "Reviewed issue"
    body = "Exact reviewed body"
    digest = hashlib.sha256(
        json.dumps(
            {"body": body, "title": title},
            sort_keys=True, separators=(",", ":"),
        ).encode()
    ).hexdigest()
    expires = expiry or (NOW + timedelta(minutes=5))
    marker = {
        "repository": "acme/widget", "issue": 9, "digest": digest,
        "author": "author", "reviewer_role": "issue-reviewer",
        "verdict": "approved", "zero_context": True,
        "destination_repo": "acme/issues",
        "labels": ["incident"],
        "expiry": expires.isoformat(), "nonce": "e" * 32,
    }

    def transport(path: str):
        if path == "/user":
            return {"login": "saturnin-merge-bot", "type": "User"}
        if path == "/repos/acme/issues":
            return {
                "full_name": "acme/issues",
                "permissions": {"push": True, "admin": False},
            }
        if path.startswith("/repos/acme/issues/issues?"):
            return []
        if path == "/repos/acme/widget/issues/9":
            return {
                "title": title, "body": body,
                "state": "open",
                "user": {"login": "author"},
            }
        if "/repos/acme/widget/issues/9/comments?" in path:
            return [] if "page=2" in path else [{
                "id": 55,
                "body": ISSUE_MARKER + json.dumps(marker),
                "created_at": NOW.isoformat(), "updated_at": NOW.isoformat(),
                "user": {"login": "review-bot", "type": "Bot"},
            }]
        raise AssertionError(path)
    return title, body, digest, marker, transport


def issue_submit_request(
    title: str, body: str, digest: str, *, nonce: str = "f" * 64,
) -> dict:
    return {
        "action": "decide_issue", "operation": "issue_submit",
        "repository": "acme/widget", "number": 9,
        "destination_repo": "acme/issues", "issue_digest": digest,
        "title": title, "body": body, "labels": ["incident"], "nonce": nonce,
    }


def published_issue(
    title: str, body: str, number: int = 77, *, state: str = "open",
) -> dict:
    return {
        "number": number, "title": title, "body": body, "state": state,
        "state_reason": "not_planned" if state == "closed" else None,
        "labels": [{"name": "incident"}],
        "user": {"login": "saturnin-issue-publisher[bot]", "type": "Bot"},
        "created_at": NOW.isoformat(), "updated_at": NOW.isoformat(),
        "html_url": f"https://github.com/acme/issues/issues/{number}",
    }


def signer(tmp_path: Path, transport=pr_transport()) -> DedicatedSigner:
    cfg = service_config()
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


def test_notes_review_contract_is_derived_and_signed_by_protected_service(
    tmp_path: Path,
) -> None:
    cfg = notes_service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, transport=pr_transport()),
        b"c" * 48,
        b"p" * 48,
        tmp_path / "notes.sqlite3",
        now=lambda: NOW,
    )

    attestation = service.authorize(request())
    payload = json.loads(attestation)

    assert payload["review_profile"] == "notes-review"
    assert payload["review_method"] == "rubber-duck"
    assert payload["review_checks"] == [
        "canonical_structure",
        "duplication",
        "factual_integrity",
        "links",
        "retrievability",
    ]
    assert payload["writer_evidence_id"] == "github:check-run:601"
    assert service.verify(attestation) == {
        "status": "verified",
        "key_state": "current",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("review_profile", ""),
        ("review_method", "ordinary"),
        ("review_checks", ["factual_integrity"]),
    ],
)
def test_notes_review_contract_tampering_is_rejected(
    tmp_path: Path, field: str, value: object,
) -> None:
    cfg = notes_service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, transport=pr_transport()),
        b"c" * 48,
        b"p" * 48,
        tmp_path / "notes.sqlite3",
        now=lambda: NOW,
    )
    payload = json.loads(service.authorize(request()))
    payload[field] = value

    with pytest.raises(SystemAttestationError):
        service.verify(json.dumps(payload))


def test_notes_authorization_fails_without_provisioned_scribe_identity(
    tmp_path: Path,
) -> None:
    cfg = replace(notes_service_config(), notes_writer_logins=frozenset())
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, transport=pr_transport()),
        b"c" * 48,
        None,
        tmp_path / "notes.sqlite3",
        now=lambda: NOW,
    )

    with pytest.raises(SystemAttestationError, match="scribe identity"):
        service.authorize(request())


def test_notes_authorization_requires_head_bound_review_and_delivery_evidence(
    tmp_path: Path,
) -> None:
    cfg = notes_service_config()

    def generic_review(path: str):
        value = pr_transport()(path)
        if "/reviews?" in path and value:
            value[0]["body"] = "ordinary approval"
        return value

    with pytest.raises(SystemAttestationError, match="review evidence"):
        DedicatedSigner(
            cfg,
            GitHub(cfg, transport=generic_review),
            b"c" * 48,
            None,
            tmp_path / "review.sqlite3",
            now=lambda: NOW,
        ).authorize(request())

    without_delivery = replace(
        cfg, notes_delivery_check_run="", notes_delivery_app_slug="",
    )
    with pytest.raises(SystemAttestationError, match="not provisioned"):
        DedicatedSigner(
            without_delivery,
            GitHub(without_delivery, transport=pr_transport()),
            b"c" * 48,
            None,
            tmp_path / "delivery.sqlite3",
            now=lambda: NOW,
        ).authorize(request())


def test_protected_notes_attestation_records_scribe_role_and_identity(
    tmp_path: Path, config, monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = notes_service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, transport=pr_transport()),
        b"c" * 48,
        None,
        tmp_path / "notes.sqlite3",
        now=lambda: NOW,
    )
    attestation = service.authorize(request())
    monkeypatch.setattr(
        "saturnin.system_attestation.verify_attestation",
        lambda value, **kwargs: service.verify(value, **kwargs),
    )
    config.policy("repos")["repos"]["notes"]["slug"] = "acme/widget"
    settings = notes_review_settings(config)

    record = ReviewLedger(config).record(
        subject="acme/widget#7",
        kind="pr",
        author="scribe",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=HEAD,
        destination_repo="acme/widget",
        review_profile=settings["profile"],
        review_method=settings["method"],
        review_checks=settings["required_checks"],
        attestation=attestation,
    )

    assert record.author == "scribe"
    assert json.loads(record.attestation_payload)["author"] == "github:author"
    assert ReviewLedger(config).for_subject("acme/widget#7", "pr") == [record]


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
            "submitted_at": "2026-09-27T16:00:00Z",
            "user": {"login": "review-bot", "type": "Bot"},
        }]
    with pytest.raises(SystemAttestationError, match="exact head"):
        signer(tmp_path, transport).authorize(request())


def test_pr_evidence_is_idempotent_across_advancing_clock(
    tmp_path: Path,
) -> None:
    current = [NOW]
    cfg = service_config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, transport=pr_transport()), b"c" * 48, b"p" * 48,
        tmp_path / "state.sqlite3", now=lambda: current[0],
    )
    first = service.authorize(request())
    current[0] += timedelta(minutes=4)
    second = service.authorize(request())

    assert second == first
    assert json.loads(second)["expires_at"] == "2026-09-27T16:00:00+00:00"


def test_same_evidence_id_rejects_altered_scope(tmp_path: Path) -> None:
    service = signer(tmp_path)
    service.authorize(request())
    service.config = ServiceConfig(
        frozenset({"acme/widget", "acme/other"}), service.config.pr_reviewers,
        service.config.issue_reviewers, service.config.allowed_verdicts,
    )
    with pytest.raises(SystemAttestationError, match="not allowlisted"):
        service.authorize(request(destination_repo="acme/other"))


def test_same_review_id_rejects_changed_current_head(tmp_path: Path) -> None:
    current_head = [HEAD]

    def transport(path: str):
        if path == "/repos/acme/widget/pulls/7":
            return {
                "head": {"sha": current_head[0]},
                "user": {"login": "author"},
            }
        if "/reviews?" in path:
            return [] if "page=2" in path else [{
                "id": 91, "commit_id": current_head[0], "state": "APPROVED",
                "submitted_at": "2026-09-27T16:00:00Z",
                "user": {"login": "review-bot", "type": "Bot"},
            }]
        raise AssertionError(path)

    service = signer(tmp_path, transport)
    service.authorize(request())
    current_head[0] = "b" * 40

    with pytest.raises(SystemAttestationError, match="already consumed"):
        service.authorize(request())


def test_concurrent_process_shaped_requests_have_one_exact_result(
    tmp_path: Path,
) -> None:
    cfg = service_config()
    state_path = tmp_path / "state.sqlite3"
    services = [
        DedicatedSigner(
            cfg, GitHub(cfg, transport=pr_transport()), b"c" * 48, b"p" * 48,
            state_path, now=lambda: NOW,
        )
        for _ in range(8)
    ]
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(
            lambda index: services[index % len(services)].authorize(request()),
            range(16),
        ))
    assert len(set(values)) == 1


def test_fresh_gate_decision_binds_live_review_head_base_checks_and_nonce(
    tmp_path: Path,
) -> None:
    cfg = service_config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=action_transport()),
        b"c" * 48, b"p" * 48, tmp_path / "actions.sqlite3",
        now=lambda: NOW,
    )
    result = service.action(action_request())
    assert result["allowed"] is True
    assert result["operation"] == "gate"
    assert result["head_sha"] == HEAD
    assert result["base_ref"] == "main"
    assert result["base_sha"] == "f" * 40
    assert result["reviewer_identity"] == "review-bot"
    assert result["review_id"] == 91
    assert result["review_state"] == "approved"
    assert result["check_runs"] == ["test:501"]
    assert result["review_profile"] == ""
    assert result["review_method"] == ""
    assert result["review_checks"] == []
    assert result["writer_evidence_id"] == ""
    assert result["nonce"] == "d" * 64
    assert result["expires_at"] == "2026-09-28T00:01:00+00:00"
    assert len(result["signature"]) == 64


def test_notes_gate_binds_contract_and_requires_provisioned_scribe(
    tmp_path: Path,
) -> None:
    cfg = notes_service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, token="protected", transport=action_transport()),
        b"c" * 48,
        None,
        tmp_path / "notes-action.sqlite3",
        now=lambda: NOW,
    )

    result = service.action(action_request())
    assert result["review_profile"] == "notes-review"
    assert result["review_method"] == "rubber-duck"
    assert result["review_checks"] == [
        "canonical_structure",
        "duplication",
        "factual_integrity",
        "links",
        "retrievability",
    ]
    assert result["writer_evidence_id"] == "github:check-run:601"

    blocked = DedicatedSigner(
        replace(cfg, notes_writer_logins=frozenset()),
        GitHub(cfg, token="protected", transport=action_transport()),
        b"c" * 48,
        None,
        tmp_path / "notes-blocked.sqlite3",
        now=lambda: NOW,
    )
    with pytest.raises(SystemAttestationError, match="scribe identity"):
        blocked.action(action_request(nonce="e" * 64))


@pytest.mark.parametrize(
    "change",
    [
        {"operation": "delete"},
        {"nonce": "short"},
        {"expected_head": "not-a-sha"},
        {"destination_repo": "acme/other"},
        {"merge_method": "force"},
        {"extra": True},
    ],
)
def test_protected_action_rejects_caller_selected_authority(
    tmp_path: Path, change: dict,
) -> None:
    value = action_request()
    value.update(change)
    cfg = service_config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=action_transport()),
        b"c" * 48, None, tmp_path / "invalid.sqlite3", now=lambda: NOW,
    )
    with pytest.raises(SystemAttestationError):
        service.action(value)


@pytest.mark.parametrize("state", ["CHANGES_REQUESTED", "DISMISSED"])
def test_historical_audit_cannot_authorize_revoked_same_head_action(
    tmp_path: Path, state: str,
) -> None:
    current_state = ["APPROVED"]

    def transport(path: str):
        return action_transport(state=current_state[0])(path)

    cfg = service_config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=transport),
        b"c" * 48, b"p" * 48, tmp_path / "revoked.sqlite3",
        now=lambda: NOW,
    )
    historical = service.authorize(request())
    assert service.verify(historical, historical=True)["status"] == "verified"
    current_state[0] = state
    with pytest.raises(SystemAttestationError, match="no current allowed approval"):
        service.action(action_request())
    assert service.verify(historical, historical=True)["status"] == "verified"


def test_ordinary_identity_cannot_forge_protected_reviewer(
    tmp_path: Path,
) -> None:
    cfg = service_config()
    for transport in (
        action_transport(reviewer="ordinary-worker"),
        action_transport(reviewer_type="User"),
    ):
        service = DedicatedSigner(
            cfg, GitHub(cfg, token="protected", transport=transport),
            b"c" * 48, b"p" * 48, tmp_path / secrets.token_hex(4) / "state.sqlite3",
            now=lambda: NOW,
        )
        with pytest.raises(SystemAttestationError, match="no current allowed approval"):
            service.action(action_request())


@pytest.mark.parametrize(
    ("transport", "message"),
    [
        (action_transport(check_conclusion="failure"), "checks are not green"),
        (action_transport(head="b" * 40), "head changed"),
    ],
)
def test_protected_action_rejects_failed_checks_and_head_changes(
    tmp_path: Path, transport, message: str,
) -> None:
    cfg = service_config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=transport),
        b"c" * 48, None, tmp_path / message.replace(" ", "-") / "state.sqlite3",
        now=lambda: NOW,
    )
    with pytest.raises(SystemAttestationError, match=message):
        service.action(action_request())


def test_gate_rejects_force_push_between_pr_snapshots(tmp_path: Path) -> None:
    base = action_transport()
    pull_calls = [0]

    def transport(path: str):
        if path == "/repos/acme/widget/pulls/7":
            pull_calls[0] += 1
            value = base(path)
            if pull_calls[0] >= 2:
                value["head"]["sha"] = "b" * 40
            return value
        return base(path)

    cfg = service_config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=transport),
        b"c" * 48, None, tmp_path / "force-push.sqlite3", now=lambda: NOW,
    )
    with pytest.raises(SystemAttestationError, match="currently mergeable"):
        service.action(action_request())


def test_read_only_ci_gate_repeats_exact_head_review_snapshot() -> None:
    calls: list[str] = []
    base = pr_transport()

    def transport(path: str):
        calls.append(path)
        return base(path)

    result = read_only_pr_gate(
        service_config(),
        GitHub(service_config(), token="read-only", transport=transport),
        "acme/widget",
        7,
        HEAD,
        now=NOW,
    )

    assert result["review_id"] == 91
    assert calls.count("/repos/acme/widget/pulls/7") == 2
    assert calls.count("/repos/acme/widget/pulls/7/reviews?per_page=100&page=1") == 2


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("dismiss", "no current allowed approval"),
        ("replace", "state changed"),
        ("head", "no current allowed approval"),
        ("api", "rate limited"),
    ],
)
def test_read_only_ci_gate_fails_closed_on_live_state_changes(
    change: str,
    message: str,
) -> None:
    pull_reads = [0]
    review_reads = [0]

    def transport(path: str):
        if path == "/repos/acme/widget/pulls/7":
            pull_reads[0] += 1
            head = "b" * 40 if change == "head" and pull_reads[0] == 2 else HEAD
            return {
                "head": {"sha": head},
                "base": {
                    "ref": "main",
                    "repo": {"full_name": "acme/widget"},
                },
                "user": {"login": "author"},
                "state": "open",
                "draft": False,
            }
        if "/reviews?" in path:
            if "page=2" in path:
                return []
            review_reads[0] += 1
            if change == "api" and review_reads[0] == 2:
                raise SystemAttestationError("rate limited")
            state = (
                "DISMISSED"
                if change == "dismiss" and review_reads[0] == 2
                else "APPROVED"
            )
            review_id = 92 if change == "replace" and review_reads[0] == 2 else 91
            return [{
                "id": review_id,
                "commit_id": HEAD,
                "state": state,
                "submitted_at": "2026-09-27T16:00:00Z",
                "user": {"login": "review-bot", "type": "Bot"},
            }]
        raise AssertionError(path)

    with pytest.raises(SystemAttestationError, match=message):
        read_only_pr_gate(
            service_config(),
            GitHub(service_config(), token="read-only", transport=transport),
            "acme/widget",
            7,
            HEAD,
            now=NOW,
        )


@pytest.mark.parametrize(
    ("repo", "number", "head"),
    [
        ("acme/other", 7, HEAD),
        ("acme/widget", 0, HEAD),
        ("acme/widget", 7, "not-a-sha"),
    ],
)
def test_read_only_ci_gate_rejects_untrusted_scope(
    repo: str, number: int, head: str,
) -> None:
    with pytest.raises(SystemAttestationError, match="scope"):
        read_only_pr_gate(
            service_config(),
            GitHub(service_config(), token="read-only", transport=pr_transport()),
            repo,
            number,
            head,
            now=NOW,
        )


@pytest.mark.parametrize(
    "pull_change",
    [
        {"state": "closed"},
        {"draft": True},
        {"base": {"ref": "release", "repo": {"full_name": "acme/widget"}}},
        {"base": {"ref": "main", "repo": {"full_name": "acme/other"}}},
    ],
)
def test_read_only_ci_gate_rejects_wrong_live_destination(
    pull_change: dict,
) -> None:
    base = pr_transport()

    def transport(path: str):
        value = base(path)
        if path == "/repos/acme/widget/pulls/7":
            return {**value, **pull_change}
        return value

    with pytest.raises(SystemAttestationError, match="live scope"):
        read_only_pr_gate(
            service_config(),
            GitHub(service_config(), token="read-only", transport=transport),
            "acme/widget",
            7,
            HEAD,
            now=NOW,
        )


def test_protected_action_rejects_wrong_token_identity_or_permissions(
    tmp_path: Path,
) -> None:
    base = action_transport()

    def transport(path: str):
        if path == "/user":
            return {"login": "ordinary-worker", "type": "User"}
        if path == "/repos/acme/widget":
            return {
                "full_name": "acme/widget",
                "permissions": {"push": True, "admin": True},
            }
        return base(path)

    cfg = service_config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, token="ordinary", transport=transport),
        b"c" * 48, None, tmp_path / "identity.sqlite3", now=lambda: NOW,
    )
    with pytest.raises(SystemAttestationError, match="identity or permissions"):
        service.action(action_request())


def test_startup_verifies_protected_policy_and_check_endpoints(
    tmp_path: Path,
) -> None:
    cfg = service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, token="protected", transport=action_transport()),
        b"c" * 48,
        None,
        tmp_path / "startup.sqlite3",
        now=lambda: NOW,
    )

    service._verify_protected_access()


@pytest.mark.parametrize("blocked_endpoint", ["protection", "check-runs"])
def test_startup_fails_closed_when_protected_endpoint_is_forbidden(
    tmp_path: Path,
    blocked_endpoint: str,
) -> None:
    cfg = service_config()
    base = action_transport()

    def transport(path: str):
        if blocked_endpoint in path:
            raise SystemAttestationError(f"{blocked_endpoint} endpoint returned 403")
        return base(path)

    service = DedicatedSigner(
        cfg,
        GitHub(cfg, token="protected", transport=transport),
        b"c" * 48,
        None,
        tmp_path / f"{blocked_endpoint}.sqlite3",
        now=lambda: NOW,
    )

    with pytest.raises(SystemAttestationError, match="403"):
        service._verify_protected_access()


def test_protected_action_requires_nonbypassable_branch_protection(
    tmp_path: Path,
) -> None:
    base = action_transport()

    def transport(path: str):
        if path.endswith("/branches/main/protection"):
            return {
                "required_pull_request_reviews": {
                    "dismiss_stale_reviews": False,
                    "required_approving_review_count": 1,
                    "bypass_pull_request_allowances": {
                        "users": [{"login": "saturnin-merge-bot"}],
                        "teams": [], "apps": [],
                    },
                },
                "required_status_checks": {
                    "strict": False, "contexts": ["test"], "checks": [],
                },
                "enforce_admins": {"enabled": False},
            }
        return base(path)

    cfg = service_config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=transport),
        b"c" * 48, None, tmp_path / "protection.sqlite3", now=lambda: NOW,
    )
    with pytest.raises(SystemAttestationError, match="branch protection"):
        service.action(action_request())


@pytest.mark.parametrize("operation", ["gate", "merge"])
@pytest.mark.parametrize(
    "allowances",
    [
        pytest.param("omitted", id="omitted"),
        pytest.param({}, id="explicit-empty-object"),
        pytest.param(
            {"users": [], "teams": [], "apps": []},
            id="canonical-complete-empty",
        ),
    ],
)
def test_protected_action_accepts_github_empty_bypass_shapes(
    tmp_path: Path,
    operation: str,
    allowances: object,
) -> None:
    base = action_transport()

    def transport(path: str):
        if path.endswith("/branches/main/protection"):
            protection = production_branch_protection()
            if allowances != "omitted":
                protection["required_pull_request_reviews"][
                    "bypass_pull_request_allowances"
                ] = allowances
            return protection
        return base(path)

    cfg = service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(
            cfg,
            token="protected",
            transport=transport,
            mutation_transport=lambda *_args: {
                "merged": True,
                "message": "merged",
                "sha": "e" * 40,
            },
        ),
        b"c" * 48,
        None,
        tmp_path / f"valid-{operation}-{type(allowances).__name__}.sqlite3",
        now=lambda: NOW,
    )

    result = service.action(action_request(operation=operation))

    assert result["allowed"] is True
    assert result.get("merged", operation != "merge") is True


@pytest.mark.parametrize(
    "allowances",
    [
        pytest.param(None, id="null"),
        pytest.param(0, id="integer"),
        pytest.param("empty", id="scalar"),
        pytest.param([], id="list"),
        pytest.param({"users": []}, id="partial-users"),
        pytest.param({"teams": []}, id="partial-teams"),
        pytest.param({"apps": []}, id="partial-apps"),
        pytest.param(
            {"users": [], "teams": []},
            id="partial-two-keys",
        ),
        pytest.param(
            {"users": [], "teams": [], "apps": [], "roles": []},
            id="extra-key",
        ),
        pytest.param(
            {"users": {}, "teams": [], "apps": []},
            id="wrong-users-type",
        ),
        pytest.param(
            {"users": [], "teams": "none", "apps": []},
            id="wrong-teams-type",
        ),
        pytest.param(
            {"users": [], "teams": [], "apps": None},
            id="wrong-apps-type",
        ),
        pytest.param(
            {"users": [{"login": "bypass-user"}], "teams": [], "apps": []},
            id="nonempty-users",
        ),
        pytest.param(
            {"users": [], "teams": [{"slug": "bypass-team"}], "apps": []},
            id="nonempty-teams",
        ),
        pytest.param(
            {"users": [], "teams": [], "apps": [{"slug": "bypass-app"}]},
            id="nonempty-apps",
        ),
        pytest.param(
            {"users": [None], "teams": [], "apps": []},
            id="malformed-member",
        ),
    ],
)
def test_protected_action_rejects_malformed_or_nonempty_bypass_shapes(
    tmp_path: Path,
    allowances: object,
) -> None:
    base = action_transport()

    def transport(path: str):
        if path.endswith("/branches/main/protection"):
            protection = production_branch_protection()
            protection["required_pull_request_reviews"][
                "bypass_pull_request_allowances"
            ] = allowances
            return protection
        return base(path)

    cfg = service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, token="protected", transport=transport),
        b"c" * 48,
        None,
        tmp_path / "invalid-bypass.sqlite3",
        now=lambda: NOW,
    )

    with pytest.raises(SystemAttestationError, match="branch protection"):
        service.action(action_request())


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        pytest.param("root", "required_pull_request_reviews", None, id="reviews-null"),
        pytest.param("review", "dismiss_stale_reviews", False, id="stale-reviews"),
        pytest.param(
            "review", "dismiss_stale_reviews", "__missing__", id="stale-missing"
        ),
        pytest.param("review", "required_approving_review_count", 0, id="zero-approvals"),
        pytest.param("review", "required_approving_review_count", True, id="bool-approvals"),
        pytest.param(
            "review", "required_approving_review_count", "1", id="string-approvals"
        ),
        pytest.param("root", "enforce_admins", "__missing__", id="admins-missing"),
        pytest.param("admin", "enabled", False, id="admins-disabled"),
        pytest.param(
            "root", "required_status_checks", "__missing__", id="statuses-missing"
        ),
        pytest.param("status", "strict", False, id="statuses-not-strict"),
        pytest.param("status", "strict", "__missing__", id="strict-missing"),
        pytest.param("status", "contexts", [], id="required-context-missing"),
    ],
)
def test_protected_action_rejects_strict_policy_failures(
    tmp_path: Path,
    section: str,
    field: str,
    value: object,
) -> None:
    base = action_transport()

    def transport(path: str):
        if path.endswith("/branches/main/protection"):
            protection = production_branch_protection()
            targets = {
                "root": protection,
                "review": protection["required_pull_request_reviews"],
                "admin": protection["enforce_admins"],
                "status": protection["required_status_checks"],
            }
            if value == "__missing__":
                targets[section].pop(field, None)
            else:
                targets[section][field] = value
            if field == "contexts":
                targets[section]["checks"] = []
            return protection
        return base(path)

    cfg = service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, token="protected", transport=transport),
        b"c" * 48,
        None,
        tmp_path / "strict-policy.sqlite3",
        now=lambda: NOW,
    )

    with pytest.raises(SystemAttestationError, match="branch protection"):
        service.action(action_request())


@pytest.mark.parametrize(
    "failure",
    ["protection-api", "review-pagination", "check-pagination"],
)
def test_protected_action_fails_closed_on_github_lookup_errors(
    tmp_path: Path,
    failure: str,
) -> None:
    base = action_transport()

    def transport(path: str):
        if failure == "protection-api" and path.endswith(
            "/branches/main/protection"
        ):
            raise SystemAttestationError("GitHub protection API failed")
        if failure == "review-pagination" and "/reviews?" in path:
            return {"not": "a page"}
        if failure == "check-pagination" and "/check-runs?" in path:
            return {
                "total_count": 2,
                "check_runs": [{
                    "id": 501,
                    "name": "test",
                    "status": "completed",
                    "conclusion": "success",
                }],
            }
        return base(path)

    cfg = service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, token="protected", transport=transport),
        b"c" * 48,
        None,
        tmp_path / f"{failure}.sqlite3",
        now=lambda: NOW,
    )

    with pytest.raises(SystemAttestationError):
        service.action(action_request())


def test_merge_revalidates_then_uses_expected_head_atomic_api(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, str, dict]] = []

    def mutate(method: str, path: str, payload: dict):
        calls.append((method, path, payload))
        return {"merged": True, "message": "merged", "sha": "e" * 40}

    cfg = service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(
            cfg, token="protected",
            transport=action_transport(), mutation_transport=mutate,
        ),
        b"c" * 48, None, tmp_path / "merge.sqlite3", now=lambda: NOW,
    )
    result = service.action(action_request(operation="merge"))
    assert result["merged"] is True
    assert calls == [(
        "PUT", "/repos/acme/widget/pulls/7/merge",
        {"sha": HEAD, "merge_method": "squash"},
    )]


def test_protected_action_replay_is_exact_and_altered_nonce_reuse_fails(
    tmp_path: Path,
) -> None:
    cfg = service_config()
    services = [
        DedicatedSigner(
            cfg, GitHub(cfg, token="protected", transport=action_transport()),
            b"c" * 48, None, tmp_path / "shared.sqlite3", now=lambda: NOW,
        )
        for _ in range(4)
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(
            lambda index: services[index].action(action_request()),
            range(4),
        ))
    assert len({json.dumps(value, sort_keys=True) for value in results}) == 1
    with pytest.raises(SystemAttestationError, match="nonce was already consumed"):
        services[0].action(action_request(merge_method="rebase"))


def test_gate_replay_expires_fail_closed(tmp_path: Path) -> None:
    current = [NOW]
    cfg = service_config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=action_transport()),
        b"c" * 48, None, tmp_path / "expiry.sqlite3",
        now=lambda: current[0],
    )
    service.action(action_request())
    current[0] += timedelta(seconds=61)
    with pytest.raises(SystemAttestationError, match="decision is expired"):
        service.action(action_request())


def test_merge_detects_review_or_check_change_before_mutation(
    tmp_path: Path,
) -> None:
    review_calls = [0]

    def transport(path: str):
        if "/reviews?" in path and "page=1" in path:
            review_calls[0] += 1
            state = "APPROVED" if review_calls[0] == 1 else "DISMISSED"
            return action_transport(state=state)(path)
        return action_transport()(path)

    cfg = service_config()
    mutated: list[bool] = []
    service = DedicatedSigner(
        cfg,
        GitHub(
            cfg, token="protected", transport=transport,
            mutation_transport=lambda *_args: mutated.append(True),
        ),
        b"c" * 48, None, tmp_path / "race.sqlite3", now=lambda: NOW,
    )
    with pytest.raises(SystemAttestationError, match="no current allowed approval"):
        service.action(action_request(operation="merge"))
    assert not mutated


def test_issue_marker_binds_every_field_and_consumes_comment(tmp_path: Path) -> None:
    digest_payload = json.dumps(
        {"body": "Body", "title": "Title"}, sort_keys=True, separators=(",", ":")
    ).encode()
    digest = hashlib.sha256(digest_payload).hexdigest()
    marker = {
        "repository": "acme/widget", "issue": 9, "digest": digest,
        "author": "author", "reviewer_role": "issue-reviewer",
        "verdict": "approved", "zero_context": True,
        "destination_repo": "acme/widget",
        "labels": [],
        "expiry": (NOW + timedelta(minutes=5)).isoformat(), "nonce": "d" * 32,
    }

    def transport(path: str):
        if path.endswith("/issues/9"):
            return {
                "title": "Title", "body": "Body", "state": "open",
                "user": {"login": "author"},
            }
        return [{
            "id": 55, "body": "saturnin-attestation:v1 " + json.dumps(marker),
            "created_at": NOW.isoformat(),
            "updated_at": NOW.isoformat(),
            "user": {"login": "review-bot", "type": "Bot"},
        }]

    cfg = service_config()
    current = [NOW]
    service = DedicatedSigner(
        cfg, GitHub(cfg, transport=transport), b"k" * 48, None,
        tmp_path / "issue.sqlite3", now=lambda: current[0],
    )
    value = service.authorize(request(kind="issue", number=9))
    assert json.loads(value)["issue_digest"] == digest
    assert service.authorize(request(kind="issue", number=9)) == value
    current[0] += timedelta(minutes=6)
    with pytest.raises(SystemAttestationError, match="expired"):
        service.authorize(request(kind="issue", number=9))
    marker["expiry"] = (NOW - timedelta(seconds=1)).isoformat()
    with pytest.raises(SystemAttestationError, match="expired"):
        DedicatedSigner(
            cfg, GitHub(cfg, transport=transport), b"n" * 48, None,
            tmp_path / "expired.sqlite3", now=lambda: current[0],
        ).authorize(request(kind="issue", number=9))
    marker["expiry"] = (NOW + timedelta(minutes=5)).isoformat()
    marker["author"] = 7
    with pytest.raises(SystemAttestationError, match="types"):
        service.authorize(request(kind="issue", number=9))


def test_protected_issue_reviewer_publishes_exact_identity_bound_marker() -> None:
    cfg = ServiceConfig(
        frozenset({"acme/widget"}),
        frozenset({"pr-review-bot"}),
        frozenset({"issue-review-bot"}),
        frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    comments: list[dict] = []
    expected_digest = hashlib.sha256(
        json.dumps(
            {"body": "Reviewed body", "title": "Reviewed title"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    def transport(path: str):
        if path == "/repos/acme/widget/issues/9":
            return {
                "title": "Reviewed title",
                "body": "Reviewed body",
                "state": "open",
                "user": {"login": "author"},
            }
        if "/comments?" in path:
            return []
        raise AssertionError(path)

    def mutate(method: str, path: str, payload: dict):
        comments.append(payload)
        return {
            "id": 55,
            "body": payload["body"],
            "created_at": NOW.isoformat(),
            "updated_at": NOW.isoformat(),
            "user": {"login": "issue-review-bot", "type": "Bot"},
        }

    result = publish_issue_review(
        cfg,
        GitHub(
            cfg,
            token="installation-token",
            transport=transport,
            mutation_transport=mutate,
        ),
        "acme/widget",
        9,
        "acme/issues",
        ["incident"],
        expected_digest,
        now=NOW,
        ttl_seconds=600,
        nonce="d" * 64,
    )

    marker = json.loads(comments[0]["body"][len(ISSUE_MARKER):])
    assert result["comment_id"] == 55
    assert result["reviewer_identity"] == "issue-review-bot"
    assert marker == {
        "author": "author",
        "destination_repo": "acme/issues",
        "digest": expected_digest,
        "expiry": "2026-09-28T00:10:00+00:00",
        "issue": 9,
        "labels": ["incident"],
        "nonce": "d" * 64,
        "repository": "acme/widget",
        "reviewer_role": "issue-reviewer",
        "verdict": "approved",
        "zero_context": True,
    }


@pytest.mark.parametrize(
    ("existing", "author", "response_user", "edited", "message"),
    [
        (True, "author", "issue-review-bot", False, "already has"),
        (False, "issue-review-bot", "issue-review-bot", False, "own issue"),
        (False, "author", "ordinary-worker", False, "identity"),
        (False, "author", "issue-review-bot", True, "identity"),
    ],
)
def test_protected_issue_reviewer_rejects_replay_self_review_and_bad_response(
    existing: bool,
    author: str,
    response_user: str,
    edited: bool,
    message: str,
) -> None:
    cfg = ServiceConfig(
        frozenset({"acme/widget"}),
        frozenset({"pr-review-bot"}),
        frozenset({"issue-review-bot"}),
        frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )

    def transport(path: str):
        if path == "/repos/acme/widget/issues/9":
            return {
                "title": "Title",
                "body": "Body",
                "state": "open",
                "user": {"login": author},
            }
        if "/comments?" in path:
            return [{
                "id": 54,
                "body": ISSUE_MARKER + "{}",
                "user": {"login": "issue-review-bot", "type": "Bot"},
            }] if existing else []
        raise AssertionError(path)

    def mutate(_method: str, _path: str, payload: dict):
        return {
            "id": 55,
            "body": payload["body"] + (" edited" if edited else ""),
            "created_at": NOW.isoformat(),
            "updated_at": NOW.isoformat(),
            "user": {"login": response_user, "type": "Bot"},
        }

    with pytest.raises(SystemAttestationError, match=message):
        publish_issue_review(
            cfg,
            GitHub(
                cfg,
                token="installation-token",
                transport=transport,
                mutation_transport=mutate,
            ),
            "acme/widget",
            9,
            "acme/issues",
            [],
            hashlib.sha256(
                json.dumps(
                    {"body": "Body", "title": "Title"},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest(),
            now=NOW,
            nonce="d" * 64,
        )


def test_protected_issue_reviewer_rejects_content_changed_after_approval() -> None:
    cfg = ServiceConfig(
        frozenset({"acme/widget"}),
        frozenset({"pr-review-bot"}),
        frozenset({"issue-review-bot"}),
        frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )

    def transport(path: str):
        if path == "/repos/acme/widget/issues/9":
            return {
                "title": "Changed title",
                "body": "Body",
                "state": "open",
                "user": {"login": "author"},
            }
        if "/comments?" in path:
            return []
        raise AssertionError(path)

    with pytest.raises(SystemAttestationError, match="changed after review"):
        publish_issue_review(
            cfg,
            GitHub(cfg, token="installation-token", transport=transport),
            "acme/widget",
            9,
            "acme/issues",
            [],
            "d" * 64,
            now=NOW,
            nonce="e" * 64,
        )


def test_issue_closure_revokes_publication_and_signer_authority(
    tmp_path: Path,
) -> None:
    title, body, digest, _marker, base_transport = issue_action_fixture()
    state = ["closed"]

    def transport(path: str):
        value = base_transport(path)
        if path == "/repos/acme/widget/issues/9":
            return {**value, "state": state[0]}
        return value

    cfg = ServiceConfig(
        frozenset({"acme/widget"}),
        frozenset({"review-bot"}),
        frozenset({"review-bot"}),
        frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    with pytest.raises(SystemAttestationError, match="not open"):
        publish_issue_review(
            cfg,
            GitHub(cfg, token="installation-token", transport=transport),
            "acme/widget",
            9,
            "acme/issues",
            ["incident"],
            digest,
            now=NOW,
            nonce="d" * 64,
        )

    service = DedicatedSigner(
        cfg,
        GitHub(cfg, token="protected", transport=transport),
        b"k" * 48,
        None,
        tmp_path / "closed-issue.sqlite3",
        now=lambda: NOW,
    )
    request_value = {
        "action": "decide_issue",
        "operation": "issue_gate",
        "repository": "acme/widget",
        "number": 9,
        "destination_repo": "acme/issues",
        "issue_digest": digest,
        "title": "",
        "body": "",
        "labels": [],
        "nonce": "e" * 64,
    }
    with pytest.raises(SystemAttestationError, match="not open"):
        service.issue_action(request_value)
    state[0] = "open"
    assert service.issue_action(request_value)["allowed"] is True
    state[0] = "closed"
    with pytest.raises(SystemAttestationError, match="not open"):
        service.issue_action({**request_value, "nonce": "f" * 64})


def test_fresh_issue_gate_and_protected_submission_are_digest_bound(
    tmp_path: Path,
) -> None:
    title, body, digest, _marker, transport = issue_action_fixture()
    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    mutations: list[tuple[str, str, dict]] = []

    def mutate(method: str, path: str, payload: dict):
        mutations.append((method, path, payload))
        return {
            "number": 77, "title": title, "body": payload["body"],
            "labels": [{"name": "incident"}], "state": "open",
            "user": {"login": "saturnin-issue-publisher[bot]", "type": "Bot"},
            "created_at": NOW.isoformat(), "updated_at": NOW.isoformat(),
            "html_url": "https://github.com/Acme/Issues/issues/77",
        }

    service = DedicatedSigner(
        cfg,
        GitHub(
            cfg, token="protected", transport=transport,
            mutation_transport=mutate,
        ),
        b"k" * 48, None, tmp_path / "issue-actions.sqlite3",
        now=lambda: NOW,
    )
    service.publisher_client = lambda _destination: service.github
    gate_request = {
        "action": "decide_issue", "operation": "issue_gate",
        "repository": "acme/widget", "number": 9,
        "destination_repo": "acme/issues", "issue_digest": digest,
        "title": "", "body": "", "labels": [], "nonce": "d" * 64,
    }
    gate = service.issue_action(gate_request)
    assert gate["comment_id"] == 55
    assert gate["reviewer_identity"] == "review-bot"
    assert gate["expires_at"] == "2026-09-28T00:01:00+00:00"
    with pytest.raises(SystemAttestationError, match="labels were not approved"):
        service.issue_action({
            **gate_request, "operation": "issue_submit", "title": title,
            "body": body, "labels": ["unreviewed"], "nonce": "e" * 64,
        })
    submission = service.issue_action({
        **gate_request, "operation": "issue_submit", "title": title,
        "body": body, "labels": ["incident"], "nonce": "f" * 64,
    })
    assert submission["submitted"] is True
    assert submission["url"].endswith("/issues/77")
    assert service.issue_action({
        **gate_request, "operation": "issue_submit", "title": title,
        "body": body, "labels": ["incident"], "nonce": "f" * 64,
    }) == submission
    assert mutations == [(
        "POST", "/repos/acme/issues/issues",
        {
            "title": title,
            "body": body + "\n\n" + submission["idempotency_marker"],
            "labels": ["incident"],
        },
    )]


def test_issue_actions_fail_closed_after_expiry_and_on_content_change(
    tmp_path: Path,
) -> None:
    title, body, digest, marker, transport = issue_action_fixture()
    current = [NOW]
    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    service = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=transport),
        b"k" * 48, None, tmp_path / "issue-expiry.sqlite3",
        now=lambda: current[0],
    )
    request_value = {
        "action": "decide_issue", "operation": "issue_gate",
        "repository": "acme/widget", "number": 9,
        "destination_repo": "acme/issues", "issue_digest": digest,
        "title": "", "body": "", "labels": [], "nonce": "d" * 64,
    }
    service.issue_action(request_value)
    current[0] += timedelta(seconds=61)
    with pytest.raises(SystemAttestationError, match="decision is expired"):
        service.issue_action(request_value)
    marker["expiry"] = (NOW - timedelta(seconds=1)).isoformat()
    with pytest.raises(SystemAttestationError, match="expired"):
        service.issue_action({**request_value, "nonce": "e" * 64})
    with pytest.raises(SystemAttestationError, match="content digest changed"):
        service.issue_action({
            **request_value, "operation": "issue_submit",
            "title": title, "body": body + " changed", "nonce": "f" * 64,
        })


def test_ambiguous_issue_submission_is_reserved_and_never_retried(
    tmp_path: Path,
) -> None:
    title, body, digest, _marker, base_transport = issue_action_fixture()
    calls = [0]
    created_payload: list[dict] = []

    def fail_after_possible_creation(method: str, path: str, payload: dict):
        calls[0] += 1
        created_payload.append(payload)
        raise SystemAttestationError("GitHub API response was lost")

    def edited_transport(path: str):
        if path.startswith("/repos/acme/issues/issues?") and created_payload:
            return [{
                "number": 77, "title": title,
                "body": created_payload[0]["body"],
                "labels": [{"name": "incident"}], "state": "open",
                "user": {
                    "login": "saturnin-issue-publisher[bot]", "type": "Bot"
                },
                "created_at": NOW.isoformat(),
                "updated_at": (NOW + timedelta(seconds=1)).isoformat(),
                "html_url": "https://github.com/acme/issues/issues/77",
            }]
        return base_transport(path)

    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    service = DedicatedSigner(
        cfg,
        GitHub(
            cfg, token="protected", transport=edited_transport,
            mutation_transport=fail_after_possible_creation,
        ),
        b"k" * 48, None, tmp_path / "ambiguous.sqlite3", now=lambda: NOW,
    )
    service.publisher_client = lambda _destination: service.github
    request_value = {
        "action": "decide_issue", "operation": "issue_submit",
        "repository": "acme/widget", "number": 9,
        "destination_repo": "acme/issues", "issue_digest": digest,
        "title": title, "body": body, "labels": ["incident"], "nonce": "f" * 64,
    }
    with pytest.raises(SystemAttestationError, match="response was lost"):
        service.issue_action(request_value)
    with pytest.raises(SystemAttestationError, match="requires reconciliation"):
        service.issue_action(request_value)
    assert calls == [1]


def test_issue_submission_recovers_safe_failure_and_reconciles_ambiguous_success(
    tmp_path: Path,
) -> None:
    title, body, digest, _marker, base_transport = issue_action_fixture()
    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    request_value = {
        "action": "decide_issue", "operation": "issue_submit",
        "repository": "acme/widget", "number": 9,
        "destination_repo": "acme/issues", "issue_digest": digest,
        "title": title, "body": body, "labels": ["incident"], "nonce": "f" * 64,
    }
    attempts = [0]

    def safe_then_success(method: str, path: str, payload: dict):
        attempts[0] += 1
        if attempts[0] == 1:
            raise GitHubMutationError("connection refused", safe_to_retry=True)
        return {
            "number": 77, "title": title, "body": payload["body"],
            "labels": [{"name": "incident"}], "state": "open",
            "user": {"login": "saturnin-issue-publisher[bot]", "type": "Bot"},
            "created_at": NOW.isoformat(), "updated_at": NOW.isoformat(),
            "html_url": "https://github.com/acme/issues/issues/77",
        }

    safe_service = DedicatedSigner(
        cfg,
        GitHub(
            cfg, token="protected", transport=base_transport,
            mutation_transport=safe_then_success,
        ),
        b"k" * 48, None, tmp_path / "safe-retry.sqlite3", now=lambda: NOW,
    )
    safe_service.publisher_client = lambda _destination: safe_service.github
    with pytest.raises(GitHubMutationError, match="connection refused"):
        safe_service.issue_action(request_value)
    assert safe_service.issue_action(request_value)["submitted"] is True
    assert attempts == [2]

    lookups = [0]

    def failed_preflight(path: str):
        if path.startswith("/repos/acme/issues/issues?"):
            lookups[0] += 1
            if lookups[0] == 1:
                raise SystemAttestationError("destination lookup failed")
        return base_transport(path)

    preflight_service = DedicatedSigner(
        cfg,
        GitHub(
            cfg, token="protected", transport=failed_preflight,
            mutation_transport=lambda method, path, payload: {
                "number": 79, "title": title, "body": payload["body"],
                "labels": [{"name": "incident"}], "state": "open",
                "user": {
                    "login": "saturnin-issue-publisher[bot]", "type": "Bot"
                },
                "created_at": NOW.isoformat(), "updated_at": NOW.isoformat(),
                "html_url": "https://github.com/acme/issues/issues/79",
            },
        ),
        b"p" * 48, None, tmp_path / "preflight.sqlite3", now=lambda: NOW,
    )
    preflight_service.publisher_client = (
        lambda _destination: preflight_service.github
    )
    with pytest.raises(SystemAttestationError, match="lookup failed"):
        preflight_service.issue_action(request_value)
    assert preflight_service.issue_action(request_value)["submitted"] is True

    created = [False]
    marked_body = [""]

    def reconcile_transport(path: str):
        if path.startswith("/repos/acme/issues/issues?") and created[0]:
            return [{
                "number": 78, "title": title, "body": marked_body[0],
                "labels": [{"name": "incident"}], "state": "open",
                "user": {
                    "login": "saturnin-issue-publisher[bot]", "type": "Bot"
                },
                "created_at": NOW.isoformat(), "updated_at": NOW.isoformat(),
                "html_url": "https://github.com/acme/issues/issues/78",
            }]
        return base_transport(path)

    def ambiguous_creation(method: str, path: str, payload: dict):
        created[0] = True
        marked_body[0] = payload["body"]
        raise GitHubMutationError("response lost")

    ambiguous_service = DedicatedSigner(
        cfg,
        GitHub(
            cfg, token="protected", transport=reconcile_transport,
            mutation_transport=ambiguous_creation,
        ),
        b"m" * 48, None, tmp_path / "reconcile.sqlite3", now=lambda: NOW,
    )
    ambiguous_service.publisher_client = (
        lambda _destination: ambiguous_service.github
    )
    with pytest.raises(GitHubMutationError, match="response lost"):
        ambiguous_service.issue_action(request_value)
    reconciled = ambiguous_service.issue_action(request_value)
    assert reconciled["submitted"] is True
    assert reconciled["issue_number"] == 78


def test_issue_publication_revalidates_before_create_and_releases_claim(
    tmp_path: Path,
) -> None:
    title, body, digest, _marker, base_transport = issue_action_fixture()
    source_reads = [0]
    revoked = [True]
    mutations: list[str] = []

    def transport(path: str):
        value = base_transport(path)
        if path == "/repos/acme/widget/issues/9":
            source_reads[0] += 1
            if revoked[0] and source_reads[0] >= 3:
                return {**value, "state": "closed"}
        return value

    def mutate(method: str, _path: str, payload: dict):
        mutations.append(method)
        return published_issue(title, payload["body"])

    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    service = DedicatedSigner(
        cfg, GitHub(cfg, transport=transport, mutation_transport=mutate),
        b"k" * 48, None, tmp_path / "pre-create.sqlite3", now=lambda: NOW,
    )
    service.publisher_client = lambda _destination: service.github
    request_value = issue_submit_request(title, body, digest)
    with pytest.raises(SystemAttestationError, match="changed before"):
        service.issue_action(request_value)
    assert mutations == []

    revoked[0] = False
    source_reads[0] = 0
    assert service.issue_action(request_value)["submitted"] is True
    assert mutations == ["POST"]


@pytest.mark.parametrize("containment_mode", ["success", "mismatch", "failure"])
def test_post_create_revocation_is_contained_or_escalated(
    tmp_path: Path, containment_mode: str,
) -> None:
    title, body, digest, _marker, base_transport = issue_action_fixture()
    source_reads = [0]
    mutations: list[str] = []
    posted_body = [""]

    def transport(path: str):
        value = base_transport(path)
        if path == "/repos/acme/widget/issues/9":
            source_reads[0] += 1
            if source_reads[0] >= 4:
                return {**value, "state": "closed"}
        return value

    def mutate(method: str, _path: str, payload: dict):
        mutations.append(method)
        if method == "POST":
            posted_body[0] = payload["body"]
            return published_issue(title, payload["body"])
        if containment_mode == "failure":
            raise SystemAttestationError("close API failed")
        response = published_issue(
            title, posted_body[0],
            state="closed",
        )
        if containment_mode == "mismatch":
            response["title"] = "edited by another actor"
        return response

    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    service = DedicatedSigner(
        cfg, GitHub(cfg, transport=transport, mutation_transport=mutate),
        b"k" * 48, None, tmp_path / f"contain-{containment_mode}.sqlite3",
        now=lambda: NOW,
    )
    service.publisher_client = lambda _destination: service.github
    request_value = issue_submit_request(title, body, digest)
    with pytest.raises(SystemAttestationError, match="revoked after"):
        service.issue_action(request_value)
    assert mutations == ["POST", "PATCH"]
    with pytest.raises(SystemAttestationError, match="revoked after creation"):
        service.issue_action(request_value)
    db = service._db()
    try:
        result = json.loads(
            db.execute(
                "SELECT result FROM actions WHERE nonce=?", ("f" * 64,)
            ).fetchone()[0]
        )
    finally:
        db.close()
    assert result["contained"] is (containment_mode == "success")
    assert result["containment_failed"] is (containment_mode != "success")


@pytest.mark.parametrize(
    "reconciliation", ["exact", "edited", "marker-removed", "api-error"]
)
def test_ambiguous_reconciliation_revalidates_and_contains_revocation(
    tmp_path: Path, reconciliation: str,
) -> None:
    title, body, digest, _marker, base_transport = issue_action_fixture()
    created = [False]
    revoked = [False]
    edited = [False]
    marked = [""]
    mutations: list[str] = []

    def transport(path: str):
        if path.startswith("/repos/acme/issues/issues?"):
            if not created[0]:
                return []
            if reconciliation == "api-error":
                raise SystemAttestationError("destination lookup failed")
            issue = published_issue(title, marked[0])
            if edited[0]:
                issue.update({
                    "title": "edited after creation",
                    "body": (
                        "edited\n" + marked[0]
                        if reconciliation == "edited" else "marker removed"
                    ),
                    "updated_at": (NOW + timedelta(seconds=1)).isoformat(),
                })
            return [issue]
        value = base_transport(path)
        if path == "/repos/acme/widget/issues/9" and revoked[0]:
            return {**value, "state": "closed"}
        return value

    def mutate(method: str, _path: str, _payload: dict):
        mutations.append(method)
        if method == "POST":
            created[0] = True
            marked[0] = _payload["body"]
            raise GitHubMutationError("creation response lost")
        if reconciliation == "exact":
            return published_issue(title, marked[0], state="closed")
        response = published_issue(
            "edited after creation", "edited\n" + marked[0], state="closed"
        )
        response["updated_at"] = (NOW + timedelta(seconds=1)).isoformat()
        return response

    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    service = DedicatedSigner(
        cfg, GitHub(cfg, transport=transport, mutation_transport=mutate),
        b"k" * 48, None, tmp_path / "ambiguous-revoked.sqlite3",
        now=lambda: NOW,
    )
    service.publisher_client = lambda _destination: service.github
    request_value = issue_submit_request(title, body, digest)
    with pytest.raises(GitHubMutationError, match="response lost"):
        service.issue_action(request_value)
    revoked[0] = True
    edited[0] = reconciliation != "exact"
    with pytest.raises(SystemAttestationError, match="revoked after"):
        service.issue_action(request_value)
    assert mutations == (
        ["POST", "PATCH"] if reconciliation == "exact" else ["POST"]
    )
    with pytest.raises(SystemAttestationError, match="revoked after creation"):
        service.issue_action(request_value)
    db = service._db()
    try:
        result = json.loads(
            db.execute(
                "SELECT result FROM actions WHERE nonce=?", ("f" * 64,)
            ).fetchone()[0]
        )
    finally:
        db.close()
    assert result["containment_failed"] is (reconciliation != "exact")


def test_issue_claim_blocks_different_nonce_and_shared_db_concurrency(
    tmp_path: Path,
) -> None:
    title, body, digest, _marker, transport = issue_action_fixture()
    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    mutation_lock = threading.Lock()
    creates = [0]

    def mutate(_method: str, _path: str, payload: dict):
        with mutation_lock:
            creates[0] += 1
        return published_issue(title, payload["body"])

    state = tmp_path / "shared-publication.sqlite3"
    services = [
        DedicatedSigner(
            cfg, GitHub(cfg, transport=transport, mutation_transport=mutate),
            b"k" * 48, None, state, now=lambda: NOW,
        )
        for _ in range(2)
    ]
    for service in services:
        service.publisher_client = lambda _destination, item=service: item.github
    request_value = issue_submit_request(title, body, digest)

    def submit(item: DedicatedSigner):
        try:
            return item.issue_action(request_value)
        except SystemAttestationError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(submit, services))
    assert any(
        isinstance(result, dict) and result["submitted"] for result in results
    )
    assert all(
        isinstance(result, dict)
        or "requires reconciliation" in str(result)
        for result in results
    )
    assert all(
        service.issue_action(request_value)["submitted"] for service in services
    )
    assert creates == [1]
    with pytest.raises(SystemAttestationError, match="already claimed"):
        services[0].issue_action({
            **request_value, "nonce": "a" * 64,
        })
    assert creates == [1]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "collision"),
        ("body", "collision"),
        ("labels", [{"name": "other"}]),
        ("state", "closed"),
        ("user", {"login": "ordinary-worker", "type": "User"}),
    ],
)
def test_destination_reconciliation_rejects_marker_collision(
    tmp_path: Path, field: str, value: object,
) -> None:
    title, body, _digest, _marker, _transport = issue_action_fixture()
    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    marked = body + "\n\n" + ISSUE_SUBMISSION_MARKER.format("f" * 64)
    candidate = published_issue(title, marked)
    candidate[field] = value
    github = GitHub(
        cfg,
        transport=lambda path: [candidate]
        if path.startswith("/repos/acme/issues/issues?") else None,
    )
    service = DedicatedSigner(
        cfg, github, b"k" * 48, None, tmp_path / f"collision-{field}.sqlite3",
        now=lambda: NOW,
    )
    assert service._find_issue_submission(
        github, "acme/issues", title, body, ["incident"], "f" * 64
    ) is None


def test_publisher_app_uses_exact_selected_repository_scope() -> None:
    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    mutations: list[tuple[str, str, dict]] = []

    def transport(path: str):
        if path == "/repos/acme/issues/installation":
            return {
                "id": 42, "app_id": 7,
                "app_slug": "saturnin-issue-publisher",
                "repository_selection": "selected",
                "permissions": {"issues": "write", "metadata": "read"},
            }
        if path == "/repos/acme/issues":
            return {"full_name": "Acme/Issues"}
        raise AssertionError(path)

    def mutate(method: str, path: str, payload: dict):
        mutations.append((method, path, payload))
        return {
            "token": "installation-token",
            "expires_at": (NOW + timedelta(hours=1)).isoformat(),
            "repository_selection": "selected",
            "permissions": {"issues": "write", "metadata": "read"},
            "repositories": [{"full_name": "acme/issues"}],
        }

    publisher = GitHubAppPublisher(
        cfg,
        PublisherCredential(7, b"private-key-material"),
        now=lambda: NOW,
        jwt_signer=lambda key, message: hashlib.sha256(key + message).digest(),
        transport=transport,
        mutation_transport=mutate,
    )
    client = publisher.client("ACME/ISSUES")
    assert client.token == "installation-token"
    assert mutations == [(
        "POST", "/app/installations/42/access_tokens",
        {
            "repositories": ["issues"],
            "permissions": {"issues": "write", "metadata": "read"},
        },
    )]


def test_publisher_app_signs_with_memory_only_test_key() -> None:
    key = subprocess.run(
        [
            "/usr/bin/openssl", "genpkey", "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:2048",
        ],
        check=True,
        capture_output=True,
        timeout=15,
    ).stdout
    signature = GitHubAppPublisher._openssl_sign(key, b"production-shape-input")
    assert len(signature) == 256
    assert b"PRIVATE KEY" not in signature


@pytest.mark.parametrize(
    "change",
    [
        {"app_id": 8},
        {"app_slug": "ordinary-worker-app"},
        {"repository_selection": "all"},
        {"permissions": {"issues": "write"}},
        {"permissions": {"issues": "write", "metadata": "read", "contents": "read"}},
    ],
)
def test_publisher_app_rejects_wrong_installation_scope(change: dict) -> None:
    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    installation = {
        "id": 42, "app_id": 7, "app_slug": "saturnin-issue-publisher",
        "repository_selection": "selected",
        "permissions": {"issues": "write", "metadata": "read"},
        **change,
    }
    publisher = GitHubAppPublisher(
        cfg, PublisherCredential(7, b"secret-private-key"),
        now=lambda: NOW,
        jwt_signer=lambda _key, _message: b"signature",
        transport=lambda _path: installation,
    )
    with pytest.raises(
        SystemAttestationError, match="installation scope is invalid"
    ) as failure:
        publisher.client("acme/issues")
    assert "secret-private-key" not in str(failure.value)


@pytest.mark.parametrize(
    "change",
    [
        {"repository_selection": "all"},
        {"permissions": {"issues": "write"}},
        {"permissions": {
            "issues": "write", "metadata": "read", "contents": "read",
        }},
        {"repositories": [{"full_name": "acme/other"}]},
        {"repositories": [
            {"full_name": "acme/issues"}, {"full_name": "acme/other"},
        ]},
        {"expires_at": (NOW + timedelta(seconds=20)).isoformat()},
        {"expires_at": (NOW + timedelta(hours=2)).isoformat()},
    ],
)
def test_publisher_app_rejects_wrong_token_scope(change: dict) -> None:
    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    token = {
        "token": "publisher-token",
        "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        "repository_selection": "selected",
        "permissions": {"issues": "write", "metadata": "read"},
        "repositories": [{"full_name": "acme/issues"}],
        **change,
    }

    def transport(path: str):
        return {
            "id": 42, "app_id": 7,
            "app_slug": "saturnin-issue-publisher",
            "repository_selection": "selected",
            "permissions": {"issues": "write", "metadata": "read"},
        }

    publisher = GitHubAppPublisher(
        cfg, PublisherCredential(7, b"secret-private-key"),
        now=lambda: NOW,
        jwt_signer=lambda _key, _message: b"signature",
        transport=transport,
        mutation_transport=lambda _method, _path, _payload: token,
    )
    with pytest.raises(
        SystemAttestationError, match="token scope is invalid"
    ) as failure:
        publisher.client("acme/issues")
    assert "publisher-token" not in str(failure.value)
    assert "secret-private-key" not in str(failure.value)


def test_issue_action_rejects_multiple_markers_and_snapshot_change(
    tmp_path: Path,
) -> None:
    _title, _body, digest, _marker, base_transport = issue_action_fixture()
    request_value = {
        "action": "decide_issue", "operation": "issue_gate",
        "repository": "acme/widget", "number": 9,
        "destination_repo": "acme/issues", "issue_digest": digest,
        "title": "", "body": "", "labels": [], "nonce": "d" * 64,
    }
    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )

    def duplicate_transport(path: str):
        value = base_transport(path)
        if "/comments?" in path and "page=2" not in path:
            second = dict(value[0])
            second["id"] = 56
            return [*value, second]
        return value

    duplicate = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=duplicate_transport),
        b"k" * 48, None, tmp_path / "duplicate.sqlite3", now=lambda: NOW,
    )
    with pytest.raises(SystemAttestationError, match="exactly one"):
        duplicate.issue_action(request_value)

    issue_reads = [0]

    def changing_transport(path: str):
        value = base_transport(path)
        if path == "/repos/acme/widget/issues/9":
            issue_reads[0] += 1
            if issue_reads[0] == 2:
                return {**value, "body": "changed after first snapshot"}
        return value

    changing = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=changing_transport),
        b"k" * 48, None, tmp_path / "changing.sqlite3", now=lambda: NOW,
    )
    with pytest.raises(SystemAttestationError, match="scope does not match"):
        changing.issue_action(request_value)


def test_issue_action_rejects_self_review(tmp_path: Path) -> None:
    _title, _body, digest, marker, base_transport = issue_action_fixture()
    marker["author"] = "review-bot"

    def transport(path: str):
        value = base_transport(path)
        if path == "/repos/acme/widget/issues/9":
            return {**value, "user": {"login": "review-bot"}}
        return value

    cfg = ServiceConfig(
        frozenset({"acme/widget"}), frozenset({"review-bot"}),
        frozenset({"review-bot"}), frozenset({"approved"}),
        issue_destinations=frozenset({"acme/issues"}),
    )
    service = DedicatedSigner(
        cfg, GitHub(cfg, token="protected", transport=transport),
        b"k" * 48, None, tmp_path / "self-review.sqlite3", now=lambda: NOW,
    )
    with pytest.raises(SystemAttestationError, match="own issue"):
        service.issue_action({
            "action": "decide_issue", "operation": "issue_gate",
            "repository": "acme/widget", "number": 9,
            "destination_repo": "acme/issues", "issue_digest": digest,
            "title": "", "body": "", "labels": [], "nonce": "d" * 64,
        })


def test_current_and_previous_verification_no_downgrade(tmp_path: Path) -> None:
    cfg = service_config()
    with pytest.raises(SystemAttestationError, match="previous"):
        DedicatedSigner(
            cfg, GitHub(cfg, transport=pr_transport()), b"k" * 48, b"k" * 48,
            tmp_path / "bad.sqlite3",
        )
    service = signer(tmp_path)
    with pytest.raises(SystemAttestationError, match="malformed"):
        service.verify("{")
    value = service.authorize(request())
    assert service.verify(value) == {"status": "verified", "key_state": "current"}
    altered = json.loads(value)
    altered["destination_repo"] = "acme/other"
    with pytest.raises(SystemAttestationError, match="does not match"):
        service.verify(json.dumps(altered))


def test_strict_legacy_verification_uses_execution_role_and_archive_keys(
    tmp_path: Path,
) -> None:
    current = b"current-legacy-master-" + b"c" * 32
    previous = b"previous-legacy-master-" + b"p" * 32
    retired = b"retired-legacy-master-" + b"r" * 32
    cfg = service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, transport=pr_transport()),
        current,
        previous,
        tmp_path / "legacy.sqlite3",
        now=lambda: NOW,
        archive_keys=(retired,),
    )
    attestation_id = "T-20260924-review:" + "b" * 64
    execution = sign_review_attestation(
        key=execution_scoped_review_attestation_key(
            current.decode(),
            "pr-reviewer",
            "T-20260924-review",
            "b" * 64,
            "acme/widget#7",
            HEAD,
            "",
        ),
        subject="acme/widget#7",
        kind="pr",
        author="github:author",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=HEAD,
        destination_repo="",
        attestation_id=attestation_id,
    )
    with pytest.raises(SystemAttestationError, match="cannot authorize"):
        service.verify(execution)
    assert service.verify(execution, historical=True) == {
        "status": "verified",
        "key_state": "current",
    }

    role = sign_review_attestation(
        key=role_scoped_review_attestation_key(
            retired.decode(), "pr-reviewer"
        ),
        subject="acme/widget#7",
        kind="pr",
        author="github:author",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=HEAD,
        destination_repo="",
        attestation_id="legacy-attestation-one",
    )
    assert service.verify(role, historical=True) == {
        "status": "verified",
        "key_state": "archive",
    }
    without_key_id = json.loads(role)
    without_key_id.pop("key_id")
    role_key = role_scoped_review_attestation_key(
        retired.decode(), "pr-reviewer"
    ).encode()
    without_key_id["signature"] = hmac.new(
        role_key,
        json.dumps(
            {
                key: value
                for key, value in without_key_id.items()
                if key != "signature"
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert service.verify(
        json.dumps(without_key_id), historical=True
    )["key_state"] == "archive"
    malformed = json.loads(role)
    malformed["unknown"] = True
    with pytest.raises(SystemAttestationError, match="schema"):
        service.verify(json.dumps(malformed), historical=True)
    malformed.pop("unknown")
    malformed["attestation_id"] = "bad:id"
    with pytest.raises(SystemAttestationError, match="id"):
        service.verify(json.dumps(malformed), historical=True)
    malformed["attestation_id"] = "legacy-attestation-one"
    malformed["reviewer"] = "issue-reviewer"
    with pytest.raises(SystemAttestationError, match="scope"):
        service.verify(json.dumps(malformed), historical=True)


def test_archive_v2_verification_cannot_authorize_a_new_record(
    tmp_path: Path,
) -> None:
    cfg = service_config()
    retired = b"r" * 48
    old_signer = DedicatedSigner(
        cfg,
        GitHub(cfg, transport=pr_transport()),
        retired,
        None,
        tmp_path / "old.sqlite3",
        now=lambda: NOW,
    )
    verifier = DedicatedSigner(
        cfg,
        GitHub(cfg, transport=pr_transport()),
        b"c" * 48,
        b"p" * 48,
        tmp_path / "new.sqlite3",
        now=lambda: NOW,
        archive_keys=(retired,),
    )
    attestation = old_signer.authorize(request())
    with pytest.raises(SystemAttestationError, match="not issued"):
        verifier.verify(attestation)
    assert verifier.verify(attestation, historical=True) == {
        "status": "verified",
        "key_state": "archive",
    }


def test_historical_legacy_ledger_verifies_only_through_root_service(
    tmp_path: Path, config, monkeypatch: pytest.MonkeyPatch,
) -> None:
    master = b"migrated-root-master-" + b"m" * 32
    cfg = service_config()
    service = DedicatedSigner(
        cfg,
        GitHub(cfg, transport=pr_transport()),
        master,
        None,
        tmp_path / "legacy-ledger.sqlite3",
        now=lambda: NOW,
    )
    subject = "acme/widget#7"
    attestation = json.loads(sign_review_attestation(
        key=role_scoped_review_attestation_key(
            master.decode(), "pr-reviewer"
        ),
        subject=subject,
        kind="pr",
        author="github:author",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=HEAD,
        attestation_id="legacy-attestation-ledger",
    ))
    record = ReviewRecord(
        subject=subject,
        kind="pr",
        author="github:author",
        reviewer="pr-reviewer",
        verdict="approved",
        head_sha=HEAD,
        attestation_id=attestation["attestation_id"],
        attestation_signature=f"{attestation['key_id']}:{attestation['signature']}",
    )
    ledger = ReviewLedger(config)
    path = ledger.dir / f"pr-{slugify(subject)}.jsonl"
    path.write_text(json.dumps(record.to_dict()) + "\n", encoding="utf-8")
    config.governance["review"]["attestation"]["authorization_source"] = "github-api"
    monkeypatch.delenv("SATURNIN_REVIEW_ATTESTATION_KEY", raising=False)
    monkeypatch.setattr(
        "saturnin.system_attestation.verify_attestation",
        lambda value, **kwargs: service.verify(value, **kwargs),
    )

    assert ledger.for_subject(subject, "pr") == [record]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"{", "malformed"),
        (b'{"version":1,"keys":[],"extra":true}', "schema"),
        (
            json.dumps({
                "version": 1,
                "keys": ["a"] * (ARCHIVE_MAX_KEYS + 1),
            }).encode(),
            "schema",
        ),
        (b'{"version":1,"keys":[7]}', "schema"),
        (b'{"version":1,"keys":["!"]}', "invalid"),
        (
            json.dumps({
                "version": 1,
                "keys": [base64.b64encode(b"short").decode()],
            }).encode(),
            "invalid",
        ),
        (
            json.dumps({
                "version": 1,
                "keys": [base64.b64encode(b"k" * 48).decode()] * 2,
            }).encode(),
            "duplicates",
        ),
    ],
)
def test_archive_credential_schema_fails_closed(
    payload: bytes, message: str,
) -> None:
    with pytest.raises(SystemAttestationError, match=message):
        _archive_credential(payload)


def test_archive_and_named_credential_loading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = b"a" * 48, b"b" * 48
    encoded = json.dumps({
        "version": 1,
        "keys": [
            base64.b64encode(first).decode(),
            base64.b64encode(second).decode(),
        ],
    }).encode()
    assert _archive_credential(encoded) == (first, second)

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert _credential("missing", optional=True) == b""
    with pytest.raises(SystemAttestationError, match="unavailable"):
        _credential("missing")
    (tmp_path / "value").write_bytes(b"credential\n")
    assert _credential("value") == b"credential"
    (tmp_path / "value").write_bytes(b"bad\0credential")
    with pytest.raises(SystemAttestationError, match="invalid"):
        _credential("value")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("zero_context", "true", "types"),
        ("subject", "other/widget#7", "scope"),
        ("author", "github:", "scope"),
        ("reviewer_identity", "", "scope"),
        ("author_role", "caller", "scope"),
        ("verdict", "invented", "scope"),
        ("destination_repo", "../bad", "repository"),
        ("nonce", "short", "scope"),
        ("attestation_id", "legacy-id", "scope"),
        ("key_id", "short", "scope"),
        ("kind", "invented", "scope"),
        ("reviewer", "issue-reviewer", "scope"),
        ("head_sha", "", "scope"),
        ("issue_digest", "f" * 64, "scope"),
        ("authorization_evidence_id", "github:comment:1", "scope"),
    ],
)
def test_v2_verifier_rejects_every_malformed_scope(
    tmp_path: Path, field: str, value: object, message: str,
) -> None:
    service = signer(tmp_path)
    payload = json.loads(service.authorize(request()))
    payload[field] = value
    with pytest.raises(SystemAttestationError, match=message):
        service.verify(json.dumps(payload))


def test_signed_attestation_remains_durable_after_authorization_expiry(
    tmp_path: Path,
) -> None:
    current = [NOW]
    cfg = service_config()
    service = DedicatedSigner(
        cfg, GitHub(cfg, transport=pr_transport()), b"c" * 48, b"p" * 48,
        tmp_path / "expiry.sqlite3", now=lambda: current[0],
    )
    value = service.authorize(request())
    current[0] += timedelta(seconds=301)
    assert service.verify(value) == {"status": "verified", "key_state": "current"}


def test_mocked_production_approval_record_gate_and_unreviewed_rejection(
    tmp_path: Path, config, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = signer(tmp_path)
    attestation = service.authorize(request())
    monkeypatch.setattr(
        "saturnin.system_attestation.verify_attestation",
        lambda value, **kwargs: service.verify(value, **kwargs),
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
    service.now = lambda: NOW + timedelta(days=30)
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
    path.parent.chmod(0o2750)

    def run() -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        path.chmod(0o660)
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
    tmp_path: Path,
) -> None:
    path = tmp_path / "sign.sock"
    thread = _one_shot_server(path, {"attestation": "signed"})
    assert request_attestation(
        kind="pr", repository="acme/widget", number=7,
        destination_repo="acme/widget", socket_path=path,
        expected_uid=os.getuid(), expected_gid=os.getgid(),
    ) == "signed"
    thread.join(timeout=5)

    path.unlink()
    thread = _one_shot_server(path, {"status": "verified", "key_state": "current"})
    assert verify_attestation(
        "signed", socket_path=path, expected_uid=os.getuid(),
        expected_gid=os.getgid(),
    ) == {"status": "verified", "key_state": "current"}
    thread.join(timeout=5)

    path.unlink()
    thread = _one_shot_server(path, {"error": "denied"})
    with pytest.raises(SystemAttestationError, match="denied"):
        verify_attestation(
            "signed", socket_path=path, expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
    thread.join(timeout=5)

    path.unlink()
    decision = {
        "allowed": True,
        "operation": "gate",
        "repository": "acme/widget",
        "number": 7,
        "destination_repo": "acme/widget",
        "expected_head": HEAD,
        "merge_method": "squash",
        "nonce": "d" * 64,
        "head_sha": HEAD,
        "base_ref": "main",
        "base_sha": "f" * 40,
        "reviewer_identity": "review-bot",
        "review_id": 91,
        "review_state": "approved",
        "check_runs": ["test:501"],
        "review_profile": "",
        "review_method": "",
        "review_checks": [],
        "writer_evidence_id": "",
        "protected_actor": "saturnin-merge-bot",
        "protection_hash": "e" * 64,
        "expires_at": "2099-01-01T00:00:00+00:00",
        "signature": "c" * 64,
    }
    thread = _one_shot_server(path, decision)
    assert request_action(
        operation="gate", repository="acme/widget", number=7,
        destination_repo="acme/widget", expected_head=HEAD,
        nonce="d" * 64, socket_path=path, expected_uid=os.getuid(),
        expected_gid=os.getgid(),
    ) == decision
    thread.join(timeout=5)

    path.unlink()
    thread = _one_shot_server(path, {**decision, "head_sha": "b" * 40})
    with pytest.raises(SystemAttestationError, match="denied"):
        request_action(
            operation="gate", repository="acme/widget", number=7,
            destination_repo="acme/widget", expected_head=HEAD,
            nonce="d" * 64, socket_path=path, expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
    thread.join(timeout=5)


def test_signer_created_listener_exposes_actual_creator_identity(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o2750)
    path = tmp_path / "sign.sock"
    listener = _create_listener(path, expected_gid=os.getgid())
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(str(path))
        peer_pid, peer_uid, _peer_gid = struct.unpack(
            "3i",
            client.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            ),
        )
        assert peer_pid == os.getpid()
        assert peer_uid == os.getuid()
        assert path.stat().st_mode & 0o777 == 0o660
    finally:
        client.close()
        listener.close()
        path.unlink(missing_ok=True)


def test_readiness_is_emitted_only_to_fixed_systemd_datagram(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "notify.sock"
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(str(path))
    receiver.settimeout(5)
    try:
        monkeypatch.setenv("NOTIFY_SOCKET", str(path))
        _notify_ready()
        assert receiver.recv(4096) == (
            b"READY=1\nSTATUS=Protected GitHub access and listener verified"
        )
    finally:
        receiver.close()
    monkeypatch.setenv("NOTIFY_SOCKET", "relative.sock")
    with pytest.raises(SystemAttestationError, match="invalid"):
        _notify_ready()


def test_inherited_listener_identifies_creator_not_acceptor(
    tmp_path: Path,
) -> None:
    path = tmp_path / "inherited.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    creator_pid = os.getpid()
    acceptor_pid = os.fork()
    if acceptor_pid == 0:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.sendall(str(os.getpid()).encode())
        finally:
            os._exit(0)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(str(path))
        peer_pid, peer_uid, _peer_gid = struct.unpack(
            "3i",
            client.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            ),
        )
        reported_acceptor = int(client.recv(64))
        assert peer_pid == creator_pid
        assert peer_uid == os.getuid()
        assert reported_acceptor == acceptor_pid
        assert peer_pid != reported_acceptor
    finally:
        client.close()
        listener.close()
        os.waitpid(acceptor_pid, 0)


def test_signer_listener_rejects_preexisting_non_socket(tmp_path: Path) -> None:
    tmp_path.chmod(0o2750)
    path = tmp_path / "sign.sock"
    path.write_text("attacker-controlled", encoding="utf-8")
    with pytest.raises(SystemAttestationError, match="unsafe"):
        _create_listener(path, expected_gid=os.getgid())


def test_github_client_rejects_paths_and_bounds_pagination() -> None:
    cfg = service_config()
    client = GitHub(cfg, transport=lambda path: [])
    with pytest.raises(SystemAttestationError, match="repository"):
        system_attestation._repo("not/a/repository")
    with pytest.raises(SystemAttestationError, match="path"):
        client.get("https://evil.invalid/repos/acme/widget")
    with pytest.raises(SystemAttestationError, match="path"):
        client.get("/repos/acme/widget/pulls/../secrets")
    assert client.pages("/repos/acme/widget/pulls/7/reviews") == []

    oversized = GitHub(cfg, transport=lambda path: [{}] * 101)
    with pytest.raises(SystemAttestationError, match="oversized"):
        oversized.pages("/repos/acme/widget/pulls/7/reviews")


def test_github_authorization_header_uses_token_without_disclosure(
    capsys: pytest.CaptureFixture[str],
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
        service_config(), token=token, request_transport=open_request
    ).get("/repos/acme/widget/pulls/7") == {}
    scheme = "Bear" + "er"
    authorization = seen["authorization"]
    assert isinstance(authorization, str)
    assert authorization.split(" ", 1) == [scheme, token]
    assert seen["timeout"] == 10

    def fail_request(_request, timeout):
        raise urllib.error.URLError(f"transport failed with {token}")

    with pytest.raises(SystemAttestationError) as caught:
        GitHub(
            service_config(), token=token, request_transport=fail_request
        ).get("/repos/acme/widget/pulls/7")
    assert token not in str(caught.value)
    assert caught.value.__cause__ is None
    _audit("denied", hashlib.sha256(b"evidence").hexdigest(), "")
    assert token not in capsys.readouterr().err


def test_publisher_http_mutations_and_credential_parser() -> None:
    credential = PublisherCredential.load(json.dumps({
        "app_id": 7,
        "private_key": (
            "-----BEGIN " + "PRIVATE KEY-----\n"
            "QUJDRA==\n"
            "-----END " + "PRIVATE KEY-----\n"
        ),
    }).encode())
    assert credential.app_id == 7
    with pytest.raises(SystemAttestationError, match="malformed"):
        PublisherCredential.load(b'{"app_id":7,"private_key":"token"}')

    seen: list[tuple[str, str, dict, str | None]] = []

    class Response:
        def __init__(self, url: str, value: dict) -> None:
            self.url, self.value = url, value

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def geturl(self):
            return self.url

        def read(self, _size):
            return json.dumps(self.value).encode()

    def open_request(request, _timeout):
        payload = json.loads(request.data)
        seen.append((
            request.method, request.full_url, payload,
            request.get_header("Authorization"),
        ))
        if request.method == "POST":
            return Response(request.full_url, {
                "token": "installation-token",
                "repositories": [{"full_name": "acme/issues"}],
            })
        return Response(request.full_url, {
            "number": 77, "state": "closed", "state_reason": "not_planned",
        })

    client = GitHub(
        service_config(), token="publisher-secret",
        request_transport=open_request,
    )
    assert client.create_installation_token(42, "issues")["token"] == (
        "installation-token"
    )
    assert client.close_issue("acme/issues", 77)["state"] == "closed"
    assert [item[0] for item in seen] == ["POST", "PATCH"]
    assert seen[0][2] == {
        "repositories": ["issues"],
        "permissions": {"issues": "write", "metadata": "read"},
    }
    assert seen[1][2] == {"state": "closed", "state_reason": "not_planned"}
    assert all(item[3] is not None for item in seen)

    with pytest.raises(SystemAttestationError, match="scope"):
        client.create_installation_token(0, "issues")
    with pytest.raises(SystemAttestationError, match="unavailable"):
        GitHub(service_config()).create_installation_token(42, "issues")
    with pytest.raises(SystemAttestationError, match="unavailable"):
        GitHub(service_config()).close_issue("acme/issues", 77)


def test_github_issue_post_and_issue_client_validate_exact_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def geturl(self):
            return "https://api.github.com/repos/acme/issues/issues"

        def read(self, _size):
            return json.dumps({
                "number": 77,
                "html_url": "https://github.com/acme/issues/issues/77",
            }).encode()

    def open_request(request, timeout):
        seen["method"] = request.method
        seen["body"] = json.loads(request.data)
        seen["authorization"] = request.get_header("Authorization")
        seen["timeout"] = timeout
        return Response()

    created = GitHub(
        service_config(), token="protected-token",
        request_transport=open_request,
    ).post_issue("acme/issues", "Title", "Body", ["incident"])
    assert created["number"] == 77
    assert seen["method"] == "POST"
    assert seen["body"] == {
        "title": "Title", "body": "Body", "labels": ["incident"],
    }
    assert seen["authorization"] == "Bearer protected-token"

    expiry = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()

    def socket_response(request, **kwargs):
        return {
            "allowed": True,
            **{key: request[key] for key in (
                "operation", "repository", "number", "destination_repo",
                "issue_digest", "title", "body", "labels", "nonce",
            )},
            "reviewer_identity": "review-bot", "comment_id": 55,
            "review_state": "approved", "approved_labels": ["incident"],
            "expires_at": expiry, "signature": "a" * 64,
            "submitted": True, "issue_number": 77,
            "url": "https://github.com/acme/issues/issues/77",
        }

    monkeypatch.setattr(system_attestation, "_socket_request", socket_response)
    result = request_issue_action(
        operation="issue_submit", repository="acme/widget", number=9,
        destination_repo="acme/issues", issue_digest="a" * 64,
        title="Title", body="Body", labels=["incident"], nonce="d" * 64,
    )
    assert result["issue_number"] == 77

    monkeypatch.setattr(
        system_attestation, "_socket_request",
        lambda request, **kwargs: {**socket_response(request), "title": "altered"},
    )
    with pytest.raises(SystemAttestationError, match="denied"):
        request_issue_action(
            operation="issue_submit", repository="acme/widget", number=9,
            destination_repo="acme/issues", issue_digest="a" * 64,
            title="Title", body="Body", labels=["incident"], nonce="d" * 64,
        )
    monkeypatch.setattr(
        system_attestation, "_socket_request",
        lambda request, **kwargs: {"error": "signer unavailable"},
    )
    with pytest.raises(SystemAttestationError, match="signer unavailable"):
        request_issue_action(
            operation="issue_gate", repository="acme/widget", number=9,
            destination_repo="acme/issues", issue_digest="a" * 64,
        )

    def gate_response(request, **kwargs):
        return {
            "allowed": True,
            **{key: request[key] for key in (
                "operation", "repository", "number", "destination_repo",
                "issue_digest", "title", "body", "labels", "nonce",
            )},
            "reviewer_identity": "review-bot", "comment_id": 55,
            "review_state": "approved", "approved_labels": [],
            "expires_at": expiry, "signature": "a" * 64,
        }

    monkeypatch.setattr(system_attestation, "_socket_request", gate_response)
    gate = request_issue_action(
        operation="issue_gate", repository="acme/widget", number=9,
        destination_repo="acme/issues", issue_digest="a" * 64,
    )
    assert len(gate["nonce"]) == 64

    with pytest.raises(SystemAttestationError, match="credential"):
        GitHub(service_config()).post_issue("acme/issues", "Title", "Body", [])

    def failed_post(_request, _timeout):
        raise urllib.error.URLError("unavailable")

    with pytest.raises(SystemAttestationError, match="submission failed"):
        GitHub(
            service_config(), token="protected-token",
            request_transport=failed_post,
        ).post_issue("acme/issues", "Title", "Body", [])

    class InvalidResponse(Response):
        def read(self, _size):
            return b"not-json"

    with pytest.raises(SystemAttestationError, match="malformed"):
        GitHub(
            service_config(), token="protected-token",
            request_transport=lambda request, timeout: InvalidResponse(),
        ).post_issue("acme/issues", "Title", "Body", [])

    class OversizedResponse(Response):
        def read(self, _size):
            return b"x" * (system_attestation.MAX_RESPONSE + 1)

    with pytest.raises(SystemAttestationError, match="oversized"):
        GitHub(
            service_config(), token="protected-token",
            request_transport=lambda request, timeout: OversizedResponse(),
        ).post_issue("acme/issues", "Title", "Body", [])

    class ListResponse(Response):
        def read(self, _size):
            return b"[]"

    with pytest.raises(SystemAttestationError, match="malformed"):
        GitHub(
            service_config(), token="protected-token",
            request_transport=lambda request, timeout: ListResponse(),
        ).post_issue("acme/issues", "Title", "Body", [])

    class RedirectResponse(Response):
        def geturl(self):
            return "https://evil.invalid/capture"

    with pytest.raises(SystemAttestationError, match="redirect"):
        GitHub(
            service_config(), token="protected-token",
            request_transport=lambda request, timeout: RedirectResponse(),
        ).post_issue("acme/issues", "Title", "Body", [])


def test_github_protected_merge_transport_is_fixed_and_expected_head_bound() -> None:
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def geturl(self):
            return "https://api.github.com/repos/acme/widget/pulls/7/merge"

        def read(self, _size):
            return b'{"merged":true,"sha":"abc"}'

    def open_request(request, timeout):
        seen["url"] = request.full_url
        seen["method"] = request.method
        seen["authorization"] = request.get_header("Authorization")
        seen["payload"] = json.loads(request.data)
        seen["timeout"] = timeout
        return Response()

    client = GitHub(
        service_config(), token="protected-token",
        request_transport=open_request,
    )
    assert client.put(
        "/repos/acme/widget/pulls/7/merge",
        {"sha": HEAD, "merge_method": "squash"},
    )["merged"] is True
    assert seen == {
        "url": "https://api.github.com/repos/acme/widget/pulls/7/merge",
        "method": "PUT",
        "authorization": "Bearer protected-token",
        "payload": {"sha": HEAD, "merge_method": "squash"},
        "timeout": 10,
    }
    with pytest.raises(SystemAttestationError, match="mutation path"):
        client.put("/repos/acme/widget/issues/7", {})
    with pytest.raises(SystemAttestationError, match="credential"):
        GitHub(service_config(), request_transport=open_request).put(
            "/repos/acme/widget/pulls/7/merge", {"sha": HEAD}
        )


def test_check_run_pagination_fails_closed_on_inconsistent_or_oversized_data() -> None:
    cfg = service_config()
    inconsistent = GitHub(
        cfg,
        transport=lambda _path: {"total_count": 2, "check_runs": []},
    )
    with pytest.raises(SystemAttestationError, match="inconsistent"):
        inconsistent.check_runs("acme/widget", HEAD)
    malformed = GitHub(cfg, transport=lambda _path: {"check_runs": "bad"})
    with pytest.raises(SystemAttestationError, match="malformed"):
        malformed.check_runs("acme/widget", HEAD)


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
        service_config(), request_transport=lambda request, timeout: response
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
