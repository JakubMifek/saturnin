"""Independent review pipelines for pull requests and issue drafts.

Reviews are recorded as files so that the gate in :mod:`saturnin.governance`
can be evaluated by any process, including a cron job or a CI helper.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from .board import utcnow
from .config import Config, default_config
from .credentials import (
    ATTESTATION_CREDENTIAL,
    PREVIOUS_ATTESTATION_CREDENTIAL,
    CredentialError,
    credential_value,
)
from .jsonlines import (
    JSONLinesError,
    atomic_replace_text,
    durable_append_text,
    objects,
    repair_unterminated_tail,
)
from .locking import file_lock

VERDICTS = ("approved", "changes_requested", "rejected", "dismissed")
KINDS = ("pr", "issue")
_HEX_SHA_RE = re.compile(r"[0-9a-fA-F]{40}")
_ISSUE_DIGEST_RE = re.compile(r"[0-9a-fA-F]{64}")
_REPOSITORY_SLUG_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_ATTESTATION_SIGNATURE_RE = re.compile(r"(?:[0-9a-f]{64}:)?[0-9a-f]{64}")


class ReviewError(RuntimeError):
    pass


@dataclass
class ReviewRecord:
    subject: str
    kind: str
    author: str
    reviewer: str
    verdict: str
    zero_context: bool = True
    head_sha: str = ""
    issue_digest: str = ""
    destination_repo: str = ""
    notes: str = ""
    attestation_id: str = ""
    attestation_signature: str = ""
    created_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReviewRecord":
        cls.validate_dict(data)
        return cls(**data)

    @classmethod
    def validate_dict(cls, data: dict[str, Any]) -> None:
        known = set(cls.__dataclass_fields__)  # noqa: SLF001 - dataclass API
        missing = sorted(known - set(data))
        if missing:
            raise TypeError(f"review record is missing field(s): {', '.join(missing)}")
        unknown = sorted(set(data) - known)
        if unknown:
            raise TypeError(f"review record has unknown field(s): {', '.join(unknown)}")
        for name in (
            "subject",
            "kind",
            "author",
            "reviewer",
            "verdict",
            "head_sha",
            "issue_digest",
            "destination_repo",
            "notes",
            "attestation_id",
            "attestation_signature",
            "created_at",
        ):
            if not isinstance(data[name], str):
                raise TypeError(f"review record field {name!r} must be a string")
        for name in ("subject", "author", "reviewer", "created_at"):
            if not data[name].strip():
                raise ValueError(f"review record field {name!r} must not be empty")
        if data["kind"] not in KINDS:
            raise ValueError(f"unknown review kind: {data['kind']}")
        if data["verdict"] not in VERDICTS:
            raise ValueError(f"unknown review verdict: {data['verdict']}")
        if type(data["zero_context"]) is not bool:
            raise TypeError("review record field 'zero_context' must be a boolean")
        head = data["head_sha"]
        digest = data["issue_digest"]
        if head and not _HEX_SHA_RE.fullmatch(head):
            raise ValueError("review record head_sha must be a full 40-character commit SHA")
        if digest and not _ISSUE_DIGEST_RE.fullmatch(digest):
            raise ValueError("review record issue_digest must be a 64-character SHA-256 digest")
        if data["kind"] == "pr" and not head:
            raise ValueError("PR review record requires head_sha")
        if data["kind"] == "issue" and not digest:
            raise ValueError("issue review record requires issue_digest")
        destination_repo = data["destination_repo"]
        if destination_repo:
            if not _REPOSITORY_SLUG_RE.fullmatch(destination_repo):
                raise ValueError(
                    "review record destination_repo must be an owner/repository slug"
                )
            if destination_repo != normalize_repository_slug(destination_repo):
                raise ValueError("review record destination_repo must be normalized")
        if data["kind"] == "issue" and not destination_repo:
            raise ValueError("issue review record requires destination_repo")
        if bool(data["attestation_id"]) != bool(data["attestation_signature"]):
            raise ValueError("review record attestation id and signature must be paired")
        if data["attestation_signature"] and not _ATTESTATION_SIGNATURE_RE.fullmatch(
            data["attestation_signature"]
        ):
            raise ValueError("review record attestation signature has the wrong format")
        try:
            created_at = datetime.fromisoformat(data["created_at"])
        except ValueError as exc:
            raise ValueError("review record created_at must be ISO-8601") from exc
        if created_at.tzinfo is None:
            raise ValueError("review record created_at must include a timezone")


REQUIRED_FIELDS = tuple(ReviewRecord.__dataclass_fields__)  # noqa: SLF001 - dataclass API
ATTESTED_FIELDS = (
    "subject",
    "kind",
    "author",
    "reviewer",
    "verdict",
    "zero_context",
    "head_sha",
    "issue_digest",
    "destination_repo",
)
ROLE_SCOPED_KEY_CONTEXT = "saturnin-review-attestation"
EXECUTION_SCOPED_KEY_CONTEXT = "saturnin-review-attestation-execution:v1"
ROTATION_MANIFEST_KEY_CONTEXT = "saturnin-review-rotation-manifest:v1"


def slugify(subject: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", subject).strip("-")
    if not slug:
        raise ReviewError(f"subject {subject!r} cannot be turned into a file name")
    digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()[:8]
    return f"{slug.lower()}-{digest}"


def issue_content_digest(title: str, body: str) -> str:
    payload = json.dumps(
        {"title": title, "body": body},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def normalize_repository_slug(repo: str) -> str:
    slug = repo.strip()
    if not _REPOSITORY_SLUG_RE.fullmatch(slug):
        raise ValueError("repository must be an owner/repository slug")
    return slug.casefold()


def _canonical_attestation_payload(payload: dict[str, Any]) -> bytes:
    covered = {field: payload[field] for field in ATTESTED_FIELDS}
    covered["attestation_id"] = payload["attestation_id"]
    if "key_id" in payload:
        covered["key_id"] = payload["key_id"]
    return json.dumps(covered, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_review_attestation(
    *,
    key: str,
    subject: str,
    kind: str,
    author: str,
    reviewer: str,
    verdict: str,
    zero_context: bool = True,
    head_sha: str = "",
    issue_digest: str = "",
    destination_repo: str = "",
    attestation_id: str | None = None,
) -> str:
    """Return a signed review attestation for the exact reviewed subject."""
    if not key:
        raise ReviewError("review attestation signing key is not configured")
    try:
        normalized_destination = (
            normalize_repository_slug(destination_repo) if destination_repo else ""
        )
    except ValueError as exc:
        raise ReviewError(f"invalid destination repository: {exc}") from exc
    if kind == "issue" and not normalized_destination:
        raise ReviewError("issue review attestations require a destination repository")
    payload: dict[str, Any] = {
        "subject": subject,
        "kind": kind,
        "author": author,
        "reviewer": reviewer,
        "verdict": verdict,
        "zero_context": zero_context,
        "head_sha": head_sha.strip(),
        "issue_digest": issue_digest.strip(),
        "destination_repo": normalized_destination,
        "attestation_id": attestation_id or secrets.token_hex(16),
        "key_id": hashlib.sha256(key.encode("utf-8")).hexdigest(),
    }
    signature = hmac.new(
        key.encode("utf-8"),
        _canonical_attestation_payload(payload),
        hashlib.sha256,
    ).hexdigest()
    payload["signature"] = signature
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def role_scoped_review_attestation_key(master_key: str, reviewer: str) -> str:
    if not master_key:
        raise ReviewError("review attestation signing key is not configured")
    reviewer_name = reviewer.strip().lower()
    if not reviewer_name:
        raise ReviewError("reviewer role is required for a scoped attestation key")
    return hmac.new(
        master_key.encode("utf-8"),
        f"{ROLE_SCOPED_KEY_CONTEXT}:{reviewer_name}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def execution_scoped_review_attestation_key(
    master_key: str,
    reviewer: str,
    task_id: str,
    nonce: str,
    subject: str,
    head_sha: str,
    issue_digest: str,
) -> str:
    if not master_key or not reviewer or not task_id or not nonce:
        raise ReviewError("complete execution scope is required for attestation key derivation")
    payload = json.dumps(
        {
            "context": EXECUTION_SCOPED_KEY_CONTEXT,
            "reviewer": reviewer.strip().lower(),
            "task_id": task_id,
            "nonce": nonce,
            "subject": subject,
            "head_sha": head_sha,
            "issue_digest": issue_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hmac.new(
        master_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _execution_key_for_payload(master_key: str, payload: dict[str, Any]) -> str:
    try:
        task_id, nonce = str(payload["attestation_id"]).split(":", 1)
    except (KeyError, ValueError):
        return role_scoped_review_attestation_key(
            master_key, str(payload["reviewer"])
        )
    return execution_scoped_review_attestation_key(
        master_key,
        str(payload["reviewer"]),
        task_id,
        nonce,
        str(payload["subject"]),
        str(payload["head_sha"]),
        str(payload["issue_digest"]),
    )


def _rotation_manifest_key(master_key: str) -> bytes:
    return hmac.new(
        master_key.encode("utf-8"),
        ROTATION_MANIFEST_KEY_CONTEXT.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _load_attestation_key(config: Config) -> str:
    settings = config.governance.get("review", {}).get("attestation", {})
    env_name = str(settings.get("key_env", "SATURNIN_REVIEW_ATTESTATION_KEY"))
    try:
        key = credential_value(env_name, ATTESTATION_CREDENTIAL)
    except CredentialError as exc:
        raise ReviewError(str(exc)) from exc
    if not key:
        raise ReviewError(f"review attestation key is not configured in {env_name}")
    return key


def review_attestation_signing_key(
    config: Config,
    reviewer: str,
    *,
    master_key: str | None = None,
) -> str:
    settings = config.governance.get("review", {}).get("attestation", {})
    key = master_key if master_key is not None else _load_attestation_key(config)
    scope_env = str(settings.get("key_scope_env", "SATURNIN_REVIEW_ATTESTATION_KEY_SCOPE"))
    if os.environ.get(scope_env) == "role":
        role_env = str(settings.get("role_env", "SATURNIN_AGENT_ROLE"))
        current_role = os.environ.get(role_env, "").strip().lower()
        reviewer_name = reviewer.strip().lower()
        if not current_role:
            raise ReviewError(
                f"{role_env} is required when {scope_env}=role for review attestations"
            )
        if not reviewer_name:
            raise ReviewError("reviewer role is required for role-scoped review attestations")
        if current_role != reviewer_name:
            raise ReviewError(f"{role_env}={current_role} may not sign as reviewer {reviewer_name}")
        return key
    if settings.get("role_scoped", True):
        return role_scoped_review_attestation_key(key, reviewer)
    return key


def _verification_keys(
    config: Config, reviewer: str, *, include_previous: bool = False
) -> list[str]:
    settings = config.governance.get("review", {}).get("attestation", {})
    key = _load_attestation_key(config)
    scope_env = str(settings.get("key_scope_env", "SATURNIN_REVIEW_ATTESTATION_KEY_SCOPE"))
    if os.environ.get(scope_env) == "role":
        role_env = str(settings.get("role_env", "SATURNIN_AGENT_ROLE"))
        current_role = os.environ.get(role_env, "").strip().lower()
        reviewer_name = reviewer.strip().lower()
        if not current_role:
            raise ReviewError(
                f"{role_env} is required when {scope_env}=role for review attestations"
            )
        if not reviewer_name:
            raise ReviewError("reviewer role is required for role-scoped review attestations")
        if current_role != reviewer_name:
            raise ReviewError(
                f"{role_env}={current_role} may not verify reviewer {reviewer_name}"
            )
        return [key]
    masters = [key]
    if include_previous:
        previous_env = str(
            settings.get("previous_key_env", "SATURNIN_REVIEW_ATTESTATION_PREVIOUS_KEY")
        )
        try:
            previous = credential_value(
                previous_env, PREVIOUS_ATTESTATION_CREDENTIAL
            )
        except CredentialError as exc:
            raise ReviewError(str(exc)) from exc
        if previous and previous != key:
            masters.append(previous)
    if settings.get("role_scoped", True):
        return [role_scoped_review_attestation_key(master, reviewer) for master in masters]
    return masters


def _verify_review_attestation(
    attestation: str,
    config: Config,
    *,
    historical_identity: tuple[str, str, str] | None = None,
) -> dict[str, Any]:
    try:
        payload = json.loads(attestation)
    except json.JSONDecodeError as exc:
        raise ReviewError(f"invalid review attestation JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReviewError("review attestation must be a JSON object")
    required = {*ATTESTED_FIELDS, "attestation_id", "signature"}
    if historical_identity is None:
        required.add("key_id")
    missing = sorted(required - set(payload))
    if missing:
        raise ReviewError(f"review attestation is missing field(s): {', '.join(missing)}")
    signature = payload.get("signature")
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", signature):
        raise ReviewError("review attestation signature must be a SHA-256 HMAC")
    for field_name in (*ATTESTED_FIELDS, "attestation_id", "key_id"):
        if field_name not in payload:
            continue
        expected_type = bool if field_name == "zero_context" else str
        if type(payload[field_name]) is not expected_type:
            raise ReviewError(f"review attestation field {field_name!r} has the wrong type")
    include_previous = historical_identity is not None
    settings = config.governance.get("review", {}).get("attestation", {})
    scope_env = str(
        settings.get(
            "key_scope_env", "SATURNIN_REVIEW_ATTESTATION_KEY_SCOPE"
        )
    )
    if os.environ.get(scope_env) == "role":
        verification_keys = _verification_keys(
            config,
            str(payload["reviewer"]),
            include_previous=include_previous,
        )
    else:
        try:
            masters = [_load_attestation_key(config)]
            if include_previous:
                previous_env = str(
                    settings.get(
                        "previous_key_env",
                        "SATURNIN_REVIEW_ATTESTATION_PREVIOUS_KEY",
                    )
                )
                previous = credential_value(
                    previous_env, PREVIOUS_ATTESTATION_CREDENTIAL
                )
                if previous and previous != masters[0]:
                    masters.append(previous)
            verification_keys = [
                _execution_key_for_payload(master, payload) for master in masters
            ]
        except (ReviewError, CredentialError):
            from .attestation_service import AttestationServiceError, verify_with_service

            try:
                verified = verify_with_service(config, attestation)
            except (AttestationServiceError, OSError) as exc:
                raise ReviewError(str(exc)) from exc
            if historical_identity is None and verified.get("previous") is True:
                raise ReviewError(
                    "previous-key attestation cannot authorize a new review record"
                )
            if historical_identity is not None and verified.get("previous") is True:
                _require_sealed_previous_attestation(config, historical_identity)
            return payload
    key_id = payload.get("key_id")
    if key_id is not None and not re.fullmatch(r"[0-9a-f]{64}", key_id):
        raise ReviewError("review attestation key_id must be a SHA-256 digest")
    matching_keys = [
        candidate
        for candidate in verification_keys
        if key_id is None
        or hmac.compare_digest(
            key_id,
            hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        )
    ]
    verified_keys = [
        candidate
        for candidate in matching_keys
        if hmac.compare_digest(
            signature,
            hmac.new(
                candidate.encode("utf-8"),
                _canonical_attestation_payload(payload),
                hashlib.sha256,
            ).hexdigest(),
        )
    ]
    if not verified_keys:
        raise ReviewError("review attestation signature does not match")
    current_key = verification_keys[0]
    uses_previous = not any(
        hmac.compare_digest(candidate, current_key) for candidate in verified_keys
    )
    if uses_previous:
        assert historical_identity is not None
        _require_sealed_previous_attestation(config, historical_identity)
    return payload


def _manifest_payload(entries: list[dict[str, str]]) -> bytes:
    return json.dumps(
        {"version": 1, "attestations": entries},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _rotation_manifest_path(config: Config) -> Path:
    return config.board_dir / "reviews" / "rotation-manifest.json"


def _load_rotation_manifest(config: Config) -> set[tuple[str, str, str]]:
    settings = config.governance.get("review", {}).get("attestation", {})
    scope_env = str(settings.get("key_scope_env", "SATURNIN_REVIEW_ATTESTATION_KEY_SCOPE"))
    if os.environ.get(scope_env) == "role":
        raise ReviewError("previous-key ledger history requires trusted supervisor verification")
    path = _rotation_manifest_path(config)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewError(f"previous-key rotation manifest is missing or invalid: {path}") from exc
    if not isinstance(data, dict) or set(data) != {"version", "attestations", "signature"}:
        raise ReviewError("previous-key rotation manifest has an invalid schema")
    entries = data["attestations"]
    signature = data["signature"]
    if data["version"] != 1 or not isinstance(entries, list):
        raise ReviewError("previous-key rotation manifest has an invalid schema")
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise ReviewError("previous-key rotation manifest has an invalid signature")
    normalized: list[dict[str, str]] = []
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"reviewer", "attestation_id", "signature"}
            or not all(isinstance(value, str) and value for value in entry.values())
        ):
            raise ReviewError("previous-key rotation manifest has an invalid entry")
        normalized.append(entry)
    if normalized != sorted(
        normalized,
        key=lambda item: (item["reviewer"], item["attestation_id"], item["signature"]),
    ):
        raise ReviewError("previous-key rotation manifest entries are not canonical")
    try:
        expected = hmac.new(
            _rotation_manifest_key(_load_attestation_key(config)),
            _manifest_payload(normalized),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ReviewError(
                "previous-key rotation manifest signature does not match"
            )
    except ReviewError as exc:
        if "not configured" not in str(exc):
            raise
        from .attestation_service import (
            AttestationServiceError,
            verify_manifest_with_service,
        )

        try:
            verify_manifest_with_service(config, normalized, signature)
        except (AttestationServiceError, OSError) as service_exc:
            raise ReviewError(str(service_exc)) from service_exc
    return {
        (entry["reviewer"], entry["attestation_id"], entry["signature"])
        for entry in normalized
    }


def _require_sealed_previous_attestation(
    config: Config,
    identity: tuple[str, str, str],
) -> None:
    if identity not in _load_rotation_manifest(config):
        raise ReviewError("previous-key review attestation is not sealed by the rotation manifest")


class ReviewLedger:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or default_config()
        self.dir: Path = self.config.board_dir / "reviews"
        self.dir.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        subject: str,
        kind: str,
        author: str,
        reviewer: str,
        verdict: str,
        zero_context: bool = True,
        head_sha: str = "",
        issue_digest: str = "",
        destination_repo: str = "",
        notes: str = "",
        attestation: str = "",
    ) -> ReviewRecord:
        attestation_id = ""
        attestation_signature = ""
        if kind not in KINDS:
            raise ReviewError(f"unknown review kind: {kind}")
        if verdict not in VERDICTS:
            raise ReviewError(f"unknown verdict: {verdict}")
        head = head_sha.strip()
        digest = issue_digest.strip()
        try:
            destination = (
                normalize_repository_slug(destination_repo) if destination_repo else ""
            )
        except ValueError as exc:
            raise ReviewError(f"invalid destination repository: {exc}") from exc
        if kind == "pr" and not head:
            raise ReviewError(
                "PR reviews require --head-sha (pass the same SHA to review record and review gate)"
            )
        if kind == "pr" and not _HEX_SHA_RE.fullmatch(head):
            raise ReviewError("PR --head-sha must be a full 40-character commit SHA")
        if kind == "issue" and not digest:
            raise ReviewError("issue reviews require the reviewed issue-content digest")
        if kind == "issue" and not _ISSUE_DIGEST_RE.fullmatch(digest):
            raise ReviewError("issue reviews require a 64-character SHA-256 issue-content digest")
        if kind == "issue" and not destination:
            raise ReviewError("issue reviews require the destination repository")
        if reviewer.strip().lower() == author.strip().lower():
            raise ReviewError("a review must be written by somebody other than the author")
        roles = self.config.routing.get("roles", {})
        reviewer_name = reviewer.strip().lower()
        if reviewer_name not in roles:
            raise ReviewError(f"unknown reviewer role {reviewer!r}; expected one of {sorted(roles)}")
        if zero_context and not bool(roles[reviewer_name].get("zero_context", False)):
            raise ReviewError(f"reviewer {reviewer!r} is not configured as zero-context")
        if self.config.governance.get("review", {}).get("attestation", {}).get(
            "required",
            False,
        ):
            if not attestation:
                raise ReviewError("review records require a signed attestation")
            payload = _verify_review_attestation(attestation, self.config)
            supplied = {
                "subject": subject,
                "kind": kind,
                "author": author,
                "reviewer": reviewer_name,
                "verdict": verdict,
                "zero_context": zero_context,
                "head_sha": head,
                "issue_digest": digest,
                "destination_repo": destination,
            }
            for field_name, supplied_value in supplied.items():
                if payload[field_name] != supplied_value:
                    raise ReviewError(
                        f"review attestation {field_name} does not match the record"
                    )
            attestation_id = str(payload["attestation_id"])
            attestation_signature = (
                f"{payload['key_id']}:{payload['signature']}"
            )
        entry = ReviewRecord(
            subject=subject,
            kind=kind,
            author=author,
            reviewer=reviewer_name,
            verdict=verdict,
            zero_context=zero_context,
            head_sha=head,
            issue_digest=digest,
            destination_repo=destination,
            notes=notes,
            attestation_id=attestation_id,
            attestation_signature=attestation_signature,
        )
        try:
            ReviewRecord.validate_dict(entry.to_dict())
        except (TypeError, ValueError) as exc:
            raise ReviewError(f"invalid review record: {exc}") from exc
        path = self.dir / f"{kind}-{slugify(subject)}.jsonl"
        # Rotation lock always precedes a per-ledger lock so sealing can take a
        # stable snapshot without deadlocking concurrent record writers.
        with file_lock(_rotation_manifest_path(self.config)):
            with file_lock(path):
                serialized = json.dumps(entry.to_dict()) + "\n"
                if path.exists():
                    raw = path.read_text(encoding="utf-8")
                    try:
                        repaired = repair_unterminated_tail(
                            raw,
                            path,
                            required_fields=REQUIRED_FIELDS,
                            validator=ReviewRecord.validate_dict,
                        )
                    except JSONLinesError as exc:
                        raise ReviewError(f"corrupt review ledger {exc}") from exc
                    if repaired != raw:
                        self._reject_replayed_attestation(path, attestation_id, repaired)
                        path.chmod(0o600)
                        atomic_replace_text(path, repaired + serialized)
                        return entry
                    self._reject_replayed_attestation(path, attestation_id, raw)
                durable_append_text(path, serialized)
        return entry

    def for_subject(self, subject: str, kind: str) -> list[ReviewRecord]:
        path = self.dir / f"{kind}-{slugify(subject)}.jsonl"
        records = (
            [
                record
                for record in self._records(path)
                if record.subject == subject and record.kind == kind
            ]
            if path.is_file()
            else []
        )
        latest: dict[str, ReviewRecord] = {}
        for record in records:
            latest[record.reviewer] = record
        return list(latest.values())

    def __iter__(self) -> Iterator[ReviewRecord]:
        for path in sorted(self.dir.glob("*.jsonl")):
            yield from self._records(path)

    def seal_rotation_manifest(
        self,
        *,
        current_master: str | None = None,
        previous_master: str | None = None,
    ) -> Path:
        path = _rotation_manifest_path(self.config)
        with file_lock(path):
            settings = self.config.governance.get("review", {}).get("attestation", {})
            scope_env = str(
                settings.get("key_scope_env", "SATURNIN_REVIEW_ATTESTATION_KEY_SCOPE")
            )
            if (
                current_master is None
                and previous_master is None
                and os.environ.get(scope_env) == "role"
            ):
                raise ReviewError("rotation manifests require the trusted supervisor environment")
            if previous_master is None:
                previous_env = str(
                    settings.get(
                        "previous_key_env",
                        "SATURNIN_REVIEW_ATTESTATION_PREVIOUS_KEY",
                    )
                )
                try:
                    previous_master = credential_value(
                        previous_env, PREVIOUS_ATTESTATION_CREDENTIAL
                    )
                except CredentialError as exc:
                    raise ReviewError(str(exc)) from exc
            else:
                previous_env = "encrypted previous-key credential"
            if not previous_master:
                raise ReviewError(f"rotation manifest requires {previous_env}")
            if current_master is None:
                current_master = _load_attestation_key(self.config)
            if hmac.compare_digest(previous_master, current_master):
                raise ReviewError("current and previous review attestation keys must differ")
            entries = [
                {
                    "reviewer": record.reviewer,
                    "attestation_id": record.attestation_id,
                    "signature": record.attestation_signature,
                }
                for record in self._records_signed_by(previous_master)
            ]
            entries.sort(
                key=lambda item: (item["reviewer"], item["attestation_id"], item["signature"])
            )
            payload = _manifest_payload(entries)
            manifest = {
                "version": 1,
                "attestations": entries,
                "signature": hmac.new(
                    _rotation_manifest_key(current_master),
                    payload,
                    hashlib.sha256,
                ).hexdigest(),
            }
            atomic_replace_text(
                path,
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            )
        return path

    def has_records_signed_by(self, master_key: str) -> bool:
        return next(iter(self._records_signed_by(master_key)), None) is not None

    def _records_signed_by(self, master_key: str) -> Iterator[ReviewRecord]:
        for ledger_path in sorted(self.dir.glob("*.jsonl")):
            with file_lock(ledger_path, exclusive=False):
                text = ledger_path.read_text(encoding="utf-8")
            try:
                records = [
                    ReviewRecord.from_dict(data)
                    for data in objects(
                        text,
                        ledger_path,
                        required_fields=REQUIRED_FIELDS,
                        validator=ReviewRecord.validate_dict,
                    )
                ]
            except JSONLinesError as exc:
                raise ReviewError(f"corrupt review ledger {exc}") from exc
            for record in records:
                if self._record_matches_master(record, master_key):
                    yield record

    @staticmethod
    def _record_matches_master(record: ReviewRecord, master_key: str) -> bool:
        payload = {field: getattr(record, field) for field in ATTESTED_FIELDS}
        payload["attestation_id"] = record.attestation_id
        try:
            key = _execution_key_for_payload(master_key, payload)
        except ReviewError:
            key = role_scoped_review_attestation_key(master_key, record.reviewer)
        stored_signature = record.attestation_signature
        if ":" in stored_signature:
            key_id, signature = stored_signature.split(":", 1)
            if not hmac.compare_digest(
                key_id, hashlib.sha256(key.encode("utf-8")).hexdigest()
            ):
                return False
            payload["key_id"] = key_id
        else:
            signature = stored_signature
        expected = hmac.new(
            key.encode("utf-8"),
            _canonical_attestation_payload(payload),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(signature, expected)

    def _records(self, path: Path) -> Iterator[ReviewRecord]:
        with file_lock(path, exclusive=False):
            text = path.read_text(encoding="utf-8")
        try:
            for data in objects(
                text,
                path,
                required_fields=REQUIRED_FIELDS,
                validator=ReviewRecord.validate_dict,
            ):
                record = ReviewRecord.from_dict(data)
                if self.config.governance.get("review", {}).get("attestation", {}).get(
                    "required",
                    False,
                ):
                    self._verify_record_attestation(record)
                yield record
        except JSONLinesError as exc:
            raise ReviewError(f"corrupt review ledger {exc}") from exc

    def _verify_record_attestation(self, record: ReviewRecord) -> None:
        if not record.attestation_id or not record.attestation_signature:
            raise ReviewError(
                f"corrupt review ledger: unauthenticated review record for {record.subject}"
            )
        payload = {
            field: getattr(record, field)
            for field in ATTESTED_FIELDS
        }
        payload["attestation_id"] = record.attestation_id
        if ":" in record.attestation_signature:
            key_id, signature = record.attestation_signature.split(":", 1)
            payload["key_id"] = key_id
            payload["signature"] = signature
        else:
            payload["signature"] = record.attestation_signature
        try:
            _verify_review_attestation(
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                self.config,
                historical_identity=(
                    record.reviewer,
                    record.attestation_id,
                    record.attestation_signature,
                ),
            )
        except ReviewError as exc:
            raise ReviewError(
                f"corrupt review ledger: invalid review attestation for {record.subject}: {exc}"
            ) from exc

    @staticmethod
    def _reject_replayed_attestation(path: Path, attestation_id: str, text: str) -> None:
        if not attestation_id:
            return
        try:
            for data in objects(
                text,
                path,
                required_fields=REQUIRED_FIELDS,
                validator=ReviewRecord.validate_dict,
            ):
                if data.get("attestation_id") == attestation_id:
                    raise ReviewError("review attestation has already been recorded")
        except JSONLinesError as exc:
            raise ReviewError(f"corrupt review ledger {exc}") from exc


_KIND_TO_REVIEWER_ROLE: dict[str, str] = {
    "pr": "pr-reviewer",
    "issue": "issue-reviewer",
}


def _allowed_reviewer_roles(kind: str, config: Config) -> set[str]:
    """Return the set of roles allowed to review the given kind.

    Falls back to the hard-coded mapping when policy does not specify one.
    """
    review_policy = config.governance.get("review", {}).get(kind, {})
    explicit = review_policy.get("allowed_reviewer_roles")
    if explicit:
        return {str(r).strip().lower() for r in explicit}
    default_role = _KIND_TO_REVIEWER_ROLE.get(kind)
    if default_role:
        return {default_role}
    return set()
