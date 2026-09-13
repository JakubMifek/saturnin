"""Independent review pipelines for pull requests and issue drafts.

Reviews are recorded as files so that the gate in :mod:`saturnin.governance`
can be evaluated by any process, including a cron job or a CI helper.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from .board import utcnow
from .config import Config, default_config
from .jsonlines import (
    JSONLinesError,
    atomic_replace_text,
    objects,
    repair_unterminated_tail,
)
from .locking import file_lock

VERDICTS = ("approved", "changes_requested", "rejected", "dismissed")
KINDS = ("pr", "issue")
_HEX_SHA_RE = re.compile(r"[0-9a-fA-F]{40}")
_ISSUE_DIGEST_RE = re.compile(r"[0-9a-fA-F]{64}")


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
    notes: str = ""
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
            "notes",
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
        try:
            created_at = datetime.fromisoformat(data["created_at"])
        except ValueError as exc:
            raise ValueError("review record created_at must be ISO-8601") from exc
        if created_at.tzinfo is None:
            raise ValueError("review record created_at must include a timezone")


REQUIRED_FIELDS = tuple(ReviewRecord.__dataclass_fields__)  # noqa: SLF001 - dataclass API


def slugify(subject: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", subject).strip("-")
    if not slug:
        raise ReviewError(f"subject {subject!r} cannot be turned into a file name")
    digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()[:8]
    return f"{slug.lower()}-{digest}"


def issue_content_digest(title: str, body: str) -> str:
    payload = json.dumps(
        {"title": title.strip(), "body": body.strip()},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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
        notes: str = "",
    ) -> ReviewRecord:
        if kind not in KINDS:
            raise ReviewError(f"unknown review kind: {kind}")
        if verdict not in VERDICTS:
            raise ReviewError(f"unknown verdict: {verdict}")
        head = head_sha.strip()
        digest = issue_digest.strip()
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
        if reviewer.strip().lower() == author.strip().lower():
            raise ReviewError("a review must be written by somebody other than the author")
        roles = self.config.routing.get("roles", {})
        reviewer_name = reviewer.strip().lower()
        if reviewer_name not in roles:
            raise ReviewError(f"unknown reviewer role {reviewer!r}; expected one of {sorted(roles)}")
        if zero_context and not bool(roles[reviewer_name].get("zero_context", False)):
            raise ReviewError(f"reviewer {reviewer!r} is not configured as zero-context")
        entry = ReviewRecord(
            subject=subject,
            kind=kind,
            author=author,
            reviewer=reviewer_name,
            verdict=verdict,
            zero_context=zero_context,
            head_sha=head,
            issue_digest=digest,
            notes=notes,
        )
        try:
            ReviewRecord.validate_dict(entry.to_dict())
        except (TypeError, ValueError) as exc:
            raise ReviewError(f"invalid review record: {exc}") from exc
        path = self.dir / f"{kind}-{slugify(subject)}.jsonl"
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
                    atomic_replace_text(path, repaired + serialized)
                    return entry
            with path.open("a", encoding="utf-8") as handle:
                handle.write(serialized)
        return entry

    def for_subject(self, subject: str, kind: str) -> list[ReviewRecord]:
        records: list[ReviewRecord] = []
        for path in sorted(self.dir.glob(f"{kind}-*.jsonl")):
            records.extend(
                record for record in self._records(path) if record.subject == subject and record.kind == kind
            )
        latest: dict[str, ReviewRecord] = {}
        for record in records:
            latest[record.reviewer] = record
        return list(latest.values())

    def __iter__(self) -> Iterator[ReviewRecord]:
        for path in sorted(self.dir.glob("*.jsonl")):
            yield from self._records(path)

    @staticmethod
    def _records(path: Path) -> Iterator[ReviewRecord]:
        with file_lock(path, exclusive=False):
            text = path.read_text(encoding="utf-8")
        try:
            for data in objects(
                text,
                path,
                required_fields=REQUIRED_FIELDS,
                tolerate_unterminated_tail=True,
                validator=ReviewRecord.validate_dict,
            ):
                yield ReviewRecord.from_dict(data)
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
