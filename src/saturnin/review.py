"""Independent review pipelines for pull requests and issue drafts.

Reviews are recorded as files so that the gate in :mod:`saturnin.governance`
can be evaluated by any process, including a cron job or a CI helper.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

from .board import utcnow
from .config import Config, default_config
from .locking import file_lock

VERDICTS = ("approved", "changes_requested", "rejected")
KINDS = ("pr", "issue")


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
    notes: str = ""
    created_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReviewRecord":
        known = {f for f in cls.__dataclass_fields__}  # noqa: SLF001 - dataclass API
        return cls(**{k: v for k, v in data.items() if k in known})


def slugify(subject: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", subject).strip("-")
    if not slug:
        raise ReviewError(f"subject {subject!r} cannot be turned into a file name")
    digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()[:8]
    return f"{slug.lower()}-{digest}"


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
        notes: str = "",
    ) -> ReviewRecord:
        if kind not in KINDS:
            raise ReviewError(f"unknown review kind: {kind}")
        if verdict not in VERDICTS:
            raise ReviewError(f"unknown verdict: {verdict}")
        if reviewer == author:
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
            notes=notes,
        )
        path = self.dir / f"{kind}-{slugify(subject)}.jsonl"
        with file_lock(path):
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry.to_dict()) + "\n")
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
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise TypeError("record must be a JSON object")
                yield ReviewRecord.from_dict(data)
            except (json.JSONDecodeError, TypeError) as exc:
                raise ReviewError(
                    f"corrupt review ledger {path} at line {line_number}: {exc}"
                ) from exc
