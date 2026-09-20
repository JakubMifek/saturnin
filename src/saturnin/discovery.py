"""Pull work in from the repositories Saturnin manages.

Saturnin should not have to poll applications itself: a project that already
runs an observability stack can alert, and an alert that can open a GitHub
issue is a task waiting to be adopted. The same inbound path serves humans
filing issues by hand, Dependabot, and anything else that can write an issue.

Discovery is therefore the single inbound door: it lists issues in managed
repositories, ignores the ones it has already seen, and creates a board task
for the rest. Deduplication is by a ``source:<repo>#<number>`` label on the
task, so re-running the loop is free.

Listing shells out to ``gh`` for the same reason mirroring does - Saturnin holds
no token of its own - but the fetch function is injectable so that the ingest
half is testable without a network.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .board import Board, Task
from .config import Config, default_config
from .issues import MirrorError, ensure_labels


class DiscoveryError(RuntimeError):
    """Raised when inbound issues cannot be read."""


@dataclass
class InboundIssue:
    repo: str
    number: int
    title: str
    url: str
    body: str = ""
    labels: list[str] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"{self.repo}#{self.number}"


Fetcher = Callable[[str, list[str]], list[InboundIssue]]


class IssueDiscovery:
    """Turn issues in managed repositories into board tasks."""

    def __init__(
        self,
        config: Config | None = None,
        board: Board | None = None,
        *,
        fetcher: Fetcher | None = None,
    ) -> None:
        self.config = config or default_config()
        self.board = board or Board(self.config)
        self._fetch = fetcher or _gh_fetch
        self._provision_labels = fetcher is None

    # -- policy --------------------------------------------------------
    @property
    def policy(self) -> dict[str, Any]:
        return self.config.policy("repos").get("discovery", {})

    @property
    def enabled(self) -> bool:
        return bool(self.policy.get("enabled", True))

    @property
    def labels(self) -> list[str]:
        return [str(label) for label in self.policy.get("labels", [])]

    def sources(self) -> list[dict[str, Any]]:
        """Repositories to watch, each with the labels that mark adoptable work."""
        sources: list[dict[str, Any]] = []
        for entry in self.policy.get("sources", []) or []:
            if isinstance(entry, str):
                entry = {"slug": entry}
            slug = entry.get("slug")
            if not slug:
                continue
            sources.append(
                {
                    "slug": str(slug),
                    "labels": entry.get("labels") or self.labels,
                    "require_labels": entry.get("require_labels") or [],
                }
            )
        return sources

    def marker(self, issue: InboundIssue) -> str:
        prefix = str(self.policy.get("source_label_prefix", "source")).casefold()
        return f"{prefix}:{issue.ref.casefold()}"

    def audit(self) -> list[str]:
        if not self.enabled:
            return []
        problems: list[str] = []
        for source in self.sources():
            labels = {str(label).casefold() for label in source.get("labels", [])}
            required = {str(label).casefold() for label in source.get("require_labels", [])}
            if "saturnin" in labels and "saturnin:trusted" not in required:
                problems.append(
                    f"discovery source {source['slug']} must require saturnin:trusted when labels include saturnin"
                )
            if "saturnin:trusted" in required and "saturnin" not in labels:
                problems.append(
                    f"discovery source {source['slug']} must include saturnin when requiring saturnin:trusted"
                )
        return problems

    # -- ingest --------------------------------------------------------
    def known_markers(self) -> set[str]:
        prefix = str(self.policy.get("source_label_prefix", "source")).casefold() + ":"
        return {
            label.casefold()
            for task in self.board
            for label in task.labels
            if label.casefold().startswith(prefix)
        }

    def ingest(self, issues: Iterable[InboundIssue]) -> list[Task]:
        """Create a board task for every issue not already on the board."""
        created: list[Task] = []
        for issue in issues:
            marker = self.marker(issue)
            task = self.board.create_if_labels_absent(
                [marker],
                issue.title,
                body=_body(issue),
                repo=issue.repo,
                labels=_carried_labels(issue, self.policy),
                priority=_priority(issue, self.policy),
                source=f"discovery:{issue.repo}",
            )
            if task is not None:
                created.append(task)
        return created

    def poll(self) -> list[InboundIssue]:
        if not self.enabled:
            return []
        found: list[InboundIssue] = []
        for source in self.sources():
            self._provision_source_labels(source)
            issues = self._fetch(source["slug"], list(source["labels"]))
            found += [
                issue
                for issue in issues
                if _has_required_labels(issue, source.get("require_labels", []))
            ]
        return found

    def run(self) -> list[Task]:
        return self.ingest(self.poll())

    def _provision_source_labels(self, source: dict[str, Any]) -> None:
        labels = {str(label) for label in source.get("labels", []) if str(label)}
        required = {str(label) for label in source.get("require_labels", []) if str(label)}
        if "saturnin" in {label.casefold() for label in labels | required}:
            labels.add("saturnin")
            labels.add("saturnin:trusted")
        if not labels:
            return
        if not self._provision_labels:
            return
        try:
            ensure_labels(str(source["slug"]), sorted(labels))
        except MirrorError as exc:
            raise DiscoveryError(
                f"could not provision discovery labels for {source['slug']}: {exc}"
            ) from exc


def _carried_labels(issue: InboundIssue, policy: dict[str, Any]) -> list[str]:
    """Labels worth copying onto the task, so routing can see them."""
    carry = {str(label).casefold() for label in policy.get("carry_labels", [])}
    return [label for label in issue.labels if label.casefold() in carry]


def _priority(issue: InboundIssue, policy: dict[str, Any]) -> str:
    mapping: dict[str, str] = policy.get("priority_by_label", {}) or {}
    issue_labels = {label.casefold() for label in issue.labels}
    for label, priority in mapping.items():
        if str(label).casefold() in issue_labels:
            return str(priority)
    return str(policy.get("default_priority", "P2"))


def _has_required_labels(issue: InboundIssue, required: Iterable[str]) -> bool:
    required_labels = {str(label).casefold() for label in required}
    if not required_labels:
        return True
    issue_labels = {label.casefold() for label in issue.labels}
    return required_labels <= issue_labels


def _body(issue: InboundIssue) -> str:
    lines = [
        f"Adopted from {issue.url or issue.ref}.",
        "",
        issue.body.strip() or "_The issue carried no description._",
        "",
        f"Close the loop on the issue itself; this task tracks Saturnin's side of {issue.ref}.",
    ]
    return "\n".join(lines)


def _gh_fetch(repo: str, labels: list[str]) -> list[InboundIssue]:
    if shutil.which("gh") is None:
        raise DiscoveryError("gh CLI not found; discovery needs it to read managed repositories")
    # Query each label separately and deduplicate, because gh --label filters
    # are ANDed, but the policy intent is OR (any configured label is adoptable).
    seen: dict[int, InboundIssue] = {}
    for label in labels:
        # Use a high limit to ensure all adoptable issues are seen, not just
        # the first 100.  gh handles internal pagination automatically.
        args = [
            "issue",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--json",
            "number,title,body,url,labels",
            "--limit",
            "10000",
            "--label",
            label,
        ]
        result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise DiscoveryError(f"gh issue list failed for {repo}: {result.stderr.strip()}")
        try:
            raw = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:  # pragma: no cover - gh contract change
            raise DiscoveryError(f"gh returned invalid JSON for {repo}: {exc}") from exc
        for item in raw:
            num = int(item["number"])
            if num not in seen:
                seen[num] = InboundIssue(
                    repo=repo,
                    number=num,
                    title=str(item["title"]),
                    url=str(item.get("url", "")),
                    body=str(item.get("body") or ""),
                    labels=[str(lbl.get("name", "")) for lbl in item.get("labels", [])],
                )
    return list(seen.values())
