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
            sources.append({"slug": str(slug), "labels": entry.get("labels") or self.labels})
        return sources

    def marker(self, issue: InboundIssue) -> str:
        prefix = str(self.policy.get("source_label_prefix", "source")).casefold()
        return f"{prefix}:{issue.ref.casefold()}"

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
        known = self.known_markers()
        created: list[Task] = []
        for issue in issues:
            marker = self.marker(issue)
            if marker in known:
                continue
            known.add(marker)
            created.append(
                self.board.create(
                    issue.title,
                    body=_body(issue),
                    repo=issue.repo,
                    labels=sorted({marker, *_carried_labels(issue, self.policy)}),
                    priority=_priority(issue, self.policy),
                    source=f"discovery:{issue.repo}",
                )
            )
        return created

    def poll(self) -> list[InboundIssue]:
        if not self.enabled:
            return []
        found: list[InboundIssue] = []
        for source in self.sources():
            found += self._fetch(source["slug"], list(source["labels"]))
        return found

    def run(self) -> list[Task]:
        return self.ingest(self.poll())


def _carried_labels(issue: InboundIssue, policy: dict[str, Any]) -> list[str]:
    """Labels worth copying onto the task, so routing can see them."""
    carry = {str(label) for label in policy.get("carry_labels", [])}
    return [label for label in issue.labels if label in carry]


def _priority(issue: InboundIssue, policy: dict[str, Any]) -> str:
    mapping: dict[str, str] = policy.get("priority_by_label", {}) or {}
    for label in issue.labels:
        if label in mapping:
            return str(mapping[label])
    return str(policy.get("default_priority", "P2"))


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
        "100",
    ]
    for label in labels:
        args += ["--label", label]
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise DiscoveryError(f"gh issue list failed for {repo}: {result.stderr.strip()}")
    try:
        raw = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:  # pragma: no cover - gh contract change
        raise DiscoveryError(f"gh returned invalid JSON for {repo}: {exc}") from exc
    return [
        InboundIssue(
            repo=repo,
            number=int(item["number"]),
            title=str(item["title"]),
            url=str(item.get("url", "")),
            body=str(item.get("body") or ""),
            labels=[str(label.get("name", "")) for label in item.get("labels", [])],
        )
        for item in raw
    ]
