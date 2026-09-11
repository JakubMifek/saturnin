"""Mirror board tasks as GitHub issues.

The local board is fast and offline; GitHub is durable. ``policies/repos.yaml``
names the private repository that holds the mirrored issues, and rule 8 of
``policies/governance.yaml`` says a task without a mirror is not durable.

Rendering is pure and testable; pushing shells out to ``gh`` so that Saturnin
never has to hold a token itself.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Iterable

from .board import Board, Task
from .config import Config, default_config


class MirrorError(RuntimeError):
    """Raised when a task cannot be mirrored."""


@dataclass
class IssuePayload:
    repo: str
    title: str
    body: str
    labels: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "title": self.title,
            "body": self.body,
            "labels": self.labels,
        }


class IssueMirror:
    """Render and push the GitHub issue that backs a board task."""

    def __init__(self, config: Config | None = None, board: Board | None = None) -> None:
        self.config = config or default_config()
        self.board = board or Board(self.config)

    # -- policy --------------------------------------------------------
    @property
    def policy(self) -> dict[str, Any]:
        return self.config.policy("repos")

    @property
    def tracking(self) -> dict[str, Any]:
        return self.policy.get("tracking", {})

    @property
    def enabled(self) -> bool:
        return bool(self.tracking.get("mirror_tasks_as_issues", False))

    @property
    def board_repo(self) -> str:
        slug = self.policy.get("repos", {}).get("board", {}).get("slug")
        if not slug:
            raise MirrorError("policies/repos.yaml defines no board repository")
        return str(slug)

    def mirrors(self, task: Task) -> bool:
        kinds = self.tracking.get("mirror_kinds") or []
        return self.enabled and task.kind in kinds

    # -- rendering -----------------------------------------------------
    def labels_for(self, task: Task) -> list[str]:
        prefix = self.policy.get("repos", {}).get("board", {}).get("label_prefix", "saturnin")
        pairs = [
            (self.tracking.get("kind_label", "kind"), task.kind),
            (self.tracking.get("state_label", "state"), task.state),
            (self.tracking.get("priority_label", "priority"), task.priority),
        ]
        if task.role:
            pairs.append((self.tracking.get("role_label", "role"), task.role))
        labels = [f"{prefix}:{key}/{value}" for key, value in pairs]
        return sorted({*labels, *task.labels})

    def render(self, task: Task) -> IssuePayload:
        if not self.mirrors(task):
            raise MirrorError(f"{task.id} is a {task.kind}; policy does not mirror it")
        lines = [
            f"<!-- saturnin:task:{task.id} -->",
            "",
            task.body.strip() or "_No description supplied at intake._",
            "",
            "| field | value |",
            "| --- | --- |",
            f"| task | `{task.id}` |",
            f"| kind | {task.kind} |",
            f"| state | {task.state} |",
            f"| priority | {task.priority} |",
            f"| role | {task.role or '_unrouted_'} |",
            f"| repo | {task.repo or '_n/a_'} |",
            f"| parent | {task.parent or '_none_'} |",
            f"| result contract | {task.result_contract or '_not agreed_'} |",
        ]
        children = self.board.children(task.id)
        if children:
            lines += ["", "### Children", ""]
            lines += [f"- [{'x' if c.state == 'done' else ' '}] `{c.id}` {c.title}" for c in children]
        lines += [
            "",
            "---",
            "Mirrored from the Saturnin board. Edit the board, not this issue: "
            "`saturnin task sync " + task.id + "`.",
        ]
        return IssuePayload(
            repo=self.board_repo,
            title=f"[{task.kind}] {task.title}",
            body="\n".join(lines),
            labels=self.labels_for(task),
        )

    # -- pushing -------------------------------------------------------
    def unmirrored(self) -> list[Task]:
        return [
            task
            for task in self.board.list(open_only=True)
            if self.mirrors(task) and not task.issue
        ]

    def syncable(self) -> list[Task]:
        """Return tasks that need syncing, including terminal tasks for a final update."""
        result: list[Task] = []
        for task in self.board:
            if not self.mirrors(task):
                continue
            if not task.issue:
                result.append(task)
                continue
            synced_at = getattr(task, "issue_synced_at", None)
            if not synced_at or synced_at < getattr(task, "updated_at", ""):
                result.append(task)
        return result

    def sync(self, task: Task, *, push: bool = False, actor: str = "chief-of-staff") -> IssuePayload:
        task = self.board.get(task.id)
        payload = self.render(task)
        rendered_updated_at = task.updated_at
        if not push:
            return payload
        url = self._push(task, payload)
        with self.board.edit(task.id) as stored:
            stored.issue = url
            if stored.updated_at == rendered_updated_at:
                stored.log("issue:synced", actor=actor, note=url)
                stored.issue_synced_at = stored.updated_at
        task.issue = url
        return payload

    def sync_all(self, tasks: Iterable[Task], *, push: bool = False) -> list[IssuePayload]:
        return [self.sync(task, push=push) for task in tasks if self.mirrors(task)]

    def _push(self, task: Task, payload: IssuePayload) -> str:
        ensure_labels(payload.repo, payload.labels)
        terminal = task.state in ("done", "cancelled")
        if task.issue:
            self._update_issue(task.issue, payload, terminal=terminal)
            return task.issue
        # Before creating, search for an existing issue with our marker to avoid
        # duplicates if a previous creation succeeded but the local save failed.
        marker = f"saturnin:task:{task.id}"
        existing = self._find_issue_by_marker(payload.repo, marker)
        if existing:
            self._update_issue(existing, payload, terminal=terminal)
            return existing
        out = run_gh(
            [
                "issue",
                "create",
                "--repo",
                payload.repo,
                "--title",
                payload.title,
                "--body",
                payload.body,
                *_label_args(payload.labels),
            ]
        )
        url = out.strip().splitlines()[-1].strip() if out.strip() else ""
        if not url:
            raise MirrorError("gh issue create returned no URL")
        if terminal:
            run_gh(["issue", "close", url])
        return url

    def _update_issue(self, issue: str, payload: IssuePayload, *, terminal: bool) -> None:
        current = self._issue_labels(issue)
        stale = sorted(
            label
            for label in current
            if self._is_metadata_label(label) and label not in payload.labels
        )
        args = [
            "issue", "edit", issue,
            "--body", payload.body,
            "--title", payload.title,
            *_label_args(payload.labels, option="--add-label"),
            *_label_args(stale, option="--remove-label"),
        ]
        run_gh(args)
        if terminal:
            run_gh(["issue", "close", issue])

    def _find_issue_by_marker(self, repo: str, marker: str) -> str | None:
        """Search for an existing issue containing the deterministic marker comment."""
        try:
            out = run_gh([
                "issue", "list", "--repo", repo, "--search", marker,
                "--state", "all", "--json", "url", "--limit", "1",
            ])
            data = json.loads(out or "[]")
            if data:
                return str(data[0]["url"])
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
        return None

    def _issue_labels(self, issue: str) -> set[str]:
        output = run_gh(["issue", "view", issue, "--json", "labels"])
        try:
            data = json.loads(output)
            return {str(label["name"]) for label in data.get("labels", [])}
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise MirrorError("gh issue view returned invalid label data") from exc

    def _is_metadata_label(self, label: str) -> bool:
        prefix = self.policy.get("repos", {}).get("board", {}).get(
            "label_prefix", "saturnin"
        )
        keys = (
            self.tracking.get("kind_label", "kind"),
            self.tracking.get("state_label", "state"),
            self.tracking.get("priority_label", "priority"),
            self.tracking.get("role_label", "role"),
        )
        return any(label.startswith(f"{prefix}:{key}/") for key in keys)


def _label_args(labels: list[str], *, option: str = "--label") -> list[str]:
    out: list[str] = []
    for label in labels:
        out += [option, label]
    return out


def ensure_labels(repo: str, labels: Iterable[str]) -> None:
    existing = _repo_labels(repo)
    for label in sorted(set(labels) - existing):
        try:
            run_gh(["label", "create", label, "--repo", repo])
        except MirrorError as create_error:
            try:
                created_by_race = label in _repo_labels(repo)
            except MirrorError:
                raise create_error
            if not created_by_race:
                raise create_error


def _repo_labels(repo: str) -> set[str]:
    output = run_gh(["label", "list", "--repo", repo, "--limit", "1000", "--json", "name"])
    try:
        data = json.loads(output)
        return {str(item["name"]) for item in data}
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise MirrorError("gh label list returned invalid label data") from exc


def run_gh(args: list[str]) -> str:
    if shutil.which("gh") is None:
        raise MirrorError("gh CLI not found; install it to use GitHub integrations")
    result = subprocess.run(
        ["gh", *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise MirrorError(f"gh {' '.join(args[:2])} failed: {result.stderr.strip()}")
    return result.stdout


def _utcnow() -> str:
    from .board import utcnow

    return utcnow()


def dumps(payloads: list[IssuePayload]) -> str:
    return json.dumps([p.to_dict() for p in payloads], indent=2)
