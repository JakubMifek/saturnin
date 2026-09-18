"""Human escalation (rule 6).

Saturnin never blocks silently. When it cannot proceed it produces a GitHub
issue body with a checklist, an urgency and explicit unblock criteria.
"""

from __future__ import annotations

from typing import Iterable

from .board import Board, BoardError, Task
from .config import Config, default_config
from .governance import Decision, Governance
from .issues import IssueMirror, MirrorError, ensure_labels, issue_search_url, run_gh
from .locking import file_lock


def render(
    *,
    title: str,
    context: str,
    checklist: Iterable[str],
    urgency: str,
    unblock_criteria: Iterable[str],
    task_id: str | None = None,
    config: Config | None = None,
) -> str:
    config = config or default_config()
    mention = config.governance.get("escalation", {}).get("mention", "@jakubmifek")
    checklist = list(checklist) or ["Decide how Saturnin should proceed"]
    unblock_criteria = list(unblock_criteria) or ["An explicit go/no-go answer"]
    lines = [
        f"# {title}",
        "",
        f"{mention} - Saturnin is blocked and needs a human decision.",
        "",
        f"**Urgency:** {urgency}",
    ]
    if task_id:
        lines += ["", f"<!-- saturnin:escalation:{task_id} -->"]
        lines.append(f"**Board task:** {task_id}")
    lines += [
        "",
        "## Context",
        context.strip() or "(no context supplied)",
        "",
        "## Checklist",
        *[f"- [ ] {item}" for item in checklist],
        "",
        "## Unblock criteria",
        *[f"- {item}" for item in unblock_criteria],
        "",
        "Saturnin keeps every other task moving in the meantime.",
    ]
    return "\n".join(lines) + "\n"


def validate(body: str, *, urgency: str, config: Config | None = None) -> Decision:
    return Governance(config or default_config()).check_escalation(body, urgency=urgency)


def submit(
    *,
    title: str,
    body: str,
    urgency: str,
    config: Config | None = None,
    task_id: str | None = None,
) -> str:
    config = config or default_config()
    decision = validate(body, urgency=urgency, config=config)
    if not decision.allowed:
        raise MirrorError("; ".join(decision.reasons))
    mirror = IssueMirror(config)
    repo = mirror.board_repo
    label = config.governance.get("escalation", {}).get("label")
    if not label:
        raise MirrorError("governance escalation policy defines no issue label")
    marker = f"saturnin:escalation:{task_id}" if task_id else ""
    if marker:
        existing = _find_issue_by_marker(repo, marker)
        if existing:
            return existing
        comment = f"<!-- {marker} -->"
        if comment not in body:
            body = f"{comment}\n\n{body}"
    ensure_labels(repo, [str(label)])
    output = run_gh(
        [
            "issue", "create",
            "--repo", repo,
            "--title", title,
            "--body", body,
            "--label", str(label),
        ]
    )
    url = output.strip().splitlines()[-1].strip() if output.strip() else ""
    if not url:
        raise MirrorError("gh issue create returned no URL")
    return url


def submit_task_escalation(
    *,
    config: Config,
    board: Board,
    task_id: str,
    title: str,
    body: str,
    urgency: str,
    actor: str,
) -> str:
    board.path_for(task_id)
    lock_path = config.var_dir / "locks" / f"escalation-{task_id}"
    with file_lock(lock_path):
        with board.edit(task_id) as task:
            existing = _task_escalation_reference(task)
            if task.state == "blocked" and existing:
                return existing
            if task.state not in ("routed", "in_progress", "review"):
                raise BoardError(
                    f"task {task_id} cannot be blocked from state {task.state}; "
                    "escalation was not submitted"
                )
            url = submit(
                title=title,
                body=body,
                urgency=urgency,
                config=config,
                task_id=task_id,
            )
            Board._apply_transition(task, "blocked", actor=actor, note=f"escalated: {url}")
            return url


def _task_escalation_reference(task: Task) -> str:
    for entry in reversed(task.history):
        note = str(entry.get("note", ""))
        if note.startswith("escalated:"):
            return note.removeprefix("escalated:").strip()
    return ""


def _find_issue_by_marker(repo: str, marker: str) -> str | None:
    output = run_gh(
        [
            "issue",
            "list",
            "--repo",
            repo,
            "--search",
            marker,
            "--state",
            "open",
            "--json",
            "url",
            "--limit",
            "1",
        ]
    )
    return issue_search_url(output)
