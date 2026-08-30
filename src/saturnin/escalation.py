"""Human escalation (rule 6).

Saturnin never blocks silently. When it cannot proceed it produces a GitHub
issue body with a checklist, an urgency and explicit unblock criteria.
"""

from __future__ import annotations

from typing import Iterable

from .config import Config, default_config
from .governance import Decision, Governance


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
