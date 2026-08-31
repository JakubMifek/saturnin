"""Governance gates.

Every irreversible action (push, merge, issue submission, server command) has to
pass through here first. The rules themselves live in
``policies/governance.yaml`` and ``policies/server_scope.yaml``.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from .config import Config, default_config
from .review import ReviewRecord


@dataclass
class Decision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.allowed

    @classmethod
    def ok(cls, *reasons: str) -> "Decision":
        return cls(True, list(reasons))

    @classmethod
    def deny(cls, *reasons: str) -> "Decision":
        return cls(False, list(reasons))


class Governance:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or default_config()
        self.policy: dict[str, Any] = self.config.governance
        self.git: dict[str, Any] = self.policy.get("git", {})
        self.review: dict[str, Any] = self.policy.get("review", {})
        self.autonomy: dict[str, Any] = self.policy.get("autonomy", {})
        self.escalation: dict[str, Any] = self.policy.get("escalation", {})
        self.delegation: dict[str, Any] = self.policy.get("delegation", {})
        self.tracking: dict[str, Any] = self.policy.get("tracking", {})

    # -- branches ------------------------------------------------------
    @property
    def default_branch(self) -> str:
        return self.git.get("default_branch", "main")

    @property
    def protected_branches(self) -> list[str]:
        return list(self.git.get("protected_branches", [self.default_branch]))

    def check_branch(self, branch: str) -> Decision:
        """Rule 1 + 2: never work on the default branch, always use a feature branch."""
        branch = branch.strip()
        if not branch:
            return Decision.deny("branch name is empty")
        if branch in self.protected_branches:
            return Decision.deny(f"'{branch}' is protected; Saturnin never writes to it")
        pattern = self.git.get("branch_name_pattern")
        if pattern and not re.match(pattern, branch):
            prefixes = ", ".join(self.git.get("branch_prefixes", []))
            return Decision.deny(
                f"'{branch}' does not match {pattern} (expected one of: {prefixes})"
            )
        return Decision.ok(f"'{branch}' is an acceptable feature branch")

    # -- reviews -------------------------------------------------------
    def _review_gate(
        self,
        records: Sequence[ReviewRecord],
        author: str,
        settings: dict[str, Any],
        subject: str,
    ) -> Decision:
        reasons: list[str] = []
        approvals = [r for r in records if r.verdict == "approved"]
        blocking = [r for r in records if r.verdict in ("changes_requested", "rejected")]
        if blocking:
            return Decision.deny(
                f"{subject}: {len(blocking)} blocking review(s) outstanding: "
                + ", ".join(f"{r.reviewer}={r.verdict}" for r in blocking)
            )
        if settings.get("independent", True) and not settings.get("author_may_review", False):
            self_reviews = [r for r in approvals if r.reviewer == author]
            if self_reviews:
                return Decision.deny(f"{subject}: author {author!r} may not review their own work")
        if settings.get("zero_context", False):
            approvals = [r for r in approvals if r.zero_context]
            if not approvals:
                return Decision.deny(f"{subject}: a zero-context reviewer approval is required")
        minimum = int(settings.get("min_approvals", 1))
        if len(approvals) < minimum:
            return Decision.deny(
                f"{subject}: {len(approvals)}/{minimum} independent approval(s)"
            )
        reasons.append(f"{subject}: {len(approvals)} independent approval(s)")
        return Decision(True, reasons)

    def merge_allowed(
        self, *, repo: str, author: str, records: Iterable[ReviewRecord]
    ) -> Decision:
        """Rule 3 + 4: merge only after an independent zero-context review."""
        records = [r for r in records if r.kind == "pr"]
        settings = self.review.get("pr", {})
        if settings.get("required", True):
            decision = self._review_gate(records, author, settings, "pr review")
            if not decision.allowed:
                return decision
            reasons = list(decision.reasons)
        else:  # pragma: no cover - defensive
            reasons = ["pr review not required by policy"]
        if repo == self.autonomy.get("self_repo"):
            if not self.autonomy.get("self_repo_autonomous_merge", False):
                return Decision.deny(f"{repo}: autonomous merge disabled by policy")
            reasons.append(f"{repo}: autonomous merge allowed after review")
            return Decision(True, reasons)
        return Decision.deny(
            f"{repo}: Saturnin does not merge in managed repos; open an issue or PR for a human"
        )

    def issue_submission_allowed(
        self, *, repo: str, author: str, records: Iterable[ReviewRecord]
    ) -> Decision:
        """Rule 5: issues for managed repos need an independent issue review."""
        records = [r for r in records if r.kind == "issue"]
        if repo == self.autonomy.get("self_repo"):
            return Decision.ok(f"{repo}: own repository, issue may be filed directly")
        if not self.autonomy.get("external_repos_allow_issue_creation", True):
            return Decision.deny(f"{repo}: issue creation is disabled by policy")
        settings = dict(self.review.get("issue", {}))
        if not settings.get("required_for_external_repos", True):  # pragma: no cover
            return Decision.ok(f"{repo}: issue review not required")
        settings.setdefault("min_approvals", 1)
        return self._review_gate(records, author, settings, "issue review")

    def push_allowed(self, *, repo: str, branch: str) -> Decision:
        branch_check = self.check_branch(branch)
        if not branch_check.allowed:
            return branch_check
        if repo != self.autonomy.get("self_repo") and not self.autonomy.get(
            "external_repos_allow_direct_push", False
        ):
            return Decision.deny(f"{repo}: direct pushes to managed repos are not allowed")
        return branch_check

    # -- escalation ----------------------------------------------------
    def check_escalation(self, body: str, *, urgency: str) -> Decision:
        reasons: list[str] = []
        missing = [
            section
            for section in self.escalation.get("required_sections", [])
            if section.replace("_", " ") not in body.lower()
        ]
        if missing:
            return Decision.deny(f"escalation is missing section(s): {', '.join(missing)}")
        levels = self.escalation.get("urgency_levels", [])
        if levels and urgency not in levels:
            return Decision.deny(f"unknown urgency {urgency!r}; expected one of {levels}")
        mention = self.escalation.get("mention")
        if mention and mention.lower() not in body.lower():
            return Decision.deny(f"escalation must mention {mention}")
        reasons.append("escalation is well formed")
        return Decision(True, reasons)

    # -- server scope --------------------------------------------------
    def check_server_command(self, command: str) -> Decision:
        """Rule 7: non-root only, apt/systemctl only for Saturnin-dedicated services."""
        scope = self.config.server_scope
        try:
            parts = shlex.split(command)
        except ValueError as exc:
            return Decision.deny(f"unparsable command: {exc}")
        if not parts:
            return Decision.deny("empty command")
        user = scope.get("user", {})
        for forbidden in user.get("forbidden_prefixes", []):
            if parts[0] == forbidden:
                return Decision.deny(f"privilege escalation via {forbidden!r} is not allowed")
        binary = parts[0].rsplit("/", 1)[-1]
        services = scope.get("services", {})
        packages = scope.get("packages", {})
        if binary == "apt" or binary.startswith("apt-"):
            if not packages.get("apt_allowed", False):
                return Decision.deny("apt is not allowed")
            sub = parts[1] if len(parts) > 1 else ""
            allowed = packages.get("apt_allowed_subcommands", [])
            if allowed and sub not in allowed:
                return Decision.deny(f"apt {sub!r} is not in the allow list {allowed}")
            return Decision.ok(
                "apt allowed only when installing dependencies of a Saturnin-dedicated service"
            )
        if binary == "systemctl":
            if not services.get("systemctl_allowed", False):
                return Decision.deny("systemctl is not allowed")
            raw_args = parts[1:]
            user_scope = "--user" in raw_args
            if services.get("scheduling_scope") == "user" and not user_scope:
                return Decision.deny("systemctl must use --user scope")
            args = [p for p in raw_args if p != "--user" and not p.startswith("-")]
            sub = args[0] if args else ""
            allowed = services.get("allowed_subcommands", [])
            if allowed and sub not in allowed:
                return Decision.deny(f"systemctl {sub!r} is not in the allow list {allowed}")
            units = args[1:]
            prefix = services.get("unit_prefix", "saturnin-")
            bad = [unit for unit in units if not unit.startswith(prefix)]
            if bad:
                return Decision.deny(
                    f"systemctl may only touch {prefix}* units, got: {', '.join(bad)}"
                )
            if not units and sub not in ("list-timers", "status"):
                return Decision.deny("systemctl needs an explicit Saturnin unit name")
            return Decision.ok("systemctl limited to Saturnin-dedicated units")
        return Decision.ok(f"{binary}: no elevated capability required")

    # -- delegation ----------------------------------------------------
    @property
    def result_contracts(self) -> list[str]:
        return list(self.delegation.get("result_contracts", []))

    def check_result_contract(self, contract: str | None) -> Decision:
        """Rule 9: a dispatch without an agreed result contract would force the
        CEO to wait for the worker, which is forbidden."""
        if self.delegation.get("ceo_may_wait_for_workers", False):
            return Decision.ok("policy permits waiting (not recommended)")
        allowed = self.result_contracts
        if not contract:
            return Decision.deny(
                "no result contract: the CEO would have to wait for the worker. "
                f"Pick one of: {', '.join(allowed)}"
            )
        if allowed and contract not in allowed:
            return Decision.deny(f"unknown result contract {contract!r}; expected one of {allowed}")
        return Decision.ok(f"results arrive via {contract}; the CEO does not wait")

    def mirror_required(self) -> bool:
        """Rule 8: tasks are mirrored as issues so local loss is survivable."""
        return bool(self.tracking.get("mirror_tasks_as_issues", False))

    # -- self check ----------------------------------------------------
    def audit(self) -> list[str]:
        problems: list[str] = []
        if not self.protected_branches:
            problems.append("no protected branches configured")
        if self.default_branch not in self.protected_branches:
            problems.append("the default branch must be protected")
        if not self.review.get("pr", {}).get("required", False):
            problems.append("PR review is not required")
        if self.review.get("pr", {}).get("author_may_review", False):
            problems.append("PR authors are allowed to review themselves")
        if self.policy.get("delegation", {}).get("ceo_may_execute", False):
            problems.append("CEO is allowed to execute work; delegation-first is violated")
        if self.config.server_scope.get("user", {}).get("allow_root", False):
            problems.append("server scope allows root")
        if self.delegation.get("ceo_may_wait_for_workers", False):
            problems.append("CEO is allowed to wait for workers; dispatch must be non-blocking")
        if not self.result_contracts:
            problems.append("no result contracts defined; dispatch cannot be non-blocking")
        if self.mirror_required() and not self.config.policy("repos").get("repos", {}).get("board"):
            problems.append("task mirroring is on but policies/repos.yaml names no board repo")
        return problems
