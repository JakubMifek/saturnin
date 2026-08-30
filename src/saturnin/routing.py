"""Dispatch engine.

The router is intentionally boring: first matching rule wins, no deliberation,
no model call. Routing must be cheap because CEO time is the scarcest resource
in the system.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .board import Board, BoardError, Task
from .config import Config, default_config


class RoutingError(RuntimeError):
    pass


@dataclass(frozen=True)
class Route:
    role: str
    squad: str | None
    priority: str
    rule: str
    escalate: bool = False


class Router:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or default_config()
        self.policy: dict[str, Any] = self.config.routing
        self.roles: dict[str, dict[str, Any]] = self.policy.get("roles", {})
        self.rules: list[dict[str, Any]] = self.policy.get("rules", [])
        self.ceo_role: str = self.config.governance.get("delegation", {}).get("ceo_role", "ceo")

    # -- matching ------------------------------------------------------
    @staticmethod
    def _haystack(task: Task) -> str:
        return " ".join([task.title, task.body, " ".join(task.labels)]).lower()

    def _matches(self, when: dict[str, Any], task: Task) -> bool:
        if not when:
            return False
        text = self._haystack(task)
        labels = {label.lower() for label in task.labels}
        if "kind" in when and task.kind != when["kind"]:
            return False
        if "any_label" in when and not labels & {str(v).lower() for v in when["any_label"]}:
            return False
        if "any_keyword" in when and not any(
            str(word).lower() in text for word in when["any_keyword"]
        ):
            return False
        return True

    def resolve(self, task: Task) -> Route:
        """Pick a route for ``task`` without mutating it."""
        for rule in self.rules:
            if self._matches(rule.get("when", {}), task):
                return self._build(rule.get("route", {}), rule.get("id", "?"))
        default = dict(self.policy.get("default_route", {}))
        if not default.get("role"):
            raise RoutingError("routing policy has no usable default_route")
        return self._build(default, "default")

    def _build(self, route: dict[str, Any], rule_id: str) -> Route:
        role = route.get("role")
        if role not in self.roles:
            raise RoutingError(f"rule {rule_id!r} points at unknown role {role!r}")
        if role == self.ceo_role:
            raise RoutingError(
                f"rule {rule_id!r} routes work to the CEO; the CEO never executes"
            )
        if not self.roles[role].get("executes", True):
            raise RoutingError(f"role {role!r} is not an executing role")
        return Route(
            role=role,
            squad=self.roles[role].get("squad"),
            priority=route.get("priority", "P2"),
            rule=rule_id,
            escalate=bool(route.get("escalate", False)),
        )

    # -- dispatch ------------------------------------------------------
    def dispatch(self, board: Board, task: Task, *, actor: str = "ceo") -> Route:
        """Assign ``task`` to a role and move it to ``routed``."""
        if task.state not in ("intake", "blocked"):
            raise BoardError(f"task {task.id} is not dispatchable from state {task.state}")
        route = self.resolve(task)
        task.role = route.role
        task.squad = route.squad
        task.priority = route.priority
        task.log(
            "dispatch",
            actor=actor,
            role=route.role,
            rule=route.rule,
            escalate=route.escalate,
        )
        # The first dispatch is what dispatch latency measures; a re-dispatch
        # after "blocked" must not reset it.
        task.routed_at = task.routed_at or task.history[-1]["ts"]
        board.transition(task, "routed", actor=actor, note=f"rule={route.rule}")
        return route

    def validate_policy(self) -> list[str]:
        """Return a list of problems with the routing policy (empty == healthy)."""
        problems: list[str] = []
        seen: set[str] = set()
        for rule in self.rules:
            rule_id = rule.get("id", "?")
            if rule_id in seen:
                problems.append(f"duplicate rule id: {rule_id}")
            seen.add(rule_id)
            if not rule.get("when"):
                problems.append(f"rule {rule_id} has no match condition")
            try:
                self._build(rule.get("route", {}), rule_id)
            except RoutingError as exc:
                problems.append(str(exc))
        try:
            self._build(dict(self.policy.get("default_route", {})), "default")
        except RoutingError as exc:
            problems.append(str(exc))
        if self.ceo_role not in self.roles:
            problems.append(f"CEO role {self.ceo_role!r} missing from role catalog")
        elif self.roles[self.ceo_role].get("executes", False):
            problems.append("CEO role is marked as executing; delegation-first is violated")
        return problems
