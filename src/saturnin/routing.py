"""Dispatch engine.

The router is intentionally boring: first matching rule wins, no deliberation,
no model call. Routing must be cheap because CEO time is the scarcest resource
in the system.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Sequence

from .board import PRIORITIES, Board, BoardError, Task
from .config import Config, default_config


class RoutingError(RuntimeError):
    pass


@dataclass(frozen=True)
class Route:
    role: str
    #: Permanent organizational unit of the lead role.
    unit: str | None
    priority: str
    rule: str
    escalate: bool = False
    #: Ad-hoc crew suggested for this task; the chief of staff may amend it.
    squad: tuple[str, ...] = ()
    #: How the result comes back, so that the CEO never waits for the worker.
    result_contract: str = "board-callback"


class Router:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or default_config()
        self.policy: dict[str, Any] = self.config.routing
        self.roles: dict[str, dict[str, Any]] = self.policy.get("roles", {})
        self.rules: list[dict[str, Any]] = self.policy.get("rules", [])
        delegation = self.config.governance.get("delegation", {})
        self.ceo_role: str = delegation.get("ceo_role", "ceo")
        self.result_contracts: list[str] = list(delegation.get("result_contracts", []))
        self.default_result_contract: str = self.policy.get(
            "default_result_contract",
            delegation.get("default_result_contract", "board-callback"),
        )

    # -- matching ------------------------------------------------------
    @staticmethod
    def _haystack(task: Task) -> str:
        return " ".join([task.title, task.body, " ".join(task.labels)]).lower()

    @staticmethod
    def _has_keyword(text: str, keyword: object) -> bool:
        parts = str(keyword).lower().split()
        if not parts:
            return False
        pattern = (
            r"(?<![\w-])"
            + r"\s+".join(re.escape(part) for part in parts)
            + r"(?![\w-])"
        )
        return bool(re.search(pattern, text))

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
            self._has_keyword(text, word) for word in when["any_keyword"]
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
        squad = tuple(route.get("squad", (role,))) or (role,)
        self._validate_squad(squad, f"rule {rule_id!r}")
        contract = route.get("result_contract", self.default_result_contract)
        if self.result_contracts and contract not in self.result_contracts:
            raise RoutingError(
                f"rule {rule_id!r} uses unknown result contract {contract!r}; "
                f"expected one of {self.result_contracts}"
            )
        return Route(
            role=role,
            unit=self.roles[role].get("unit"),
            priority=route.get("priority", "P2"),
            rule=rule_id,
            escalate=bool(route.get("escalate", False)),
            squad=squad,
            result_contract=contract,
        )

    def _validate_squad(self, squad: Sequence[str], source: str) -> None:
        unknown = [member for member in squad if member not in self.roles]
        if unknown:
            raise RoutingError(f"{source} suggests unknown squad members: {unknown}")
        if self.ceo_role in squad:
            raise RoutingError(
                f"{source} puts the CEO in a squad; the CEO never executes"
            )

    # -- dispatch ------------------------------------------------------
    def dispatch(
        self,
        board: Board,
        task: Task,
        *,
        actor: str | None = None,
        squad: Sequence[str] | None = None,
    ) -> Route:
        """Assign ``task`` to a role and move it to ``routed``.

        ``squad`` overrides the rule's suggested crew: squads are assembled per
        task, not fixed teams.
        """
        # Fall back to the configured CEO role so audit trails are consistent
        # even if the policy ever renames that role.
        effective_actor = actor if actor is not None else self.ceo_role
        if squad is not None:
            self._validate_squad(squad, "dispatch override")
        with board.edit(task.id) as current:
            if current.state not in ("intake", "blocked"):
                raise BoardError(
                    f"task {current.id} is not dispatchable from state {current.state}"
                )
            route = self.resolve(current)
            current.role = route.role
            current.unit = route.unit
            current.squad = list(squad or route.squad)
            # A pre-set priority (P0 incidents, discovery's own priority mapping)
            # reflects urgency already known at intake; a rule must never
            # silently downgrade it, only raise it.
            if PRIORITIES.index(route.priority) < PRIORITIES.index(current.priority):
                current.priority = route.priority
            # Rule 9: agree up front how the result comes back. Saturnin dispatches
            # and moves on; it never blocks on a worker.
            current.result_contract = route.result_contract
            current.log(
                "dispatch",
                actor=effective_actor,
                role=route.role,
                rule=route.rule,
                escalate=route.escalate,
                squad=",".join(current.squad),
                result_contract=route.result_contract,
            )
            # The first dispatch is what dispatch latency measures; a re-dispatch
            # after "blocked" must not reset it.
            current.routed_at = current.routed_at or current.history[-1]["ts"]
            current.state = "routed"
            current.log("state:routed", actor=effective_actor, note=f"rule={route.rule}")
        task.__dict__.update(current.__dict__)
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
