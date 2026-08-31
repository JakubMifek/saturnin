from __future__ import annotations

import pytest

from saturnin.board import Board
from saturnin.config import Config
from saturnin.routing import Router, RoutingError


def test_policy_is_healthy(config: Config) -> None:
    assert Router(config).validate_policy() == []


def test_keyword_routing(config: Config, board: Board) -> None:
    router = Router(config)
    task = board.create("Fix failing build in the deploy pipeline")
    assert router.resolve(task).role == "code-worker"
    docs = board.create("Update the runbook documentation")
    assert router.resolve(docs).role == "scribe"


def test_kind_routing(config: Config, board: Board) -> None:
    task = board.create("Review PR 12", kind="pr-review")
    route = Router(config).resolve(task)
    assert route.role == "pr-reviewer"
    assert route.priority == "P1"


def test_escalation_label_is_p0_and_never_ceo(config: Config, board: Board) -> None:
    task = board.create("Need a decision", labels=["escalation"])
    route = Router(config).resolve(task)
    assert route.escalate is True
    assert route.priority == "P0"
    assert route.role != "ceo"


def test_default_route(config: Config, board: Board) -> None:
    task = board.create("Zzzz unclassifiable blurb")
    assert Router(config).resolve(task).role == "chief-of-staff"


def test_dispatch_updates_task(config: Config, board: Board) -> None:
    task = board.create("Implement the widget")
    route = Router(config).dispatch(board, task)
    stored = board.get(task.id)
    assert stored.state == "routed"
    assert stored.role == route.role
    assert stored.unit == "engineering"
    # Squads are ad hoc; the rule only suggests a starting crew.
    assert stored.squad and stored.role in stored.squad
    # Rule 9: dispatch always agrees how the result comes back.
    assert stored.result_contract == route.result_contract
    assert stored.routed_at is not None
    assert stored.history[-2]["event"] == "dispatch"


def test_dispatch_preserves_updates_made_after_task_was_loaded(
    config: Config, board: Board
) -> None:
    stale = board.create("Implement the widget")
    with board.edit(stale.id) as current:
        current.body = "updated by another squad"

    Router(config).dispatch(board, stale)

    assert board.get(stale.id).body == "updated by another squad"


def test_dispatch_twice_is_refused(config: Config, board: Board) -> None:
    task = board.create("Implement the widget")
    router = Router(config)
    router.dispatch(board, task)
    with pytest.raises(Exception):
        router.dispatch(board, board.get(task.id))


def test_routing_to_ceo_is_rejected(config: Config, board: Board) -> None:
    router = Router(config)
    router.rules = [{"id": "bad", "when": {"kind": "task"}, "route": {"role": "ceo"}}]
    with pytest.raises(RoutingError, match="CEO never executes"):
        router.resolve(board.create("anything"))
    assert any("CEO" in p for p in router.validate_policy())


def test_unknown_role_is_rejected(config: Config, board: Board) -> None:
    router = Router(config)
    router.rules = [{"id": "bad", "when": {"kind": "task"}, "route": {"role": "ghost"}}]
    assert router.validate_policy()


def test_squad_is_assembled_per_task(config: Config, board: Board) -> None:
    task = board.create("Implement the widget")
    route = Router(config).dispatch(board, task, squad=["code-worker", "scribe"])
    assert route.squad  # the rule's suggestion is still reported
    assert board.get(task.id).squad == ["code-worker", "scribe"]


@pytest.mark.parametrize(
    ("squad", "message"),
    [(["ceo"], "CEO never executes"), (["ghost"], "unknown squad")],
)
def test_invalid_squad_override_is_rejected_before_board_mutation(
    config: Config, board: Board, squad: list[str], message: str
) -> None:
    task = board.create("Implement the widget")
    before = task.to_dict()

    with pytest.raises(RoutingError, match=message):
        Router(config).dispatch(board, task, squad=squad)

    assert board.get(task.id).to_dict() == before


def test_unknown_result_contract_is_rejected(config: Config) -> None:
    router = Router(config)
    with pytest.raises(RoutingError):
        router._build({"role": "code-worker", "result_contract": "telepathy"}, "bad")


def test_ceo_may_not_be_in_a_squad(config: Config) -> None:
    router = Router(config)
    with pytest.raises(RoutingError):
        router._build({"role": "code-worker", "squad": ["ceo"]}, "bad")
