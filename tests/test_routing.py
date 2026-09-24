from __future__ import annotations

import pytest

from saturnin.board import Board, BoardError
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


def test_keyword_routing_uses_word_boundaries(config: Config, board: Board) -> None:
    router = Router(config)
    task = board.create("Download the release artifact")
    assert router.resolve(task).role == "chief-of-staff"
    compound = board.create("Plan a down-time maintenance window")
    assert router.resolve(compound).role == "chief-of-staff"
    incident = board.create("Production is down")
    assert router.resolve(incident).role == "code-worker"


def test_kind_routing(config: Config, board: Board) -> None:
    task = board.create("Review PR 12", kind="pr-review")
    route = Router(config).resolve(task)
    assert route.role == "pr-reviewer"
    assert route.priority == "P1"


@pytest.mark.parametrize(
    ("kind", "role"),
    [("pr-review", "pr-reviewer"), ("issue-review", "issue-reviewer")],
)
def test_review_kind_routing_precedes_incident_keywords(
    config: Config, board: Board, kind: str, role: str
) -> None:
    task = board.create("Review failing incident", kind=kind)
    assert Router(config).resolve(task).role == role


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
    # Rule 8: dispatch always agrees how the result comes back.
    assert stored.result_contract == route.result_contract
    assert stored.routed_at is not None
    assert stored.history[-2]["event"] == "dispatch"


def test_dispatch_never_downgrades_a_preset_priority(
    config: Config, board: Board
) -> None:
    # A P0 incident (or a discovery-mapped priority) must survive dispatch even
    # if the matched rule's own priority is less urgent (rule 8: never silently
    # downgrade urgent work).
    task = board.create("Update the runbook documentation", priority="P0")
    Router(config).dispatch(board, task)
    assert board.get(task.id).priority == "P0"


def test_dispatch_still_raises_priority_when_rule_is_more_urgent(
    config: Config, board: Board
) -> None:
    task = board.create("Need a decision", labels=["escalation"], priority="P3")
    route = Router(config).dispatch(board, task)
    assert route.priority == "P0"
    assert board.get(task.id).priority == "P0"


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
    with pytest.raises(BoardError):
        router.dispatch(board, board.get(task.id))


def test_dispatch_rejects_container_kinds(config: Config, board: Board) -> None:
    task = board.create("Platform roadmap", kind="epic")
    with pytest.raises(BoardError, match="container"):
        Router(config).dispatch(board, task)


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
    "text",
    [
        "Implement cache ownership and record the decision",
        "Implement publication of the investigation result",
        "Implement export of this durable information",
    ],
)
def test_durable_information_automatically_includes_scribe(
    config: Config, board: Board, text: str
) -> None:
    task = board.create(text)

    route = Router(config).dispatch(board, task, squad=["code-worker"])

    assert route.role == "code-worker"
    assert board.get(task.id).squad == ["code-worker", "scribe"]


def test_private_notes_changes_route_only_to_scribe_with_reviewer(
    config: Config, board: Board
) -> None:
    task = board.create("Apply synthetic vault bootstrap", labels=["vault-change"])

    route = Router(config).dispatch(board, task)

    assert route.role == "scribe"
    assert route.result_contract == "pr-gate"
    assert board.get(task.id).squad == ["scribe", "pr-reviewer"]


def test_private_notes_change_rejects_non_scribe_lead(
    config: Config, board: Board
) -> None:
    task = board.create("Apply public bootstrap", labels=["notes-write"])

    with pytest.raises(RoutingError, match="only be led"):
        Router(config).resolve(task, lead_role="code-worker")


def test_unlabelled_notes_repository_task_routes_only_to_scribe(
    config: Config, board: Board
) -> None:
    task = board.create(
        "Apply repository bootstrap",
        repo=config.policy("repos")["repos"]["notes"]["slug"],
    )

    route = Router(config).dispatch(board, task)

    assert route.role == "scribe"
    assert route.rule == "private-notes-change"
    assert board.get(task.id).squad == ["scribe", "pr-reviewer"]


@pytest.mark.parametrize("lead_role", ["code-worker", "bootstrap-worker"])
def test_notes_repository_rejects_lead_overrides(
    config: Config, board: Board, lead_role: str
) -> None:
    task = board.create(
        "Apply managed repository manifest",
        repo=config.policy("repos")["repos"]["notes"]["slug"].upper(),
    )
    additional_roles = (
        {"bootstrap-worker": {"unit": "engineering", "executes": True}}
        if lead_role == "bootstrap-worker"
        else None
    )

    with pytest.raises(RoutingError, match="only be led"):
        Router(config).resolve(
            task,
            lead_role=lead_role,
            additional_roles=additional_roles,
        )


def test_notes_repository_squad_override_cannot_remove_scribe_lead(
    config: Config, board: Board
) -> None:
    task = board.create(
        "Apply generic bootstrap",
        repo=config.policy("repos")["repos"]["notes"]["slug"],
    )

    route = Router(config).dispatch(board, task, squad=["code-worker"])

    assert route.role == "scribe"
    assert board.get(task.id).role == "scribe"
    assert board.get(task.id).squad == ["code-worker", "scribe", "pr-reviewer"]


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


def test_dispatch_default_actor_uses_configured_ceo_role(
    config: Config, board: Board
) -> None:
    """dispatch() must stamp the configured ceo_role, not the hardcoded literal 'ceo'."""
    router = Router(config)
    original_role = router.ceo_role
    router.ceo_role = "chief"
    task = board.create("Implement something")
    router.dispatch(board, task)
    stored = board.get(task.id)
    dispatch_events = [e for e in stored.history if e["event"] == "dispatch"]
    assert dispatch_events, "dispatch event not recorded"
    assert dispatch_events[-1]["actor"] == "chief"
    # Restore so the fixture stays clean.
    router.ceo_role = original_role


def test_dispatch_accepts_explicit_actor(config: Config, board: Board) -> None:
    """Caller-supplied actor (e.g., 'discovery') overrides the default."""
    task = board.create("Fix a build issue")
    Router(config).dispatch(board, task, actor="discovery")
    stored = board.get(task.id)
    dispatch_events = [e for e in stored.history if e["event"] == "dispatch"]
    assert dispatch_events[-1]["actor"] == "discovery"


def test_relabel_and_reroute_updates_already_routed_task_atomically(
    config: Config, board: Board
) -> None:
    task = board.create("Needs classification")
    router = Router(config)
    router.dispatch(board, task)

    route = router.relabel_and_reroute(
        board,
        task.id,
        labels=["fix"],
        actor="chief-of-staff",
    )

    stored = board.get(task.id)
    assert route.role == "code-worker"
    assert stored.state == "routed"
    assert stored.role == "code-worker"
    assert "fix" in stored.labels
    assert stored.history[-2]["event"] == "reroute"
    assert stored.history[-2]["actor"] == "chief-of-staff"
