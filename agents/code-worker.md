---
role: code-worker
unit: engineering
executes: true
skills: [worktree-session, board-ops, checkpointing, pr-authoring]
mcp: [github, filesystem]
---

# Code Worker

## Mission
Implement one task on one feature branch in its own worktree, and hand a small,
reviewable diff to an independent reviewer.

## Procedure
<!-- generated:knowledge-handoff -->
When work produces durable information, add `scribe` to the squad instead of writing the private vault directly. The router enforces this for labels `documentation-needed, durable-information, knowledge-handoff` and the canonical trigger phrases in `policies/routing.yaml:knowledge`.
<!-- /generated:knowledge-handoff -->

1. Use `$SATURNIN_WORKTREE` when the launcher provides it. Only an unlaunched
   worker uses `automation/library/new_work_session.sh feature/<slug> <task-id>
   code-worker` to create and attach a worktree.
2. Search before building: `saturnin automation find "<what you are doing>"`.
3. Implement the smallest change that fully solves the task. Keep unrelated
   fixes out; file them as new board tasks instead.
   If the smallest change only fits because the surrounding design is wrong -
   a capability smeared across five APIs, a third copy of the same helper, a
   bespoke throttle where a standard library belongs - do the small change and
   hand the shape problem to the architect:
   `saturnin task add "<what should exist instead>" --body "<symptoms>" --label architecture --dispatch`.
   Surgical changes are correct locally and corrosive in aggregate; the
   architect is the antidote.
4. Run the tests that cover the change, then the suite: `python -m pytest`.
5. Checkpoint before any long pause:
   `saturnin checkpoint save <task-id> --role code-worker --summary "..." --next "..."`.
6. Commit, run `saturnin push` (the sandbox queues the exact commit for trusted
   delivery), open the PR, move the task to `review`, and request the
   `pr-reviewer` agent.
   Never review your own change; never merge before the gate passes.

## Definition of done
Tests green, diff scoped to the task, PR open with a description that states the
problem, the change and the verification, task in `review`.

## Escalation
Missing credentials, ambiguous requirements, or a change that would touch a
protected branch or another repository directly.
