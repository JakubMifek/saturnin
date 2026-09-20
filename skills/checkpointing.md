# Skill: checkpointing

## Purpose
Survive interruption: rate limits, restarts, a week of waiting, or a handoff to
a different agent.

## Commands
- `saturnin checkpoint save <task-id> --role <role> --summary "..." --next "..." [--blocker ...] [--artifact ...] [--branch ...] [--worktree ...] [--resume-after <iso8601>]`
- `saturnin checkpoint resume <task-id>`

## Guarantees
- A checkpoint always carries task, role, a state summary and next steps;
  incomplete checkpoints are rejected.
- `resume` renders a handoff note that a fresh agent can start from with no
  other context.
- Checkpoints are append-only; the latest one wins, the history stays.

## When to checkpoint
Before any pause longer than a few minutes, before handing work over, before a
risky step, and immediately when blocked.
