# Skill: worktree-session

## Purpose
Give every parallel worker an isolated checkout on its own feature branch.

## Commands
- `automation/library/new_work_session.sh feature/<slug> [task-id] [role]` -
  `role` is the agent starting the session and is recorded as the actor for
  the task's `in_progress` transition; required whenever `task-id` is given.
- `saturnin worktree create <branch> [--task <id>]`
- `saturnin worktree list`
- `saturnin worktree cleanup [--apply]`

## Guarantees
- Branch names are validated against `policies/governance.yaml` before a
  worktree is created; protected branches are impossible to check out this way.
- Worktrees land under `var/worktrees/<branch-with-slashes-escaped>`.
- Cleanup behavior comes from `policies/cleanup.yaml`; the command logs every
  action with its reason.

## Refusals
- Any cleanup rejected by `policies/cleanup.yaml` or the policy-backed branch
  gate.
