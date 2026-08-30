# Skill: worktree-session

## Purpose
Give every parallel worker an isolated checkout on its own feature branch.

## Commands
- `automation/library/new_work_session.sh feature/<slug> [task-id]`
- `saturnin worktree create <branch> [--base main] [--task <id>]`
- `saturnin worktree list`
- `saturnin worktree cleanup [--apply]`

## Guarantees
- Branch names are validated against `policies/governance.yaml` before a
  worktree is created; protected branches are impossible to check out this way.
- Worktrees land under `var/worktrees/<branch-with-slashes-escaped>`.
- Cleanup is a dry run unless `--apply` is given, is capped per run, and logs
  every action with its reason.

## Refusals
- Removing a worktree with uncommitted changes or an open board task.
- Deleting unmerged branches (they are reported, never removed).
