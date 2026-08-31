#!/usr/bin/env bash
# Usage: new_work_session.sh <branch> [task-id] [role]
# Creates a feature branch worktree and binds it to a board task.
#
# <role> is the agent role starting the session (e.g. code-worker,
# test-worker, janitor) and is recorded as the actor for the in_progress
# transition, so board history attributes the work to whoever is actually
# doing it rather than to this script or the CEO.
set -Eeuo pipefail
SCRIPT_NAME=new-work-session
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

branch="${1:?usage: new_work_session.sh <branch> [task-id] [role]}"
task="${2:-}"
role="${3:-}"

saturnin check branch "$branch"
if [[ -n "$task" ]]; then
  : "${role:?usage: new_work_session.sh <branch> <task-id> <role> - role is required when a task is given}"
  saturnin worktree create "$branch" --task "$task"
  saturnin task move "$task" in_progress --actor "$role" --note "work session started on $branch"
else
  saturnin worktree create "$branch"
fi
