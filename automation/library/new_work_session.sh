#!/usr/bin/env bash
# Usage: new_work_session.sh <branch> [task-id]
# Creates a feature branch worktree and binds it to a board task.
set -Eeuo pipefail
SCRIPT_NAME=new-work-session
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

branch="${1:?usage: new_work_session.sh <branch> [task-id]}"
task="${2:-}"

saturnin check branch "$branch"
if [[ -n "$task" ]]; then
  saturnin worktree create "$branch" --task "$task"
  saturnin task move "$task" in_progress --note "work session started on $branch"
else
  saturnin worktree create "$branch"
fi
