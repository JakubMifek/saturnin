# Skill: board-ops

## Purpose
Create, inspect and move work on the centralised board.

## Commands
- `saturnin task add "<title>" [--body ...] [--label ...] [--repo ...]
  [--priority P0..P3] [--dispatch]`; review tasks also bind
  `--review-subject`, `--review-author`, and the reviewed head SHA or issue digest.
- `saturnin task list [--open] [--state S] [--role R] [--priority P]`
- `saturnin task show <id>` / `saturnin task move <id> <state> [--note ...]`
- `saturnin task attach <id> --branch feature/x --worktree <path>`
- `saturnin dispatch <id> | --all [--dry-run]`
- `saturnin board metrics | roles`

## Guarantees
- State changes are validated (`intake → routed → in_progress → review → done`);
  illegal transitions fail loudly instead of corrupting history.
- Every change appends to the task's history with actor and timestamp.

## Refusals
- Empty titles, unknown priorities, path-traversing task ids.
- Dispatching a task that is already in flight.
