# The work board

Everything Saturnin owns is a task here. The board is the single source of truth
for state; chat transcripts are not.

```
board/tasks/T-YYYYMMDD-xxxxxx.json   one task, full history, gitignored runtime state
board/checkpoints/<task-id>.jsonl    append-only handoff checkpoints
board/reviews/<kind>-<subject>.jsonl append-only review verdicts
```

## Task shape

| Field | Meaning |
| --- | --- |
| `id` | `T-<date>-<random>`, stable forever |
| `title` / `body` | what and why, in the requester's words |
| `kind` | `task`, `pr-review`, `issue-review`, `automation`, `improvement` |
| `state` | `intake → routed → in_progress → review → done` (+ `blocked`, `cancelled`) |
| `priority` | `P0` drop everything … `P3` when idle |
| `role` / `squad` | who owns it, set by the router - never by hand |
| `repo` | the repository it concerns, if any |
| `branch` / `worktree` | where the work happens |
| `checkpoint` | timestamp of the latest checkpoint |
| `history` | every event with actor and timestamp |

## Everyday commands

```bash
saturnin task add "<title>" --body "..." --label ops --dispatch
saturnin task list --open
saturnin task show <id>
saturnin task move <id> in_progress --actor code-worker --note "started"
saturnin task attach <id> --branch feature/x --worktree var/worktrees/feature__x
saturnin board metrics
```

Illegal state transitions are refused, so the board cannot quietly drift out of
sync with reality. Runtime files are gitignored: the board is state, not source.
