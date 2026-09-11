# The work board

Everything Saturnin owns is represented as a task here. The local board is the
fast work queue and cache; mirrored GitHub Issues are the durable system of
record. Chat transcripts are neither.

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
| `kind` | `objective`, `epic`, `feature`, `task`, `pr-review`, `issue-review`, `automation`, `improvement` |
| `parent` | the container this work belongs to (`objective > epic > feature > task`) |
| `state` | `intake → routed → in_progress → review → done` (+ `blocked`, `cancelled`) |
| `priority` | `P0` drop everything … `P3` when idle |
| `role` / `unit` | the lead role and its permanent organizational unit, set by the router |
| `squad` | the ad-hoc crew for this task; assembled at dispatch, never a fixed team |
| `result_contract` | how the result comes back, so the CEO never waits (rule 9) |
| `issue` | the mirrored GitHub issue - the durable copy of this task (rule 8) |
| `repo` | the repository it concerns, if any |
| `branch` / `worktree` | where the work happens |
| `checkpoint` | timestamp of the latest checkpoint |
| `history` | every event with actor and timestamp |

## Hierarchy

Containers exist so that a hundred tasks stay legible, not so that they can be
managed. Only leaf work is ever dispatched.

```bash
saturnin task add "Widget platform" --kind epic
saturnin task add "Widget API" --kind feature --parent T-...
saturnin task add "Rate limit the write path" --parent T-... --dispatch
saturnin task tree            # the whole board, with roll-up progress per container
```

## Durability

Task files are gitignored: the board is state, not source. The durable copy is a
GitHub issue in the private board repository, kept in step by
`saturnin task sync --all --push` and the `saturnin-mirror` timer.
`saturnin doctor` fails while open tasks have no issue, so "it only exists on
that server" is a condition the system complains about rather than one you
discover after the disk dies. See [ADR-0001](../docs/adr/0001-system-of-record.md).

## Concurrency: several squads write here at once

Parallel worktrees mean parallel writes to the same board, so:

- Every write takes an exclusive `flock` on a `.lock` sidecar and lands through
  an atomic `os.replace`; readers take a shared lock. A half-written task file is
  therefore impossible.
- **Any read-modify-write must go through `Board.edit()`**, which holds the lock
  across the whole cycle:

  ```python
  with board.edit(task_id) as task:      # locked
      task.log("progress", actor="code-worker")
  ```

  The naive `get()` … mutate … `save()` sequence is a lost update waiting for a
  second squad, and is a review finding.
- Locks are per task, so two squads working on two tasks never contend.
- A lock that cannot be taken within ten seconds raises `LockTimeout` rather
  than blocking forever - a stuck lock is a bug to see, not to sleep on.
- One task, one branch, one worktree: workers never share a checkout, so the
  board is the only shared resource in the first place.

## Everyday commands

```bash
saturnin task add "<title>" --body "..." --label ops --dispatch
saturnin task list --open
saturnin task show <id>
saturnin task move <id> in_progress --actor code-worker --note "started"
saturnin task attach <id> --branch feature/x --worktree var/worktrees/feature__x
saturnin board metrics
saturnin task sync <id>            # preview the mirrored issue
saturnin task sync --all --push    # file/refresh them for real
```

Illegal state transitions are refused, so the board cannot quietly drift out of
sync with reality.
