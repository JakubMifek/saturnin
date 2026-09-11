# Checkpoint, handoff and delayed resume

Long sessions end badly: context runs out, a rate limit hits, a dependency
arrives next week. A checkpoint is the minimum another agent needs to continue
without archaeology.

## Save one

```bash
saturnin checkpoint save <task-id> \
  --role code-worker \
  --summary "Migrated 3 of 7 tables; the FK on orders needs a data backfill." \
  --next "backfill orders.customer_id" --next "migrate tables 4-7" \
  --blocker "needs a maintenance window" \
  --artifact "var/worktrees/feature__migration/notes.md" \
  --branch feature/migration \
  --resume-after 2026-09-01T06:00:00+00:00
```

Required: task, role, summary, at least one next step. Incomplete checkpoints
are refused - a checkpoint nobody can act on is worse than none.

## Resume

```bash
saturnin checkpoint resume <task-id>
```

Prints the handoff note: state, next steps as a checklist, blockers, artifacts
and the earliest resume time. `saturnin run` gives the fresh agent **that note
plus the task body** - not the old session's transcript.

## Rules of thumb

| Situation | Action |
| --- | --- |
| Pause longer than a few minutes | checkpoint |
| Handing over to another role | checkpoint, then move the task |
| Blocked on a human | checkpoint with `--blocker`, escalate, move to `blocked` |
| Waiting for a date/event | checkpoint with `--resume-after` |
| Before a risky step | checkpoint, so the retry starts from a known point |

## Delayed resume

`--resume-after` records the earliest sensible restart. The
`saturnin-resume.timer` runs `saturnin checkpoint sweep`, which launches due
tasks once and leaves future checkpoints alone.

Checkpoints are append-only: `saturnin checkpoint resume` shows the latest,
`board/checkpoints/<task-id>.jsonl` keeps the whole story.
