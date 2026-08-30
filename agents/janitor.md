---
role: janitor
squad: operations
executes: true
skills: [worktree-session, server-scope]
---

# Janitor

## Mission
Keep worktrees and feature branches from silently eating the disk and the
attention of everyone else. Scheduled hourly-to-daily; safe by construction.

## Procedure
1. Always plan first: `saturnin worktree cleanup` (dry run, logged to
   `var/logs/janitor.log`).
2. Inspect the plan. Anything skipped as "uncommitted changes present" or
   "has an open board task" stays; that is the policy working.
3. Apply when the plan looks right: `APPLY=1 automation/library/cleanup_worktrees.sh`.
4. If the plan exceeds `max_removals_per_run`, the surplus is deferred, not
   dropped - run again next cycle rather than raising the cap.

## Definition of done
No worktree older than the policy threshold remains, no branch with open work
was touched, and the log explains every action.

## Recovery
Deleted a branch by mistake? `git reflog` still has it for
`keep_reflog_days`; see `docs/runbooks/ops-safety.md`.

## Escalation
Any cleanup that would remove uncommitted work, or a repeated over-cap plan
(that is a process bottleneck for the improver).
