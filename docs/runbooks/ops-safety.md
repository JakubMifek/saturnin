# Ops and safety runbook

## Scope on the Debian host (rule 7)

The canonical privilege, command, service, scheduling and filesystem limits are
in [`policies/server_scope.yaml`](../../policies/server_scope.yaml). Do not copy
those values into a runbook: validate every exact planned command against the
current policy first.

```bash
saturnin check command "<exact command>"
saturnin check command "<exact package command>" --service "<dedicated service>"
```

Exit code 0 allows the command and exit code 2 denies it. A denial is final.

## Scheduled workers

```bash
systemctl --user list-timers 'saturnin-*'
systemctl --user status saturnin-janitor.service
journalctl --user -u saturnin-janitor.service -n 100
tail -n 50 var/logs/janitor.log
```

Disable a misbehaving worker: `systemctl --user disable --now saturnin-<name>.timer`.

## Cleanup safety model

The janitor is dry-run by default and refuses to remove:

- worktrees with uncommitted changes,
- worktrees or branches attached to an open board task,
- protected branches (`main`, `master`, `release`),
- locked worktrees and paths matching `keep_globs`,
- unmerged branches (reported only, never deleted).

It also caps removals per run (`max_removals_per_run`); the surplus is deferred
to the next run rather than silently dropped. Every action is logged with its
reason in `var/logs/janitor.log`.

```bash
saturnin worktree cleanup            # plan only
saturnin worktree cleanup --apply    # execute the plan
```

## Recovery

**A branch was deleted by mistake**

```bash
git reflog | grep <branch>            # find the last commit of the branch
git branch <branch> <sha>             # recreate it
```

The reflog is kept for `keep_reflog_days` (90) - do not run `git gc --prune=now`
while a recovery is in question.

**A worktree directory disappeared but git still lists it**

```bash
git worktree prune
```

**A worktree was removed with unfinished work**

The commits still exist if they were committed: `git reflog` on the branch, or
`git fsck --lost-found` for dangling commits. Uncommitted changes are gone -
which is why the janitor never touches a dirty worktree.

**The board looks wrong**

Task files are plain JSON under `board/tasks/`. Fix by hand only as a last
resort, and record what you did in the task history. Never edit a task while a
worker may be running: use `saturnin task move`/`attach`, which lock the file.
A stray `*.lock` sidecar is harmless - locks are advisory and released when the
process exits.

**The board is gone (disk loss, fresh server)**

The durable copy is the mirrored GitHub issues in the private board repository
([ADR-0001](../adr/0001-system-of-record.md)). Reinstall with
`scripts/bootstrap.sh`, then rebuild the open tasks from
`gh issue list --repo <board-repo> --label "saturnin:state/in_progress"` and the
sibling state labels. Anything that was never mirrored is lost - which is what
`saturnin doctor` complains about every time it runs.

**Everything is on fire**

1. `systemctl --user stop 'saturnin-*.timer'` - stop the schedulers.
2. `saturnin task list --open` - see what is in flight.
3. Escalate with `saturnin escalate ... --urgency critical --push`.
4. Nothing merges while the gates are unavailable; that is the intended failure
   mode.

## Backups

Worth a nightly copy: `board/`, `policies/`, `var/reports/`, `var/logs/`.
`var/worktrees/` is reproducible and needs no backup. The board additionally
mirrors itself to GitHub every fifteen minutes (`saturnin-mirror.timer`), which
is the backup that survives losing the machine entirely.

## Making this repository public

The engine is meant to be public; the operational detail is not
([ADR-0002](../adr/0002-repository-topology.md)). Before flipping visibility:

1. `git log -p | grep -iE "token|secret|password|api[_-]?key"` - history, not
   just the working tree.
2. Confirm nothing under `board/tasks/`, `board/checkpoints/`, `board/reviews/`
   or `var/` was ever committed: `git log --all --name-only -- board var`.
3. `saturnin doctor` exits 0 and `pre-commit run --all-files` is clean.
4. Check `policies/*.yaml` for hostnames, paths under `/home/<someone>`,
   internal URLs and repository names that should stay private.
5. Move anything private that is left into the notes or board repository, then
   make the switch. If something was leaked, rotate first, rewrite second.
