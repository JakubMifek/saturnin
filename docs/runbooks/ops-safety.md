# Ops and safety runbook

## Scope on the Debian host (rule 7)

- Non-root only. `sudo`, `su`, `doas`, `pkexec` are refused by
  `saturnin check command`, and that refusal is final.
- `apt install|update|list|show` only, and only for dependencies of a
  Saturnin-dedicated service.
- `systemctl` only for `saturnin-*` units; scheduling only through user-scope
  timers or the Saturnin user's crontab.
- Writes stay under `/home/saturnin`.

Check anything unusual first:

```bash
saturnin check command "systemctl --user restart saturnin-janitor.timer"   # 0
saturnin check command "sudo apt install nginx"                            # 2
```

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
resort, and record what you did in the task history.

**Everything is on fire**

1. `systemctl --user stop 'saturnin-*.timer'` - stop the schedulers.
2. `saturnin task list --open` - see what is in flight.
3. Escalate with `saturnin escalate ... --urgency critical`.
4. Nothing merges while the gates are unavailable; that is the intended failure
   mode.

## Backups

Worth a nightly copy: `board/`, `policies/`, `var/reports/`, `var/logs/`.
`var/worktrees/` is reproducible and needs no backup.
