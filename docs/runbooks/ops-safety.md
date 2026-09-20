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

## Review attestation key

Keep `SATURNIN_REVIEW_ATTESTATION_KEY` outside the checkout and outside worker
unit environments. Only trusted supervisor processes (for example CI jobs or a
dedicated supervisor shell profile) should load it. Worker launches derive
role-scoped signing keys and pass them only to configured reviewer roles.

To rotate the key, stop `saturnin-*` timers, retain the old master key as the
previous verification key, and install the new current key:

```bash
export SATURNIN_REVIEW_ATTESTATION_PREVIOUS_KEY='old-secret'
export SATURNIN_REVIEW_ATTESTATION_KEY='new-secret'
saturnin review seal-rotation
```

Run the sealing command before restarting timers. It writes a manifest
authenticated by a dedicated derivation of the current master key and seals
the exact reviewer, attestation ID, and signature tuples retained from the old
key. Previous-key records fail closed if this manifest is absent, malformed,
or altered; newly minted old-key attestations are never accepted. Keep master
and previous keys only in the trusted supervisor environment. Rotate again
only after retiring or archiving records signed by the previous key.

## Cleanup safety model

The janitor applies the refusal conditions, protected branches, and per-run
limits from `policies/cleanup.yaml` and `policies/governance.yaml`. Inspect its
plan before applying it. Every action is logged with its reason in
`var/logs/janitor.log`.

```bash
saturnin worktree cleanup            # plan only
saturnin worktree cleanup --apply    # execute the plan
```

## Recovery

**A branch was deleted by mistake**

```bash
saturnin check command "git reflog show --all --date=iso"
git reflog show --all --date=iso        # find the last commit SHA
git branch <branch> <sha>             # recreate it
```

Before destructive cleanup, Saturnin sets repository-local reflog and unreachable
object expiry from `keep_reflog_days` (90). A deleted branch no longer has a
named reflog, so use `git reflog --all`. Do not run `git gc --prune=now` while a
recovery is in question.

**A worktree directory disappeared but git still lists it**

```bash
saturnin worktree cleanup --apply
```

**A worktree was removed with unfinished work**

Commits remain on their branch after worktree removal; use `git reflog --all`
for recent ref movements. If the commit is no longer referenced by any reflog:

```bash
saturnin check command "git fsck --unreachable"
git fsck --unreachable
```

Uncommitted changes are gone, which is why the janitor never touches a dirty
worktree.

**The board looks wrong**

Task files are plain JSON under `board/tasks/`. Fix by hand only as a last
resort, and record what you did in the task history. Never edit a task while a
worker may be running: use `saturnin task move`/`attach`, which lock the file.
A stray `*.lock` sidecar is harmless - locks are advisory and released when the
process exits.

**The board is gone (disk loss, fresh server)**

By default mirroring is disabled (`tracking.mirror_tasks_as_issues: false`), so
the primary recovery path is your own backups of `board/` and `var/`. Restore
those first, then follow the
[day-1 startup runbook](day-1-startup.md) from a trusted administrator shell.

If optional mirroring is enabled for your installation, you can also rebuild
from the private board repository issues
([ADR-0001](../adr/0001-system-of-record.md)): inspect open tasks and their
sibling state labels in the configured board repository. Anything that was
never mirrored is lost.

**Everything is on fire**

1. `systemctl --user stop 'saturnin-*.timer'` - stop the schedulers.
2. `saturnin task list --open` - see what is in flight.
3. Escalate with
   `saturnin escalate "Recovery requires human intervention" --urgency critical --push`.
4. Nothing merges while the gates are unavailable; that is the intended failure
   mode.

## Backups

Worth a nightly copy: `board/`, `policies/`, `var/reports/`, `var/logs/`.
`var/worktrees/` is reproducible and needs no backup. Once ADR-0002 is accepted,
the board can additionally mirror itself to GitHub with `saturnin-mirror.timer`,
which is the backup that survives losing the machine entirely.

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
