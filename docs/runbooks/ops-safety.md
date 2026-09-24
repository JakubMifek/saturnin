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

### Host prerequisites

The credential owner must have systemd 256 or newer, a running systemd user
manager, a persistent machine ID, and a system credential host key owned by
root with mode `0400`. User-scoped encryption is bound to that host key plus
the owner's numeric UID, account name, and machine ID. It is not portable to a
different identity or freshly installed host.

Creating the host key is a one-time administrator action, not an operation
Saturnin may perform. A human administrator runs:

```bash
sudo systemd-creds setup
sudo stat -c '%U %G %a %n' /var/lib/systemd/credential.secret
```

The metadata check must report `root root 400`. The host key contents must
never be printed. After the reviewed PR is merged, the unprivileged Saturnin
owner runs:

```bash
cd /home/saturnin/saturnin
saturnin credential prerequisites
umask 077
saturnin credential provision-attestation
saturnin credential status review-attestation
```

`provision-attestation` generates both current and initial previous-slot keys
inside the process and streams them to `systemd-creds` over stdin. Neither key
is accepted in argv, a prompt, an environment variable, or a plaintext file.
Status decrypts only into captured process memory and prints status and paths,
never values. Encrypted files are owner-owned `0600` files in an owner-owned
`0700` directory.

Create a dedicated fine-grained token at
<https://github.com/settings/personal-access-tokens/new>. Select only
`JakubMifek/saturnin`, choose read-only **Contents**, **Issues**, and
**Pull requests** repository permissions (GitHub adds read-only **Metadata**),
then ingest it from a no-echo prompt:

```bash
saturnin credential store-github-mcp
saturnin credential status github-mcp
```

The token prompt uses `getpass`; paste it only there. Do not put it in a shell
assignment, pipeline, argv, task, board item, log, or environment file, and do
not reuse `gh auth token`. The encrypted files are stored under
`~/.config/systemd/user/saturnin-credentials/`. Once both statuses are valid:

```bash
scripts/install_user_units.sh
systemctl --user daemon-reload
systemctl --user restart saturnin-improve.timer saturnin-resume.timer saturnin-discovery.timer
```

The units use private mount namespaces. Systemd decrypts credentials into the
service credential directory in protected runtime memory. The launcher derives
attestation keys only for configured reviewer roles. A GitHub MCP token exists
in an owner-only runtime MCP configuration only while its worker is active;
normal completion, launch failure, and recovery reconciliation remove that
file. It never enters task, board, Git, or log content.

### Rotation, sealing, and rollback

Stop supervisors and verify a clean starting state:

```bash
systemctl --user stop saturnin-improve.timer saturnin-resume.timer saturnin-discovery.timer
saturnin credential status review-attestation
saturnin credential rotate-attestation
saturnin credential seal-attestation-rotation
saturnin credential status review-attestation
systemctl --user start saturnin-improve.timer saturnin-resume.timer saturnin-discovery.timer
```

The first status must say `rotation=ready`; the last must also return to
`rotation=ready`. Rotation saves owner-only ciphertext rollback copies, moves
the old current key to the previous slot in memory, generates a new current
key internally, and enters `pending-seal`. Sealing passes both decrypted values
directly to the review ledger API, without environment variables, then deletes
rollback artifacts. A second rotation is refused while any rotation is pending.

If rotation or sealing fails, keep the timers stopped. Retry sealing when
status is `pending-seal`, or restore both encrypted slots:

```bash
saturnin credential rollback-attestation-rotation
saturnin credential status review-attestation
```

Rollback is retry-safe and removes its recovery artifacts only after both
restored slots decrypt successfully. Once sealing completes, rollback is
intentionally unavailable. Do not rotate again until records requiring the
previous key have been retired or archived.

### Backup and recovery

The ciphertext alone is not a recoverable backup. Recovery requires all of:

- the complete `saturnin-credentials` directory from a `rotation=ready` state;
- the root-only `/var/lib/systemd/credential.secret` host master;
- the same machine ID, numeric UID, and account name.

Use a root-owned, encrypted, offline or separate-filesystem backup destination.
The owner backs up ciphertext without decrypting it:

```bash
saturnin credential status all
install -d -m 0700 /secure-backup/saturnin/credentials
cp --archive ~/.config/systemd/user/saturnin-credentials/. /secure-backup/saturnin/credentials/
chmod -R go-rwx /secure-backup/saturnin/credentials
```

A human administrator separately backs up the host master and identity
metadata to that encrypted destination without displaying them:

```bash
sudo install -D -o root -g root -m 0400 /var/lib/systemd/credential.secret /secure-backup/saturnin/systemd/credential.secret
sudo install -D -o root -g root -m 0444 /etc/machine-id /secure-backup/saturnin/systemd/machine-id
id -u saturnin
```

Record the reported UID and account name in the protected backup inventory.
After host-key loss, keep all Saturnin timers stopped. A human administrator
must first verify that the restored host has the same machine ID and account
identity, then restore the host master:

```bash
sudo cmp --silent /etc/machine-id /secure-backup/saturnin/systemd/machine-id
id -u saturnin
sudo install -D -o root -g root -m 0400 /secure-backup/saturnin/systemd/credential.secret /var/lib/systemd/credential.secret
```

The owner then restores and validates ciphertext:

```bash
install -d -m 0700 ~/.config/systemd/user/saturnin-credentials
cp --archive /secure-backup/saturnin/credentials/. ~/.config/systemd/user/saturnin-credentials/
chmod 0700 ~/.config/systemd/user/saturnin-credentials
chmod 0600 ~/.config/systemd/user/saturnin-credentials/*
saturnin credential prerequisites
saturnin credential status all
```

If the identity or machine ID differs, do not overwrite it merely to recover a
credential. Provision fresh credentials and treat old attestations as an
explicit governance recovery requiring human review.

To revoke a compromised credential, stop the `saturnin-*` timers first, run
`saturnin credential revoke review-attestation` or
`saturnin credential revoke github-mcp`, and leave supervisors stopped until a
replacement is provisioned and validated. Revocation removes the encrypted
files and does not print their contents.

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

Before destructive cleanup, Saturnin applies the retention configured by
`policies/cleanup.yaml:safety.keep_reflog_days`. A deleted branch no longer has
a named reflog, so use `git reflog --all`. Do not run `git gc --prune=now` while
a recovery is in question.

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

Uncommitted changes are not recoverable from Git metadata. Follow the current
policy-backed cleanup plan and preserve work before any approved removal.

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
