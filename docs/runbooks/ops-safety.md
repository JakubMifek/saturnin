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

<!-- generated:credential-admin-setup -->
This is a bounded human-administrator operation; Saturnin and its workers remain forbidden from using privilege elevation.

```bash
sudo systemd-creds setup
sudo stat -c '%U %G %a %n' /var/lib/systemd/credential.secret
```

The metadata check must report `root root 400`. Never print the host key contents.
<!-- /generated:credential-admin-setup -->

On systemd 256 and newer, unprivileged `--user` operations
are brokered to the system credential service; there is no separate
Saturnin-owned plaintext master or exportable user keyring to initialize.
Recovery therefore depends on the root-owned host master and the bound host
and account identity described below. After the reviewed PR is merged, the
unprivileged Saturnin owner runs:

```bash
cd /home/saturnin/saturnin
saturnin credential prerequisites
umask 077
saturnin credential provision-attestation
saturnin credential status review-attestation
saturnin credential rotate-attestation
saturnin credential seal-attestation-rotation
saturnin credential status review-attestation
```

`provision-attestation` generates both current and initial previous-slot keys
inside the process and streams them to `systemd-creds` over stdin. Neither key
is accepted in argv, a prompt, an environment variable, or a plaintext file.
Status decrypts only into captured process memory and prints status and paths,
never values. Encrypted files are owner-owned `0600` files in an owner-owned
`0700` directory. The first status reports `signer=rotation-required`; the
final status must report `rotation=ready; signer=ready` before unit
installation.

Once status is valid:

<!-- generated:signer-unit-interface -->
This interface is restricted to the `user`-scoped `saturnin-attestation.service` unit.

```bash
scripts/install_attestation_unit.sh install
scripts/install_attestation_unit.sh status
scripts/install_attestation_unit.sh uninstall
```

Install is retry-safe and restores the prior signer definition and state after a partial failure. Status performs no mutation. Uninstall removes only the signer definition, enablement link, and pinned runtime snapshot `%h/.config/systemd/user/saturnin-attestation-runtime.pyz`, leaves encrypted credentials in place, and is safe to repeat.
<!-- /generated:signer-unit-interface -->

The uninstall action is the selective rollback for the signer installation.
It does not revoke or delete credentials. Use the credential lifecycle commands
below separately when revocation is intended.

<!-- generated:attestation-boundary -->
During autonomous operation, the master and previous keys are loaded only by `saturnin-attestation.service` in its private mount, network, runtime, and credential namespace. Supervisor and worker units do not load either credential. Explicit owner lifecycle commands may decrypt them in bounded process memory only while the signer and supervisors are stopped.

The signer remains disabled until the owner rotates the master and seals a version-2 migration manifest. That manifest enumerates the exact immutable historical attestations, records a signed ledger digest and timestamp cutoff, and never permits a legacy role-scoped signature to authorize a new record.

For a routed reviewer task, the trusted launcher asks the service for a session bound to task, role, author, subject, immutable head or issue digest, a random nonce, and the launched process identity. The session expires after 900 seconds, accepts one signature, and verifies that the connecting process descends from that exact launch. Its Unix socket is bind-mounted only into that reviewer's sandbox; `/run` and `/proc` remain isolated for all workers.

No worker receives a master or derived key in argv, environment, files, descriptors, logs, board data, or Git. Ordinary workers do not receive the session socket. The signed ledger retains only scope, key identifier, nonce, and signature, never plaintext key material.
<!-- /generated:attestation-boundary -->

GitHub MCP credential storage and injection are deliberately not part of this
bootstrap. GitHub access requires a separately reviewed external-broker design.

### Rotation, sealing, and rollback

Stop supervisors and verify a clean starting state:

```bash
systemctl --user stop saturnin-improve.timer saturnin-resume.timer saturnin-discovery.timer saturnin-attestation.service
saturnin credential status review-attestation
saturnin credential rotate-attestation
saturnin credential seal-attestation-rotation
saturnin credential status review-attestation
systemctl --user start saturnin-attestation.service
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

Use a mounted encrypted, offline or separate-filesystem backup destination.
The owner chooses that destination interactively and backs up ciphertext
without decrypting it:

```bash
saturnin credential status all
read -r -p 'Encrypted backup mount: ' SATURNIN_ENCRYPTED_BACKUP
test -n "$SATURNIN_ENCRYPTED_BACKUP" && test "${SATURNIN_ENCRYPTED_BACKUP#/}" != "$SATURNIN_ENCRYPTED_BACKUP"
install -d -m 0700 "$SATURNIN_ENCRYPTED_BACKUP/saturnin/credentials"
cp --archive ~/.config/systemd/user/saturnin-credentials/. "$SATURNIN_ENCRYPTED_BACKUP/saturnin/credentials/"
chmod -R go-rwx "$SATURNIN_ENCRYPTED_BACKUP/saturnin/credentials"
```

A human administrator separately backs up the host master and identity
metadata to that encrypted destination without displaying them:

<!-- generated:credential-admin-recovery -->
The destination must be a mounted, encrypted, offline or separate filesystem. Set its path in the administrator shell and reject an empty or relative value:

```bash
read -r -p 'Encrypted backup mount: ' SATURNIN_ENCRYPTED_BACKUP
test -n "${SATURNIN_ENCRYPTED_BACKUP}" && test "${SATURNIN_ENCRYPTED_BACKUP#/}" != "${SATURNIN_ENCRYPTED_BACKUP}"
sudo install -d -o root -g root -m 0700 "${SATURNIN_ENCRYPTED_BACKUP}/saturnin/systemd"
sudo install -m 0400 /var/lib/systemd/credential.secret "${SATURNIN_ENCRYPTED_BACKUP}/saturnin/systemd/credential.secret"
sudo install -m 0444 /etc/machine-id "${SATURNIN_ENCRYPTED_BACKUP}/saturnin/systemd/machine-id"
id -u saturnin
```

Record the reported UID and account name in the protected backup inventory. For recovery, keep all Saturnin timers stopped and run:

```bash
read -r -p 'Encrypted backup mount: ' SATURNIN_ENCRYPTED_BACKUP
test -n "${SATURNIN_ENCRYPTED_BACKUP}" && test "${SATURNIN_ENCRYPTED_BACKUP#/}" != "${SATURNIN_ENCRYPTED_BACKUP}"
sudo cmp --silent /etc/machine-id "${SATURNIN_ENCRYPTED_BACKUP}/saturnin/systemd/machine-id"
id -u saturnin
sudo install -o root -g root -m 0400 "${SATURNIN_ENCRYPTED_BACKUP}/saturnin/systemd/credential.secret" /var/lib/systemd/credential.secret
```

The administrator must verify the recorded UID and account name before restoring the host key.
<!-- /generated:credential-admin-recovery -->

The owner then restores and validates ciphertext:

```bash
read -r -p 'Encrypted backup mount: ' SATURNIN_ENCRYPTED_BACKUP
test -n "$SATURNIN_ENCRYPTED_BACKUP" && test "${SATURNIN_ENCRYPTED_BACKUP#/}" != "$SATURNIN_ENCRYPTED_BACKUP"
install -d -m 0700 ~/.config/systemd/user/saturnin-credentials
cp --archive "$SATURNIN_ENCRYPTED_BACKUP/saturnin/credentials/." ~/.config/systemd/user/saturnin-credentials/
chmod 0700 ~/.config/systemd/user/saturnin-credentials
chmod 0600 ~/.config/systemd/user/saturnin-credentials/*
saturnin credential prerequisites
saturnin credential status all
```

If the identity or machine ID differs, do not overwrite it merely to recover a
credential. Provision fresh credentials and treat old attestations as an
explicit governance recovery requiring human review.

To revoke a compromised credential, stop the `saturnin-*` timers and signer,
run `saturnin credential revoke review-attestation`, and leave them stopped
until a replacement is provisioned and validated. Revocation removes the
encrypted files and does not print their contents.

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

1. Stage the intended candidate and run
   `automation/library/disclosure_gate.sh . .`. It archives the Git index
   rather than reading mutable worktree bytes, scans text and binary bytes with
   the pinned scanner and repository disclosure policy, and identifies
   locations without printing matched values. Governance CI passes the full PR
   commit SHA to scan that immutable tree instead.
2. Inspect history separately with a maintained history-capable secret scanner.
   The PR gate intentionally evaluates the merge candidate, not already-public
   history.
3. Confirm nothing under `board/tasks/`, `board/checkpoints/`, `board/reviews/`
   or `var/` was ever committed: `git log --all --name-only -- board var`.
4. `saturnin doctor` exits 0 and `pre-commit run --all-files` is clean.
5. Check `policies/*.yaml` for hostnames, paths under `/home/<someone>`,
   internal URLs and repository names that should stay private.
6. Move anything private that is left through the governed generic private-store
   abstraction, then
   make the switch. If something was leaked, rotate first, rewrite second.
