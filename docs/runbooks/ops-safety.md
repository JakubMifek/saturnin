# Ops and safety runbook

## Ordinary Saturnin services

Validate ordinary commands against `policies/server_scope.yaml`. Saturnin and
its workers never use `sudo`, root, or the system signer administration
interface.

```bash
saturnin check command "<exact command>"
systemctl --user list-timers 'saturnin-*'
```

## Dedicated attestation service

The signer is a system service and a human-administrator boundary. Never run
checkout Python with `sudo`. Through a trusted administrator channel, provision
the independently approved exact-head evidence as the fixed root-owned file
`/root/saturnin-attestation-admin.sha256`. It must contain the administrator
SHA-256 and fixed staged pathname in `sha256sum --check` format; do not create
it from this checkout or from an ordinary-UID process. From the exact reviewed
checkout, use this fixed bootstrap sequence:

Before that sequence, a human must create the dedicated
`saturnin-merge-bot` GitHub account and a fine-grained token limited to
`saturnin` (Contents and Pull requests write) and `saturnin-ops` (Issues
write), with no Administration permission on either repository. Add that
account with Write, not Admin, repository access. At a
trusted root console—not an ordinary-UID shell, environment, file, pipe, or
clipboard—encrypt the token under its fixed credential name:

```bash
/usr/bin/install -d -o root -g root -m 0750 /etc/saturnin-attestation
/bin/bash -c 'umask 077; IFS= read -r -s token; printf %s "$token" | /usr/bin/systemd-creds encrypt --name=github.token - /etc/saturnin-attestation/github.token.cred; unset token'
/usr/bin/chown root:root /etc/saturnin-attestation/github.token.cred
/usr/bin/chmod 0600 /etc/saturnin-attestation/github.token.cred
```

Configure `main` branch protection to apply to administrators, dismiss stale
approvals, require one approving review, require the strict `test` check, and
grant no bypass to any user, team, app, role, or repository owner. Enable
approval reviews from the configured Copilot reviewer. Replace the ordinary
UID's GitHub credential with a fine-grained token lacking Administration and
default-branch bypass authority and lacking Issues write access to
`saturnin-ops`; otherwise that ordinary credential could edit protected issue
submission evidence. The service validates the protected token's
fixed login and effective write/non-admin repository permissions before
creating its socket; installation rolls back if that validation fails.

```bash
cd /path/to/exact-reviewed-checkout
sudo /usr/bin/install -d -o root -g root -m 0700 /run/saturnin-attestation-bootstrap
sudo /usr/bin/install -o root -g root -m 0500 scripts/manage_system_attestation.py /run/saturnin-attestation-bootstrap/saturnin-attestation-admin.py
sudo /usr/bin/test -f /root/saturnin-attestation-admin.sha256
sudo /usr/bin/sha256sum --strict --check /root/saturnin-attestation-admin.sha256
sudo /usr/bin/python3 -I /run/saturnin-attestation-bootstrap/saturnin-attestation-admin.py install
sudo /usr/bin/rm -- /run/saturnin-attestation-bootstrap/saturnin-attestation-admin.py
sudo /usr/bin/rmdir -- /run/saturnin-attestation-bootstrap
```

The copy operation does not interpret checkout bytes. The verified copy and
its parent are root-owned and non-writable to the ordinary UID, closing the
verification/execution race. `-I` excludes the checkout and user Python paths,
so a checkout-local `secrets.py` or other import shadow cannot run. The staged
administrator pins and digest-checks all checkout artifact descriptors before
publication. A changed source, wrong external digest, alias, or race aborts.
It atomically publishes the fixed `/usr/sbin/saturnin-attestation-admin`
interface; its grammar accepts only five actions and no paths, commands, units,
users, ownership changes, or packages. Repeat this bootstrap for reviewed
administrator updates; do not execute a replacement directly from a checkout.
Production source acquisition requires exact reviewed checkout files owned by
the fixed operator UID 1000; only the staged administrator and installed
artifacts are required to be root-owned.

<!-- generated:signer-unit-interface -->
This human-administrator interface manages only the `system`-scoped `saturnin-attestation.service` unit.

```bash
sudo /usr/sbin/saturnin-attestation-admin install
sudo /usr/sbin/saturnin-attestation-admin status
sudo /usr/sbin/saturnin-attestation-admin uninstall
sudo /usr/sbin/saturnin-attestation-admin rotate
sudo /usr/sbin/saturnin-attestation-admin rollback
```

Install is retry-safe and restores the prior signer definition and state after a partial failure. Status performs no mutation. Rotate and rollback decrypt each generation under root, validate its identity, and re-encrypt it with its destination embedded name before atomic publication. Both restart the service and require an active health result; any failure restores the complete prior credential set and service. No action accepts a path, unit, owner, package, or arbitrary command.
<!-- /generated:signer-unit-interface -->

The installer creates only the declared sysuser, tmpfiles, system units,
configuration, and exact runtime. Installation stages and digest-checks all
artifacts before atomic publication and removes the transaction on failure.
`status` is read-only. `uninstall` intentionally leaves service state and
encrypted credentials for administrator recovery. Before any live privileged
action, the interface requires the reviewed `jakubmifek` account and primary
group to resolve bidirectionally to UID 1000 and GID 1000; a missing or reused
identity fails closed before the administration lock or any other mutation.

<!-- generated:attestation-boundary -->
The system `saturnin-attestation.service` runs as the non-login `saturnin-signer` identity from root-controlled runtime and configuration. The system manager decrypts current, previous, and bounded retired HMAC credentials into its private credential tmpfs; ordinary workers never receive key material. The service, not PID 1, creates the canonical listener. Clients authenticate its kernel-reported UID plus the stable signer-owned socket directory and endpoint identity; this deliberately avoids cross-UID ptrace-gated `/proc` inspection. Systemd readiness is reported only after protected credential validation and listener creation.

For pull requests the service obtains the live head, author, and exact commit-bound latest review state directly from GitHub over TLS. For issues it recomputes title/body digest and accepts one exact, expiring, nonce-bound machine marker in an allowlisted dedicated GitHub App bot comment. A default-branch-only protected environment holds that App key and requires an independent human approver; ordinary workers cannot publish as the bot. The marker also binds approved labels. Every issue gate is fresh; submission repeats authorization and the signer creates exact reviewed content in an independently allowlisted destination with a deterministic hidden idempotency marker. Ambiguous submission outcomes reconcile only against one exact marker-bearing issue authored by the protected identity. Evidence expiry limits new authorization, not later audit verification of a durable record. Socket filesystem access permits transport only: independent GitHub authorization remains required. Repository and API origins are fixed allowlists; caller claims and socket credentials are not authority.

Consumed evidence and its exact idempotent attestation are serialized in dedicated state for audit only. Altered reuse fails. Every PR gate obtains a fresh, expiring, one-time protected decision over the live head, base, review ID/state/identity and required checks. Merge repeats that lookup immediately before the signer uses GitHub's expected-head atomic merge API. The signer also requires strict branch protection with stale-review dismissal, required reviews/checks, administrator enforcement and no bypass identities. Its fixed non-admin merge identity and root-provisioned credential never enter the ordinary UID; workers receive neither signing sessions nor credentials.

GitHub-hosted governance cannot access the host signer. Its `pull_request_target` job executes only default-branch code with a read-only token and repeats a live exact-head review lookup; it signs nothing and cannot merge. Sandboxed reviewers queue scope-bound gate callbacks for host execution instead of receiving signer socket access.
<!-- /generated:attestation-boundary -->

### Protected issue-review App

This is a GitHub administration ceremony, not a Saturnin worker action. Create
a dedicated App whose bot login exactly matches
`config/attestation.json` (`saturnin-issue-reviewer[bot]`). Grant only
**Metadata: read** and **Issues: read/write**, disable webhook delivery, and
install it for **selected repositories only** on the configured source
repository. Do not install it on issue destinations unless they are also
review sources.

Create the `issue-review-approval` Environment with all of these protections:

1. Allow deployment only from the repository's default branch; tags and other
   branches are forbidden.
2. Require at least one reviewer who is independent of Saturnin workers and
   issue authors. Prevent self-review where the GitHub plan supports it.
3. Store the App private key only as the environment secret
   `SATURNIN_ISSUE_REVIEWER_PRIVATE_KEY`; store its numeric App ID as the
   environment variable `SATURNIN_ISSUE_REVIEWER_APP_ID`.
4. Give ordinary worker, server, merge-bot, and repository secrets no copy of
   either value. Their tokens must not impersonate the App bot.

The approver must independently recompute and compare the source issue's
title/body digest, destination, exact label JSON, and TTL in the pending
deployment before approving
`.github/workflows/issue-review-marker.yml`. Dispatch only on the exact default
branch. The workflow obtains the installation for the exact source repository,
requests a repository- and permission-scoped token, and publishes one
short-lived digest-bound marker. A duplicate or ambiguous publication blocks;
never create a replacement marker manually.

### Provisioning and rotation

The system manager decrypts `current.key.cred`, `previous.key.cred`,
`archive.keys.cred`, and the mandatory `github.token` credential-store entry
into its credential tmpfs. The administrator interface
generates key bytes in process and streams them directly to `systemd-creds`;
it never accepts or prints a key.

```bash
sudo /usr/sbin/saturnin-attestation-admin install
sudo /usr/sbin/saturnin-attestation-admin status
sudo /usr/sbin/saturnin-attestation-admin rotate
sudo /usr/sbin/saturnin-attestation-admin rollback
```

Rotation serializes by fixed credential names, retains the old current key as
previous, moves the outgoing previous key into the verification-only encrypted
archive, and restarts the service only after atomic publication. The archive
is schema-validated, duplicate-free, and bounded at 16 keys. A failed restart
restores the exact prior current, previous, and archive generation and writes
fail-closed recovery evidence. Rollback is the only reversal and does not
accept caller-selected files.

On first installation only, the administrator checks the fixed UID-1000 source
`/home/jakubmifek/.config/systemd/user/saturnin-credentials`. It accepts only
the reviewed current and previous filenames, embedded names, and plaintext
SHA-256 identities recorded in ADR 0005. Every path component and retained
O_NOFOLLOW descriptor is checked before and after decryption; aliases, links,
mount or content mutation, partial target state, and hash mismatches fail the
whole transaction. Plaintext is passed only through root process pipes and is
re-encrypted as `current.key` and `previous.key`. If the source is absent,
bootstrap creates fresh keys; it never silently falls back after a rejected
migration.

The issue marker expiry and the PR's live exact-head state are checked when
authorization is minted. The signed expiry remains covered evidence; it does
not invalidate a durable signed ReviewLedger record when a gate is evaluated
later. A consumed, identical evidence item remains idempotent after its
authorization deadline, while changed or previously unconsumed stale evidence
fails.

The service accepts only the local AF_UNIX socket and needs outbound HTTPS to
the fixed `api.github.com` origin. The system sandbox prevents network binds;
application validation refuses alternate origins and redirects. The
socket and its setgid runtime parent use the existing primary group `jakubmifek`, so
the already-running user manager has immediate access after provisioning.
Their modes are respectively `0660` and `2750`, excluding other users. This
filesystem access grants only transport, not trust: the signer independently
requires GitHub authorization and grants no access to credentials or state.

### Recovery

Keep encrypted credentials and `/var/lib/saturnin-attestation` in an
administrator-controlled encrypted backup together with the systemd host key.
Never copy plaintext credential-directory contents or log request bodies.
After restoration, run `status`, start the service, authorize a mocked approved
head, verify the returned attestation, and confirm an unreviewed head fails.

At the 16-key archive bound, rotation stops fail-closed. There is intentionally
no online “drop oldest” action: do not retire a key while any retained ledger
record depends on it. Continue by preserving the exact encrypted credential,
host key, state database, and dependent ledgers as one disaster-recovery set,
then obtain explicit governance approval either to stop rotation or to retire
the dependent records under the repository retention procedure. After an
approved disaster restore, restore that whole set; never hand-edit
`archive.keys.cred`.

## Cleanup safety model

The janitor applies `policies/cleanup.yaml` refusal conditions, including
`policies/cleanup.yaml:safety.keep_reflog_days`, and logs each action to
`var/logs/janitor.log`. Inspect its plan before applying it.
