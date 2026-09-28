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
The system `saturnin-attestation.service` runs as the non-login `saturnin-signer` identity from root-controlled runtime and configuration. The system manager decrypts current, previous, and bounded retired HMAC credentials into its private credential tmpfs; ordinary workers never receive key material. The service, not PID 1, creates the canonical listener, so client `SO_PEERCRED` verification authenticates the signer UID and process.

For pull requests the service obtains the live head, author, and exact commit-bound latest review state directly from GitHub over TLS. For issues it recomputes title/body digest and accepts one exact, expiring, nonce-bound machine marker in an allowlisted bot comment. Evidence expiry limits new authorization, not later verification of an already signed durable record. Socket filesystem access permits transport only: independent GitHub authorization remains required. Repository and API origins are fixed allowlists; caller claims and socket credentials are not authority.

Consumed evidence and its exact idempotent attestation are serialized in dedicated state. Altered reuse fails. The ordinary client authenticates a root-owned service peer and records the returned scope in ReviewLedger; workers receive neither signing sessions nor credentials.
<!-- /generated:attestation-boundary -->

### Provisioning and rotation

The system manager decrypts `current.key.cred`, `previous.key.cred`,
`archive.keys.cred`, and the optional `github.token` credential-store entry
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
