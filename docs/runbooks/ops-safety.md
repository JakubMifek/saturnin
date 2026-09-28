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

The signer is a system service and a human-administrator boundary. Review the
source tree and embedded artifact digests, then perform the first transaction
with `sudo ./scripts/manage_system_attestation.py install`. It atomically
publishes the fixed `/usr/sbin/saturnin-attestation-admin` interface; its
grammar accepts only five actions and no paths, commands, units, users, or
packages.

<!-- generated:signer-unit-interface -->
This human-administrator interface manages only the `system`-scoped `saturnin-attestation.service` unit.

```bash
sudo /usr/sbin/saturnin-attestation-admin install
sudo /usr/sbin/saturnin-attestation-admin status
sudo /usr/sbin/saturnin-attestation-admin uninstall
sudo /usr/sbin/saturnin-attestation-admin rotate
sudo /usr/sbin/saturnin-attestation-admin rollback
```

Install is retry-safe and restores the prior signer definition and state after a partial failure. Status performs no mutation. Rotate and rollback only exchange encrypted credential generations. No action accepts a path, unit, owner, package, or arbitrary command.
<!-- /generated:signer-unit-interface -->

The installer creates only the declared sysuser, tmpfiles, system units,
configuration, and exact runtime. Installation stages and digest-checks all
artifacts before atomic publication and removes the transaction on failure.
`status` is read-only. `uninstall` intentionally leaves service state and
encrypted credentials for administrator recovery.

<!-- generated:attestation-boundary -->
The system `saturnin-attestation.service` runs as the non-login `saturnin-signer` identity from root-controlled runtime and configuration. The system manager decrypts current and previous HMAC credentials into its private credential tmpfs; ordinary workers never receive key material.

For pull requests the service obtains the live head, author, and exact commit-bound latest review state directly from GitHub over TLS. For issues it recomputes title/body digest and accepts one exact, expiring, nonce-bound machine marker in an allowlisted bot comment. Repository and API origins are fixed allowlists; caller claims and socket credentials are not authority.

Consumed evidence and its exact idempotent attestation are serialized in dedicated state. Altered reuse fails. The ordinary client authenticates a root-owned service peer and records the returned scope in ReviewLedger; workers receive neither signing sessions nor credentials.
<!-- /generated:attestation-boundary -->

### Provisioning and rotation

The system manager decrypts `current.key.cred`, `previous.key.cred`, and the
optional GitHub token into its credential tmpfs. The administrator interface
generates key bytes in process and streams them directly to `systemd-creds`;
it never accepts or prints a key.

```bash
sudo /usr/sbin/saturnin-attestation-admin install
sudo /usr/sbin/saturnin-attestation-admin status
sudo /usr/sbin/saturnin-attestation-admin rotate
sudo /usr/sbin/saturnin-attestation-admin rollback
```

Rotation serializes by fixed credential names, retains the old current key as
previous, and restarts the service only after atomic publication. A failed
restart restores the prior generation. Rollback is the only reversal and does
not accept caller-selected files.

Legacy user-owned signer ciphertext is not migrated: its same-UID origin
cannot establish trustworthy key identity. Bootstrap creates a fresh system
key; old ledgers remain read-only evidence and cannot authorize a new record.
This is an explicit trust reset rather than a weakened migration.

### Recovery

Keep encrypted credentials and `/var/lib/saturnin-attestation` in an
administrator-controlled encrypted backup together with the systemd host key.
Never copy plaintext credential-directory contents or log request bodies.
After restoration, run `status`, start the socket, authorize a mocked approved
head, verify the returned attestation, and confirm an unreviewed head fails.

## Cleanup safety model

The janitor applies `policies/cleanup.yaml` refusal conditions, including
`policies/cleanup.yaml:safety.keep_reflog_days`, and logs each action to
`var/logs/janitor.log`. Inspect its plan before applying it.
