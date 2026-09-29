# ADR 0005: Dedicated attestation privilege boundary

## Status

Accepted.

## Decision

Signing moves from the ordinary Saturnin UID to the non-login
`saturnin-signer` system identity. Runtime, configuration, credentials, and
state are rooted in administrator-controlled `/usr`, `/etc`, and `/var/lib`
trees. The signer remains a non-login identity. The socket and runtime parent
use the fixed ordinary operator's reviewed existing primary group,
`jakubmifek` (GID 1000), so provisioning does not depend on supplemental-group
refresh or create a client group. Modes `0660` and `0750` exclude other users.
Group access reaches only the AF_UNIX socket and grants no signing authority;
GitHub authorization remains independent.

The service constructs fixed GitHub API requests itself. Pull-request authority
requires an allowlisted repository, live head, author, an allowlisted bot's
latest exact-commit review, an allowed verdict, and zero-context reviewer role.
Issue authority requires an allowlisted bot comment with the exact v1 marker,
independently recomputed title/body digest, author, role, verdict, destination,
expiry, and nonce. Evidence consumption is durable and idempotent only for the
identical scope. The covered `expires_at` is stable upstream evidence metadata:
the marker expiry for issues and the review submission time for pull requests.
Issue marker expiry is enforced before first issuance. The field remains signed evidence, but it does not expire an already signed
ReviewLedger record during later verification.

Those durable attestations are audit records, never live action authority.
Every PR gate requests a new signer decision bound to operation, repository,
PR, destination, exact live head/base, reviewer identity, review ID/state,
required successful checks, nonce, and a 60-second expiry. The signer performs
the same independent lookup again immediately before merge and invokes
GitHub's merge API itself with the expected head SHA. Nonces are serialized in
root-controlled state, so identical retry is idempotent and altered or
concurrent reuse fails closed.
Issue gates likewise obtain fresh short-lived decisions. Issue submission
repeats the source issue/comment lookup, and the signer itself creates the
digest-bound title and body with the marker-approved labels in an explicitly
allowlisted destination.
The signer requires strict destination-branch protection with stale-review
dismissal, the configured review and check requirements, and empty bypass
allowances. Its fixed merge account must have write but not administration
permission, and protection must apply to administrators, so GitHub rechecks
review and status policy atomically at merge.

The daemon itself creates, verifies, listens on, and removes the canonical
AF_UNIX socket. Socket activation is forbidden. Clients authenticate the
kernel-reported dedicated signer UID and stable inode beneath the exact
signer-owned setgid directory before and after connection; they do not depend
on ptrace-gated cross-UID `/proc/<pid>/exe` access. The runtime directory
assigns the fixed operator group and the daemon
sets exact mode `0660`; ordinary group members cannot replace entries in the
`2750` directory. Its only network client constructs HTTPS requests to the
exact `https://api.github.com` origin;
redirects and caller-selected origins are refused. Authorization attempts are
bounded per peer UID. Audit records contain only an outcome and hashes of the
evidence identifier and authorization scope. SIGTERM stops acceptance and
closes the inherited listener cleanly.

The system unit is `Type=notify`. Readiness is emitted only after protected
GitHub credential identity/permissions validation and canonical listener
creation, so installer and rotation health checks cannot succeed during
startup validation.

The one authorized legacy migration source is fixed at
`/home/jakubmifek/.config/systemd/user/saturnin-credentials` for UID 1000.
The administrator opens its exact files without following links, pins and
rechecks file, directory, mount, and content identity, decrypts with the two
reviewed legacy names, and verifies reviewed plaintext hashes. Fresh root-only
current and previous keys are always generated; legacy keys enter only the
bounded verification archive and can never authorize new records. The
dedicated service strictly verifies the exact
historical role- and execution-scoped schemas with those keys; legacy payloads
can never authorize a new record. Plaintext is never written. Any partial
system state, substitution, mutation, or mismatch aborts and restores all
system artifacts.

No checkout Python is executed with privilege. Initial installation and every
administrator update copy the administrator bytes without execution to the
fixed root-owned bootstrap directory, compare that copy to a SHA-256 obtained
from independently approved exact-head evidence, and only then invoke the same
root-owned copy with `/usr/bin/python3 -I`. The checkout digest is not an
authority. Isolated mode excludes checkout-local modules before the
administrator pins and digest-checks every artifact descriptor. It reads
reviewed checkout artifacts as the fixed operator UID while requiring its own
staged executable and every installed target to remain root-controlled.

Merge authority requires a separately provisioned encrypted `github.token`
credential in the root-owned configuration directory. It is not accepted from
the operator environment or ordinary `gh` storage. Production installation
refuses to start without that credential; provisioning it and removing merge
authority from the ordinary account are human GitHub administration steps.
The allowlisted reviewer is a distinct GitHub-controlled bot identity; GitHub,
not the ordinary caller, assigns that identity and review state.
New v2 review records must also match a byte-identical signer-issued row in the
root-owned authorization database.

Rotation moves the outgoing previous key into a root-encrypted,
duplicate-free `archive.keys` credential. The archive is verification-only,
is never a signing or new-record authorization source, and is bounded at 16
keys. Verification reports `current`, `previous`, or `archive`, allowing
ReviewLedger to accept noncurrent keys only for an exact historical record.
Rollback restores the exact current, previous, and archive snapshot.

## Consequences

Compromise of the ordinary UID, checkout, board, launcher, historical ledger,
or socket client cannot choose trusted live fields, expose keys, or execute a
merge. Review workers receive no signing session. Availability now depends on
GitHub and the system service. The reviewed
legacy migration preserves existing attestations without accepting legacy
user-owned key material as current authority. Durable ledger availability
therefore requires retaining every
verification key used by retained records.
