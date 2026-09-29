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
The signer requires strict destination-branch protection with stale-review
dismissal, the configured review and check requirements, and empty bypass
allowances. Its fixed merge account must have write but not administration
permission, so GitHub rechecks review and status policy atomically at merge.

The daemon itself creates, verifies, listens on, and removes the canonical
AF_UNIX socket. Socket activation is forbidden: `SO_PEERCRED` therefore names
the dedicated signer process that created the listener, rather than PID 1.
The setgid runtime directory assigns the fixed operator group and the daemon
sets exact mode `0660`; ordinary group members cannot replace entries in the
`2750` directory. Its only network client constructs HTTPS requests to the
exact `https://api.github.com` origin;
redirects and caller-selected origins are refused. Authorization attempts are
bounded per peer UID. Audit records contain only an outcome and hashes of the
evidence identifier and authorization scope. SIGTERM stops acceptance and
closes the inherited listener cleanly.

The one authorized legacy migration source is fixed at
`/home/jakubmifek/.config/systemd/user/saturnin-credentials` for UID 1000.
The administrator opens its exact files without following links, pins and
rechecks file, directory, mount, and content identity, decrypts with the two
reviewed legacy names, verifies reviewed plaintext hashes, and re-encrypts to
the fixed `current.key` and `previous.key` names. This is a reviewed migration,
not a fresh-key bootstrap. The dedicated service strictly verifies the exact
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
administrator pins and digest-checks every artifact descriptor.

Merge authority requires a separately provisioned encrypted `github.token`
credential in the root-owned configuration directory. It is not accepted from
the operator environment or ordinary `gh` storage. Production installation
refuses to start without that credential; provisioning it and removing merge
authority from the ordinary account are human GitHub administration steps.
The allowlisted reviewer is a distinct GitHub-controlled bot identity; GitHub,
not the ordinary caller, assigns that identity and review state.

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
legacy migration preserves existing attestations without accepting arbitrary
user-owned key material; only an absent reviewed legacy source causes a fresh
key bootstrap. Durable ledger availability therefore requires retaining every
verification key used by retained records.
