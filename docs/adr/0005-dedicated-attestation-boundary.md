# ADR 0005: Dedicated attestation privilege boundary

## Status

Accepted.

## Decision

Signing moves from the ordinary Saturnin UID to the non-login
`saturnin-signer` system identity. Runtime, configuration, credentials, and
state are rooted in administrator-controlled `/usr`, `/etc`, and `/var/lib`
trees. A dedicated `saturnin` client group contains the fixed ordinary
operator `jakubmifek`; the signer remains a non-login identity and is not a
member of that client group. The group can reach only the AF_UNIX socket and
grants no signing authority.

The service constructs fixed GitHub API requests itself. Pull-request authority
requires an allowlisted repository, live head, author, an allowlisted bot's
latest exact-commit review, an allowed verdict, and zero-context reviewer role.
Issue authority requires an allowlisted bot comment with the exact v1 marker,
independently recomputed title/body digest, author, role, verdict, destination,
expiry, and nonce. Evidence consumption is durable and idempotent only for the
identical scope. The covered `expires_at` is the upstream authorization
capability's deadline at signing time. It remains signed evidence, but it does
not expire an already signed ReviewLedger record during later verification.

The daemon accepts only its socket-activated AF_UNIX listener. Its only network
client constructs HTTPS requests to the exact `https://api.github.com` origin;
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

Rotation moves the outgoing previous key into a root-encrypted,
duplicate-free `archive.keys` credential. The archive is verification-only,
is never a signing or new-record authorization source, and is bounded at 16
keys. Verification reports `current`, `previous`, or `archive`, allowing
ReviewLedger to accept noncurrent keys only for an exact historical record.
Rollback restores the exact current, previous, and archive snapshot.

## Consequences

Compromise of the ordinary UID, checkout, board, launcher, or socket client
cannot choose signed fields or expose keys. Review workers receive no signing
session. Availability now depends on GitHub and the system service. The reviewed
legacy migration preserves existing attestations without accepting arbitrary
user-owned key material; only an absent reviewed legacy source causes a fresh
key bootstrap. Durable ledger availability therefore requires retaining every
verification key used by retained records.
