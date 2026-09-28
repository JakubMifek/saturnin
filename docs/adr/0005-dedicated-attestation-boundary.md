# ADR 0005: Dedicated attestation privilege boundary

## Status

Accepted.

## Decision

Signing moves from the ordinary Saturnin UID to the non-login
`saturnin-signer` system identity. Runtime, configuration, credentials, and
state are rooted in administrator-controlled `/usr`, `/etc`, and `/var/lib`
trees. A socket is reachable by Saturnin but grants no authority.

The service constructs fixed GitHub API requests itself. Pull-request authority
requires an allowlisted repository, live head, author, an allowlisted bot's
latest exact-commit review, an allowed verdict, and zero-context reviewer role.
Issue authority requires an allowlisted bot comment with the exact v1 marker,
independently recomputed title/body digest, author, role, verdict, destination,
expiry, and nonce. Evidence consumption is durable and idempotent only for the
identical scope.

## Consequences

Compromise of the ordinary UID, checkout, board, launcher, or socket client
cannot choose signed fields or expose keys. Review workers receive no signing
session. Availability now depends on GitHub and the system service. Legacy
user-owned keys are not migrated because their identity cannot be proven;
deployment performs an explicit fresh-key bootstrap.
