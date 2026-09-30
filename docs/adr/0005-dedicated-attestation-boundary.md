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
allowlisted destination. It appends a deterministic, nonce-bound hidden marker.
The marker contains a signer-authenticated claim that an ordinary worker
cannot forge onto another publisher-authored issue.
Before mutation and after any ambiguous result, the signer paginates the
destination and accepts only one exact open marker-bearing issue authored by a
dedicated publisher App with unchanged creation/update timestamps. It obtains
a fresh source authorization immediately before creation and checks the source
again immediately afterward. GitHub provides no atomic cross-repository
"create only if source authorization is still current" operation; this narrow
residual race is accepted only for issue publication. If the post-create check
finds revocation, expiry, closure, an API failure, or changed evidence, the
signer closes the exact safely attributable destination issue as not planned,
records a signed terminal containment result, emits hash-only audit evidence,
and never reports success. A failed or ambiguous close is recorded and
escalated as containment failure. Delayed reconciliation revalidates the
source before destination lookup. If the authenticated marker was edited away,
appears ambiguously, or cannot be fetched after revocation, the signer records
a signed terminal containment failure rather than leaving a retry that could
later become success. Definite pre-send failures release the
reservation; ambiguous, successful, and containment outcomes retain the
source/destination/digest claim so another nonce cannot duplicate publication.
This exception does not weaken PR review, check, head, or merge freshness.
The signer requires strict destination-branch protection with stale-review
dismissal, the configured review and check requirements, and empty bypass
allowances. Its fixed merge account must have write but not administration
permission, and protection must apply to administrators, so GitHub rechecks
review and status policy atomically at merge.

GitHub-hosted governance has no route to the host signer socket. Its
base-controlled `pull_request_target` job therefore performs only a read-only
decision: trusted default-branch code uses a read-only workflow token to fetch
the exact PR head and all review pages twice. It fails on any state change,
blocking or stale review, unexpected reviewer identity, pagination/API error,
or event-head mismatch. It creates no attestation and has no merge permission;
the protected signer remains the sole merge authority. Sandboxed reviewers
likewise queue exact-scope gate callbacks for host execution and never receive
socket or key access.

Issue markers are published by a separate GitHub App identity. The App is
installed only on the selected source repository with Issues write and
Metadata read; each installation token is further narrowed to that repository
and those permissions. Its private key exists only in a protected
`issue-review-approval` GitHub Environment. That environment permits
deployments only from the default branch and requires an independent human
reviewer who verifies the issue, destination, labels, and TTL before approval.
The workflow checks out and executes only the default branch. The App response
must prove the configured bot identity, exact immutable marker body, and
current creation timestamp. Workers and the system merge credential do not
receive the App key or token.

Destination issues are published by a third, independent GitHub App identity.
Its root-encrypted credential is distinct from both the merge account and the
source review-marker App. The publisher App is installed only on explicitly
configured destination repositories using selected-repository access and
exactly Metadata read plus Issues write. For each action the signer discovers
the destination installation using an App JWT, verifies the App ID, selection,
and exact permissions, then requests and revalidates a short-lived token
narrowed to that single repository. The private key is signed through an
anonymous memory file and is never placed in argv, environment, ordinary-worker
state, or persistent plaintext. Startup fails before readiness if any
destination installation or token scope is wrong.

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
The fine-grained merge token has Contents and Pull requests write plus
Administration and Checks read on the fixed PR repository and no destination
Issues permission. The account remains a Write collaborator, not an
administrator. Readiness probes both protected read endpoints and every
publisher installation before the listener becomes available.
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
