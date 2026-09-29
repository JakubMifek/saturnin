# Security policy

Saturnin runs shell commands, manages git repositories and files issues on
GitHub. That is useful and it is exactly the attack surface, so the boundaries
are written down rather than assumed.

## Threat model

Saturnin is single-user software running as an unprivileged user on a personal
Debian server. It is not multi-tenant and has no authentication of its own: the
security boundary is the operating-system user account plus the credentials
`gh` holds. Anyone who can run `saturnin` can do anything Saturnin can do.

## Safety controls implemented in code

| Control | Where |
| --- | --- |
| Workers get isolated Git metadata with no `origin` push destination; `saturnin push` queues the exact isolated commit for a trusted host broker that revalidates the task worktree, repository and branch before delivery | `AgentLauncher`, `worker_callbacks`, `Governance.push_allowed` |
| No merge without an independent, zero-context review by someone other than the author | `Governance.merge_allowed`, `ReviewLedger` |
| No issue filed in a managed repository without an independent issue review | `Governance.issue_submission_allowed` |
| Never runs as root; `apt` only for Saturnin-dedicated service dependencies; `systemctl` only for `saturnin-*` units; timers only in the user scope | `Governance.check_server_command`, `policies/server_scope.yaml` |
| Cleanup follows the canonical lifecycle and safety policy | `WorktreeManager`, `policies/cleanup.yaml` |
| Launched agents get only the MCP servers their contract allows; non-executing roles get none | `AgentLauncher`, `policies/mcp.yaml`, `src/saturnin/contracts.py` |
| Public PRs scan the immutable commit tree, including binary bytes, with a checksum-pinned Gitleaks release and exact repository markers, using scanner code and allowlists from the trusted base | `disclosure_gate.sh`, `policies/disclosure.yaml`, `policies/gitleaks.toml` |

Check anything unusual before running it:

```bash
saturnin check command "systemctl --user restart saturnin-janitor.timer"
saturnin check branch feature/whatever
```

Exit code 0 means allowed, 2 means denied. **Do not work around a denial.** If a
gate is wrong, change the policy in a reviewed PR - that is the whole point of
keeping the rules as data.

## Credentials

- The ordinary Saturnin UID uses `gh` only for non-authoritative reads and
  publication. Its credential must not have merge authority. The dedicated
  signer alone receives the root-provisioned encrypted merge credential.
<!-- generated:attestation-boundary -->
The system `saturnin-attestation.service` runs as the non-login `saturnin-signer` identity from root-controlled runtime and configuration. The system manager decrypts current, previous, and bounded retired HMAC credentials into its private credential tmpfs; ordinary workers never receive key material. The service, not PID 1, creates the canonical listener. Clients authenticate its kernel-reported UID plus the stable signer-owned socket directory and endpoint identity; this deliberately avoids cross-UID ptrace-gated `/proc` inspection. Systemd readiness is reported only after protected credential validation and listener creation.

For pull requests the service obtains the live head, author, and exact commit-bound latest review state directly from GitHub over TLS. For issues it recomputes title/body digest and accepts one exact, expiring, nonce-bound machine marker in an allowlisted bot comment. The marker also binds approved labels. Every issue gate is fresh; submission repeats authorization and the signer creates exact reviewed content in an independently allowlisted destination. Evidence expiry limits new authorization, not later audit verification of a durable record. Socket filesystem access permits transport only: independent GitHub authorization remains required. Repository and API origins are fixed allowlists; caller claims and socket credentials are not authority.

Consumed evidence and its exact idempotent attestation are serialized in dedicated state for audit only. Altered reuse fails. Every PR gate obtains a fresh, expiring, one-time protected decision over the live head, base, review ID/state/identity and required checks. Merge repeats that lookup immediately before the signer uses GitHub's expected-head atomic merge API. The signer also requires strict branch protection with stale-review dismissal, required reviews/checks, administrator enforcement and no bypass identities. Its fixed non-admin merge identity and root-provisioned credential never enter the ordinary UID; workers receive neither signing sessions nor credentials.
<!-- /generated:attestation-boundary -->
- Nothing secret belongs in this repository. `board/tasks/`, `var/` and
  checkpoints are gitignored; private material belongs in the private
  companion repositories (ADR-0002).
- `.pre-commit-config.yaml` archives the index tree, while required governance
  CI archives the immutable PR commit. Both scan raw file bytes and report only
  rule, a path digest and line:
  candidate-controlled paths, matched values and raw scanner output are never
  printed. Tracked symlink blobs are scanned as inert regular-file bytes and
  are never followed. Policy and scanner configuration come from the same
  selected index or commit tree and must pass the trusted audit before use.
- Disclosure exceptions are limited to exact line or complete-match digests
  under `tests/fixtures/disclosure/`; regex equivalents are rejected. A PR may
  propose scanner or allowlist changes, but `pull_request_target` validates
  them with base-branch code, executes only base-branch automation, and treats
  the fork or same-repository PR checkout strictly as data.
  Inline `gitleaks:allow` annotations, candidate `.gitleaksignore` files and
  baseline reports cannot suppress findings; only the trusted, digest-bound
  fixture exceptions are active. Custom scanner rules must match the trusted
  rule-ID set and exact definition digests, preventing built-in rule shadowing.
- Private/runtime state stays under ignored `board/` and `var/` paths. External
  private stores are referenced through the generic topology abstractions in
  policy and ADR-0002, never through committed private names or contents.

## Reporting a problem

This is a personal system with a single maintainer. Report a suspected bypass -
a way to merge without review, to push to a protected branch, to escape the
server scope, or to make an agent run a tool its contract forbids - by opening
a private issue in the board repository with the label `saturnin:security`, or
by contacting @jakubmifek directly. Please do not open a public issue with a
working bypass in it.
