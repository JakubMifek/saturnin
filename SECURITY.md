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

Check anything unusual before running it:

```bash
saturnin check command "systemctl --user restart saturnin-janitor.timer"
saturnin check branch feature/whatever
```

Exit code 0 means allowed, 2 means denied. **Do not work around a denial.** If a
gate is wrong, change the policy in a reviewed PR - that is the whole point of
keeping the rules as data.

## Credentials

- Saturnin holds no tokens itself. GitHub access is delegated to the `gh` CLI,
  which owns its own credential storage.
<!-- generated:attestation-boundary -->
During autonomous operation, the master and previous keys are loaded only by `saturnin-attestation.service` in its private mount, network, runtime, and credential namespace. Supervisor and worker units do not load either credential. Explicit owner lifecycle commands may decrypt them in bounded process memory only while the signer and supervisors are stopped.

For a routed reviewer task, the trusted launcher asks the service for a session bound to task, role, author, subject, immutable head or issue digest, a random nonce, and the launched process identity. The session expires after 900 seconds, accepts one signature, and verifies that the connecting process descends from that exact launch. Its Unix socket is bind-mounted only into that reviewer's sandbox; `/run` and `/proc` remain isolated for all workers.

No worker receives a master or derived key in argv, environment, files, descriptors, logs, board data, or Git. Ordinary workers do not receive the session socket. The signed ledger retains only scope, key identifier, nonce, and signature, never plaintext key material.
<!-- /generated:attestation-boundary -->
- Nothing secret belongs in this repository. `board/tasks/`, `var/` and
  checkpoints are gitignored; private material belongs in the private
  companion repositories (ADR-0002).
- `.pre-commit-config.yaml` blocks committed private keys and malformed files.
  Run a full secret scan before pushing changes; if it fires, rotate first and
  clean the history second.

## Reporting a problem

This is a personal system with a single maintainer. Report a suspected bypass -
a way to merge without review, to push to a protected branch, to escape the
server scope, or to make an agent run a tool its contract forbids - by opening
a private issue in the board repository with the label `saturnin:security`, or
by contacting @jakubmifek directly. Please do not open a public issue with a
working bypass in it.
