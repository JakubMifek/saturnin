# Day 1 - starting Saturnin

Target host: the local Debian server, unprivileged user (`saturnin` in
production, any user for a trial run). Nothing here needs root.

## 1. Install

```bash
git clone https://github.com/JakubMifek/saturnin.git ~/saturnin
cd ~/saturnin
scripts/bootstrap.sh            # venv + package + directories + doctor
source .venv/bin/activate
```

`bootstrap.sh` is idempotent: run it again after every pull.
It now prints companion repositories from `policies/repos.yaml` and, when `gh`
is available, tells you which ones still need `gh repo create`.
Provision `SATURNIN_REVIEW_ATTESTATION_KEY` only in the trusted supervisor
environment (for example CI secrets or a dedicated supervisor shell profile),
never in the repository checkout or worker-authored scripts. The launcher
derives role-scoped signing keys from it and injects them only into
`pr-reviewer` and `issue-reviewer` workers.

## 2. Verify the installation

```bash
saturnin doctor          # exits 0 and prints "Everything is in order, sir."
saturnin board roles     # the catalog, with the CEO marked DELEGATES ONLY
python -m pytest         # the suite must be green before you trust the gates
```

## 3. Accept the first task

```bash
saturnin task add "Fix the failing deploy pipeline" \
  --body "The nightly deploy fails on the migration step." --dispatch
saturnin task list --open
```

The committed default is non-launching: the task is routed, and `saturnin run
<task-id>` reports `{"disabled": true}`. Keep that safe default in
`policies/mcp.yaml`; enable a prepared host through ignored runtime state:

```bash
saturnin launcher status
saturnin launcher enable
```

Enablement succeeds only after version probes pass for `bwrap`, `pasta`,
`copilot`, `npx` and `uvx`, and the installed GitHub MCP server matches the
pinned release and checksum.

<!-- generated:server-prerequisites -->
| Executable | Additional resolved target roots | Script interpreters |
| --- | --- | --- |
| `bwrap` | none | none |
| `pasta` | none | none |
| `copilot` | none | none |
| `npx` | `/usr/share/nodejs/npm` | `node` |
| `uvx` | `/opt/pipx/venvs/uv` | none |

Selected executables, resolved targets, and script interpreters must be owned by **root**; group-writable paths are **forbidden** and world-writable paths are **forbidden**.
Script interpreters are resolved from the fixed system path: `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`.
<!-- /generated:server-prerequisites -->

The host-local file contains only the enablement boolean, lives under
`var/config/`, and is not a credential store. To return to the safe default,
run `saturnin launcher disable`.

The equivalent individually governed probes are:

```bash
saturnin check command "bwrap --version"
saturnin check command "pasta --version"
saturnin check command "copilot --version"
saturnin check command "npx --version"
saturnin check command "uvx --version"
saturnin check command "$PWD/var/bin/github-mcp-server --version"
```

## 4. Do the work in a worktree

```bash
automation/library/new_work_session.sh feature/deploy-migration <task-id> code-worker
cd var/worktrees/feature__deploy-migration
# ... the worker implements, tests, commits, opens a PR ...
saturnin checkpoint save <task-id> --role code-worker \
  --summary "Migration fixed, awaiting review" --next "address review findings"
```

## 5. Review before merge

<!-- generated:pr-review-flow -->
```bash
HEAD_SHA="$(gh pr view <N> --repo JakubMifek/saturnin --json headRefOid --jq .headRefOid)"
VERDICT=approved
attestation="$(saturnin review attest JakubMifek/saturnin#<N> --kind pr \
  --author <author-role> --reviewer pr-reviewer --verdict "$VERDICT" \
  --head-sha "$HEAD_SHA")"
saturnin review record JakubMifek/saturnin#<N> --kind pr \
  --author <author-role> --reviewer pr-reviewer --verdict "$VERDICT" \
  --head-sha "$HEAD_SHA" --attestation "$attestation"
saturnin review gate JakubMifek/saturnin#<N> --kind pr \
  --repo JakubMifek/saturnin --author <author-role> --head-sha "$HEAD_SHA"
```

Resolve the PR head once and pass that identical SHA through attest, record and gate.
<!-- /generated:pr-review-flow -->

For another repository: draft the issue, `--kind issue`, and let the
issue-reviewer gate it before filing.

## 6. Turn on the scheduled workers

```bash
scripts/install_user_units.sh          # user-scope systemd timers
systemctl --user list-timers 'saturnin-*'
```

- `saturnin-janitor.timer` - daily cleanup governed by
  `policies/cleanup.yaml` through `automation/library/cleanup_worktrees.sh`.
- `saturnin-improve.timer` - hourly measure/detect/dispatch cycle.
- `saturnin-poller.timer` - every five minutes, collects results for tasks whose
  answer cannot report back on its own, so nobody ever waits (rule 8).
- `saturnin-resume.timer` - every minute, resumes tasks when delayed checkpoints
  become due.
- `saturnin-mirror.timer` - optional until ADR-0002 is accepted; when enabled,
  mirrors open tasks as GitHub issues so the board survives this machine.
- `saturnin-discovery.timer` - every ten minutes, adopts labelled issues raised
  in managed repositories (alerts, CI, humans) as board tasks. The scaffold
  watches `JakubMifek/saturnin` for `saturnin` issues only after a
  maintainer adds the `saturnin:trusted` label; see [observability](../observability.md).

Timers that must survive logout require systemd user lingering to be provisioned
by the server administrator for the dedicated Saturnin user. This is host-level
setup, not a Saturnin command. Without it, user timers run only while that
user's systemd manager remains active.

## 7. The daily rhythm

| When | Command | Who |
| --- | --- | --- |
| On every request | `saturnin task add ... --dispatch --no-launch` | CEO |
| Hourly (timer) | `automation/library/improvement_cycle.sh` | improver |
| Daily (timer) | `automation/library/cleanup_worktrees.sh` | janitor |
| Every 1 min (timer) | `automation/library/resume_checkpoints.sh` | chief-of-staff |
| Every 5 min (timer) | `automation/library/result_poller.sh` | chief-of-staff |
| Every 15 min (timer) | `automation/library/mirror_tasks.sh` | chief-of-staff |
| Every 10 min (timer) | `automation/library/discover_issues.sh` | chief-of-staff |
| Weekly | read `var/reports/`, groom `policies/improvement.yaml` | improver |

## 8. When something is unclear

Escalate; do not guess:

```bash
saturnin escalate "Need a scoped deploy token" \
  --context "The deploy worker cannot reach the registry." \
  --item "Create a token with registry:write" \
  --unblock "Token in the vault under saturnin/registry" \
  --urgency high --task <task-id> --push
```

Without `--push`, the same command prints a preview instead of filing the issue.
