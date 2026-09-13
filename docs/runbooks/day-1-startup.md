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

The default installation is non-launching: the task is routed, and `saturnin run
<task-id>` reports `{"disabled": true}` until `policies/mcp.yaml` is configured
for this host. Enable launching only after the worker has an attached feature
branch/worktree, installs and verifies the pinned GitHub MCP server, and checks
that the `copilot`, `npx` and `uvx` prerequisites are installed.

## 4. Do the work in a worktree

```bash
automation/library/new_work_session.sh feature/deploy-migration <task-id> code-worker
cd var/worktrees/feature__deploy-migration
# ... the worker implements, tests, commits, opens a PR ...
saturnin checkpoint save <task-id> --role code-worker \
  --summary "Migration fixed, awaiting review" --next "address review findings"
```

## 5. Review before merge

```bash
HEAD_SHA="$(gh pr view 12 --repo JakubMifek/saturnin --json headRefOid --jq .headRefOid)"
attestation="$(saturnin review attest JakubMifek/saturnin#12 --kind pr \
  --author code-worker --reviewer pr-reviewer --verdict approved \
  --head-sha "$HEAD_SHA")"
saturnin review record JakubMifek/saturnin#12 --kind pr \
  --author code-worker --reviewer pr-reviewer --verdict approved \
  --head-sha "$HEAD_SHA" --attestation "$attestation"
saturnin review gate JakubMifek/saturnin#12 --kind pr \
  --repo JakubMifek/saturnin --author code-worker --head-sha "$HEAD_SHA"
# exit 0 = may merge
```

Resolve the PR head once and pass that identical SHA through attest, record and
gate. Do not substitute a local checkout SHA unless it has just been verified
against the PR head.

For another repository: draft the issue, `--kind issue`, and let the
issue-reviewer gate it before filing.

## 6. Turn on the scheduled workers

```bash
scripts/install_user_units.sh          # user-scope systemd timers
systemctl --user list-timers 'saturnin-*'
```

- `saturnin-janitor.timer` - daily stale worktree/branch cleanup (dry run by
  default; set `APPLY=1` in the unit's environment when you trust it).
- `saturnin-improve.timer` - hourly measure/detect/dispatch cycle.
- `saturnin-poller.timer` - every five minutes, collects results for tasks whose
  answer cannot report back on its own, so nobody ever waits (rule 8).
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
| Every 5 min (timer) | `automation/library/result_poller.sh` | chief-of-staff |
| Every 15 min (timer) | `automation/library/mirror_tasks.sh` | chief-of-staff |
| Every 10 min (timer) | `automation/library/discover_issues.sh` | chief-of-staff |
| Weekly | read `var/reports/`, groom `docs/improvement-backlog.md` | improver |

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
