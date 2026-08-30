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

The task is routed the moment it is created. Start the agent named by the route
(`agents/<role>.md`) with the task body and its skill contracts.

## 4. Do the work in a worktree

```bash
automation/library/new_work_session.sh feature/deploy-migration <task-id>
cd var/worktrees/feature__deploy-migration
# ... the worker implements, tests, commits, opens a PR ...
saturnin checkpoint save <task-id> --role code-worker \
  --summary "Migration fixed, awaiting review" --next "address review findings"
```

## 5. Review before merge

```bash
saturnin review record JakubMifek/saturnin#12 --kind pr \
  --author code-worker --reviewer pr-reviewer --verdict approved
saturnin review gate JakubMifek/saturnin#12 --kind pr \
  --repo JakubMifek/saturnin --author code-worker   # exit 0 = may merge
```

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
  answer cannot report back on its own, so nobody ever waits (rule 9).
- `saturnin-mirror.timer` - every fifteen minutes, mirrors open tasks as GitHub
  issues so the board survives this machine (rule 8).

Without a login session, keep the timers alive across logouts:
`loginctl enable-linger $USER`.

## 7. The daily rhythm

| When | Command | Who |
| --- | --- | --- |
| On every request | `saturnin task add ... --dispatch` | CEO |
| Hourly (timer) | `automation/library/improvement_cycle.sh` | improver |
| Daily (timer) | `automation/library/cleanup_worktrees.sh` | janitor |
| Every 5 min (timer) | `automation/library/result_poller.sh` | chief-of-staff |
| Every 15 min (timer) | `automation/library/mirror_tasks.sh` | chief-of-staff |
| Weekly | read `var/reports/`, groom `docs/improvement-backlog.md` | improver |

## 8. When something is unclear

Escalate; do not guess:

```bash
saturnin escalate "Need a scoped deploy token" \
  --context "The deploy worker cannot reach the registry." \
  --item "Create a token with registry:write" \
  --unblock "Token in the vault under saturnin/registry" \
  --urgency high --task <task-id>
```

Open the printed body as a GitHub issue with the label `saturnin:escalation`.
