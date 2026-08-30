# Delegation policy and role catalog

The machine-readable source of truth is `policies/routing.yaml`; the behavioural
contracts are in [`../agents/`](../agents/). This page is the human summary.

## Squads

| Squad | Roles | Owns |
| --- | --- | --- |
| command | `ceo`, `chief-of-staff` | routing, unblocking, escalation |
| engineering | `code-worker`, `test-worker` | code and tests |
| assurance | `pr-reviewer`, `issue-reviewer` | independent, zero-context review |
| operations | `ops-worker`, `janitor` | Debian server, worktree/branch hygiene |
| platform | `automation-smith`, `improver`, `scribe`, `researcher` | tooling, metrics, docs, research |

## Dispatch rules (first match wins)

| Order | Rule | Trigger | Route |
| --- | --- | --- | --- |
| 1 | `escalation` | labels `escalation`, `blocked`, `human-needed` | chief-of-staff, **P0**, escalate |
| 2 | `incident` | outage, incident, broken, failing, down, hotfix | code-worker, P0 |
| 3 | `review-pr` | kind `pr-review` | pr-reviewer, P1 |
| 4 | `review-issue` | kind `issue-review` | issue-reviewer, P1 |
| 5 | `cleanup` | worktree, stale branch, cleanup, prune, disk | janitor, P3 |
| 6 | `server` | debian, server, systemd, timer, cron, service, apt | ops-worker, P2 |
| 7 | `automation` | automate, script, recurring, repeated, workflow | automation-smith, P2 |
| 8 | `tests` | test, pytest, coverage, flaky | test-worker, P2 |
| 9 | `docs` | docs, documentation, readme, runbook | scribe, P3 |
| 10 | `research` | research, investigate, compare, evaluate | researcher, P3 |
| 11 | `improvement` | bottleneck, metric, throughput, improve | improver, P2 |
| 12 | `code` | implement, bug, feature, refactor, fix | code-worker, P2 |
| - | default | anything else | chief-of-staff, P2 |

Check a route without changing anything:

```bash
saturnin dispatch <task-id> --dry-run
```

## Invariants

- **No rule may route to `ceo`.** The router raises, and `saturnin doctor`
  fails, if one ever does. The CEO's inbox is decisions, not work.
- Only roles marked `executes: true` may receive tasks.
- Priorities: `P0` drop-everything, `P1` today, `P2` normal, `P3` when idle.
- Escalation routes to the chief of staff *with the escalate flag*: the CEO
  decided a human is needed; filing the issue is still execution.

## Changing the policy

1. Edit `policies/routing.yaml` (and `agents/<role>.md` for a new role).
2. `saturnin doctor` - must exit 0.
3. PR + independent review, like any other change. Adding or retiring a role
   additionally needs a human sign-off issue.
