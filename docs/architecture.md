# Architecture

Saturnin is a small, boring core with replaceable parts. Everything that could
be a policy is a YAML file; everything that could be repeated is a script;
everything else is a thin Python module with tests.

```
                 human request / GitHub / cron
                              |
                     +--------v---------+
                     |   Task intake    |  saturnin task add
                     +--------+---------+
                              |
                     +--------v---------+   policies/routing.yaml
                     |   Router (CEO)   |   table lookup, <60s, no execution
                     +--------+---------+
        +---------------------+----------------------+
        |            |            |         |        |
   code-worker  test-worker  ops-worker  janitor  automation-smith ...
        |            |            |         |        |
   git worktree per worker (feature branches, parallel)
        |
   +----v-----+   independent, zero-context
   | reviewer |   saturnin review record / gate
   +----+-----+
        |
   merge (this repo only) | issue draft -> issue-reviewer -> file in managed repo
        |
   +----v---------+   board metrics -> bottlenecks -> one change at a time
   | improvement  |   saturnin improve  (scheduled)
   +--------------+
```

## Components

| Component | Module | Responsibility |
| --- | --- | --- |
| Work board | `saturnin/board.py` | One JSON file per task, validated state machine, full history. |
| Router | `saturnin/routing.py` | First-match dispatch, refuses to route work to the CEO. |
| Governance | `saturnin/governance.py` | Branch, push, merge, issue and server-command gates. |
| Review ledger | `saturnin/review.py` | Append-only review verdicts; latest per reviewer wins. |
| Worktrees | `saturnin/worktrees.py` | Create/list worktrees, plan and apply stale cleanup. |
| Checkpoints | `saturnin/checkpoints.py` | Handoff notes and delayed resume. |
| Automation | `saturnin/automation.py` | Registry search + repeat detection. |
| Telemetry | `saturnin/telemetry.py` | Dispatch latency, cycle time, WIP, blocked ratio. |
| Improvement | `saturnin/improve.py` | Bottleneck findings -> board tasks + JSON reports. |
| Escalation | `saturnin/escalation.py` | Well-formed human escalation bodies. |
| Locking | `saturnin/locking.py` | Cooperative `flock` so parallel squads cannot lose board updates. |
| Issue mirror | `saturnin/issues.py` | Renders and pushes the GitHub issue that makes a task durable (rule 8). |
| Discovery | `saturnin/discovery.py` | The inbound door: adopts labelled issues from managed repositories - alerts, CI, humans - as routed board tasks, deduplicated by a `source:<repo>#<n>` label. |
| Contracts | `saturnin/contracts.py` | Cross-checks `agents/*.md` front matter against the role catalog and MCP policy. |
| Doc sync | `saturnin/docsync.py` | Regenerates policy tables inside the docs; fails the build on drift. |
| CLI | `saturnin/cli.py` | The only supported interface for agents and humans. |

## Storage layout

```
policies/     rules (governance, routing, cleanup, server scope, improvement)
agents/       one contract per role
skills/       shared capability contracts
automation/   registry.yaml + library/*.sh
board/tasks/       T-YYYYMMDD-xxxxxx.json      (runtime, gitignored)
board/checkpoints/ <task-id>.jsonl             (runtime, gitignored)
board/reviews/     <kind>-<subject>.jsonl      (runtime, gitignored)
var/worktrees/     one directory per feature branch
var/logs/          janitor.log and friends
var/reports/       improvement-<timestamp>.json
systemd/           user units for the scheduled workers
```

State is plain text on purpose: it survives crashes, diffs well, and can be
inspected with `cat` when everything else is on fire.

## Runtime

The primary runtime is the local Debian server, running as the unprivileged
`saturnin` user with systemd **user** timers (`systemd/`). GitHub Actions is an
integration helper only: it runs the test suite and the review gate on PRs; it
never owns state and never schedules the orchestrator.

## Extension points

- **New role**: add `agents/<role>.md` + an entry in `policies/routing.yaml`.
- **New routing behaviour**: add a rule; rules are ordered, first match wins.
- **New automation**: add a script to `automation/library/` + registry entry.
- **New policy**: add a YAML file and read it via `Config.policy("<name>")`.
- **New scheduled worker**: add a `systemd/saturnin-*.{service,timer}` pair.

`saturnin doctor` validates all of the above and exits `2` if the parts disagree.
