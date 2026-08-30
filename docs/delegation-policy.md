# Delegation policy and role catalog

The machine-readable source of truth is `policies/routing.yaml`; the behavioural
contracts are in [`../agents/`](../agents/). This page is the human summary.

## Organizational units

A unit is where a role permanently lives. It is an org chart, not a team roster.

<!-- generated:roles -->
| Role | Unit | Executes | Purpose |
| --- | --- | --- | --- |
| `ceo` | command | **never** | Routes, decides, escalates. Never writes code, never runs commands. |
| `chief-of-staff` | command | yes | Keeps the board clean, chases stale work, prepares handoffs. |
| `code-worker` | engineering | yes | Implements changes on a feature branch inside its own worktree. |
| `test-worker` | engineering | yes | Writes and repairs tests, reproduces bugs, owns e2e suites and monitors. |
| `architect` | engineering | yes | Looks across many surgical changes, spots structural drift (scattered APIs, duplicated features, bespoke code where an industry-standard library belongs) and files follow-up tasks for the code worker. |
| `pr-reviewer` | assurance | yes | Reviews a diff with no prior context of the authoring session. |
| `issue-reviewer` | assurance | yes | Reviews issue drafts before they are filed in managed repos. |
| `ops-worker` | operations | yes | Non-root Debian server work inside the Saturnin user scope. |
| `janitor` | operations | yes | Worktree/branch lifecycle, stale cleanup, disk hygiene. |
| `automation-smith` | platform | yes | Turns repeated work into reusable scripts in the automation library. |
| `improver` | platform | yes | Measures throughput, finds bottlenecks, proposes topology/policy upgrades. |
| `scribe` | platform | yes | Docs, runbooks, checkpoints and handoff notes. |
| `researcher` | platform | yes | Investigates options and reports back; no repository writes. |
<!-- /generated:roles -->

## Squads are assembled per task, never predefined

A squad is the crew for **one** task, put together at dispatch by the CEO or the
chief of staff, and dissolved when the task closes. Two tasks that look alike may
need different crews, and that is the point: fixed teams optimise for the average
task, which does not exist.

```bash
# Routing suggests a starting crew; override it whenever the task disagrees.
saturnin dispatch <task-id> --squad code-worker --squad ops-worker --squad pr-reviewer
```

Rules of assembly:

- The lead role is whatever the router picked; it owns the task and the board.
- Add a role only when the task genuinely needs its skill. A spare reviewer is
  not free - it is another context to fill.
- The reviewer is never the author, so a squad never reviews its own work: the
  `pr-reviewer` in a squad list is a *placeholder for an independent instance*,
  dispatched with the diff and the requirement only.
- The CEO is never in a squad. The router refuses to build one that contains it.
- For work inside a managed project repository, start from the squad declared in
  that repository's `.saturnin/repo.yaml` (see
  [`managed-repo-contract.md`](managed-repo-contract.md)) - the project knows
  its own needs better than a global default does.

## Dispatch rules (first match wins)

<!-- generated:routing -->
| Rule | Matches | Goes to | Priority | Results via |
| --- | --- | --- | --- | --- |
| `escalation` | any_label: escalation, blocked, human-needed | `chief-of-staff` | P0 | escalation |
| `incident` | any_keyword: outage, incident, broken, failing, down, hotfix | `code-worker` | P0 | pr-gate |
| `review-pr` | kind: pr-review | `pr-reviewer` | P1 | pr-gate |
| `review-issue` | kind: issue-review | `issue-reviewer` | P1 | board-callback |
| `cleanup` | any_keyword: worktree, stale branch, cleanup, prune, disk | `janitor` | P3 | board-callback |
| `server` | any_keyword: debian, server, systemd, timer, cron, service, apt | `ops-worker` | P2 | board-callback |
| `automation` | any_keyword: automate, script, recurring, repeated, workflow | `automation-smith` | P2 | board-callback |
| `tests` | any_keyword: test, pytest, coverage, flaky | `test-worker` | P2 | board-callback |
| `docs` | any_keyword: docs, documentation, readme, runbook | `scribe` | P3 | board-callback |
| `research` | any_keyword: research, investigate, compare, evaluate | `researcher` | P3 | board-callback |
| `architecture` | any_keyword: architecture, design review, structural, duplication, extract library, technical debt, tech debt | `architect` | P2 | board-callback |
| `improvement` | any_keyword: bottleneck, metric, throughput, improve, refactor process | `improver` | P2 | board-callback |
| `code` | any_keyword: implement, bug, feature, refactor, fix | `code-worker` | P2 | pr-gate |
| _default_ | anything else | `chief-of-staff` | P2 | board-callback |
<!-- /generated:routing -->

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
