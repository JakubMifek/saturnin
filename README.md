# Saturnin

> "Saturnin belonged to that minority of people who, when handed a plate of
> doughnuts, actually throw them." - after Zdeněk Jirotka, *Saturnin* (1942)

Saturnin is a delegation-first autonomous orchestrator for personal engineering
operations: my project repositories and my local Debian server. It is named
after Jirotka's manservant - resourceful, unflappable, quietly subversive, and
absolutely certain that his employer's time is too precious to be spent on chores.

**The CEO does no execution work. Ever.** Saturnin routes; assistants,
specialists and workers do the work.

## Quick start

```bash
git clone https://github.com/JakubMifek/saturnin.git ~/saturnin
cd ~/saturnin && scripts/bootstrap.sh && source .venv/bin/activate

saturnin doctor                                  # policies healthy?
saturnin task add "Fix the nightly deploy" --dispatch
saturnin task list --open
```

Full walkthrough: [`docs/runbooks/day-1-startup.md`](docs/runbooks/day-1-startup.md).

## What it does

| Capability | Command |
| --- | --- |
| Task intake + centralised board | `saturnin task add\|list\|show\|move\|attach` |
| Ultra-fast dispatch (table lookup, no deliberation) | `saturnin dispatch <id> \| --all` |
| Governance gates (branches, merges, issues, server) | `saturnin check branch\|command` |
| Independent PR/issue review pipelines | `saturnin review record\|gate` |
| Checkpoints, handoff and delayed resume | `saturnin checkpoint save\|resume` |
| Worktree lifecycle + safe stale cleanup | `saturnin worktree create\|list\|cleanup` |
| Reusable automation library + repeat detection | `saturnin automation find\|list\|detect` |
| Human escalation issues | `saturnin escalate` |
| Continuous self-improvement loop | `saturnin improve`, `saturnin board metrics` |

## Governance in one screen

1. Never push to the default branch.
2. Feature branches plus one git worktree per parallel worker.
3. Every code PR is reviewed by an independent **zero-context** reviewer agent.
4. In this repository, PRs may be opened and merged autonomously after that review.
5. In other managed repositories: issues only, and each draft passes an
   independent issue reviewer first.
6. Blocked? A GitHub issue tagging `@jakubmifek` with checklist, urgency and
   unblock criteria - never silence.
7. Server: non-root only; `apt`/`systemctl` only for Saturnin-dedicated services;
   timers and cron only in the Saturnin user scope.

The rules are machine-readable in [`policies/`](policies) and enforced by
`saturnin` itself; `saturnin doctor` fails if code and policy disagree.

## Layout

```
.github/copilot-instructions.md   how Saturnin (the CEO) must behave
agents/                           one contract per role, replaceable
skills/                           shared capability contracts
policies/                         governance, routing, cleanup, server scope, improvement
automation/                       registry.yaml + reusable library scripts
board/                            tasks, checkpoints, review verdicts (runtime)
docs/                             architecture, operating model, persona, runbooks
scripts/, systemd/                bootstrap and the scheduled workers
src/saturnin/, tests/             the implementation and its tests
```

## Runtime

Primary runtime is the local Debian server, as an unprivileged user with
systemd **user** timers (`saturnin-janitor`, `saturnin-improve`). GitHub Actions
is only an integration helper: tests, policy health and the branch gate on PRs.

## Documentation

- [Architecture](docs/architecture.md)
- [Operating model](docs/operating-model.md)
- [Persona](docs/persona-saturnin.md)
- [Delegation policy and role catalog](docs/delegation-policy.md)
- [Day-1 startup](docs/runbooks/day-1-startup.md) ·
  [Ops and safety](docs/runbooks/ops-safety.md) ·
  [Checkpoint and handoff](docs/runbooks/checkpoint-handoff.md)
- [Improvement backlog](docs/improvement-backlog.md)

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
saturnin doctor
```
