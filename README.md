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
| Work hierarchy (objective/epic/feature/task) | `saturnin task tree`, `--parent` |
| Durable copy of every task as a GitHub issue | `saturnin task sync --all --push` |
| Ultra-fast dispatch (table lookup, no deliberation) | `saturnin dispatch <id> \| --all` |
| Governance gates (branches, merges, issues, server) | `saturnin check branch\|command` |
| Independent PR/issue review pipelines | `saturnin review record\|gate` |
| Checkpoints, handoff and delayed resume | `saturnin checkpoint save\|resume` |
| Worktree lifecycle + safe stale cleanup | `saturnin worktree create\|list\|cleanup` |
| Reusable automation library + repeat detection | `saturnin automation find\|list\|detect` |
| Human escalation issues | `saturnin escalate` |
| Continuous self-improvement loop | `saturnin improve`, `saturnin board metrics` |
| Managed-repo contract validation | `saturnin repo check <path>` |
| Documentation generated from policy | `saturnin docs render [--check]` |

## Governance in one screen

<!-- generated:rules-list -->
1. Never push to the default branch.
2. Feature branches plus one worktree per parallel worker.
3. Every code PR is reviewed by an independent zero-context reviewer.
4. Autonomous PR flow in this repository once that review passed.
5. Managed repos: issues allowed, each independently reviewed first.
6. Human escalation via a GitHub issue tagging `@jakubmifek`.
7. Server: non-root; apt/systemctl only for Saturnin services; user-scope timers.
8. Every task is mirrored as a GitHub issue, so losing this machine costs nothing.
9. The CEO never waits for a worker; every dispatch names a result contract.
<!-- /generated:rules-list -->

The rules are machine-readable in [`policies/`](policies) and enforced by
`saturnin` itself. The list above is generated from `policies/governance.yaml`:
nothing that lives in a policy is re-typed into prose, and `saturnin doctor`
fails if code, policy, agent contracts or documentation disagree
([ADR-0004](docs/adr/0004-policy-as-source-of-truth.md)).

## Layout

```
AGENTS.md                         orientation for agents working on this repo
.github/copilot-instructions.md   how Saturnin (the CEO) must behave
agents/                           one contract per role, replaceable
skills/                           shared capability contracts
policies/                         governance, routing, cleanup, server scope, improvement
automation/                       registry.yaml + reusable library scripts
board/                            tasks, checkpoints, review verdicts (runtime)
docs/                             architecture, operating model, persona, runbooks
docs/adr/                         decisions worth not re-litigating
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
