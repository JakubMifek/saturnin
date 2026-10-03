# Agent catalog

Each file in this directory defines one replaceable agent. An agent definition
is a contract, not a personality: mission, inputs, allowed actions, procedure,
definition of done, and escalation path. Swap a file, and the role changes -
nothing else in the system has to move.

<!-- generated:roles -->
| Role | Unit | Executes | Purpose |
| --- | --- | --- | --- |
| `ceo` | command | **never** | Routes, decides, escalates. Never writes code, never runs commands. |
| `chief-of-staff` | command | yes | Keeps the board clean, chases stale work, prepares handoffs. |
| `code-worker` | engineering | yes | Implements changes on a feature branch inside its own worktree. |
| `test-worker` | engineering | yes | Writes and repairs tests, reproduces bugs, owns e2e suites and monitors. |
| `architect` | engineering | yes | Looks across many surgical changes, spots structural drift (scattered APIs, duplicated features, bespoke code where an industry-standard library belongs) and files follow-up tasks for the code worker. |
| `pr-reviewer` | assurance | yes | Reviews a diff with no prior context, including private-vault integrity checks. |
| `issue-reviewer` | assurance | yes | Reviews issue drafts before they are filed in managed repos. |
| `ops-worker` | operations | yes | Non-root Debian server work inside the Saturnin user scope. |
| `janitor` | operations | yes | Worktree/branch lifecycle, stale cleanup, disk hygiene. |
| `automation-smith` | platform | yes | Turns repeated work into reusable scripts in the automation library. |
| `improver` | platform | yes | Measures throughput, finds bottlenecks, proposes topology/policy upgrades. |
| `scribe` | platform | yes | Sole writer and curator of the private notes vault; owns durable documentation. |
| `researcher` | platform | yes | Investigates options and reports back; no repository writes. |
<!-- /generated:roles -->

The table above is generated from `policies/routing.yaml` by
`saturnin docs render`; `saturnin doctor` fails if this file, the role catalog
and the agent front matter disagree about which roles exist, which unit they
belong to, or the CEO's delegation-only status.

`unit` is a permanent organizational home, **not** a squad. Squads are put
together per task by the CEO or the chief of staff out of whatever roles that
task needs - see [`../docs/delegation-policy.md`](../docs/delegation-policy.md).

## Skills

Skills are shared, reusable capabilities that several agents may claim. Their
contracts are in [`../skills/`](../skills/). An agent may only use a skill it
lists in its own definition.
