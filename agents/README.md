# Agent catalog

Each file in this directory defines one replaceable agent. An agent definition
is a contract, not a personality: mission, inputs, allowed actions, procedure,
definition of done, and escalation path. Swap a file, and the role changes -
nothing else in the system has to move.

| Agent | Role id | Squad | Executes? |
| --- | --- | --- | --- |
| [`ceo.md`](ceo.md) | `ceo` | command | **No - delegates only** |
| [`chief-of-staff.md`](chief-of-staff.md) | `chief-of-staff` | command | yes |
| [`code-worker.md`](code-worker.md) | `code-worker` | engineering | yes |
| [`test-worker.md`](test-worker.md) | `test-worker` | engineering | yes |
| [`pr-reviewer.md`](pr-reviewer.md) | `pr-reviewer` | assurance | yes (zero-context) |
| [`issue-reviewer.md`](issue-reviewer.md) | `issue-reviewer` | assurance | yes (zero-context) |
| [`ops-worker.md`](ops-worker.md) | `ops-worker` | operations | yes |
| [`janitor.md`](janitor.md) | `janitor` | operations | yes |
| [`automation-smith.md`](automation-smith.md) | `automation-smith` | platform | yes |
| [`improver.md`](improver.md) | `improver` | platform | yes |
| [`scribe.md`](scribe.md) | `scribe` | platform | yes |
| [`researcher.md`](researcher.md) | `researcher` | platform | yes |

The machine-readable half of this catalog lives in `policies/routing.yaml`;
`saturnin doctor` fails if the two disagree about which roles exist or about the
CEO's delegation-only status.

## Skills

Skills are shared, reusable capabilities that several agents may claim. Their
contracts are in [`../skills/`](../skills/). An agent may only use a skill it
lists in its own definition.
