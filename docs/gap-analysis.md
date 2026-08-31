# Gap analysis: what comparable systems do, and where Saturnin is thin

Two review comments asked for this: *"Look through other repositories in GitHub
for similar projects. Suggest improvements based on observed practices"* and
*"Find holes in this setup, propose fixes."*

Surveyed: AutoGPT, CrewAI, AutoGen, LangGraph, OpenHands, SWE-agent, MetaGPT,
Aider, smolagents, and the reference MCP servers repository.

## Where Saturnin is already ahead

| Practice | Saturnin | The field |
| --- | --- | --- |
| Escalation | structured GitHub issue with required checklist, urgency and unblock criteria, enforced by `saturnin escalate` | CrewAI, AutoGen and MetaGPT block on `input()`; LangGraph has `interrupt()`. All of them stall a headless server. |
| Config/doc consistency | `saturnin doctor` fails when policy, role catalog, agent contracts, registry and generated docs disagree | usually nothing; AutoGPT regenerates an API schema in a hook |
| Telemetry | dispatch latency, cycle time, WIP per role, blocked ratio, feeding an automatic improvement loop | rare; smolagents has `monitoring.py`, most have none |
| Governance | rules as data, enforced in code, with a review ledger that cannot be satisfied by the author | ad hoc, usually prose in a contributing guide |

The blocking-human-input pattern is the one to keep resisting: it is the single
most common design in the field and the least compatible with a server that must
keep running while nobody is looking (ADR-0003).

## Holes found, and what was done

| Hole | Fix | State |
| --- | --- | --- |
| No `AGENTS.md` at the root - every coding tool looks for it first | added, pointing at the governance rules and the CLI | done |
| Board had no concurrency control; parallel squads could lose updates | `flock` on every write, `Board.edit()` for read-modify-write, documented in `board/README.md` | done |
| No work hierarchy - flat tasks only | `objective > epic > feature > task`, `saturnin task tree`, roll-up progress | done |
| Tasks existed only on one machine | mirrored as GitHub issues, `doctor` fails when open work is unmirrored (ADR-0001) | done |
| Rules duplicated across four documents | generated blocks from policy, checked in `doctor` and CI (ADR-0004) | done |
| No per-agent tool boundary | `policies/mcp.yaml` + per-agent `mcp:` allow-list, validated by `doctor` | done |
| Nothing watched hosted applications | monitors declared per project, `run_monitors.sh`, failures become P0 tasks | done |
| No record of *why* decisions were made | `docs/adr/` | done |
| Nothing prevented malformed policies being committed | `.pre-commit-config.yaml` (yaml/json checks, ruff, secret detection) | done |
| No security model written down | `SECURITY.md` | done |
| Coverage was unmeasured | 80% branch-coverage floor in the test worker contract and CI | done |

## Holes still open

These are not a list in a document - they live in `policies/improvement.yaml`
under `backlog:`, and `saturnin improve` files each one as a board task
(deduplicated by its `finding:<id>` marker) which is then mirrored as an issue
under rule 8. A gap therefore has an owner and a state, and closing one means
deleting its entry from the policy, not editing this table.

<!-- generated:backlog -->
| Gap | Severity | Fix |
| --- | --- | --- |
| `cost-accounting` - measure cost per role, task and repository | warn | Record model, token counts and elapsed time per dispatch in var/telemetry, surface cost per role in `saturnin board metrics`, and add a spend threshold to policies/improvement.yaml so the loop can flag an expensive role the same way it flags a slow one. |
| `quality-regression-blindspot` - detect quality regressions, not only slow ones | warn | Track review outcomes per role - changes requested, follow-up findings, reverted merges - and treat a rising rejection rate as a finding. |
| `policy-rollback` - make a bad policy change reversible | warn | Version policy changes, keep the previous revision in var/, and add `saturnin policy rollback` plus a dry run that replays the last N dispatches through the proposed routing table. |
| `policy-schema` - validate policy structure with a schema | info | Add a JSON Schema per policy file and validate all of them in `doctor`. |
| `evaluation-harness` - replay dispatches to evaluate a policy change | info | Record dispatch trajectories and replay them against a candidate policy, as Aider and SWE-agent do for agent behaviour. |
| `observability-pipeline` - replace polled monitors with an alerting pipeline | warn | Adopt the Loki/Grafana path in docs/observability.md - projects alert, alerts become issues, the discovery loop turns issues into board tasks - and demote run_monitors.sh to the fallback for projects without a stack. |
| `worktree-post-create-hook` - run project setup when a worktree is created | info | Read a post-create command from the managed repo manifest and run it in new_work_session.sh. |
| `project-credentials` - document how workers obtain project credentials | info | Decide on a secret source (host keyring or pass), document it in SECURITY.md, and give workers a read-only accessor rather than the store. |
<!-- /generated:backlog -->

## Anti-patterns deliberately not adopted

- **Blocking human-input agents** (`HumanProxyAgent`, `HumanInputTool`) - they
  deadlock a headless server; rule 9 forbids the shape entirely.
- **Redis or a message bus for agent communication** (MetaGPT) - infrastructure
  for a problem a single-user server does not have.
- **Devcontainers as the production runtime** - the runtime is systemd user
  units on Debian, deliberately.
- **GitHub auto-merge** - it would bypass the independent review gate, which is
  the one thing that must never be bypassed.
- **Monorepo with sub-packages** (AutoGen, LangGraph) - Saturnin is one small
  package; splitting it would buy nothing but import paths.
