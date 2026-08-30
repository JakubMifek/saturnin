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

## Holes still open (filed, not fixed here)

1. **JSON Schema for `policies/*.yaml`.** `doctor` validates semantics but not
   structure, so a typo in a key name is only caught if some code happens to
   read it. A schema per policy file plus a `jsonschema` check in `doctor` would
   catch it at the edge. *Medium effort, high value.*
2. **A real evaluation harness.** Aider and SWE-agent both replay recorded
   trajectories to detect regressions in agent behaviour. Saturnin can measure
   its board but cannot yet answer "did that routing change make dispatch
   worse?" other than by watching the metric drift. *High effort, high value -
   the natural next step for the improver role.*
3. **Worktree post-create hooks.** AutoGPT's `.branchlet.json` runs a setup
   command in each new worktree. Saturnin creates the worktree but leaves
   `pip install -e .` to the worker. *Low effort.*
4. **Changelog.** No release notes; `version` in `pyproject.toml` is decorative.
   Worth having once the engine is public. *Low effort.*
5. **Secrets handling.** Saturnin shells out to `gh` and holds no token itself,
   which is right, but there is no documented story for project credentials that
   workers legitimately need. *Needs a human decision.*

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
