# AGENTS.md

Orientation for any AI agent working **on** this repository. If you are acting
**as** Saturnin, read [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
first - it is the CEO's operating manual and it outranks this file.

## What this repository is

Saturnin is a delegation-first orchestrator: a CEO that routes work and never
executes it, a catalog of agents that do, and a set of governance rules enforced
by code rather than by good intentions. The runtime is a Python CLI (`saturnin`)
on a local Debian server; GitHub Actions is an integration helper, never the
runtime.

## The rules you cannot argue with

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

Rules live in `policies/governance.yaml`. Changing one is a reviewed PR like any
other change.

## Layout

| Path | What it is |
| --- | --- |
| `src/saturnin/` | the runtime; `cli.py` is the only supported interface |
| `policies/*.yaml` | every rule as data: governance, routing, cleanup, server scope, improvement, repos, mcp |
| `agents/*.md` | one contract per role - mission, procedure, boundaries, escalation |
| `skills/*.md` | reusable capabilities agents may claim |
| `automation/library/*.sh` | reusable scripts, indexed in `automation/registry.yaml` |
| `docs/`, `docs/adr/` | architecture, operating model, runbooks, decisions |
| `board/` | local work board (task JSON is gitignored; issues are the durable copy) |
| `systemd/` | user-scope timers - the actual scheduler |

## Working here

```bash
scripts/bootstrap.sh && source .venv/bin/activate
python -m pytest --cov          # tests plus the 80% branch-coverage floor
saturnin doctor                 # policies, contracts, registry and docs must agree
saturnin docs render            # regenerate policy tables in the docs
```

`saturnin doctor` exits 2 when anything disagrees with anything else. Treat it
as the build: if it is red, the change is not finished.

## House rules for changes

1. **Search before building**: `saturnin automation find "<what you are doing>"`.
   Reinvention is the most expensive habit here.
2. **Never restate a policy in prose.** If a document needs a rule table, use a
   generated block (ADR-0004). Duplicated rules become contradictory rules.
3. **Adding a role** means both `policies/routing.yaml` and `agents/<role>.md`;
   `doctor` fails if they disagree about unit, execution or skills.
4. **Comments explain why, never what.** Extensive in-code commentary is a
   review finding; better names and smaller functions are the fix.
5. **Prefer a well-maintained library** to a bespoke implementation of something
   standard (throttling, retries, parsing, auth).
6. **Keep the diff scoped** to one task; unrelated fixes become new board tasks.
7. **Never commit to `main`.** Work on `feature|fix|chore|docs|automation|experiment/<slug>`
   and let an independent reviewer through the gate before merging.
