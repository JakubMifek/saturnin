# The managed repository contract

> Each project will likely have its own repository, we might want to form some
> sort of contract on what data will the repository contain to make our
> management easier.

A repository that Saturnin manages must be able to explain itself to a worker
that has never seen it before, in one file, in under a minute. That file is
`.saturnin/repo.yaml`. Without it, every dispatch into the project starts with
rediscovery - which is CEO time spent on archaeology.

Validate any repository against the contract:

```bash
saturnin repo check /path/to/project        # exit 0 = compliant, 2 = problems
```

The contract itself is data, in `policies/repos.yaml` under
`managed_repo_contract`, so it can be tightened without touching code.

## Required files

| File | Purpose |
| --- | --- |
| `.saturnin/repo.yaml` | machine-readable project contract (below) |
| `.github/copilot-instructions.md` | what an agent must know before touching this repo |

## `.saturnin/repo.yaml`

```yaml
project:
  name: Widget API
  purpose: Public HTTP API for widget management.

context:
  stack: [python3.12, fastapi, postgres]
  entry_points:
    - src/widget_api/main.py
  run: docker compose up
  test: python -m pytest
  # Anything a newcomer would waste an hour discovering.
  gotchas:
    - Migrations must run before the test suite.

# The roles this project's work usually needs. A starting point for squad
# assembly, not a fixed team - see docs/delegation-policy.md.
squad: [code-worker, test-worker, pr-reviewer]

conventions:
  style: ruff, line length 100
  tests: pytest, 80% branch coverage minimum
  review: no merge without an independent zero-context reviewer
  commits: conventional commits

# Optional: project-specific agent contracts layered on top of agents/.
agents:
  - .saturnin/agents/db-migrator.md

# Optional: MCP servers this project's agents may use, from policies/mcp.yaml.
mcp: [github, filesystem]

# Optional: synthetic monitors, run by automation/library/run_monitors.sh.
monitors:
  - name: health
    url: https://widgets.example.com/healthz
    expect_status: 200
    timeout_seconds: 10
```

## Why each key exists

- **`project` and `context`** answer the review comment "might want to have some
  context on the project as well". A zero-context reviewer is denied the
  *authoring session*, never the *project* - reviewing a diff without knowing
  what the system is for produces theatre, not findings.
- **`squad`** is where ad-hoc squad assembly starts. The project knows whether
  its work usually needs an ops worker; the global default cannot.
- **`conventions`** is what stops every PR review re-deciding house style.
- **`agents`** lets a project ship a role that only makes sense there (a
  migration specialist, a protocol expert) without polluting the global catalog.
  These are layered on top of `agents/`, never replacements for governance.
- **`mcp`** narrows tool access per project, on top of the per-role allow-list.
- **`monitors`** is how a hosted application gets autonomous end-to-end watching
  without any per-project code in Saturnin.

## Onboarding a repository

1. Copy the template above into `.saturnin/repo.yaml` and fill it in honestly -
   an aspirational `test:` command is worse than none.
2. Write `.github/copilot-instructions.md`: what the project is, what an agent
   must never do, how to run and test it. Link to this repository's governance
   rather than restating it (ADR-0004).
3. `saturnin repo check .` until it exits 0.
4. Register the repository in `policies/repos.yaml` if Saturnin should file
   issues there. Remember rule 5: in managed repositories Saturnin may open
   issues, each one independently reviewed first - it never pushes directly.
