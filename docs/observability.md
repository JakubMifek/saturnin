# Observability: how a failing application becomes a task

Polling an application from outside tells you it answered a request. It does not
tell you the queue is backing up, the error rate tripled, or the last deploy
doubled p99 latency. The project's own stack knows all of that already, so the
job is not to build a second monitoring system inside Saturnin - it is to make
sure what that stack notices arrives on the board.

## The pipeline

```
app  ->  Prometheus / Loki  ->  Grafana alert rule  ->  Alertmanager webhook
                                                              |
                                                              v
                                             GitHub issue in the project repo
                                                              |
                                     saturnin discover (every 10 minutes)
                                                              |
                                             board task -> routed -> squad
```

Every hop already exists as a product; Saturnin owns only the last two.

**1. The project emits.** Metrics to Prometheus, logs to Loki. Nothing
Saturnin-specific: this is what the project would do anyway.

**2. Grafana decides.** Alert rules live with the dashboards, in the project's
provisioning, and are reviewed like code. An alert firing is a *judgement about
the system*, which is exactly the thing a curl loop cannot make.

**3. The alert becomes an issue.** This is the part you were unsure about, and
it does work - just not directly. Grafana has no native "create a GitHub issue"
contact point, so the alert goes to a webhook receiver and something turns it
into an issue. Three ways, in ascending order of moving parts:

- **`repository_dispatch`** (recommended). Point the Grafana contact point or
  Alertmanager receiver at
  `https://api.github.com/repos/<owner>/<repo>/dispatches` with a fine-grained
  token that may only dispatch. A workflow in the project repository handles the
  event and calls `gh issue create` with the `alert` label. The token lives in
  Grafana, the logic lives in the project, and GitHub is doing the authoring.
- **Alertmanager webhook to a small local receiver** on the Saturnin host, which
  shells out to `gh`. Fewer round trips, but now Saturnin runs an inbound HTTP
  service, which is a security surface it does not otherwise have.
- **A polling bridge** that reads the Alertmanager API on a timer and opens the
  issue. Slowest, but needs no inbound port at all - a reasonable choice for a
  home server behind NAT.

Whichever is chosen, two properties matter more than the mechanism: the issue
must be **deduplicated** (one issue per firing alert, reopened rather than
duplicated - use the alert fingerprint in the title or body) and it must be
**closed when the alert resolves**, or the board fills with ghosts.

**4. Saturnin adopts it.** `saturnin discover` lists issues in the repositories
named in `policies/repos.yaml` under `discovery.sources`, ignores anything it
has already seen (a `source:<repo>#<n>` label on the task), copies the labels
that matter, maps `incident`/`alert`/`security` to P0, and routes the result
through the normal router. `saturnin-discovery.timer` runs it every ten minutes.
For public intake in `JakubMifek/saturnin`, discovery reads issues labelled
`saturnin` and only adopts them after a maintainer adds `saturnin:trusted`.

The discovery loop is worth having whatever happens upstream: it is also how a
human-filed issue, a failing nightly pipeline or a Dependabot alert reaches the
board. One inbound door, one deduplication rule, one routing table.

## Where the curl monitors fit now

`automation/library/run_monitors.sh` remains, deliberately, but as the
**fallback for projects that have no stack yet** - a new service on day one
deserves a health check before it deserves Grafana. It is honest about its
limits: it proves an endpoint answers, nothing more, and it runs from the
Saturnin host, so it cannot distinguish "the application is down" from "this
machine's network is down".

Rule of thumb: a project with users gets the pipeline; a project with a
`healthz` and three days of history gets the curl loop. Moving from one to the
other is tracked as the `observability-pipeline` gap in
`policies/improvement.yaml`.

## What a project must declare

Nothing extra for the pipeline path beyond existing in
`discovery.sources`. For the fallback path, monitors go in `.saturnin/repo.yaml`
under `monitors:` - see [the managed repository contract](managed-repo-contract.md).

## Failure modes worth knowing

| Symptom | Likely cause |
| --- | --- |
| Alerts fire, no board tasks | the issue label is not in `discovery.labels` |
| The same alert opens a task every ten minutes | the upstream bridge is creating a new issue per evaluation instead of reusing one |
| Tasks appear but stay in intake | discovery ran with `--no-dispatch`, or the router has no rule and the default route is saturated |
| Nothing at all | `gh auth status`; discovery reads issues with your token, and a private project repository needs access |
