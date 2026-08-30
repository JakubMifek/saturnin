# Improvement backlog

Seeded by hand, then maintained by the improvement loop
(`saturnin improve` files a task per finding; the improver promotes recurring
ones here). Ordered by expected effect on throughput per unit of risk.

## Ready

- [ ] **GitHub intake bridge** - poll issues labelled `saturnin:task` in managed
      repos and create board tasks automatically (today: manual `task add`).
- [ ] **Agent launcher** - a `saturnin run <task-id>` that starts the agent named
      by the route with exactly its contracts, instead of a human copy-paste.
- [ ] **Review request automation** - open the PR, request the zero-context
      reviewer and record the verdict from the GitHub review event.
- [ ] **Board index** - a `board/index.json` summary so `task list` stays fast
      past a few thousand tasks.
- [ ] **Per-role WIP limits** - refuse dispatch above the limit and queue instead,
      making overload visible at dispatch time rather than in a weekly metric.

## Investigating

- [ ] **Better repeat detection** - the current signature is a bag of title
      words; cluster on body similarity as well.
- [ ] **Cost/latency telemetry per role** - decide topology changes on money and
      minutes, not only on counts.
- [ ] **Squad-level parallelism** - run several code workers on one epic with a
      shared integration branch.

## Deliberately not doing (yet)

- Autonomous merges in managed repositories - rule 5 stands.
- Any orchestration that lives in GitHub Actions; Actions stay integrations.
- Relaxing the zero-context rule for "small" PRs; small PRs are where mistakes
  hide.

## How an item gets here

1. `saturnin improve` files a finding as a board task.
2. The improver picks the worst bottleneck, proposes exactly one change, and
   records the before/after metric on the task.
3. If the metric moved, the item is closed and noted here. If not, the change is
   reverted and the item returns to *Investigating* with what was learned.
