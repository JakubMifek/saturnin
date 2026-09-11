# Improvement backlog

Seeded by hand, then maintained by the improvement loop
(`saturnin improve` files a task per finding; the improver promotes recurring
ones here). Ordered by expected effect on throughput per unit of risk.

## Ready

- [ ] **Review request automation** - open the PR, request the zero-context
      reviewer and record the verdict from the GitHub review event.
- [ ] **Board index** - a `board/index.json` summary so `task list` stays fast
      past a few thousand tasks.
- [ ] **Per-role WIP limits** - refuse dispatch above the limit and queue instead,
      making overload visible at dispatch time rather than in a weekly metric.

## Investigating

- [ ] **Better repeat detection** - the current signature is a bag of title
      words; cluster on body similarity as well.
- [ ] **Squad-level parallelism** - run several code workers on one epic with a
      shared integration branch.
- [ ] **Evaluation harness** - replay recorded dispatches so a routing or policy
      change can be judged before it ships, instead of by watching the metric
      drift afterwards (see [gap-analysis.md](gap-analysis.md)).
- [ ] **Worktree post-create hook** - install the package and dev tooling in a
      new worktree automatically, rather than leaving it to the worker.

## Deliberately not doing (yet)

- Autonomous merges in managed repositories - rule 5 stands.
- Any orchestration that lives in GitHub Actions; Actions stay integrations.
- Relaxing the zero-context rule for "small" PRs; small PRs are where mistakes
  hide.

## Work hierarchy

Epics and features exist now: task kinds are `objective > epic > feature > task`,
with `--parent`, `saturnin task tree` and roll-up progress. Only leaf work is
dispatched - containers make progress legible, they are not a planning ritual.
Why the board keeps its own hierarchy instead of leaning entirely on GitHub is
[ADR-0001](adr/0001-system-of-record.md).

## How an item gets here

1. `saturnin improve` files a finding as a board task **and** the mirror files it
   as a GitHub issue (rule 8) - a finding that lives only on one server is a
   finding that will be lost. Issues carry the board metadata as labels
   (`saturnin:kind/improvement`, `saturnin:state/...`), which is the practical
   form of "everything is an issue with a different label and assignee":
   dispatch stays local and fast, durability and human review happen on GitHub.
2. The improver picks the worst bottleneck, proposes exactly one change, and
   records the before/after metric on the task.
3. If the metric moved, the item is closed and noted here. If not, the change is
   reverted and the item returns to *Investigating* with what was learned.
