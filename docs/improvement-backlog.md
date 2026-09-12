# Improvement backlog

The policy-backed list below is filed and tracked by `saturnin improve`.

<!-- generated:backlog -->
| Gap | Severity | Fix |
| --- | --- | --- |
| `review-request-automation` - automate zero-context review requests | warn | Add a policy-aware automation that requests the reviewer and records the resulting GitHub review event. |
| `board-index` - index the board for large installations | info | Maintain a locked board/index.json summary for list and filter operations. |
| `per-role-wip-limits` - enforce per-role WIP limits | warn | Refuse dispatch above the configured role limit and leave work visibly queued. |
| `repeat-detection` - improve repeated-work detection | info | Include task-body similarity when clustering repeated work. |
| `squad-parallelism` - support squad-level parallelism | info | Add a governed integration workflow for parallel workers on one epic. |
| `cost-accounting` - measure cost per role, task and repository | warn | Record model, token counts and elapsed time per dispatch in var/telemetry, surface cost per role in `saturnin board metrics`, and add a spend threshold to policies/improvement.yaml so the loop can flag an expensive role the same way it flags a slow one. |
| `quality-regression-blindspot` - detect quality regressions, not only slow ones | warn | Track review outcomes per role - changes requested, follow-up findings, reverted merges - and treat a rising rejection rate as a finding. |
| `policy-rollback` - make a bad policy change reversible | warn | Version policy changes, keep the previous revision in var/, and add `saturnin policy rollback` plus a dry run that replays the last N dispatches through the proposed routing table. |
| `policy-schema` - validate policy structure with a schema | info | Add a JSON Schema per policy file and validate all of them in `doctor`. |
| `evaluation-harness` - replay dispatches to evaluate a policy change | info | Record dispatch trajectories and replay them against a candidate policy, as Aider and SWE-agent do for agent behaviour. |
| `observability-pipeline` - replace polled monitors with an alerting pipeline | warn | Adopt the Loki/Grafana path in docs/observability.md - projects alert, alerts become issues, the discovery loop turns issues into board tasks - and demote run_monitors.sh to the fallback for projects without a stack. |
| `worktree-post-create-hook` - run project setup when a worktree is created | info | Read a post-create command from the managed repo manifest and run it in new_work_session.sh. |
| `project-credentials` - document how workers obtain project credentials | info | Decide on a secret source (host keyring or pass), document it in SECURITY.md, and give workers a read-only accessor rather than the store. |
<!-- /generated:backlog -->

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
