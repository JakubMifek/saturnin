# ADR-0003: The CEO never waits for a worker

Status: **Accepted**
Date: 2026-08-30

## Context

From review:

> Saturnin must not wait for worker resolution. It is rather desired to just
> dispatch the worker and then describe how results are to be gathered OR fire
> another worker to add an automation to poll for results periodically and
> trigger Saturnin when done. We do not want to stall the thread just waiting
> for results under any circumstances.

The original loop said "track: the worker moves the task", which is technically
non-blocking but leaves the obvious failure open: when nothing reports back on
its own, the natural move is to wait and check. A waiting CEO is a stopped
queue, and the whole system exists to keep that queue moving.

## Decision

Waiting is a governance violation, not a style preference. It is **rule 8** in
`policies/governance.yaml`, enforced in code by
`Governance.check_result_contract` and applied at dispatch by the router.

Every dispatch names how the result will arrive:

| Contract | Result arrives when | Who builds it |
| --- | --- | --- |
| `board-callback` | the worker moves the task itself; Saturnin sees it on the next board sweep | nobody - it is the default |
| `pr-gate` | the review verdict satisfies `saturnin review gate --kind pr --head-sha <sha>` | the reviewer |
| `poller` | a scheduled probe detects the external signal and pushes the task forward | **a dispatched worker**, never the CEO |
| `escalation` | a human answers the escalation issue | the chief of staff |

The `poller` contract is the important one: when nothing in our control will
report back (a long external build, a third-party deployment, someone else's
review), Saturnin does not watch it. It dispatches a worker to register a
declarative `status-file` probe through `saturnin poller register`; the trusted
worker callback installs `var/pollers/<task-id>.json`, and the
`saturnin-poller` timer runs `automation/library/result_poller.sh` every five
minutes, re-reading the signal file and moving the task to `review` or
`blocked` on the worker's behalf.

Building the poller is itself work, so it is delegated too. The CEO's
involvement in any task ends at dispatch.

## Consequences

- Dispatch stays O(1) in CEO time regardless of how long the work takes.
- Every long-running integration gains a reusable probe; after three of them the
  automation smith turns the pattern into a library entry, as usual.
- A task with no plausible result contract is a signal that the work is not
  actually delegable yet - that is an intake defect, and the chief of staff
  clarifies it.
- The board sweep (`saturnin task list --open`, `saturnin board metrics`)
  replaces "checking on" anybody. If a result never arrives, the improvement
  loop notices the stalled task, not the CEO's memory.
