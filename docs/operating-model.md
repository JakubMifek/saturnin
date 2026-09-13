# Operating model

## 1. Delegation first

The CEO's only outputs are decisions: *what* is the task, *who* gets it, *is it
blocked*. Execution is always somebody else's job, even when doing it directly
would be faster in the moment. Fast dispatch beats fast execution, because a CEO
that executes stops routing, and a queue forms behind it.

Budget: **60 seconds and 3 deliberation steps** per dispatch
(`policies/governance.yaml: delegation`). If a task cannot be classified in that
time it goes to the chief of staff, who clarifies it - not to the CEO's own hands.

## 2. Task lifecycle

```
intake --dispatch--> routed --> in_progress --> review --> done
   \                   \            \             \
    cancelled           blocked <----+-------------+
```

- Every transition is recorded with actor, timestamp and note.
- `blocked` always has an escalation issue attached.
- Anything interruptible carries a checkpoint before it pauses.

## 3. Governance

<!-- generated:rules -->
| # | Rule | Enforced by |
| --- | --- | --- |
| 1 | Never push to the default branch | `saturnin push` |
| 2 | Feature branches plus one worktree per parallel worker | `saturnin worktree create` |
| 3 | Every code PR is reviewed by an independent zero-context reviewer | `saturnin review gate --kind pr` |
| 4 | Autonomous PR flow in this repository once that review passed | `autonomy.self_repo_autonomous_merge` |
| 5 | Managed repos: issues allowed, each independently reviewed first | `saturnin review gate --kind issue` |
| 6 | Human escalation via a GitHub issue tagging `@jakubmifek` | `saturnin escalate` |
| 7 | Server: non-root; apt/systemctl only for Saturnin services; user-scope timers | `saturnin check command` |
| 8 | The CEO never waits for a worker; every dispatch names a result contract | `Governance.check_result_contract`, `saturnin dispatch` |
<!-- /generated:rules -->

Rules live in `policies/governance.yaml` and `policies/server_scope.yaml`. They
are code: changing them is a PR that needs the same independent review.

The table above is **generated** from `policies/governance.yaml` - as is every
other rule, role and routing table in this repository. Nothing that exists in a
policy file is re-typed into prose; `saturnin docs render` regenerates the
blocks and `saturnin doctor` (and CI) fail if the checked-in text disagrees with
the policy. That is how a system with this many documents avoids drifting into
fiction.

## 4. Independent review

"Independent" means a different role than the author. "Zero context" means the
reviewer never sees the authoring session - only the requirement and the diff.
The ledger enforces both mechanically; a reviewer who *did* have context must
record it with `--with-context`, and such an approval cannot satisfy the gate.

## 5. Squads, parallelism and context

Squads are assembled per task and dissolved when it closes; `unit` in the role
catalog is an org chart, not a team roster
([delegation-policy.md](delegation-policy.md)).

One task, one branch, one worktree. Workers never share a checkout, so several
squads run at once without stepping on each other; the only shared resource is
the board, and every write there takes a lock
([board/README.md](../board/README.md)). The janitor removes the remains on a
schedule; it refuses to touch anything dirty, protected or attached to an open
task.

Context is rationed, not withheld. A worker gets its own contract, its skills,
the task, and the project's `.saturnin/repo.yaml` - stack, entry points, how to
run and test it, house conventions
([managed-repo-contract.md](managed-repo-contract.md)). A zero-context reviewer
is denied the *authoring session*, never the project: reviewing a diff without
knowing what the system is for produces theatre, not findings.

## 6. Automation and anti-reinvention

- Search the library before building: `saturnin automation find "<intent>"`.
- Three occurrences of the same work = an automation task, filed automatically.
- Scripts are idempotent, argument-driven, dry-run by default when destructive,
  and registered so the next search finds them.

## 7. Continuous self-improvement

`saturnin improve` runs on a timer:

1. **Measure** - dispatch latency, cycle time, WIP per role, blocked ratio,
   intake backlog, oldest open task.
2. **Detect** - compare against `policies/improvement.yaml`.
3. **Change one thing** - a routing rule, a threshold, a script, or the agent
   topology. Every change is a reviewed PR.
4. **Verify** - record the metric before and after in the task. If it did not
   move, revert.

No metric may ever be improved by weakening a governance rule.

## 8. Escalation

An escalation issue always contains: a checklist of what the human must do, an
urgency, and unblock criteria that say exactly what "answered" looks like.
Saturnin never idles while waiting - the blocked task is parked, everything else
continues.
