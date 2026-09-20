# Skills

A skill is a capability contract: the commands it owns, its inputs, its
guarantees and its refusals. Agents declare the skills they may use in their
front matter; anything not declared is out of scope for that agent.

| Skill | Owned commands | Used by |
| --- | --- | --- |
| [board-ops](board-ops.md) | `saturnin task`, `saturnin dispatch`, `saturnin board` | most roles |
| [worktree-session](worktree-session.md) | `saturnin worktree`, `new_work_session.sh` | code/test workers, janitor, smith |
| [checkpointing](checkpointing.md) | `saturnin checkpoint` | every long-running role |
| [review-ledger](review-ledger.md) | `saturnin review` | reviewers, PR authors |
| [escalation](escalation.md) | `saturnin escalate` | CEO, chief of staff |
| [automation-library](automation-library.md) | `saturnin automation` | automation smith, improver |
| [server-scope](server-scope.md) | `saturnin check command` | ops worker, janitor |
| [pr-authoring](pr-authoring.md) | git + gh, gated by `saturnin review gate` | authoring roles |
