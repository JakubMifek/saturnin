# ADR index

Decisions that were expensive to reach and would otherwise be re-litigated every
few weeks. One file per decision, numbered, never deleted - a reversed decision
gets a new ADR that supersedes the old one, so the reasoning survives.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-system-of-record.md) | GitHub Issues are the system of record; the board is a fast cache | Proposed |
| [0002](0002-repository-topology.md) | Three repositories: public engine, private board, private notes | Proposed |
| [0003](0003-non-blocking-dispatch.md) | The CEO never waits for a worker | Accepted |
| [0004](0004-policy-as-source-of-truth.md) | Policies are the source of truth; documentation is generated | Accepted |

Template:

```markdown
# ADR-000N: <decision in one line>

Status: Proposed | Accepted | Superseded by ADR-000M
Date: YYYY-MM-DD

## Context
What forced the decision. Include the constraint that makes the obvious answer wrong.

## Decision
What we do. Concrete enough to check against the code.

## Alternatives considered
What was rejected and why - this is the part future readers actually need.

## Consequences
What this costs, and what becomes possible or impossible.
```

Who writes one: the architect for structural decisions, the improver when a
policy or topology change is proposed, the scribe on request. A decision that
changes a governance rule needs the same independent review as any other diff.
