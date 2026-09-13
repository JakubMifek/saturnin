# ADR-0001: Target durability model after mirroring is enabled

Status: **Proposed** - needs a decision from @jakubmifek on the repository split
(see ADR-0002).
Date: 2026-08-30

## Context

Three questions arrived together in review and turn out to be one question:

1. "Tasks are gitignored. If local untracked data is lost, we have no reference."
2. "We don't have epics and features, only issues. How do we solve this?"
3. "Maybe everything (board, etc.) is just an issue with a different label and
   assignee?"

The board today is one JSON file per task under `board/tasks/`, gitignored.
While mirroring stays disabled, the local board plus configured backups are the
authoritative durability path. It is fast, offline, greppable and needs no
network - which is exactly right for dispatch, and exactly why backups are
required until mirroring is enabled.

The obvious alternative - "just use GitHub Issues for everything" - has the
opposite failure mode. Every dispatch would need a network round trip, the
router would be rate limited, `saturnin doctor` could not run on a plane, and a
GitHub outage would stop the CEO. Rule 8 says the CEO never waits; an API call
per routing decision is waiting.

## Decision

Both, with an explicit direction of authority.

- **Current state while mirroring is disabled:** the local board plus configured
  backups are authoritative.
- **Target state once ADR-0002 is accepted and mirroring is enabled:** every
  task that matters is mirrored as an issue in a dedicated private repository,
  and those issues become the durable system of record.
- **The local board remains a cache and a work queue.** It carries the state
  machine, the history, the dispatch metadata and the locking.
- **The mirror is a background job, not a blocking step** -
  `automation/library/mirror_tasks.sh` plus
  `saturnin task sync --all --push` on demand. The timer and doctor audit stay
  opt-in until ADR-0002 is accepted and the repositories exist.
- **Board metadata travels as labels** (`saturnin:kind/epic`,
  `saturnin:state/in_progress`, `saturnin:role/code-worker`,
  `saturnin:priority/P0`), so the issue list is filterable without any custom
  tooling. This is the "everything is an issue with a different label and
  assignee" idea, applied to the durable copy rather than to the hot path.
- **Hierarchy is native to the board and expressed in the issue body.** Kinds
  are `objective > epic > feature > task`; a child records `parent`, containers
  get a rendered checklist of children and a roll-up
  (`saturnin task tree`, `Board.rollup`). Issue *types* and sub-issues on GitHub
  can carry the same shape later without changing the board model.

## Alternatives considered

- **GitHub Issues only.** Rejected: network in the dispatch path, rate limits,
  no offline operation, and the state machine would have to be reconstructed
  from labels on every read.
- **A database (SQLite/Postgres) as the board.** Rejected for now: it solves a
  concurrency problem we have already solved with `flock`, and it costs the
  property that makes the board debuggable - `cat board/tasks/T-*.json` when
  everything else is on fire.
- **A project management tool (Jira, Linear).** Rejected: another integration to
  keep alive, and none of it is where the code review already happens.

## Consequences

- Losing the server costs a re-sync, not a week of work.
- Two representations exist, so they can disagree; `doctor` is what keeps that
  honest, and the mirror is idempotent by design (the issue body is generated,
  never hand-edited).
- Epics and features are cheap to add but must not become a planning hobby: the
  router only ever dispatches leaf work, and containers exist to make progress
  legible, not to be managed.
- If the board ever needs multi-machine concurrency, this decision is what makes
  swapping the storage layer possible without touching the routing path.
