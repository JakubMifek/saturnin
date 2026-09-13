# ADR-0002: Three repositories - public engine, private board, private notes

Status: **Proposed** - one open question for @jakubmifek, see "Decision needed".
Date: 2026-08-30

## Context

From review:

> On second thought we might want to have a dedicated repository for docs - in
> form of wiki or even better obsidian notes. That way, this repository can
> become public, all our private information either stays uncommitted or is
> placed in wiki - private repository. Tasks need a new home though - a new
> repository as well. Should we create a unique repo for board and tasks/issues
> or should we merge it together with wiki?

Today everything lives here: engine code, policies, agent contracts, docs, and
(gitignored) tasks. That mixture is what prevents the repository from being
public - and the engine is the part most worth publishing.

## Decision

Split by *sensitivity and access pattern*, not by content type. Three
repositories, declared in `policies/repos.yaml` and validated by
`saturnin doctor`:

| Repo | Visibility | Holds | Why separate |
| --- | --- | --- | --- |
| `JakubMifek/saturnin` | public | engine code, policies, agent and skill contracts, runbooks that contain no private detail | It is the reusable part. Public is also a discipline: nothing secret can accumulate here by accident. |
| `JakubMifek/saturnin-ops` | private | mirrored task issues (durable copy once mirroring is enabled), escalation issues | Issues need automation (labels, assignees, timelines) and a real API. A wiki cannot be dispatched from. |
| `JakubMifek/saturnin-notes` | private | long-form notes, project context, Obsidian vault | Notes are written and read by humans, change constantly, and would drown the engine's history in noise. |

### The open question, answered: separate board repo, not merged with the notes

Board and notes look similar (both private, both "content") but behave nothing
alike:

- **Different write patterns.** The board is written by machines, hundreds of
  times a day, through the Issues API. Notes are written by a human in an editor
  and synced as files.
- **Different lifetimes.** A task is hot for days then archival forever. A note
  is edited for years.
- **Different tooling.** Issues need labels, assignees, cross-references and
  search. Obsidian needs plain files, links and no automation churn.
- **Different blast radius.** An automation bug that spams the board repo with
  issues is annoying; the same bug in a notes vault destroys writing.

Merging them means every board automation has commit access to the notes, and
every note sync races the mirror timer. They stay separate.

**Decision needed from @jakubmifek**: confirm the two private repository names
(`saturnin-ops`, `saturnin-notes`) and create them, or say which naming you
prefer. Until they exist, `saturnin task sync` remains a preview/opt-in mirror
path, the mirror timer is not enabled by the installer, and `doctor` does not
make this proposed topology a hard gate.

## Consequences

- This repository can go public once the split lands; the checklist is in
  `docs/runbooks/ops-safety.md`.
- Cross-repo references become the norm: a task issue links to the PR in the
  engine repo; a note links to the task. That is a feature - the links are the
  audit trail.
- Three repositories mean three places to keep in step. `policies/repos.yaml` is
  the single declaration of what lives where, and every managed project repo
  additionally carries its own `.saturnin/repo.yaml`
  (see [`../managed-repo-contract.md`](../managed-repo-contract.md)).
- Anything private that has not moved yet must stay uncommitted. `.gitignore`
  already excludes `board/tasks/`, `var/` and checkpoints.
