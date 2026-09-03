# ADR-0004: Policies are the source of truth; documentation is generated

Status: **Accepted**
Date: 2026-08-30

## Context

From review:

> We seem to have these hard coded in a lot of places. There are a lot of
> duplicities in general across many files. Is that wise? How do we prevent
> drift?

It is not wise, and it was true: the governance rules appeared in
`policies/governance.yaml`, `docs/operating-model.md`,
`.github/copilot-instructions.md` and the README; the role catalog appeared in
`policies/routing.yaml`, `agents/README.md`, `docs/delegation-policy.md` and in
each agent's front matter. Four copies of a rule are four rules, and the one the
agent reads is whichever it happened to open.

Some duplication is genuinely useful: an agent reading `agents/code-worker.md`
should not have to load the whole policy tree to know what it may do. The
problem is not the copy, it is the *unverified* copy.

## Decision

Every fact lives in exactly one policy file. Where a document repeats it, the
repetition is **generated**, not typed:

```markdown
<!-- generated:NAME -->
...regenerated from the policy; never edit by hand...
<!-- /generated:NAME -->
```

(with `NAME` one of the generators below - the real markers are lowercase)

- `saturnin docs render` rewrites every generated block.
- `saturnin docs render --check` exits 2 when a block is stale; `saturnin doctor`
  and CI both run it, so a policy change that does not update the docs fails the
  build.
- Generators available: `rules`, `rules-list`, `roles`, `routing`, `backlog`
  (`src/saturnin/docsync.py`).

For facts that cannot be generated - an agent's prose contract - the *structured*
part is cross-checked instead: `src/saturnin/contracts.py` asserts that every
`agents/*.md` front matter agrees with `policies/routing.yaml` about which roles
exist, their unit, whether they execute, which skills exist, and which MCP
servers they may hold. `saturnin doctor` fails on any disagreement, and
`tests/test_contracts.py` fails in CI.

## Consequences

- Adding a role means editing `policies/routing.yaml` and writing
  `agents/<role>.md`; forgetting either is a failing build rather than a
  confused agent.
- Documentation tables are no longer editable by hand. That surprises humans
  once; the markers say so in place.
- Prose that *interprets* policy (the operating model's explanations, the
  persona) is still hand-written and still capable of drifting. Reviewers are
  asked to treat "prose that restates a rule instead of explaining it" as a
  finding: restate less, link more.
- The same mechanism is available to managed project repositories through
  `.saturnin/repo.yaml`, so a project's own conventions can be generated into
  its instructions file rather than copied.
