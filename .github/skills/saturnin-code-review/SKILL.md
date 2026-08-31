---
name: saturnin-code-review
description: Review guidance for Saturnin pull requests. Use this whenever reviewing a diff in this repository (including automated Copilot code review).
---

Saturnin is governed by code, not prose: `policies/*.yaml` is the source of
truth and `saturnin doctor` fails when anything built on top of it drifts.
When reviewing a change in this repository, check the following before
anything else:

1. **Generated blocks are not hand-edited.** Docs contain
   `<!-- generated:NAME --> ... <!-- /generated:NAME -->` blocks rendered from
   `policies/*.yaml` by `saturnin docs render`. A diff that edits text inside
   one of these blocks by hand is wrong even if the words are correct - the
   fix belongs in the policy file, and `saturnin docs render` regenerates the
   doc. Flag any such edit as blocking.

2. **A rule has exactly one home.** If a PR adds or changes a governance rule,
   role, skill, or other policy fact, it must land in the relevant
   `policies/*.yaml` file, not be typed directly into a doc, agent contract, or
   comment. Duplicated facts are how this repository drifted before (see
   `docs/adr/0004-policy-as-source-of-truth.md`).

3. **Agent/skill contracts stay consistent.** `agents/*.md` front matter
   declares `skills:` that must exist as files in `skills/`, and roles must
   match `policies/routing.yaml`. If a PR adds or renames an agent or skill,
   run `saturnin doctor` and confirm it exits 0 - do not take a passing test
   suite alone as proof.

4. **Board mutations go through the lock.** Any code that reads then writes a
   task JSON file directly, instead of using `Board.edit()`
   (`src/saturnin/board.py`), is a race condition, not a style nit - it must be
   flagged as blocking.

5. **The seven governance rules are load-bearing.** Watch specifically for:
   pushes or merge instructions targeting `main`/`master`/`release` directly;
   automation that runs outside a feature-branch worktree; a PR merged without
   an independent review recorded via `saturnin review record` /
   `saturnin review gate` (author and reviewer must differ, and
   `--with-context` reviews never satisfy the gate); and server-scope changes
   (`apt`, `systemctl`, `su`/`sudo`) that are not scoped to a `saturnin-*`
   service or user-scope timer per `policies/server_scope.yaml`.

6. **Shell scripts in `automation/library/`** must pass `bash -n` and must use
   flags the CLI actually defines - check `src/saturnin/cli.py` rather than
   assuming a flag name (for example, `saturnin escalate` takes repeatable
   `--item`, not `--checklist`; `saturnin task move` defaults `--actor` to
   `ceo`, so automation acting on behalf of a role must pass `--actor`
   explicitly or the history misattributes the work).

Run `python -m pytest` and `saturnin doctor` yourself when the repository
state lets you; do not rely solely on the PR description's claims about test
results.
