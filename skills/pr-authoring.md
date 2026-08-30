# Skill: pr-authoring

## Purpose
Produce a diff somebody else can review quickly and merge safely.

## Procedure
1. Branch and worktree via `worktree-session`; never work in the main checkout.
2. Small, single-purpose commits; unrelated findings become new board tasks.
3. PR body: problem, change, verification, risk. No narrative about the session.
4. Ask for the independent reviewer; record the verdict with `review-ledger`.
5. Merge only when `saturnin review gate ... --kind pr` exits `0`, and only in
   this repository. Elsewhere: hand the branch or file an issue.

## Refusals
- Pushing to `main`/`master`/`release`.
- Merging your own change, or merging with an open `changes_requested`.
