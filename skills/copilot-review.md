# Skill: copilot-review

## Purpose
Use GitHub's built-in Copilot code review as a fast, always-available
first pass on a PR, without letting it stand in for the independent review
the merge gate requires.

## Commands
- `gh pr comment <pr> --body "@copilot review"` - request or re-request a
  review; use only after pushing at least one commit since the last request.
- Read findings via the `github` MCP server: `pull_request_read` with
  `get_reviews` (the verdict) and `get_review_comments` (the per-line
  findings, each with an id).
- Reply to a specific finding once, after it is addressed, quoting the commit
  that fixes it; never leave a finding unaddressed and unanswered.

## Guarantees
- Copilot's review is a pre-screen, not the reviewer of record: it never
  satisfies `saturnin review gate` and it is never the `--reviewer` recorded
  by `review-ledger`.
- Every blocking finding it raises gets either a fix or a stated reason for
  disagreement before the independent reviewer is asked in.
- Handing the diff to `pr-reviewer` happens after Copilot's findings are
  resolved, so the zero-context human reviewer is not repeating triage work
  a bot already did.

## Refusals
- Requesting a fresh review before addressing (or explicitly rejecting) the
  findings from the previous one.
- Treating a "no changes needed" Copilot pass as a recorded verdict - only
  `saturnin review record` puts a verdict on the ledger.
