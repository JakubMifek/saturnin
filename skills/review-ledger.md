# Skill: review-ledger

## Purpose
Make the independent-review requirement mechanical instead of aspirational.

## Commands
- PR: capture the current head SHA, then pass the same value to
  `saturnin review record <subject> --kind pr ... --head-sha <sha>` and
  either `saturnin review gate <subject> --kind pr ... --head-sha <sha>` or
  `saturnin review merge <subject> --repo <repo> --author <role>`.
- Issue: compute `issue_content_digest(title, body)` and pass it to both
  `saturnin review record <subject> --kind issue ... --issue-digest <digest>`
  and either `saturnin review gate <subject> --kind issue ... --issue-digest <digest>`
  or `saturnin review submit-issue <subject> --repo <repo> --author <role> --title ... --body ...`.

## Guarantees
- Author and reviewer can never be the same role.
- PR merges require an approval from a reviewer that had **zero context**;
  `--with-context` marks a review that cannot satisfy the gate.
- Only the latest verdict per reviewer counts; a `changes_requested` blocks.
- In managed (non-Saturnin) repositories the gate never allows a merge, and
  issue submission requires an independent issue review.

## Exit codes
`0` allowed, `2` blocked - safe to use directly in scripts and CI.
