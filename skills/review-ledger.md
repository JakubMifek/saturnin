# Skill: review-ledger

## Purpose
Make the independent-review requirement mechanical instead of aspirational.

## Commands
- `saturnin review record <subject> --kind pr|issue --author <role> --reviewer <role> --verdict approved|changes_requested|rejected [--notes ...] [--with-context]`
- `saturnin review gate <subject> --kind pr|issue --repo <owner/repo> --author <role>`

## Guarantees
- Author and reviewer can never be the same role.
- PR merges require an approval from a reviewer that had **zero context**;
  `--with-context` marks a review that cannot satisfy the gate.
- Only the latest verdict per reviewer counts; a `changes_requested` blocks.
- In managed (non-Saturnin) repositories the gate never allows a merge, and
  issue submission requires an independent issue review.

## Exit codes
`0` allowed, `2` blocked - safe to use directly in scripts and CI.
