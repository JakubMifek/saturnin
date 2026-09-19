# Skill: review-ledger

## Purpose
Make the independent-review requirement mechanical instead of aspirational.

## Commands
- Bind a launched review worker to one immutable draft at intake:
  `saturnin task add "Review <subject>" --kind pr-review|issue-review --repo <repo>
  --review-subject <subject> --review-author <role>
  --review-head-sha <sha>|--review-issue-digest <digest> --dispatch`.
- PR: capture the current head SHA, sign the exact verdict with
  `saturnin review attest <subject> --kind pr ... --head-sha <sha>`, then pass
  that value to
  `saturnin review record <subject> --kind pr ... --head-sha <sha> --attestation "$attestation"` and
  either `saturnin review gate <subject> --kind pr ... --head-sha <sha>` or
  `saturnin review merge <subject> --repo <repo> --author <role>`.
- Issue: compute `issue_content_digest(title, body)` and pass it to both
  `saturnin review attest <subject> --kind issue --repo <repo> ... --issue-digest <digest>`
  and
  `saturnin review record <subject> --kind issue --repo <repo> ... --issue-digest <digest> --attestation "$attestation"`
  and either `saturnin review gate <subject> --kind issue ... --issue-digest <digest>`
  or `saturnin review submit-issue <origin-task-id> --repo <repo> --author <role>
  --title ... --body ...`.

## Guarantees
- Author and reviewer can never be the same role.
- PR merges require an approval from a reviewer that had **zero context**;
  `--with-context` marks a review that cannot satisfy the gate.
- Only the latest verdict per reviewer counts; a `changes_requested` blocks.
- Gates trust only signed reviewer attestations that bind reviewer role, author,
  subject, verdict, head SHA or issue digest, and a non-replayed attestation id.
- In managed (non-Saturnin) repositories the gate never allows a merge, and
  issue submission requires an independent issue review.

## Exit codes
`0` allowed, `2` blocked - safe to use directly in scripts and CI.
