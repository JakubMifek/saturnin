# Skill: review-ledger

## Purpose
Make the independent-review requirement mechanical instead of aspirational.

## Commands
- Bind a launched review worker to one immutable draft at intake:
  `saturnin task add "Review <subject>" --kind pr-review|issue-review --repo <repo>
  --review-subject <subject> --review-author <role>
  --review-head-sha <sha>|(--review-issue-digest <digest>
  --review-issue-title <title> --review-issue-body <body>) --dispatch`.
- A PR review worktree must have the recorded head SHA checked out. The launcher
  derives the merge-base diff from local Git objects. Issue title/body values
  must hash to the recorded digest. Reviewers receive that verified content,
  and launch fails before a signing key is provided when verification fails.

### PR flow

<!-- generated:pr-review-flow -->
```bash
HEAD_SHA="$(gh pr view <N> --repo JakubMifek/saturnin --json headRefOid --jq .headRefOid)"
saturnin review gate JakubMifek/saturnin#<N> --kind pr \
  --repo JakubMifek/saturnin --author <author-role> --head-sha "$HEAD_SHA"
```

The review worker's prose verdict is advisory. The configured GitHub reviewer bot must submit the current exact-head approval. This command is queued as a scope-checked trusted callback and the host signer independently re-fetches GitHub before deciding.
<!-- /generated:pr-review-flow -->

### Issue flow

<!-- generated:issue-review-flow -->
```bash
digest="$(python -c 'from saturnin.review import issue_content_digest; print(issue_content_digest("TITLE", "BODY"))')"
gh workflow run issue-review-marker.yml --ref main \
  -f source='<source-owner/source-repo>#<N>' \
  -f destination='<destination-owner/repo>' \
  -f labels='[]' -f ttl_seconds=600 -f issue_digest="$digest"
gh run watch <protected-workflow-run-id> --exit-status
saturnin review gate <source-owner/source-repo>#<N> --kind issue \
  --repo <destination-owner/repo> --author <author-role> --issue-digest "$digest"
```

The protected `issue-review-approval` environment must be approved by an independent reviewer. Its dedicated GitHub App publishes the exact short-lived marker; ordinary worker credentials cannot. The gate is a scope-checked trusted callback and independently re-fetches the marker.
<!-- /generated:issue-review-flow -->

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
