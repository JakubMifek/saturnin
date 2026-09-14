## Problem

<!-- What was wrong or missing. Link the board task id. -->

## Change

<!-- What this diff does. Keep it to one purpose. -->

## Verification

<!-- Commands run and their outcome, e.g. `python -m pytest`. -->

## Governance checklist

- [ ] Branch is a feature branch (`saturnin check branch <branch>` exits 0)
- [ ] Independent zero-context reviewer requested (never the author)
- [ ] Capture the reviewed PR revision once: `HEAD_SHA="$(gh pr view <number> --repo <owner/repo> --json headRefOid --jq .headRefOid)"`
- [ ] Review attestation created for that revision: `attestation="$(saturnin review attest <repo#N> --kind pr ... --head-sha "$HEAD_SHA")"`
- [ ] Review verdict recorded: `saturnin review record <repo#N> --kind pr ... --head-sha "$HEAD_SHA" --attestation "$attestation"`
- [ ] Merge gate passes: `saturnin review gate <repo#N> --kind pr --repo ... --author ... --head-sha "$HEAD_SHA"`
- [ ] Board task moved to `review`
