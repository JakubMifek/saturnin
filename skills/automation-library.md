# Skill: automation-library

## Purpose
Never build the same thing twice; turn repetition into scripts.

## Commands
- `saturnin automation find "<what you want to do>"` - **run this first**
- `saturnin automation list`
- `saturnin automation detect [--threshold N] [--propose]`

## Guarantees
- `find` weighs registry triggers highest and refuses weak single-word matches,
  so a hit means "this really covers it".
- `detect` groups tasks by a normalised title signature and ignores review,
  improvement and automation tasks so the loop cannot feed itself.
- `--propose` files at most one task per repeated signature, ever.

## Contract for new scripts
`set -Eeuo pipefail`, source `_common.sh`, arguments not hard-coded paths,
idempotent, dry-run by default when destructive, registered in
`automation/registry.yaml`.
