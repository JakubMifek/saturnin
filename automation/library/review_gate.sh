#!/usr/bin/env bash
# Trusted-base CI gate over current exact-head GitHub review state.
set -Eeuo pipefail
SCRIPT_NAME=review-gate
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

kind="${1:?usage: review_gate.sh pr <owner/repo#number> <expected-head>}"
subject="${2:?missing subject}"
expected_head="${3:?missing expected head}"
[[ "$kind" == pr ]] || { echo "CI live gate supports pull requests only" >&2; exit 2; }
[[ "$subject" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*$ ]] || {
  echo "subject must be owner/repository#number" >&2
  exit 2
}
[[ "$expected_head" =~ ^[0-9a-f]{40}$ ]] || {
  echo "expected head must be a lowercase 40-character SHA" >&2
  exit 2
}

saturnin review ci-gate "$subject" \
  --head-sha "$expected_head" \
  --config "$repo_root/config/attestation.json"
