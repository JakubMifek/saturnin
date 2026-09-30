#!/usr/bin/env bash
# Trusted-base CI gate over current exact-head GitHub review state.
set -Eeuo pipefail
SCRIPT_NAME=review-gate
script_path="$(command -p readlink -f -- "${BASH_SOURCE[0]}")"
SATURNIN_HOME="$(cd -P -- "${script_path%/*}/../.." && pwd)"
export SATURNIN_HOME
source "$SATURNIN_HOME/automation/library/_common.sh"

if (( $# != 3 )); then
  echo "usage: review_gate.sh pr <owner/repo#number> <expected-head>" >&2
  exit 2
fi
kind="$1"
subject="$2"
expected_head="$3"
[[ "$kind" == pr ]] || { echo "CI live gate supports pull requests only" >&2; exit 2; }
[[ "$subject" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[1-9][0-9]*$ ]] || {
  echo "subject must be owner/repository#number" >&2
  exit 2
}
[[ "$expected_head" =~ ^[0-9a-f]{40}$ ]] || {
  echo "expected head must be a lowercase 40-character SHA" >&2
  exit 2
}
config="$SATURNIN_HOME/config/attestation.json"
[[ -f "$config" ]] || {
  echo "trusted attestation config missing: $config" >&2
  exit 2
}

(
  unset PYTHONHOME PYTHONPATH
  saturnin --home "$SATURNIN_HOME" review ci-gate "$subject" \
    --head-sha "$expected_head"
)
