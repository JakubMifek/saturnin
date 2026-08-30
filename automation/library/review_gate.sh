#!/usr/bin/env bash
# Usage: review_gate.sh <pr|issue> <subject> <repo> <author>
# Exits non-zero when the independent review requirement is not satisfied.
set -Eeuo pipefail
SCRIPT_NAME=review-gate
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

kind="${1:?usage: review_gate.sh <pr|issue> <subject> <repo> <author>}"
subject="${2:?missing subject}"
repo="${3:?missing repo}"
author="${4:?missing author}"

saturnin review gate "$subject" --kind "$kind" --repo "$repo" --author "$author"
