#!/usr/bin/env bash
# Launch fresh agents for checkpoints whose delayed-resume time has arrived.
set -Eeuo pipefail
SCRIPT_NAME=resume-checkpoints
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

saturnin checkpoint sweep
