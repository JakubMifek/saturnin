#!/usr/bin/env bash
# Route everything waiting in intake. The CEO's only recurring duty.
set -Eeuo pipefail
SCRIPT_NAME=dispatch-sweep
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

saturnin dispatch --all
saturnin task list --open
