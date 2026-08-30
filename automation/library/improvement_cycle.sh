#!/usr/bin/env bash
# Measure the board, detect bottlenecks and file improvement tasks.
set -Eeuo pipefail
SCRIPT_NAME=improvement-cycle
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

saturnin improve
saturnin automation detect --propose
saturnin dispatch --all
