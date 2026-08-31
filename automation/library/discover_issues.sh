#!/usr/bin/env bash
# Adopt issues from managed repositories as board tasks.
#
# This is the inbound door: alerting stacks, CI and humans all file issues, and
# Saturnin turns them into routed work. Nothing here polls an application - the
# project's own observability does that and raises the issue (see
# docs/observability.md). DRY_RUN=1 lists what would be adopted.
set -Eeuo pipefail
SCRIPT_NAME=discovery
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  saturnin discover --dry-run
else
  saturnin discover
fi
