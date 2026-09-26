#!/usr/bin/env bash

saturnin_require_unprivileged_user() {
  if [[ "$(id -u)" -eq 0 ]]; then
    echo "Refusing to manage user units as root." >&2
    return 1
  fi
}

saturnin_validate_render_path() {
  local path=$1
  if [[ ! "$path" =~ ^/[A-Za-z0-9/._-]+$ ]]; then
    echo "SATURNIN_HOME must be an absolute canonical path using only [A-Za-z0-9/._-]." >&2
    return 1
  fi
}

saturnin_render_unit() {
  local source=$1 destination=$2 home=$3
  SATURNIN_HOME_ESCAPED="$home" SATURNIN_HOME_ENV_ESCAPED="$home" \
    TEMPLATE_PATH="$source" DEST="$destination" python3 -c '
from pathlib import Path
import os
template = Path(os.environ["TEMPLATE_PATH"]).read_text()
Path(os.environ["DEST"]).write_text(
    template.replace("@SATURNIN_HOME@", os.environ["SATURNIN_HOME_ESCAPED"])
    .replace("@SATURNIN_HOME_ENV@", os.environ["SATURNIN_HOME_ENV_ESCAPED"])
)
'
}
