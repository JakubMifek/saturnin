#!/usr/bin/env bash
set -euo pipefail

candidate=${1:?usage: disclosure_gate.sh CANDIDATE_REPOSITORY TRUSTED_BASE}
trusted=${2:?usage: disclosure_gate.sh CANDIDATE_REPOSITORY TRUSTED_BASE}
source_ref=${3:-index}
trusted_policy="$trusted/policies/disclosure.yaml"
work="$trusted/var/disclosure-gate-$$"
tree="$work/tracked"
report="$work/findings.json"
SATURNIN_HOME=$trusted
export SATURNIN_HOME
source "$trusted/automation/library/_common.sh"
mkdir -p "$tree"
trap 'rm -rf "$work"' EXIT

if [[ -n ${GITLEAKS_BIN:-} ]]; then
  echo "disclosure gate rejects scanner overrides"
  exit 2
fi

if [[ "$source_ref" == index ]]; then
  treeish=$(git -C "$candidate" write-tree) || {
    echo "disclosure gate could not resolve the candidate index"
    exit 2
  }
elif [[ "$source_ref" =~ ^[0-9a-f]{40}$ ]]; then
  treeish=$(git -C "$candidate" rev-parse --verify "${source_ref}^{tree}") || {
    echo "disclosure gate could not resolve the immutable candidate commit"
    exit 2
  }
else
  echo "disclosure gate source must be index or a full commit SHA"
  exit 2
fi
if ! git -C "$candidate" archive --format=tar "$treeish" 2>/dev/null |
  tar -xf - -C "$tree" 2>/dev/null; then
  echo "disclosure gate could not materialize tracked candidate content"
  exit 2
fi
if ! saturnin_python - "$candidate" "$treeish" "$tree" <<'PY'
import os
import pathlib
import subprocess
import sys

repo, treeish, root_arg = sys.argv[1:]
root = pathlib.Path(root_arg).resolve()
records = subprocess.check_output(
    ["git", "-C", repo, "ls-tree", "-rz", treeish]
).split(b"\0")
for record in records:
    if not record:
        continue
    metadata, path_bytes = record.split(b"\t", 1)
    mode, object_type, object_id = metadata.split()
    if mode != b"120000":
        continue
    relative = pathlib.PurePosixPath(os.fsdecode(path_bytes))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("unsafe tracked symlink path")
    path = root.joinpath(*relative.parts)
    if not path.is_symlink():
        raise ValueError("archive did not materialize the tracked symlink")
    blob = subprocess.check_output(
        ["git", "-C", repo, "cat-file", "blob", object_id.decode("ascii")]
    )
    path.unlink()
    path.write_bytes(blob)
PY
then
  echo "disclosure gate could not safely prepare candidate content"
  exit 2
fi

policy="$tree/policies/disclosure.yaml"
config="$tree/policies/gitleaks.toml"
if ! PYTHONPATH="$trusted/src${PYTHONPATH:+:$PYTHONPATH}" \
  saturnin_python -m saturnin.disclosure --audit-only \
    --root "$tree" --policy "$policy"; then
  echo "disclosure gate rejected selected-tree policy"
  exit 2
fi

readarray -t pin < <(saturnin_python - "$trusted_policy" <<'PY'
import sys, yaml
data = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))["scanner"]
print(data["version"])
print(data["linux_x64_sha256"])
print(data["linux_x64_binary_sha256"])
PY
)
if (( ${#pin[@]} != 3 )); then
  echo "disclosure gate could not load trusted scanner pin"
  exit 2
fi
version=${pin[0]}
checksum=${pin[1]}
binary_checksum=${pin[2]}
gitleaks="$trusted/var/disclosure-tools/gitleaks-$version"

if [[ ! -x "$gitleaks" ]]; then
  archive="$work/gitleaks.tar.gz"
  mkdir -p "$(dirname "$gitleaks")"
  curl --fail --silent --show-error --location \
    "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz" \
    --output "$archive"
  printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --status
  tar -xzf "$archive" -C "$work" gitleaks
  install -m 0755 "$work/gitleaks" "$gitleaks"
fi
if ! printf '%s  %s\n' "$binary_checksum" "$gitleaks" | sha256sum --check --status; then
  echo "disclosure gate scanner binary failed checksum verification"
  exit 2
fi

marker_status=0
PYTHONPATH="$trusted/src${PYTHONPATH:+:$PYTHONPATH}" \
  saturnin_python -m saturnin.disclosure --root "$tree" --policy "$policy" || marker_status=$?

scanner_status=0
"$gitleaks" dir "$tree" --config "$config" \
  --gitleaks-ignore-path /dev/null --ignore-gitleaks-allow \
  --no-banner --redact=100 \
  --report-format json --report-path "$report" >/dev/null 2>&1 || scanner_status=$?

if (( scanner_status == 1 )); then
  if ! saturnin_python - "$report" "$tree" <<'PY'
import hashlib, json, pathlib, sys
report = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2]).resolve()
for item in json.loads(report.read_text(encoding="utf-8")):
    path = pathlib.Path(str(item.get("File", "")))
    try:
        path = path.resolve().relative_to(root)
    except (ValueError, OSError):
        path = pathlib.Path("[outside-scan-root]")
    rule = str(item.get("RuleID", "credential")).replace("\n", " ")
    line = int(item.get("StartLine", 0))
    file_id = hashlib.sha256(path.as_posix().encode()).hexdigest()[:12]
    print(f"disclosure violation: rule={rule} file_sha256={file_id} line={line}")
PY
  then
    echo "disclosure gate could not summarize redacted findings"
    exit 2
  fi
elif (( scanner_status != 0 )); then
  echo "disclosure gate scanner failed without exposing scanner output"
  exit 2
fi

if (( marker_status == 2 )); then
  exit 2
fi
if (( marker_status == 1 || scanner_status == 1 )); then
  echo "disclosure gate blocked tracked content; matched values are redacted"
  exit 1
fi
echo "disclosure gate passed: Git-tracked content only"
