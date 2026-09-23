#!/usr/bin/env bash
set -euo pipefail

candidate=${1:?usage: disclosure_gate.sh CANDIDATE_REPOSITORY TRUSTED_BASE}
trusted=${2:?usage: disclosure_gate.sh CANDIDATE_REPOSITORY TRUSTED_BASE}
policy="$trusted/policies/disclosure.yaml"
config="$trusted/policies/gitleaks.toml"
work="$trusted/var/disclosure-gate-$$"
tree="$work/tracked"
report="$work/findings.json"
python_bin=${PYTHON_BIN:-python3}
mkdir -p "$tree"
trap 'rm -rf "$work"' EXIT

readarray -t pin < <("$python_bin" - "$policy" <<'PY'
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
gitleaks=${GITLEAKS_BIN:-"$trusted/var/disclosure-tools/gitleaks-$version"}

if [[ -z ${GITLEAKS_BIN:-} && ! -x "$gitleaks" ]]; then
  archive="$work/gitleaks.tar.gz"
  mkdir -p "$(dirname "$gitleaks")"
  curl --fail --silent --show-error --location \
    "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz" \
    --output "$archive"
  printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --status
  tar -xzf "$archive" -C "$work" gitleaks
  install -m 0755 "$work/gitleaks" "$gitleaks"
fi
if [[ -z ${GITLEAKS_BIN:-} ]] &&
  ! printf '%s  %s\n' "$binary_checksum" "$gitleaks" | sha256sum --check --status; then
  echo "disclosure gate scanner binary failed checksum verification"
  exit 2
fi

if ! (
  cd "$candidate" &&
  git ls-files -z |
    tar --null --verbatim-files-from --files-from=- --create --file=-
) 2>/dev/null | tar -xf - -C "$tree" 2>/dev/null; then
  echo "disclosure gate could not materialize tracked candidate content"
  exit 2
fi
# A tracked symlink is data, never authority to make the scanner read outside
# the candidate tree.
if ! find "$tree" -type l -delete 2>/dev/null; then
  echo "disclosure gate could not safely prepare candidate content"
  exit 2
fi

marker_status=0
PYTHONPATH="$trusted/src${PYTHONPATH:+:$PYTHONPATH}" \
  "$python_bin" -m saturnin.disclosure --root "$tree" --policy "$policy" || marker_status=$?

scanner_status=0
"$gitleaks" dir "$tree" --config "$config" --no-banner --redact=100 \
  --report-format json --report-path "$report" >/dev/null 2>&1 || scanner_status=$?

if (( scanner_status == 1 )); then
  if ! "$python_bin" - "$report" "$tree" <<'PY'
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
