#!/bin/bash
set -euo pipefail

RESULTS_DIR="${RESULTS_DIR:-/results}"
RAW_DIR="$RESULTS_DIR/raw"
NORM_DIR="$RESULTS_DIR/normalized"
REPORT_DIR="$RESULTS_DIR/report"
EVIDENCE_DIR="$RESULTS_DIR/evidence/lab"

require_runner_container() {
  if [[ ! -d /servers || ! -f /app/generate-report.py ]]; then
    echo "[ERROR] runner/run-scans.sh must be executed inside the runner container." >&2
    echo "[ERROR] Use 'docker compose up --build -d' followed by 'docker compose run --rm runner'." >&2
    exit 64
  fi
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "[ERROR] Required command '$command_name' was not found in the runner container." >&2
    exit 127
  fi
}

validate_json_file() {
  python3 - "$1" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
if not text.strip():
    raise SystemExit(1)
json.loads(text)
PY
}

write_result_json() {
  local destination="$1"
  local scanner="$2"
  local server="$3"
  local target_path="$4"
  local status="$5"
  local message="$6"
  local exit_code="$7"
  local stdout_file="$8"
  local stderr_file="$9"
  local tmp_output

  tmp_output="$(mktemp "${destination}.tmp.XXXXXX")"
  python3 - "$tmp_output" "$scanner" "$server" "$target_path" "$status" "$message" "$exit_code" "$stdout_file" "$stderr_file" <<'PY'
import json
import sys
from datetime import datetime, timezone

(
    destination,
    scanner,
    server,
    target_path,
    status,
    message,
    exit_code,
    stdout_file,
    stderr_file,
) = sys.argv[1:]

payload = {
    "scanner_name": scanner,
    "server_name": server,
    "target": target_path,
    "status": status,
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "error": None,
    "reason": None,
    "notes": [],
    "evidence": {},
}

if status == "skipped":
    payload["reason"] = message
elif message:
    payload["error"] = message
    payload["notes"] = [message]

if stdout_file:
    payload["evidence"]["stdout"] = stdout_file
if stderr_file:
    payload["evidence"]["stderr"] = stderr_file
if exit_code not in ("", "-"):
    payload["exit_code"] = int(exit_code)

with open(destination, "w") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")
PY
  mv "$tmp_output" "$destination"
}

run_stdout_scanner_json() {
  local scanner="$1"
  local server="$2"
  local target_path="$3"
  local destination="$4"
  local allowed_exit_codes="$5"
  shift 5

  local evidence_dir="$EVIDENCE_DIR/$scanner"
  local stdout_file="$evidence_dir/${server}.stdout.log"
  local stderr_file="$evidence_dir/${server}.stderr.log"
  local tmp_output
  local exit_code

  mkdir -p "$evidence_dir"
  : > "$stdout_file"
  : > "$stderr_file"
  tmp_output="$(mktemp "${destination}.tmp.XXXXXX")"

  set +e
  "$@" >"$stdout_file" 2>"$stderr_file"
  exit_code=$?
  set -e

  if [[ " $allowed_exit_codes " == *" $exit_code "* ]]; then
    if [[ -s "$stdout_file" ]] && validate_json_file "$stdout_file"; then
      cp "$stdout_file" "$tmp_output"
      mv "$tmp_output" "$destination"
    else
      rm -f "$tmp_output"
      write_result_json "$destination" "$scanner" "$server" "$target_path" "failed" \
        "$scanner produced invalid JSON output" "-" "$stdout_file" "$stderr_file"
      echo "  [WARN] $scanner produced invalid JSON for $server"
    fi
  else
    rm -f "$tmp_output"
    write_result_json "$destination" "$scanner" "$server" "$target_path" "failed" \
      "$scanner exited with status $exit_code" "$exit_code" "$stdout_file" "$stderr_file"
    echo "  [WARN] $scanner failed for $server (exit $exit_code)"
  fi
}

run_file_scanner_json() {
  local scanner="$1"
  local server="$2"
  local target_path="$3"
  local destination="$4"
  local allowed_exit_codes="$5"
  shift 5

  local evidence_dir="$EVIDENCE_DIR/$scanner"
  local stdout_file="$evidence_dir/${server}.stdout.log"
  local stderr_file="$evidence_dir/${server}.stderr.log"
  local tmp_output
  local exit_code

  mkdir -p "$evidence_dir"
  : > "$stdout_file"
  : > "$stderr_file"
  tmp_output="$(mktemp "${destination}.tmp.XXXXXX")"

  set +e
  "$@" "$tmp_output" >"$stdout_file" 2>"$stderr_file"
  exit_code=$?
  set -e

  if [[ " $allowed_exit_codes " == *" $exit_code "* ]]; then
    if [[ -s "$tmp_output" ]] && validate_json_file "$tmp_output"; then
      mv "$tmp_output" "$destination"
    else
      rm -f "$tmp_output"
      write_result_json "$destination" "$scanner" "$server" "$target_path" "failed" \
        "$scanner produced invalid JSON output" "-" "$stdout_file" "$stderr_file"
      echo "  [WARN] $scanner produced invalid JSON for $server"
    fi
  else
    rm -f "$tmp_output"
    write_result_json "$destination" "$scanner" "$server" "$target_path" "failed" \
      "$scanner exited with status $exit_code" "$exit_code" "$stdout_file" "$stderr_file"
    echo "  [WARN] $scanner failed for $server (exit $exit_code)"
  fi
}

require_runner_container
require_command python3
require_command mcpscan
require_command mcp-guard

mkdir -p "$RAW_DIR/mcpscan" "$RAW_DIR/cisco-scanner" "$RAW_DIR/mcp-guard" "$NORM_DIR" "$REPORT_DIR" "$EVIDENCE_DIR"

echo "=========================================="
echo " MCP Security Lab — Scanner Runner"
echo "=========================================="

# Server list with source code paths
declare -A SERVERS=(
  ["normal-strict"]="/servers/normal-strict"
  ["normal-realistic"]="/servers/normal-realistic"
  ["normal-tricky"]="/servers/normal-tricky"
  ["vuln-exec"]="/servers/vuln-exec"
  ["vuln-authless"]="/servers/vuln-authless"
  ["vuln-filesystem"]="/servers/vuln-filesystem"
  ["vuln-config-exec"]="/servers/vuln-config-exec"
  ["vuln-runtime-only"]="/servers/vuln-runtime-only"
  ["vuln-network"]="/servers/vuln-network"
  ["vuln-allowlist-bypass"]="/servers/vuln-allowlist-bypass"
  ["vuln-hidden-transport"]="/servers/vuln-hidden-transport"
)

# ── MCPScan ──────────────────────────────────────
echo ""
echo ">>> Running MCPScan (Stage 1: semgrep taint analysis)"
for server in "${!SERVERS[@]}"; do
  path="${SERVERS[$server]}"
  echo "  Scanning $server ($path)..."
  run_file_scanner_json "mcpscan" "$server" "$path" "$RAW_DIR/mcpscan/${server}.json" "0" \
    mcpscan scan "$path" --no-monitor-desc --no-monitor-code --save --out
done

# ── Cisco mcp-scanner ────────────────────────────
# The Cisco mcp-scanner CLI does not accept arbitrary source paths; it operates
# on running MCP endpoints (`remote`/`stdio`), MCP config files (`config`), or
# pre-dumped tools/prompts/resources JSON (`static`). The path-based loop below
# is therefore not applicable in this stage and we emit a structured placeholder
# so downstream report generation still has a file per server.
echo ""
echo ">>> Skipping Cisco mcp-scanner for source-path stage (emitting placeholders)"
for server in "${!SERVERS[@]}"; do
  path="${SERVERS[$server]}"
  echo "  Placeholder for $server ($path)"
  write_result_json "$RAW_DIR/cisco-scanner/${server}.json" "cisco-scanner" "$server" "$path" "skipped" \
    "cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint" "-" "" ""
done

# ── mcp-guard ────────────────────────────────────
echo ""
echo ">>> Running mcp-guard (policy-based guardrail)"
for server in "${!SERVERS[@]}"; do
  path="${SERVERS[$server]}"
  echo "  Scanning $server ($path)..."
  run_stdout_scanner_json "mcp-guard" "$server" "$path" "$RAW_DIR/mcp-guard/${server}.json" "0 1" \
    mcp-guard scan --path "$path" --output json
done

# ── Normalize & Report ───────────────────────────
echo ""
echo ">>> Generating normalized results and report"
python3 /app/generate-report.py

echo ""
echo "=========================================="
echo " Scan complete. Results in $RESULTS_DIR"
echo "=========================================="
