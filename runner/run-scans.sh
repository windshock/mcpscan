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
text = path.read_text().strip()
if not text:
    raise SystemExit(1)
try:
    json.loads(text)
except json.JSONDecodeError:
    # Some scanners (cisco mcp-scanner on certain cases) print a banner line
    # or trailing diagnostic after the JSON payload. Try to recover the
    # outermost JSON object so downstream normalization still runs.
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        raise SystemExit(1)
    snippet = text[start : end + 1]
    json.loads(snippet)
    path.write_text(snippet)
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
require_command snyk-agent-scan

mkdir -p "$RAW_DIR/mcpscan" "$RAW_DIR/cisco-scanner" "$RAW_DIR/mcp-guard" "$RAW_DIR/mcp-guard-endpoint" "$RAW_DIR/cisco-config" "$RAW_DIR/invariant-scan" "$RAW_DIR/invariant-config" "$NORM_DIR" "$REPORT_DIR" "$EVIDENCE_DIR"

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

# In-network MCP SSE endpoints, used by both the Cisco remote scan and the
# mcp-guard endpoint probe. Service names + container ports come from
# docker-compose.yml.
declare -A ENDPOINTS=(
  ["normal-strict"]="http://normal-strict:8000/sse"
  ["normal-realistic"]="http://normal-realistic:8000/sse"
  ["normal-tricky"]="http://normal-tricky:8000/sse"
  ["vuln-exec"]="http://vuln-exec:8000/sse"
  ["vuln-authless"]="http://vuln-authless:8000/sse"
  ["vuln-filesystem"]="http://vuln-filesystem:8000/sse"
  ["vuln-config-exec"]="http://vuln-config-exec:8000/sse"
  ["vuln-runtime-only"]="http://vuln-runtime-only:8000/sse"
  ["vuln-network"]="http://vuln-network:3000/sse"
  ["vuln-allowlist-bypass"]="http://vuln-allowlist-bypass:3000/sse"
  ["vuln-hidden-transport"]="http://vuln-hidden-transport:3000/sse"
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
# Cisco mcp-scanner does not support arbitrary source paths; it operates on
# running MCP endpoints (`remote`/`stdio`), MCP config files (`config`), or
# pre-dumped tools/prompts/resources JSON (`static`). For this lab we use
# remote mode against the running SSE endpoints. yara_analyzer is offline-
# only, so this stage works without external API keys.
echo ""
echo ">>> Running Cisco mcp-scanner (remote mode, yara analyzer)"
for server in "${!SERVERS[@]}"; do
  endpoint="${ENDPOINTS[$server]:-}"
  if [[ -z "$endpoint" ]]; then
    write_result_json "$RAW_DIR/cisco-scanner/${server}.json" "cisco-scanner" "$server" "-" "skipped" \
      "no SSE endpoint mapped for $server" "-" "" ""
    continue
  fi
  echo "  Scanning $server ($endpoint)..."
  run_stdout_scanner_json "cisco-scanner" "$server" "$endpoint" "$RAW_DIR/cisco-scanner/${server}.json" "0 1" \
    mcp-scanner --analyzers yara --format raw --log-level error remote --server-url "$endpoint"
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

# ── mcp-guard endpoint scan ──────────────────────
# Live probe of each running MCP server. Detects runtime-only properties
# (authless reachability, CORS wildcard, hidden admin endpoints) that source
# scanning cannot reliably surface. Probes send POST/PUT requests with empty
# bodies to admin paths — lab-only.
echo ""
echo ">>> Running mcp-guard endpoint probes (runtime/endpoint coverage)"
for server in "${!SERVERS[@]}"; do
  endpoint="${ENDPOINTS[$server]:-}"
  if [[ -z "$endpoint" ]]; then
    echo "  [SKIP] $server has no configured endpoint"
    write_result_json "$RAW_DIR/mcp-guard-endpoint/${server}.json" "mcp-guard-endpoint" "$server" "-" "skipped" \
      "no endpoint configured for $server" "-" "" ""
    continue
  fi
  echo "  Probing $server ($endpoint)..."
  run_stdout_scanner_json "mcp-guard-endpoint" "$server" "$endpoint" "$RAW_DIR/mcp-guard-endpoint/${server}.json" "0 1" \
    mcp-guard scan --endpoint "$endpoint" --output json
done

# ── Cisco config-mode (supply-chain corpus) ──────
# Cisco's `config` subcommand is its natural threat-model fit (malicious MCP
# configs that auto-launch dangerous commands). Run it against the OX
# research fixture so the comparison report has an honest measurement of
# cisco's supply-chain coverage, not just the lab's capability servers.
OX_FIXTURE="/app/ox_research_cases.json"
if [[ ! -f "$OX_FIXTURE" ]]; then
  OX_FIXTURE="/servers/../guard/tests/fixtures/ox_research_cases.json"
fi

if [[ -f "$OX_FIXTURE" ]]; then
  echo ""
  echo ">>> Running Cisco mcp-scanner (config mode against OX research corpus)"
  ox_tmp="$(mktemp -d)"
  python3 - "$OX_FIXTURE" "$ox_tmp" <<'PY'
import json, sys, pathlib
fixture, outdir = sys.argv[1], pathlib.Path(sys.argv[2])
cases = json.loads(pathlib.Path(fixture).read_text())
for case in cases:
    name = case["name"].replace(" ", "_").replace("/", "_")
    (outdir / f"{name}.json").write_text(json.dumps(case["payload"], indent=2))
PY
  for case_file in "$ox_tmp"/*.json; do
    case_name="$(basename "$case_file" .json)"
    echo "  Scanning $case_name..."
    run_stdout_scanner_json "cisco-config" "$case_name" "$case_file" \
      "$RAW_DIR/cisco-config/${case_name}.json" "0 1" \
      mcp-scanner --analyzers yara --format raw --log-level error \
        config --config-path "$case_file"
  done
  rm -rf "$ox_tmp"
else
  echo ""
  echo ">>> Skipping Cisco config-mode stage (OX fixture not found)"
fi

# ── Invariant/Snyk mcp-scan (remote SSE) ─────────
# `mcp-scan` (renamed `snyk-agent-scan`) calls api.snyk.io to analyse tool
# descriptions, requires SNYK_TOKEN. Without one, `issues` is always empty —
# we still record the run so the comparison report shows the dependency
# explicitly instead of silently zero.
if [[ -z "${SNYK_TOKEN:-}" ]]; then
  echo ""
  echo ">>> Skipping Invariant/Snyk mcp-scan stages (SNYK_TOKEN not set; would return 0 issues)"
  for server in "${!SERVERS[@]}"; do
    write_result_json "$RAW_DIR/invariant-scan/${server}.json" "invariant-scan" "$server" "-" "skipped" \
      "SNYK_TOKEN unset; mcp-scan returns issues=[] without auth" "-" "" ""
  done
else
  echo ""
  echo ">>> Running Invariant/Snyk mcp-scan (remote SSE mode)"
  inv_tmp="$(mktemp -d)"
  for server in "${!SERVERS[@]}"; do
    endpoint="${ENDPOINTS[$server]:-}"
    if [[ -z "$endpoint" ]]; then
      write_result_json "$RAW_DIR/invariant-scan/${server}.json" "invariant-scan" "$server" "-" "skipped" \
        "no SSE endpoint mapped for $server" "-" "" ""
      continue
    fi
    cfg="$inv_tmp/${server}.json"
    python3 - "$cfg" "$server" "$endpoint" <<'PY'
import json, sys
cfg, name, url = sys.argv[1:]
json.dump({"mcpServers": {name.replace("-", "_"): {"type": "sse", "url": url}}}, open(cfg, "w"))
PY
    echo "  Scanning $server ($endpoint)..."
    run_stdout_scanner_json "invariant-scan" "$server" "$endpoint" "$RAW_DIR/invariant-scan/${server}.json" "0 1 2" \
      snyk-agent-scan scan --json --server-timeout 30 "$cfg"
  done
  rm -rf "$inv_tmp"
fi

# ── Invariant/Snyk mcp-scan (config-mode against OX corpus) ──
if [[ -n "${SNYK_TOKEN:-}" && -f "$OX_FIXTURE" ]]; then
  echo ""
  echo ">>> Running Invariant/Snyk mcp-scan (config mode against OX research corpus)"
  ox_inv_tmp="$(mktemp -d)"
  python3 - "$OX_FIXTURE" "$ox_inv_tmp" <<'PY'
import json, sys, pathlib
fixture, outdir = sys.argv[1], pathlib.Path(sys.argv[2])
cases = json.loads(pathlib.Path(fixture).read_text())
for case in cases:
    name = case["name"].replace(" ", "_").replace("/", "_")
    (outdir / f"{name}.json").write_text(json.dumps(case["payload"], indent=2))
PY
  for case_file in "$ox_inv_tmp"/*.json; do
    case_name="$(basename "$case_file" .json)"
    echo "  Scanning $case_name..."
    # Stdio cases require user consent to launch — pass --dangerously-run-mcp-servers
    # so the corpus runs unattended. Lab-only; do NOT use this flag against
    # untrusted configs in production.
    run_stdout_scanner_json "invariant-config" "$case_name" "$case_file" \
      "$RAW_DIR/invariant-config/${case_name}.json" "0 1 2" \
      snyk-agent-scan scan --json --dangerously-run-mcp-servers --suppress-mcpserver-io true \
        --server-timeout 15 "$case_file"
  done
  rm -rf "$ox_inv_tmp"
fi

# ── Normalize & Report ───────────────────────────
echo ""
echo ">>> Generating normalized results and report"
python3 /app/generate-report.py

echo ""
echo "=========================================="
echo " Scan complete. Results in $RESULTS_DIR"
echo "=========================================="
