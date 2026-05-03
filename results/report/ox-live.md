# OX Live Validation Report

Generated: 2026-05-03T09:11:45.971386+00:00

- **Products**: 14
- **Launch-expected products**: 8 (success: 3, reachable: 3)
- **Expected manual blockers**: 6 (no self-hosted launch path)
- **Fixture-only scans (config_fixture)**: 14
- **Live endpoint scans**: 0
- **Unexpected launch failures**: 5

> Note: scan results from `config_fixture` mode validate that mcp-guard detects the OX research configuration; they do **not** scan a running product. Live endpoint scans are only counted when `scan_mode == endpoint`.

| Product | Launch | Health | Scan (mode) | Findings | Expected Block | Reason |
|---------|--------|--------|-------------|----------|----------------|--------|
| agent-zero | success | reachable | success (config_fixture) | TP:1/FP:0/FN:0 | no | - |
| bisheng | failed | unreachable | success (config_fixture) | TP:1/FP:0/FN:0 | no | command_failed |
| docsgpt | failed | unreachable | success (config_fixture) | TP:1/FP:0/FN:0 | no | command_failed |
| flowise | success | reachable | success (config_fixture) | TP:2/FP:0/FN:0 | no | - |
| gpt-researcher | success | reachable | success (config_fixture) | TP:1/FP:0/FN:0 | no | - |
| jaaz | failed | unreachable | success (config_fixture) | TP:1/FP:0/FN:0 | yes | manual_blocked |
| langchain-chatchat | failed | unreachable | success (config_fixture) | TP:1/FP:0/FN:0 | yes | manual_blocked |
| langflow | failed | unreachable | success (config_fixture) | TP:1/FP:0/FN:0 | no | command_failed |
| letta-ai | failed | unreachable | success (config_fixture) | TP:1/FP:0/FN:0 | no | command_failed |
| litellm | failed | unreachable | success (config_fixture) | TP:1/FP:0/FN:0 | no | command_failed |
| openhands | failed | unreachable | success (config_fixture) | TP:1/FP:0/FN:0 | yes | manual_blocked |
| promptfoo | failed | unreachable | success (config_fixture) | TP:2/FP:0/FN:0 | yes | manual_blocked |
| upsonic | failed | unreachable | success (config_fixture) | TP:2/FP:0/FN:0 | yes | manual_blocked |
| windsurf | failed | unreachable | success (config_fixture) | TP:1/FP:0/FN:0 | yes | manual_blocked |

## Details

### Agent Zero (agent-zero)
- Source: https://github.com/frdel/agent-zero
- Launch: success via `docker_image`
- Health: reachable
- Scan: success (mode: `config_fixture`)
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"health": "results/raw/ox-live/evidence/agent-zero/health.json", "launch_command": ["docker", "run", "-d", "--name", "mcpscan-ox-agent-zero", "--label", "mcpscan.ox-live=true", "-p", "38090:80", "agent0ai/agent-zero:v1.7"], "launch_logs": "results/raw/ox-live/evidence/agent-zero/launch.log", "scan_stderr": "results/raw/ox-live/evidence/agent-zero/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/agent-zero/scan.stdout"}`

### BISHENG (bisheng)
- Source: https://github.com/dataelement/bisheng
- Launch: failed via `repo_compose`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Failure Reason: `command_failed`
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/bisheng/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/bisheng/scan.stdout"}`
- Notes: error: pathspec 'v2.4.0-beta1-fix' did not match any file(s) known to git

### DocsGPT (docsgpt)
- Source: https://github.com/arc53/DocsGPT
- Launch: failed via `repo_compose`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Failure Reason: `command_failed`
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/docsgpt/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/docsgpt/scan.stdout"}`
- Notes: fatal: reference is not a tree: 72b3d944534244baed4727824f30c55bc3d82495

### Flowise (flowise)
- Source: https://github.com/FlowiseAI/Flowise
- Launch: success via `docker_image`
- Health: reachable
- Scan: success (mode: `config_fixture`)
- Expected Findings: config_to_execution, allowlist_bypass
- Detected Findings: config_to_execution, allowlist_bypass
- Evidence: `{"health": "results/raw/ox-live/evidence/flowise/health.json", "launch_command": ["docker", "run", "-d", "--name", "mcpscan-ox-flowise", "--label", "mcpscan.ox-live=true", "-e", "PORT=3000", "-p", "33000:3000", "flowiseai/flowise:latest"], "launch_logs": "results/raw/ox-live/evidence/flowise/launch.log", "scan_stderr": "results/raw/ox-live/evidence/flowise/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/flowise/scan.stdout"}`

### GPT-Researcher (gpt-researcher)
- Source: https://github.com/assafelovic/gpt-researcher
- Launch: success via `repo_compose`
- Health: reachable
- Scan: success (mode: `config_fixture`)
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"health": "results/raw/ox-live/evidence/gpt-researcher/health.json", "launch_command": ["/usr/local/bin/docker", "compose", "-f", "/Users/1004276/Downloads/mcpscan/results/workdir/ox-live/gpt-researcher/docker-compose.yml", "-f", "/Users/1004276/Downloads/mcpscan/results/workdir/ox-live/gpt-researcher/.mcpscan-compose.override.yaml", "-p", "mcpscan-ox-gpt-researcher", "up", "-d", "--remove-orphans"], "launch_logs": "results/raw/ox-live/evidence/gpt-researcher/launch.log", "scan_stderr": "results/raw/ox-live/evidence/gpt-researcher/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/gpt-researcher/scan.stdout"}`

### Jaaz (jaaz)
- Source: https://www.jaaz.one/
- Launch: failed via `manual_blocked`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Expected Manual Blocker: yes (no official self-hosted launch path)
- Failure Reason: `manual_blocked`
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/jaaz/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/jaaz/scan.stdout"}`
- Notes: manual_blocked: no official self-hosted repository or Docker launch path was identified

### LangChain ChatChat (langchain-chatchat)
- Source: https://github.com/chatchat-space/Langchain-Chatchat
- Launch: failed via `manual_blocked`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Expected Manual Blocker: yes (no official self-hosted launch path)
- Failure Reason: `manual_blocked`
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/langchain-chatchat/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/langchain-chatchat/scan.stdout"}`
- Notes: manual_blocked: official Docker deployment requires host-network and GPU-oriented Xinference companion services

### LangFlow (langflow)
- Source: https://github.com/langflow-ai/langflow
- Launch: failed via `docker_image`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Failure Reason: `command_failed`
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/langflow/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/langflow/scan.stdout"}`
- Notes: write /var/lib/docker/tmp/GetImageBlob3760287540: no space left on device

### LettaAI (letta-ai)
- Source: https://github.com/letta-ai/letta
- Launch: failed via `repo_compose`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Failure Reason: `command_failed`
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/letta-ai/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/letta-ai/scan.stdout"}`
- Notes: error: pathspec '0.16.7' did not match any file(s) known to git

### LiteLLM (litellm)
- Source: https://github.com/BerriAI/litellm
- Launch: failed via `docker_image`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Failure Reason: `command_failed`
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/litellm/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/litellm/scan.stdout"}`
- Notes: write /var/lib/docker/tmp/GetImageBlob2755048035: no space left on device

### OpenHands (openhands)
- Source: https://github.com/All-Hands-AI/OpenHands
- Launch: failed via `manual_blocked`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Expected Manual Blocker: yes (no official self-hosted launch path)
- Failure Reason: `manual_blocked`
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/openhands/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/openhands/scan.stdout"}`
- Notes: manual_blocked: official compose path builds a local app image and nested runtime, which is not yet automated in this repository

### PromptFoo (promptfoo)
- Source: https://github.com/promptfoo/promptfoo
- Launch: failed via `manual_blocked`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Expected Manual Blocker: yes (no official self-hosted launch path)
- Failure Reason: `manual_blocked`
- Expected Findings: config_to_execution, allowlist_bypass
- Detected Findings: config_to_execution, allowlist_bypass
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/promptfoo/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/promptfoo/scan.stdout"}`
- Notes: manual_blocked: promptfoo is distributed primarily as a CLI package without a stable official server container

### Upsonic (upsonic)
- Source: https://github.com/Upsonic/Upsonic
- Launch: failed via `manual_blocked`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Expected Manual Blocker: yes (no official self-hosted launch path)
- Failure Reason: `manual_blocked`
- Expected Findings: config_to_execution, allowlist_bypass
- Detected Findings: config_to_execution, allowlist_bypass
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/upsonic/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/upsonic/scan.stdout"}`
- Notes: manual_blocked: official self-hosted Docker launch path was not identified from the public repository

### Windsurf (windsurf)
- Source: https://windsurf.com/
- Launch: failed via `manual_blocked`
- Health: unreachable
- Scan: success (mode: `config_fixture`)
- Expected Manual Blocker: yes (no official self-hosted launch path)
- Failure Reason: `manual_blocked`
- Expected Findings: config_to_execution
- Detected Findings: config_to_execution
- Evidence: `{"scan_stderr": "results/raw/ox-live/evidence/windsurf/scan.stderr", "scan_stdout": "results/raw/ox-live/evidence/windsurf/scan.stdout"}`
- Notes: manual_blocked: Windsurf Editor does not expose a public self-hosted Docker launch path
