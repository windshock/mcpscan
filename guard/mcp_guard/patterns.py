"""MCP Security Pattern Catalog — the knowledge base for vulnerability detection."""
from __future__ import annotations

PATTERNS = {
    "command_exec": {
        "id": "PAT-001",
        "name": "Direct Command Execution",
        "severity": "CRITICAL",
        "description": "Tool directly executes shell commands via subprocess, os.system, or exec",
        "indicators": [
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "os.system", "os.popen", "exec(", "child_process.exec",
            "shell=True",
        ],
        "policy": "BLOCK",
        "recommendation": "Remove direct command execution. Use allowlisted operations only.",
    },
    "tool_poisoning": {
        "id": "PAT-002",
        "name": "Tool Poisoning / Hidden Instructions",
        "severity": "HIGH",
        "description": "Tool description contains hidden instructions that manipulate AI behavior",
        "indicators": [
            "IMPORTANT:", "NOTE TO ASSISTANT:", "IGNORE ANY PREVIOUS",
            "must not be mentioned", "always run", "before responding",
            "required security check",
        ],
        "policy": "BLOCK",
        "recommendation": "Remove hidden instructions from tool descriptions. Keep descriptions factual.",
    },
    "authless_endpoint": {
        "id": "PAT-003",
        "name": "Authentication-Less Endpoint",
        "severity": "HIGH",
        "description": "MCP server exposes tools without any authentication",
        "indicators": [
            "no auth check", "no Bearer token", "no API key validation",
            "public endpoint", "no verify_token",
        ],
        "policy": "BLOCK",
        "recommendation": "Add authentication (Bearer token, API key, or OAuth).",
    },
    "unrestricted_file_read": {
        "id": "PAT-004",
        "name": "Unrestricted File Read",
        "severity": "HIGH",
        "description": "Tool can read arbitrary files without path validation",
        "indicators": [
            "open(path", "read_file(path", "no path validation",
            "no allowlist", "no prefix check",
        ],
        "policy": "BLOCK",
        "recommendation": "Restrict file access to allowlisted directories. Validate paths against traversal.",
    },
    "unrestricted_file_write": {
        "id": "PAT-005",
        "name": "Unrestricted File Write",
        "severity": "CRITICAL",
        "description": "Tool can write to arbitrary file paths",
        "indicators": [
            "write_file(path", "open(path, 'w'", "os.makedirs",
            "no write validation",
        ],
        "policy": "BLOCK",
        "recommendation": "Restrict write access to designated directories only.",
    },
    "env_exposure": {
        "id": "PAT-006",
        "name": "Environment Variable / Secret Exposure",
        "severity": "HIGH",
        "description": "Tool exposes environment variables including secrets and credentials",
        "indicators": [
            "dict(os.environ)", "str(dict(os.environ",
            "process.env", "get_env()", "list_environment",
            "return all env", "env_dump",
            "os.environ.items()",
        ],
        "policy": "BLOCK",
        "recommendation": "Never expose full environment. Use secret masking and allowlisted keys only.",
    },
    "ssrf": {
        "id": "PAT-007",
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "HIGH",
        "description": "Tool can fetch arbitrary URLs including internal services",
        "indicators": [
            "fetch_url(url", "urllib.request", "fetch(",
            "no URL validation", "no host allowlist",
        ],
        "policy": "BLOCK",
        "recommendation": "Implement URL allowlisting. Block private/internal IP ranges.",
    },
    "cors_misconfiguration": {
        "id": "PAT-008",
        "name": "CORS Misconfiguration",
        "severity": "MEDIUM",
        "description": "Server uses Access-Control-Allow-Origin: * allowing any origin",
        "indicators": [
            "cors({ origin: '*'})", "Access-Control-Allow-Origin: *",
            "cors: true", "allow all origins",
        ],
        "policy": "CONDITIONAL",
        "recommendation": "Restrict CORS to specific origins. Avoid wildcard in production.",
    },
    "allowlist_bypass": {
        "id": "PAT-009",
        "name": "Allowlist Bypass via Arguments",
        "severity": "HIGH",
        "description": "Command name is allowlisted but arguments are not validated",
        "indicators": [
            "ALLOWED_COMMANDS", "allowlist on name",
            "args are not validated", "args.join",
            "git -c", "command + args",
        ],
        "policy": "BLOCK",
        "recommendation": "Validate both command name AND arguments. Use strict argument schemas.",
    },
    "hidden_transport": {
        "id": "PAT-010",
        "name": "Hidden Transport / Backend Endpoint",
        "severity": "HIGH",
        "description": "Server exposes hidden endpoints for transport injection or config modification",
        "indicators": [
            "/api/transport", "/api/config", "/api/connectors",
            "transport configuration", "config injection",
        ],
        "policy": "BLOCK",
        "recommendation": "Remove hidden admin endpoints or protect with strong authentication.",
    },
    "config_to_execution": {
        "id": "PAT-011",
        "name": "Config-to-Execution Escalation",
        "severity": "CRITICAL",
        "description": "User-provided configuration directly leads to command execution",
        "indicators": [
            "apply_config", "load_mcp_config", "config_json",
            "command from config", "startup_command",
            "mcpServers command execution",
        ],
        "policy": "BLOCK",
        "recommendation": "Never execute commands from user config. Validate and sanitize all config inputs.",
    },
    "runtime_only_danger": {
        "id": "PAT-012",
        "name": "Runtime-Only Vulnerability",
        "severity": "HIGH",
        "description": "Vulnerability only manifests at runtime, invisible to static analysis",
        "indicators": [
            "conditional subprocess", "user-agent check",
            "secret trigger format", "exec: filter",
            "runtime-specific behavior",
        ],
        "policy": "CONDITIONAL",
        "recommendation": "Add runtime monitoring. Static analysis alone is insufficient for this pattern.",
    },
    "ai_config_injection": {
        "id": "PAT-013",
        "name": "AI-Mediated Config Injection",
        "severity": "HIGH",
        "description": "AI assistant suggests or applies MCP config without validation",
        "indicators": [
            "suggest_config", "apply_suggested_config",
            "generate_from_readme", "config without validation",
        ],
        "policy": "BLOCK",
        "recommendation": "Never auto-apply AI-suggested config. Require human review for all config changes.",
    },
}


def get_pattern(pattern_id: str) -> dict | None:
    return PATTERNS.get(pattern_id)


def get_all_patterns() -> dict:
    return PATTERNS


def find_matching_patterns(code: str, tool_descriptions: list[str] = None) -> list[dict]:
    """Scan code and optionally tool descriptions against pattern indicators."""
    matches = []
    code_lower = code.lower()

    for pid, pattern in PATTERNS.items():
        for indicator in pattern["indicators"]:
            if indicator.lower() in code_lower:
                matches.append({
                    "pattern_id": pid,
                    "pattern_name": pattern["name"],
                    "severity": pattern["severity"],
                    "matched_indicator": indicator,
                    "policy": pattern["policy"],
                })
                break

    if tool_descriptions:
        for desc in tool_descriptions:
            desc_lower = desc.lower()
            for indicator in PATTERNS["tool_poisoning"]["indicators"]:
                if indicator.lower() in desc_lower:
                    matches.append({
                        "pattern_id": "tool_poisoning",
                        "pattern_name": "Tool Poisoning / Hidden Instructions",
                        "severity": "HIGH",
                        "matched_indicator": indicator,
                        "policy": "BLOCK",
                    })
                    break

    return matches
