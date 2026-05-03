"""MCP Security Pattern Catalog — the knowledge base for vulnerability detection."""
from __future__ import annotations

import re

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
        "description": "Tool exposes environment variable values (full key+value dump)",
        "indicators": [
            "dict(os.environ)", "str(dict(os.environ",
            "os.environ.items()", "os.environ.copy()",
            "Object.entries(process.env)", "JSON.stringify(process.env)",
            "list_environment", "get_env()",
            "Returns all environment variables",
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
            "fetch_url", "Fetches content from any URL",
            "Sends a POST request to any URL", "send_webhook",
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
            'origin: "*"', "origin: '*'",
            "Access-Control-Allow-Origin: *",
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
            "SECRET_TRIGGER", "secret trigger format",
            "user-agent check", "exec: filter",
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
    "command_exec_via_args": {
        "id": "PAT-014",
        "name": "Command Execution via Arguments",
        "severity": "HIGH",
        "description": "Allowlisted command name but arguments are passed unvalidated to a shell",
        "indicators": [
            "ALLOWED_COMMANDS", "args.join", "command + args",
            "${cmd} ${", "[cmd] + args",
        ],
        "policy": "BLOCK",
        "recommendation": "Validate arguments. Use a strict argument schema or argv-based exec without shell.",
    },
    "remote_config_loading": {
        "id": "PAT-015",
        "name": "Remote Config Loading",
        "severity": "HIGH",
        "description": "Loads configuration JSON from a remote URL and applies it (potentially executing commands)",
        "indicators": [
            "load_mcp_config",
            "Loads an MCP configuration from a remote URL",
            "fetched config is parsed",
        ],
        "policy": "BLOCK",
        "recommendation": "Never fetch and apply config from untrusted URLs. Pin config sources and verify integrity.",
    },
    "internal_metadata_exposure": {
        "id": "PAT-016",
        "name": "Internal Metadata Exposure",
        "severity": "HIGH",
        "description": "Server exposes internal hostnames, network configuration, service endpoints, or process metadata",
        "indicators": [
            "internal_services", "exposed_ports", "Object.keys(process.env",
            "docker_network", "internal service metadata",
            "debug_info",
        ],
        "policy": "BLOCK",
        "recommendation": "Do not return internal network/process metadata from tools. Restrict diagnostics to operators.",
    },
    "connector_metadata_exposure": {
        "id": "PAT-017",
        "name": "Connector Metadata Exposure",
        "severity": "HIGH",
        "description": "Endpoint exposes connector configuration including stdio commands and credentials",
        "indicators": [
            "/api/connectors", "PGPASSWORD",
            "internal-db-password", "type: \"stdio\", command",
        ],
        "policy": "BLOCK",
        "recommendation": "Do not expose connector configuration over HTTP. Keep credentials in protected secrets.",
    },
    "config_injection": {
        "id": "PAT-018",
        "name": "Config Injection Endpoint",
        "severity": "HIGH",
        "description": "Endpoint accepts arbitrary configuration that is applied at runtime",
        "indicators": [
            "/api/config",
            "Configuration has been applied",
            "applied to the server",
        ],
        "policy": "BLOCK",
        "recommendation": "Remove ad-hoc config-apply endpoints or gate them behind strong auth and validation.",
    },
    "excessive_permissions": {
        "id": "PAT-019",
        "name": "Excessive Filesystem / System Permissions",
        "severity": "HIGH",
        "description": "Tool exposes a wide range of filesystem or system operations without scoping",
        "indicators": [
            "read_file + write_file + delete_file",
            "broad filesystem capability",
        ],
        "policy": "BLOCK",
        "recommendation": "Reduce tool capabilities. Split tools by intent and scope each to allowlisted resources.",
    },
    "conditional_command_exec": {
        "id": "PAT-020",
        "name": "Conditional Command Execution",
        "severity": "HIGH",
        "description": "Subprocess execution is gated by runtime input (format flag, header, or filter prefix)",
        "indicators": [
            "if format ==", "if component ==",
            "filter.startswith(\"exec:\")",
            "filter.startswith('exec:')",
            "request_headers.get",
        ],
        "policy": "BLOCK",
        "recommendation": "Remove hidden runtime-triggered command execution. Disallow shell exec entirely.",
    },
    "static_analysis_bypass": {
        "id": "PAT-021",
        "name": "Static Analysis Bypass",
        "severity": "HIGH",
        "description": "Code uses runtime triggers (string equality, magic prefixes) to evade static scanners",
        "indicators": [
            "SECRET_TRIGGER_FORMAT", "SECRET_TRIGGER_AGENT",
            "MCP-Inspector/", "debug-internal",
        ],
        "policy": "BLOCK",
        "recommendation": "Eliminate hidden runtime triggers. Treat all execution paths as reachable.",
    },
}


_VALIDATION_TOKENS = (
    ".startswith(",
    ".resolve()",
    "realpath",
    "os.path.normpath",
    "ALLOWED_PATH",
    "ALLOWED_PREFIX",
    "is_safe_path",
    "if \"..\" in path",
    "if '..' in path",
)

_EXPLICIT_UNRESTRICTED_PHRASES = (
    "no path validation",
    "no path restriction",
    "no restrictions apply",
    "any file on the system",
    "unrestricted file",
    "no allowlist",
    "no prefix check",
)

_AUTH_TOKENS = (
    "BEARER_TOKEN",
    "verify_token",
    "verify_api_key",
    "Authorization",
    "Bearer ",
    "auth_required",
    "api_key",
    "apikey",
    "OAuth",
)


def get_pattern(pattern_id: str) -> dict | None:
    return PATTERNS.get(pattern_id)


def get_all_patterns() -> dict:
    return PATTERNS


def _make_match(pattern_id: str, indicator: str) -> dict:
    pattern = PATTERNS[pattern_id]
    return {
        "pattern_id": pattern_id,
        "pattern_name": pattern["name"],
        "severity": pattern["severity"],
        "matched_indicator": indicator,
        "policy": pattern["policy"],
    }


def _detect_tool_poisoning(tool_descriptions: list[str] | None) -> list[dict]:
    if not tool_descriptions:
        return []
    indicators = PATTERNS["tool_poisoning"]["indicators"]
    matches = []
    for desc in tool_descriptions:
        desc_lower = desc.lower()
        for indicator in indicators:
            if indicator.lower() in desc_lower:
                matches.append(_make_match("tool_poisoning", indicator))
                break
    return matches


def _detect_static_analysis_bypass(code: str) -> list[dict]:
    matches = []
    for indicator in PATTERNS["static_analysis_bypass"]["indicators"]:
        if indicator in code:
            matches.append(_make_match("static_analysis_bypass", indicator))
            break
    return matches


def _detect_conditional_command_exec(code: str) -> list[dict]:
    has_subprocess = bool(
        re.search(r"\bsubprocess\.(run|call|Popen)\b", code)
        or re.search(r"\bexec\s*\(", code)
        or re.search(r"\bos\.system\s*\(", code)
    )
    if not has_subprocess:
        return []
    triggers = [
        ("if format ==", r"if\s+format\s*==\s*['\"]"),
        ("if component ==", r"if\s+component\s*==\s*['\"]"),
        ("filter.startswith(\"exec:\")", r"filter\.startswith\(\s*['\"]exec:['\"]"),
        ("user_agent ==", r"user_agent\s*==\s*['\"]"),
        ("request_headers.get", r"request_headers\.get\("),
    ]
    matches = []
    for indicator, regex in triggers:
        if re.search(regex, code):
            matches.append(_make_match("conditional_command_exec", indicator))
    return matches


def _detect_runtime_only_family(code: str) -> list[dict]:
    """Detect SECRET_TRIGGER + conditional subprocess as a family.

    Returns runtime_only_danger + any conditional_command_exec / static_analysis_bypass
    sub-findings. When this fires, callers should suppress generic command_exec /
    env_exposure detections to avoid double-counting the same runtime-only behavior.
    """
    sab = _detect_static_analysis_bypass(code)
    cce = _detect_conditional_command_exec(code)
    if not (sab or cce):
        return []

    matches = []
    matches.extend(sab)
    matches.extend(cce)
    indicator = "runtime-triggered subprocess gated by hardcoded value"
    matches.append(_make_match("runtime_only_danger", indicator))
    return matches


def _detect_allowlist_bypass(code: str) -> list[dict]:
    matches = []
    has_allowed_const = "ALLOWED_COMMANDS" in code or "allowlist on name" in code
    has_args_concat = bool(
        re.search(r"\.join\(", code)
        or re.search(r"\[\s*cmd\s*\]\s*\+\s*args", code)
        or re.search(r"command\s*\+\s*['\"]\s*['\"]?\s*\+\s*args", code)
    )
    has_exec = bool(
        re.search(r"\bexec\s*\(", code)
        or re.search(r"\bsubprocess\.(run|call|Popen)\b", code)
        or re.search(r"\bspawn\s*\(", code)
    )
    if has_allowed_const:
        matches.append(_make_match("allowlist_bypass", "ALLOWED_COMMANDS"))
    if "git -c" in code or "core.pager=" in code:
        matches.append(_make_match("allowlist_bypass", "git -c"))
    if has_allowed_const and has_args_concat and has_exec:
        matches.append(_make_match("command_exec_via_args", "ALLOWED_COMMANDS + unvalidated args"))
    return matches


def _detect_remote_config_loading(code: str) -> list[dict]:
    matches = []
    for indicator in PATTERNS["remote_config_loading"]["indicators"]:
        if indicator.lower() in code.lower():
            matches.append(_make_match("remote_config_loading", indicator))
            break
    return matches


def _detect_config_to_execution(code: str) -> list[dict]:
    matches = []
    for indicator in PATTERNS["config_to_execution"]["indicators"]:
        if indicator in code:
            matches.append(_make_match("config_to_execution", indicator))
            break
    return matches


def _detect_command_exec(code: str, *, suppress: bool) -> list[dict]:
    if suppress:
        return []
    matches = []
    for indicator in PATTERNS["command_exec"]["indicators"]:
        if indicator in code:
            matches.append(_make_match("command_exec", indicator))
            break
    return matches


def _detect_unrestricted_file_read(code: str) -> list[dict]:
    has_read = bool(
        re.search(r"open\s*\(\s*\w*path\b", code)
        or re.search(r"\bread_file\s*\(", code)
        or re.search(r"\bfs\.(readFile|readFileSync)\b", code)
    )
    if not has_read:
        return []

    code_lower = code.lower()
    explicit = next(
        (phrase for phrase in _EXPLICIT_UNRESTRICTED_PHRASES if phrase in code_lower),
        None,
    )
    has_validation = any(token in code for token in _VALIDATION_TOKENS)

    if has_validation and not explicit:
        return []
    indicator = explicit or "open(path) without restriction"
    return [_make_match("unrestricted_file_read", indicator)]


def _detect_unrestricted_file_write(code: str) -> list[dict]:
    has_write = bool(
        re.search(r"\bwrite_file\s*\(\s*\w*path", code)
        or re.search(r"open\s*\(\s*\w*path[^)]*['\"]w", code)
        or re.search(r"\bos\.makedirs\b", code)
        or re.search(r"\bfs\.writeFile\b", code)
    )
    if not has_write:
        return []
    code_lower = code.lower()
    has_validation = any(token in code for token in _VALIDATION_TOKENS)
    explicit_unrestricted = any(
        phrase in code_lower
        for phrase in (
            "any file on the system",
            "no write validation",
            "no path validation",
            "creates parent directories",
        )
    )
    if has_validation and not explicit_unrestricted:
        return []
    indicator = "write_file(path) without restriction"
    return [_make_match("unrestricted_file_write", indicator)]


def _detect_env_exposure(code: str, *, suppress: bool) -> list[dict]:
    if suppress:
        return []
    matches = []
    for indicator in PATTERNS["env_exposure"]["indicators"]:
        if indicator in code:
            matches.append(_make_match("env_exposure", indicator))
            break
    return matches


def _detect_ssrf(code: str, *, suppress: bool) -> list[dict]:
    if suppress:
        return []
    matches = []
    for indicator in PATTERNS["ssrf"]["indicators"]:
        if indicator in code:
            matches.append(_make_match("ssrf", indicator))
            break
    return matches


def _detect_cors_misconfiguration(code: str) -> list[dict]:
    if re.search(r"origin\s*:\s*['\"]\*['\"]", code):
        return [_make_match("cors_misconfiguration", 'origin: "*"')]
    if "Access-Control-Allow-Origin: *" in code:
        return [_make_match("cors_misconfiguration", "Access-Control-Allow-Origin: *")]
    if "cors: true" in code or "allow all origins" in code.lower():
        return [_make_match("cors_misconfiguration", "cors: true")]
    return []


def _detect_hidden_transport(code: str) -> list[dict]:
    indicators = ["/api/transport", "/api/config", "/api/connectors"]
    for indicator in indicators:
        if indicator in code:
            return [_make_match("hidden_transport", indicator)]
    return []


def _detect_internal_metadata_exposure(code: str) -> list[dict]:
    signals = [
        "internal_services",
        "exposed_ports",
        "docker_network",
        "Object.keys(process.env",
    ]
    hits = [s for s in signals if s in code]
    if hits:
        return [_make_match("internal_metadata_exposure", hits[0])]
    return []


def _detect_connector_metadata_exposure(code: str) -> list[dict]:
    if "/api/connectors" in code and ("PGPASSWORD" in code or "internal-db-password" in code or "type: \"stdio\"" in code):
        return [_make_match("connector_metadata_exposure", "/api/connectors with stdio command + credentials")]
    return []


def _detect_config_injection(code: str) -> list[dict]:
    if "/api/config" in code and ("Configuration has been applied" in code or "applied to the server" in code):
        return [_make_match("config_injection", "/api/config accepts arbitrary body")]
    return []


def _detect_excessive_permissions(code: str) -> list[dict]:
    capabilities = {
        "read": bool(re.search(r"def\s+read_file\b", code) or re.search(r"\bfs\.readFile\b", code)),
        "write": bool(re.search(r"def\s+write_file\b", code) or re.search(r"\bfs\.writeFile\b", code)),
        "delete": bool(re.search(r"def\s+delete_file\b|\bos\.remove\b|\bfs\.unlink\b", code)),
        "env": bool(re.search(r"def\s+get_env\b", code)),
    }
    if sum(capabilities.values()) >= 3:
        present = [k for k, v in capabilities.items() if v]
        return [_make_match("excessive_permissions", "+".join(sorted(present)))]
    return []


def _detect_ai_config_injection(code: str) -> list[dict]:
    matches = []
    for indicator in PATTERNS["ai_config_injection"]["indicators"]:
        if indicator in code:
            matches.append(_make_match("ai_config_injection", indicator))
            break
    return matches


def find_matching_patterns(code: str, tool_descriptions: list[str] = None) -> list[dict]:
    """Scan code and tool descriptions, returning a list of match dicts.

    Detection runs as a pipeline so that specific patterns (allowlist bypass,
    runtime-only family, remote config loading) suppress generic ones (command
    execution, env exposure, SSRF) when the same code is already covered by a
    more precise finding.
    """
    matches: list[dict] = []

    runtime_family = _detect_runtime_only_family(code)
    matches.extend(runtime_family)
    has_runtime = bool(runtime_family)

    allowlist = _detect_allowlist_bypass(code)
    matches.extend(allowlist)
    has_allowlist = bool(allowlist)

    config_exec = _detect_config_to_execution(code)
    matches.extend(config_exec)

    remote_config = _detect_remote_config_loading(code)
    matches.extend(remote_config)
    has_remote_config = bool(remote_config)

    matches.extend(_detect_command_exec(code, suppress=has_runtime or has_allowlist))
    matches.extend(_detect_unrestricted_file_read(code))
    matches.extend(_detect_unrestricted_file_write(code))
    matches.extend(_detect_env_exposure(code, suppress=has_runtime))
    matches.extend(_detect_ssrf(code, suppress=has_remote_config))
    matches.extend(_detect_cors_misconfiguration(code))
    matches.extend(_detect_hidden_transport(code))
    matches.extend(_detect_internal_metadata_exposure(code))
    matches.extend(_detect_connector_metadata_exposure(code))
    matches.extend(_detect_config_injection(code))
    matches.extend(_detect_excessive_permissions(code))
    matches.extend(_detect_ai_config_injection(code))

    matches.extend(_detect_tool_poisoning(tool_descriptions))

    return matches
