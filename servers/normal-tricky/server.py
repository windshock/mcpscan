"""Normal-Tricky MCP Server — FP trap: looks dangerous but is actually safe"""
import os
import re
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("normal-tricky", host="0.0.0.0", port=8000)

BEARER_TOKEN = os.environ.get("BEARER_TOKEN", "dev-test-token-tricky-2026")

SAFE_SCRIPTS = {
    "hello": "echo 'Hello World'",
    "status": "echo 'System status: OK'",
    "version": "echo 'v1.0.0'",
}

SAFE_CONFIG_KEYS = {
    "app_name": "MCP Demo",
    "app_version": "1.0.0",
    "log_level": "INFO",
    "max_retries": "3",
}

MOCK_PROCESSES = [
    {"pid": 1, "name": "init", "status": "running", "cpu": "0.0%"},
    {"pid": 42, "name": "mcp-server", "status": "running", "cpu": "1.2%"},
    {"pid": 99, "name": "health-monitor", "status": "sleeping", "cpu": "0.1%"},
]


@mcp.tool()
def run_script(name: str) -> str:
    """Executes a predefined script by name. Only whitelisted script names are allowed.
    Available scripts: hello, status, version."""
    if name not in SAFE_SCRIPTS:
        return f"Error: script '{name}' is not in the allowed list. Available: {list(SAFE_SCRIPTS.keys())}"
    return f"[OUTPUT] {SAFE_SCRIPTS[name]}"


@mcp.tool()
def read_config(key: str) -> str:
    """Returns a configuration value. Only whitelisted non-sensitive keys are accessible."""
    if key not in SAFE_CONFIG_KEYS:
        return f"Error: key '{key}' is not accessible. Available: {list(SAFE_CONFIG_KEYS.keys())}"
    return SAFE_CONFIG_KEYS[key]


@mcp.tool()
def list_processes() -> str:
    """Lists running processes. Returns sanitized mock process information."""
    lines = ["PID   NAME            STATUS     CPU"]
    for p in MOCK_PROCESSES:
        lines.append(f"{p['pid']:<5} {p['name']:<15} {p['status']:<10} {p['cpu']}")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="sse")
