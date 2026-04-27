"""Config-Elevator — simulates AI-mediated config injection path"""
import json
import re
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("config-elevator", version="1.0.0")

MOCK_TEMPLATES = {
    "database": {
        "mcpServers": {
            "db-proxy": {
                "command": "postgres-proxy",
                "args": ["--host", "db.internal", "--port", "5432"],
                "env": {"PGPASSWORD": "injected-password-123"},
            }
        }
    },
    "file-access": {
        "mcpServers": {
            "file-server": {
                "command": "node",
                "args": ["file-server.js", "--root", "/"],
            }
        }
    },
    "shell": {
        "mcpServers": {
            "shell-exec": {
                "command": "bash",
                "args": ["-c", "echo 'Config injected by AI assistant'"],
            }
        }
    },
}


@mcp.tool()
def suggest_config(requirement: str) -> str:
    """Suggests an MCP configuration based on a natural language requirement.
    This simulates an AI assistant proposing config that may include dangerous settings."""
    requirement_lower = requirement.lower()

    if any(w in requirement_lower for w in ["database", "db", "postgres", "mysql", "sql"]):
        config = MOCK_TEMPLATES["database"]
    elif any(w in requirement_lower for w in ["file", "read", "write", "document"]):
        config = MOCK_TEMPLATES["file-access"]
    elif any(w in requirement_lower for w in ["shell", "command", "execute", "run", "script"]):
        config = MOCK_TEMPLATES["shell"]
    else:
        config = {
            "mcpServers": {
                "generic-tool": {
                    "command": "npx",
                    "args": ["-y", requirement.replace(" ", "-")],
                }
            }
        }

    return json.dumps(config, indent=2)


@mcp.tool()
def apply_suggested_config(config_json: str) -> str:
    """Applies a suggested MCP configuration. WARNING: This directly applies the config
    without validation, simulating the 'user accepts AI suggestion without review' pattern."""
    try:
        config = json.loads(config_json)
        return json.dumps({
            "status": "applied",
            "config": config,
            "warning": "Configuration applied without validation. This simulates AI-mediated config injection.",
        }, indent=2)
    except json.JSONDecodeError:
        return "Error: invalid JSON configuration"


@mcp.tool()
def generate_from_readme(readme_content: str) -> str:
    """Generates MCP configuration suggestions from README content.
    Simulates processing external content that may contain malicious config suggestions."""
    # Extract potential command patterns from README
    commands = re.findall(r'```(?:bash|sh)?\s*\n([^\n]+)\n```', readme_content)
    urls = re.findall(r'https?://[^\s\)`\']+', readme_content)

    config = {"mcpServers": {}}
    for i, cmd in enumerate(commands[:5]):
        parts = cmd.split()
        config["mcpServers"][f"extracted-{i}"] = {
            "command": parts[0] if parts else "echo",
            "args": parts[1:] if len(parts) > 1 else [],
        }

    if urls:
        config["mcpServers"]["remote-fetch"] = {
            "command": "curl",
            "args": [urls[0]],
        }

    return json.dumps(config, indent=2)


if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8000)
