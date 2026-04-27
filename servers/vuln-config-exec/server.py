"""Vuln-Config-Exec MCP Server — config to execution escalation"""
import json
import subprocess
import urllib.request
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vuln-config-exec", host="0.0.0.0", port=8000)


@mcp.tool()
def apply_config(config_json: str) -> str:
    """Applies a configuration JSON. The config may contain a 'command' field that will be executed.
    Accepts JSON like: {"command": "echo hello", "args": [...]}"""
    try:
        config = json.loads(config_json)
        cmd = config.get("command") or config.get("cmd")
        args = config.get("args", [])
        if not cmd:
            return "Error: no 'command' or 'cmd' field in config"
        if args:
            full_cmd = [cmd] + args
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=30)
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        return output[:10000]
    except json.JSONDecodeError:
        return "Error: invalid JSON"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def load_mcp_config(url: str) -> str:
    """Loads an MCP configuration from a remote URL and applies it.
    The fetched config is parsed and any commands within are executed."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "mcp-config-loader/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8")
        config = json.loads(content)
        results = []
        if "mcpServers" in config:
            for name, server_conf in config["mcpServers"].items():
                if "command" in server_conf:
                    cmd = server_conf["command"]
                    args = server_conf.get("args", [])
                    try:
                        r = subprocess.run([cmd] + args, capture_output=True, text=True, timeout=30)
                        results.append(f"[{name}] {r.stdout[:500]}")
                    except Exception as e:
                        results.append(f"[{name}] Error: {e}")
        return "\n".join(results) if results else f"Loaded config from {url}: no executable entries found"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def update_settings(key: str, value: str) -> str:
    """Updates a server setting. If the key is 'startup_command', the value is executed as a command."""
    if key == "startup_command":
        try:
            result = subprocess.run(value, shell=True, capture_output=True, text=True, timeout=30)
            return f"Executed startup command: {result.stdout[:500]}"
        except Exception as e:
            return f"Error executing command: {e}"
    return f"Setting '{key}' updated to '{value}'"


if __name__ == "__main__":
    mcp.run(transport="sse")
