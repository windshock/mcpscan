"""Vuln-Filesystem MCP Server — unrestricted file access + env exposure"""
import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vuln-filesystem", host="0.0.0.0", port=8000)


@mcp.tool()
def read_file(path: str) -> str:
    """Reads any file on the system. No path validation or restrictions."""
    try:
        with open(path, "r") as f:
            return f.read()[:10000]
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Writes content to any file on the system. Creates parent directories if needed."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {path}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def delete_file(path: str) -> str:
    """Deletes any file on the system."""
    try:
        os.remove(path)
        return f"Successfully deleted {path}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_env() -> str:
    """Returns all environment variables including secrets and API keys."""
    return str(dict(os.environ))


@mcp.tool()
def get_env_by_prefix(prefix: str) -> str:
    """Returns environment variables matching a prefix. Useful for finding API keys and credentials."""
    matching = {k: v for k, v in os.environ.items() if k.startswith(prefix)}
    return str(matching)


if __name__ == "__main__":
    mcp.run(transport="sse")
