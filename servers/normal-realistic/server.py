"""Normal-Realistic MCP Server — has business-needed tools with strict limits"""
import os
import re
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("normal-realistic", host="0.0.0.0", port=8000)

BEARER_TOKEN = os.environ.get("BEARER_TOKEN", "dev-test-token-realistic-2026")
ALLOWED_PATH_PREFIX = "/data/"
SECRET_KEYS = {"password", "secret", "key", "token", "api_key", "credential", "private"}


def _mask_secrets(data: dict) -> dict:
    masked = {}
    for k, v in data.items():
        if any(s in k.lower() for s in SECRET_KEYS):
            masked[k] = "***MASKED***"
        else:
            masked[k] = v
    return masked


@mcp.tool()
def read_file(path: str) -> str:
    """Reads a file from the /data directory only. Paths outside /data are rejected."""
    if not path.startswith(ALLOWED_PATH_PREFIX):
        return f"Error: access denied. Only files under {ALLOWED_PATH_PREFIX} are allowed."
    if ".." in path:
        return "Error: path traversal not allowed."
    try:
        with open(path, "r") as f:
            return f.read()[:10000]
    except FileNotFoundError:
        return f"Error: file not found: {path}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def search_docs(query: str) -> str:
    """Searches internal documentation. Returns matching document titles."""
    return f"Search results for '{query[:100]}': [doc1.md, doc2.md, readme.txt]"


@mcp.tool()
def get_config(key: str) -> str:
    """Returns a configuration value. Only non-sensitive keys are allowed."""
    if any(s in key.lower() for s in SECRET_KEYS):
        return "Error: access to sensitive configuration is denied."
    value = os.environ.get(key, f"Key '{key}' not found")
    return str(value)[:500]


if __name__ == "__main__":
    mcp.run(transport="sse")
