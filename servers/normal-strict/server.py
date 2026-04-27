"""Normal-Strict MCP Server — FP baseline (safest possible)"""
import os
from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("normal-strict", host="0.0.0.0", port=8000)

BEARER_TOKEN = os.environ.get("BEARER_TOKEN", "dev-test-token-normal-2026")


def verify_token(token: str | None) -> bool:
    if not token:
        return False
    return token == BEARER_TOKEN


@mcp.tool()
def get_time() -> str:
    """Returns the current UTC time."""
    return datetime.now(timezone.utc).isoformat()


@mcp.tool()
def calculate(expression: str) -> str:
    """Evaluates a simple arithmetic expression. Only numbers and basic operators (+-*/) are allowed."""
    import re
    if not re.match(r'^[\d\s\+\-\*\/\(\)\.]+$', expression):
        return "Error: invalid expression"
    try:
        result = eval(expression, {"__builtins__": {}}, {})
        return str(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def echo(message: str) -> str:
    """Echoes back the provided message. Maximum 200 characters."""
    return message[:200]


if __name__ == "__main__":
    mcp.run(transport="sse")
