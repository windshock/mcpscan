"""MCP Guard Scanner — analyzes MCP server code, config, and endpoints."""
from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from mcp import ClientSession
from mcp.client.sse import sse_client

from .patterns import PATTERNS, find_matching_patterns

logging.getLogger("mcp.client.sse").setLevel(logging.CRITICAL)
logging.getLogger("httpx_sse").setLevel(logging.CRITICAL)


def scan_path(path: str) -> dict:
    """Scan a local directory or file for MCP vulnerability patterns."""
    target = Path(path)

    if target.is_file():
        code = target.read_text(errors="ignore")
        tool_descriptions = _extract_tool_descriptions(code)
        matches = find_matching_patterns(code, tool_descriptions)
        return _build_result(str(target), matches, code)

    if target.is_dir():
        all_code = ""
        all_tool_descriptions = []
        for f in target.rglob("*"):
            if f.suffix in (".py", ".ts", ".js", ".json", ".yaml", ".yml", ".toml"):
                try:
                    code = f.read_text(errors="ignore")
                    all_code += f"\n# --- {f.relative_to(target)} ---\n{code}"
                    all_tool_descriptions.extend(_extract_tool_descriptions(code))
                except Exception:
                    continue

        matches = find_matching_patterns(all_code, all_tool_descriptions)
        return _build_result(str(target), matches, all_code)

    return {"error": f"Path not found: {path}"}


def scan_config(config_json: str) -> dict:
    """Scan an MCP configuration JSON for dangerous patterns."""
    try:
        config = json.loads(config_json)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}"}

    matches = []

    if "mcpServers" in config:
        for name, server_conf in config["mcpServers"].items():
            if "command" in server_conf:
                matches.append({
                    "pattern_id": "config_to_execution",
                    "pattern_name": "Config-to-Execution Escalation",
                    "severity": "CRITICAL",
                    "matched_indicator": f"mcpServers.{name}.command = {server_conf['command']}",
                    "policy": "BLOCK",
                })
            if "args" in server_conf:
                args = server_conf["args"]
                if any(a.startswith("-") for a in args):
                    matches.append({
                        "pattern_id": "allowlist_bypass",
                        "pattern_name": "Allowlist Bypass via Arguments",
                        "severity": "HIGH",
                        "matched_indicator": f"mcpServers.{name}.args contains flags: {args}",
                        "policy": "BLOCK",
                    })
            if "env" in server_conf:
                env = server_conf["env"]
                secret_keys = [k for k in env if any(s in k.lower() for s in ["password", "secret", "key", "token"])]
                if secret_keys:
                    matches.append({
                        "pattern_id": "env_exposure",
                        "pattern_name": "Environment Variable / Secret Exposure",
                        "severity": "HIGH",
                        "matched_indicator": f"mcpServers.{name}.env contains secrets: {secret_keys}",
                        "policy": "BLOCK",
                    })

    return _build_result("config_json", matches, config_json)


def probe_endpoint(endpoint_url: str) -> dict:
    """Probe a likely MCP endpoint and collect lightweight metadata."""
    base_url, sse_url = _resolve_probe_urls(endpoint_url)
    summary = {
        "base_url": base_url,
        "sse_url": sse_url,
        "reachable": False,
        "auth_required": None,
        "mcp_detected": False,
        "tool_count": 0,
        "tool_names": [],
        "tools": [],
        "markers": [],
        "checks": [],
        "error": None,
    }

    try:
        tools = asyncio.run(_list_tools_via_sse(sse_url))
        summary["reachable"] = True
        summary["mcp_detected"] = True
        summary["auth_required"] = False
        summary["markers"].extend(["sse_endpoint", "mcp_tools_listed"])
        summary["tools"] = tools
        summary["tool_count"] = len(tools)
        summary["tool_names"] = [tool.get("name", "") for tool in tools]
        summary["checks"].append({"url": sse_url, "kind": "mcp_sse", "status": 200})
    except Exception as exc:
        summary["error"] = str(exc)
        summary["checks"].append(
            {
                "url": sse_url,
                "kind": "mcp_sse",
                "status": None,
                "error": str(exc),
            }
        )

    for path in ("/health", "/", "/messages"):
        check = _http_probe(urljoin(base_url, path.lstrip("/")))
        summary["checks"].append(check)
        status = check.get("status")
        headers = check.get("headers", {})

        if status and 200 <= status < 500:
            summary["reachable"] = True

        if status in (401, 403):
            summary["auth_required"] = True
            summary["markers"].append("auth_required")

        if headers.get("access-control-allow-origin") == "*":
            summary["markers"].append("cors_wildcard")

        content_type = (check.get("content_type") or "").lower()
        body_excerpt = (check.get("body_excerpt") or "").lower()
        if "text/event-stream" in content_type:
            summary["markers"].append("sse_content_type")
        if "modelcontextprotocol" in body_excerpt or "tools" in body_excerpt:
            summary["markers"].append("mcp_like_body")

    summary["markers"] = sorted(set(summary["markers"]))
    return summary


def scan_endpoint(endpoint_url: str) -> dict:
    """Scan a live endpoint and map it into the normal result shape."""
    summary = probe_endpoint(endpoint_url)
    tools = summary.get("tools", [])
    server_info = {"auth": summary["auth_required"] is not False}

    if tools:
        result = scan_endpoint_info(tools, server_info)
        result["target"] = endpoint_url
        result["notes"] = []
        result["probe_summary"] = summary
        return result

    partial_matches = []
    if summary.get("auth_required") is False:
        partial_matches.append(
            {
                "pattern_id": "authless_endpoint",
                "pattern_name": "Authentication-Less Endpoint",
                "severity": "HIGH",
                "matched_indicator": f"Endpoint reachable without authentication: {summary['base_url']}",
                "policy": "BLOCK",
            }
        )
    if "cors_wildcard" in summary.get("markers", []):
        partial_matches.append(
            {
                "pattern_id": "cors_misconfiguration",
                "pattern_name": "CORS Misconfiguration",
                "severity": "MEDIUM",
                "matched_indicator": "Access-Control-Allow-Origin: *",
                "policy": "CONDITIONAL",
            }
        )

    result = _build_result(endpoint_url, partial_matches, json.dumps(summary, indent=2))
    result["notes"] = [summary["error"] or "Endpoint responded but MCP tool discovery did not succeed."]
    result["probe_summary"] = summary
    return result


def scan_endpoint_info(tool_list: list[dict], server_info: dict = None) -> dict:
    """Scan tool metadata and server info from a live MCP endpoint."""
    matches = []
    all_descriptions = []

    for tool in tool_list:
        desc = tool.get("description", "")
        name = tool.get("name", "")
        all_descriptions.append(desc)

        # Check for command execution patterns in tool names
        exec_names = ["execute", "run", "exec", "shell", "command", "system"]
        if any(e in name.lower() for e in exec_names):
            matches.append({
                "pattern_id": "command_exec",
                "pattern_name": "Direct Command Execution",
                "severity": "CRITICAL",
                "matched_indicator": f"tool name: {name}",
                "policy": "BLOCK",
            })

        # Check input schema for dangerous patterns
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        if "cmd" in properties or "command" in properties:
            matches.append({
                "pattern_id": "command_exec",
                "pattern_name": "Direct Command Execution",
                "severity": "CRITICAL",
                "matched_indicator": f"tool '{name}' accepts cmd/command parameter",
                "policy": "BLOCK",
            })
        if "url" in properties:
            matches.append({
                "pattern_id": "ssrf",
                "pattern_name": "Server-Side Request Forgery",
                "severity": "HIGH",
                "matched_indicator": f"tool '{name}' accepts url parameter",
                "policy": "BLOCK",
            })
        if "path" in properties:
            matches.append({
                "pattern_id": "unrestricted_file_read",
                "pattern_name": "Unrestricted File Read",
                "severity": "HIGH",
                "matched_indicator": f"tool '{name}' accepts path parameter",
                "policy": "CONDITIONAL",
            })

    # Check for tool poisoning in descriptions
    from .patterns import find_matching_patterns
    desc_matches = find_matching_patterns("", all_descriptions)
    matches.extend(desc_matches)

    if server_info and server_info.get("auth") is False:
        matches.append({
            "pattern_id": "authless_endpoint",
            "pattern_name": "Authentication-Less Endpoint",
            "severity": "HIGH",
            "matched_indicator": "No authentication detected",
            "policy": "BLOCK",
        })

    return _build_result("endpoint", matches, json.dumps(tool_list, indent=2))


def _extract_tool_descriptions(code: str) -> list[str]:
    """Extract tool description strings from code."""
    descriptions = []

    # Python: triple-quoted strings after @mcp.tool() or in tool definitions
    py_pattern = r'(?:description\s*=\s*|"""?\s*)([^"\n]{20,})'
    for m in re.finditer(py_pattern, code):
        descriptions.append(m.group(1).strip())

    # TypeScript/JavaScript: description in object literals
    ts_pattern = r'description:\s*["`]([^"`\n]{20,})["`]'
    for m in re.finditer(ts_pattern, code):
        descriptions.append(m.group(1).strip())

    return descriptions


async def _list_tools_via_sse(sse_url: str) -> list[dict]:
    async with sse_client(sse_url, timeout=3, sse_read_timeout=3) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.list_tools()
            return [
                tool.model_dump(by_alias=True, mode="json", exclude_none=True)
                for tool in result.tools
            ]


def _http_probe(url: str) -> dict:
    headers = {}
    try:
        req = Request(url, method="GET", headers={"Accept": "*/*"})
        with urlopen(req, timeout=2) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            body_excerpt = response.read(512).decode("utf-8", errors="ignore")
            return {
                "url": url,
                "kind": "http",
                "status": response.status,
                "content_type": headers.get("content-type"),
                "headers": headers,
                "body_excerpt": body_excerpt,
            }
    except HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()}
        body_excerpt = exc.read(512).decode("utf-8", errors="ignore")
        return {
            "url": url,
            "kind": "http",
            "status": exc.code,
            "content_type": headers.get("content-type"),
            "headers": headers,
            "body_excerpt": body_excerpt,
        }
    except (URLError, TimeoutError, OSError) as exc:
        return {
            "url": url,
            "kind": "http",
            "status": None,
            "content_type": None,
            "headers": headers,
            "body_excerpt": "",
            "error": str(exc),
        }


def _resolve_probe_urls(endpoint_url: str) -> tuple[str, str]:
    parsed = urlparse(endpoint_url)
    if not parsed.scheme:
        endpoint_url = f"http://{endpoint_url}"
        parsed = urlparse(endpoint_url)

    normalized = parsed._replace(path=parsed.path or "/", query="", fragment="")
    base_url = normalized.geturl().rstrip("/")
    if parsed.path.endswith("/sse"):
        sse_url = normalized.geturl()
        base_url = normalized._replace(path=parsed.path[:-4] or "/").geturl().rstrip("/")
    else:
        sse_url = urljoin(f"{base_url}/", "sse")
    return base_url, sse_url


def _build_result(target: str, matches: list, source: str) -> dict:
    """Build a scan result dict from matches."""
    deduped = []
    seen = set()
    for m in matches:
        key = (m["pattern_id"], m["matched_indicator"])
        if key not in seen:
            seen.add(key)
            deduped.append(m)

    severities = [m["severity"] for m in deduped]
    if "CRITICAL" in severities:
        risk = "CRITICAL"
    elif "HIGH" in severities:
        risk = "HIGH"
    elif "MEDIUM" in severities:
        risk = "MEDIUM"
    elif deduped:
        risk = "LOW"
    else:
        risk = "NONE"

    return {
        "target": target,
        "risk": risk,
        "findings": deduped,
        "finding_count": len(deduped),
        "source_length": len(source),
    }
