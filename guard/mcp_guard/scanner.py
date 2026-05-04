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


HIDDEN_PROBES = (
    {"path": "/api/connectors", "method": "GET", "body": None},
    {"path": "/api/transport", "method": "POST", "body": "{}"},
    {"path": "/api/config", "method": "PUT", "body": "{}"},
)


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
        "hidden_probes": [],
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

    for spec in HIDDEN_PROBES:
        probe = _http_probe(
            urljoin(base_url, spec["path"].lstrip("/")),
            method=spec["method"],
            body=spec.get("body"),
        )
        summary["hidden_probes"].append(probe)
        status = probe.get("status")
        if status is not None and status != 404:
            summary["markers"].append(f"hidden:{spec['path']}")
            if status and 200 <= status < 500:
                summary["reachable"] = True

    summary["markers"] = sorted(set(summary["markers"]))
    return summary


def scan_endpoint(endpoint_url: str) -> dict:
    """Scan a live endpoint and map it into the normal result shape."""
    summary = probe_endpoint(endpoint_url)

    matches: list[dict] = []
    matches.extend(_findings_from_tool_list(summary.get("tools") or []))
    matches.extend(_findings_from_probe_markers(summary))
    matches.extend(_findings_from_hidden_probes(summary.get("hidden_probes") or []))

    notes: list[str] = []
    if not summary.get("tools") and summary.get("error"):
        notes.append(summary["error"])
    if not summary.get("reachable"):
        notes.append("Endpoint not reachable; findings only reflect probe-level checks.")

    result = _build_result(endpoint_url, matches, json.dumps(summary, indent=2))
    result["notes"] = notes
    result["probe_summary"] = summary
    return result


def scan_endpoint_info(tool_list: list[dict], server_info: dict = None) -> dict:
    """Scan tool metadata and server info from a live MCP endpoint."""
    matches: list[dict] = []
    matches.extend(_findings_from_tool_list(tool_list))

    if server_info and server_info.get("auth") is False:
        matches.append(_endpoint_match("authless_endpoint", "No authentication detected"))

    return _build_result("endpoint", matches, json.dumps(tool_list, indent=2))


def _endpoint_match(pattern_id: str, indicator: str) -> dict:
    from .patterns import PATTERNS

    pattern = PATTERNS.get(
        pattern_id,
        {
            "name": pattern_id,
            "severity": "HIGH",
            "policy": "BLOCK",
        },
    )
    return {
        "pattern_id": pattern_id,
        "pattern_name": pattern["name"],
        "severity": pattern["severity"],
        "matched_indicator": indicator,
        "policy": pattern["policy"],
    }


def _findings_from_tool_list(tool_list: list[dict]) -> list[dict]:
    """Translate live MCP tool metadata into pattern matches."""
    matches: list[dict] = []
    all_descriptions: list[str] = []
    seen_descriptions = False

    exec_names = ("execute_", "run_with", "shell", "_exec", "exec_", "_command")
    metadata_keywords = ("metadata", "internal_service", "diagnostic")
    metadata_descriptions = (
        "internal service metadata",
        "internal services",
        "network configuration",
        "service endpoints",
    )
    config_apply_names = ("apply_config", "update_settings", "set_config")
    config_load_names = ("load_mcp_config", "load_config", "fetch_config")

    has_command_param = False
    has_args_param = False
    allowlist_hint = False
    capabilities = {"read": False, "write": False, "delete": False, "env": False}

    for tool in tool_list:
        desc = tool.get("description", "") or ""
        name = tool.get("name", "") or ""
        all_descriptions.append(desc)
        seen_descriptions = True

        lname = name.lower()
        ldesc = desc.lower()

        if (
            lname in {"execute", "run", "exec", "shell"}
            or any(e in lname for e in exec_names)
        ):
            matches.append(
                _endpoint_match("command_exec", f"tool name suggests command execution: {name}")
            )

        schema = tool.get("inputSchema", {}) or {}
        properties = schema.get("properties", {}) or {}

        if "cmd" in properties or "command" in properties:
            has_command_param = True
            matches.append(
                _endpoint_match(
                    "command_exec",
                    f"tool '{name}' accepts cmd/command parameter",
                )
            )
        if "args" in properties:
            has_args_param = True
        if "url" in properties:
            matches.append(
                _endpoint_match("ssrf", f"tool '{name}' accepts url parameter")
            )
        if "path" in properties:
            if "write" in lname or "delete" in lname or "remove" in lname:
                matches.append(
                    _endpoint_match(
                        "unrestricted_file_write",
                        f"tool '{name}' accepts path parameter for write/delete",
                    )
                )
                capabilities["write" if "write" in lname else "delete"] = True
            else:
                matches.append(
                    _endpoint_match(
                        "unrestricted_file_read",
                        f"tool '{name}' accepts path parameter",
                    )
                )
                if "read" in lname:
                    capabilities["read"] = True

        if any(token in lname for token in config_load_names) and "url" in properties:
            matches.append(
                _endpoint_match(
                    "remote_config_loading",
                    f"tool '{name}' loads configuration from a remote URL",
                )
            )
        if any(token in lname for token in config_apply_names + config_load_names):
            matches.append(
                _endpoint_match(
                    "config_to_execution",
                    f"tool '{name}' applies a configuration that can drive execution",
                )
            )
        if lname.startswith("delete_") or "remove_file" in lname:
            capabilities["delete"] = True
        if lname.startswith("get_env") or lname == "list_environment" or lname == "dump_env":
            capabilities["env"] = True

        if any(token in ldesc for token in ("allowlist", "whitelist", "must be in")):
            allowlist_hint = True

        if any(token in lname for token in metadata_keywords) or any(
            phrase in ldesc for phrase in metadata_descriptions
        ):
            matches.append(
                _endpoint_match(
                    "internal_metadata_exposure",
                    f"tool '{name}' exposes internal metadata",
                )
            )

        if "Returns all environment variables" in desc or lname in {
            "list_environment",
            "get_env",
            "dump_env",
        }:
            matches.append(
                _endpoint_match(
                    "env_exposure",
                    f"tool '{name}' exposes environment variables",
                )
            )

    if has_command_param and has_args_param and allowlist_hint:
        matches.append(
            _endpoint_match(
                "command_exec_via_args",
                "tool exposes command + args params with an allowlist hint",
            )
        )
        matches.append(
            _endpoint_match(
                "allowlist_bypass",
                "tool exposes command allowlist with unvalidated args",
            )
        )

    if sum(capabilities.values()) >= 3:
        present = "+".join(sorted(k for k, v in capabilities.items() if v))
        matches.append(
            _endpoint_match("excessive_permissions", f"tool surface exposes {present}")
        )

    if seen_descriptions:
        from .patterns import find_matching_patterns

        desc_matches = find_matching_patterns("", all_descriptions)
        matches.extend(desc_matches)

    return matches


def _findings_from_probe_markers(summary: dict) -> list[dict]:
    matches: list[dict] = []
    markers = summary.get("markers") or []
    if summary.get("auth_required") is False:
        matches.append(
            _endpoint_match(
                "authless_endpoint",
                f"reachable without authentication: {summary.get('base_url')}",
            )
        )
    if "cors_wildcard" in markers:
        matches.append(
            _endpoint_match("cors_misconfiguration", "Access-Control-Allow-Origin: *")
        )
    return matches


def _findings_from_hidden_probes(hidden: list[dict]) -> list[dict]:
    matches: list[dict] = []
    for probe in hidden:
        path = urlparse(probe.get("url", "")).path
        status = probe.get("status")
        body = (probe.get("body_excerpt") or "")
        if status is None or status == 404:
            continue
        if path == "/api/connectors":
            matches.append(
                _endpoint_match(
                    "hidden_transport",
                    f"hidden admin endpoint reachable: {path}",
                )
            )
            if any(token in body for token in ("stdio", "command", "PGPASSWORD", "internal-db-password")):
                matches.append(
                    _endpoint_match(
                        "connector_metadata_exposure",
                        f"GET {path} returned connector configuration",
                    )
                )
        elif path == "/api/transport":
            matches.append(
                _endpoint_match(
                    "hidden_transport",
                    f"hidden admin endpoint reachable: {path}",
                )
            )
        elif path == "/api/config":
            matches.append(
                _endpoint_match(
                    "hidden_transport",
                    f"hidden admin endpoint reachable: {path}",
                )
            )
            if "applied" in body or "Configuration" in body:
                matches.append(
                    _endpoint_match(
                        "config_injection",
                        f"PUT {path} accepts arbitrary configuration body",
                    )
                )
    return matches


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


def _http_probe(url: str, method: str = "GET", body: str | None = None) -> dict:
    headers = {}
    request_headers = {"Accept": "*/*"}
    payload: bytes | None = None
    if body is not None:
        request_headers["Content-Type"] = "application/json"
        payload = body.encode("utf-8")
    try:
        req = Request(url, method=method, headers=request_headers, data=payload)
        with urlopen(req, timeout=5) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            body_excerpt = response.read(2048).decode("utf-8", errors="ignore")
            return {
                "url": url,
                "kind": "http",
                "method": method,
                "status": response.status,
                "content_type": headers.get("content-type"),
                "headers": headers,
                "body_excerpt": body_excerpt,
            }
    except HTTPError as exc:
        try:
            headers = {k.lower(): v for k, v in exc.headers.items()}
            body_excerpt = exc.read(2048).decode("utf-8", errors="ignore")
        finally:
            exc.close()
        return {
            "url": url,
            "kind": "http",
            "method": method,
            "status": exc.code,
            "content_type": headers.get("content-type"),
            "headers": headers,
            "body_excerpt": body_excerpt,
        }
    except (URLError, TimeoutError, OSError) as exc:
        return {
            "url": url,
            "kind": "http",
            "method": method,
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
    """Build a scan result dict from matches.

    Each match carries an optional ``source`` field; when absent we stamp
    ``"mcp-guard"`` so downstream consumers (PolicyEngine, CLI output) can
    distinguish capability-based findings from cisco-emitted ones.
    """
    deduped = []
    seen = set()
    for m in matches:
        if not m.get("source"):
            m["source"] = "mcp-guard"
        key = (m["pattern_id"], m["matched_indicator"], m.get("source"))
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
