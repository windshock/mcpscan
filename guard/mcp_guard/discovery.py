"""macOS-first target discovery for mcp-guard."""
from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import yaml

from .scanner import probe_endpoint

PROJECT_MARKERS = (
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Dockerfile",
    "server.py",
    "mcp.json",
)
MCP_TEXT_MARKERS = (
    "fastmcp",
    "@modelcontextprotocol",
    "modelcontextprotocol",
    "mcp.tool",
    "sse",
    "mcpservers",
)
CURRENT_USER = os.environ.get("USER", "")


@dataclass
class Candidate:
    kind: str
    display_name: str
    target: str
    score: int = 0
    source: str = "host"
    pid: int | None = None
    command: str | None = None
    port: int | None = None
    target_host: str | None = None
    container_name: str | None = None
    service_name: str | None = None
    image: str | None = None
    host_path: str | None = None
    probe_summary: dict[str, Any] | None = None
    evidence: list[str] = field(default_factory=list)
    public_urls: list[str] = field(default_factory=list)
    scan_ready: bool = True
    auto_selectable: bool = False

    def merge(self, other: "Candidate") -> None:
        self.score = max(self.score, other.score)
        self.evidence = sorted(set(self.evidence + other.evidence))
        self.public_urls = sorted(set(self.public_urls + other.public_urls))
        if not self.command and other.command:
            self.command = other.command
        if not self.pid and other.pid:
            self.pid = other.pid
        if not self.port and other.port:
            self.port = other.port
        if not self.target_host and other.target_host:
            self.target_host = other.target_host
        if not self.container_name and other.container_name:
            self.container_name = other.container_name
        if not self.service_name and other.service_name:
            self.service_name = other.service_name
        if not self.image and other.image:
            self.image = other.image
        if not self.host_path and other.host_path:
            self.host_path = other.host_path
        if not self.probe_summary and other.probe_summary:
            self.probe_summary = other.probe_summary
        if other.scan_ready:
            self.scan_ready = True

    def fingerprint(self) -> str:
        if self.kind == "path":
            return f"path:{Path(self.target).resolve()}"
        if self.kind == "config":
            return f"config:{Path(self.target).resolve()}"
        return f"endpoint:{self.target}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence"] = sorted(set(data["evidence"]))
        data["public_urls"] = sorted(set(data["public_urls"]))
        return data


def ensure_supported_platform() -> None:
    if platform.system() != "Darwin":
        raise RuntimeError(
            "Auto-discovery is currently supported on macOS only. Use --path, --config, or --endpoint."
        )


def discover_targets(cwd: str | None = None, enable_probe: bool = True) -> dict[str, Any]:
    """Discover likely scan targets from host, Docker, and tunnel metadata."""
    ensure_supported_platform()
    base_dir = Path(cwd or Path.cwd()).resolve()
    candidates: list[Candidate] = []
    process_map = _load_process_map()

    candidates.extend(_discover_host_candidates(process_map, base_dir, enable_probe=enable_probe))

    docker_available = False
    docker_error = None
    try:
        docker_candidates = _discover_docker_candidates(base_dir, enable_probe=enable_probe)
        if docker_candidates is not None:
            docker_available = True
            candidates.extend(docker_candidates)
    except RuntimeError as exc:
        docker_error = str(exc)

    tunnel_links = _discover_tunnel_links(process_map)
    _apply_tunnel_links(candidates, tunnel_links)

    merged = _merge_candidates(candidates)
    _score_candidates(merged)
    merged.sort(key=lambda candidate: candidate.score, reverse=True)

    result = {
        "platform": platform.system(),
        "docker_available": docker_available,
        "candidate_count": len(merged),
        "candidates": [candidate.to_dict() for candidate in merged],
    }
    if docker_error:
        result["docker_error"] = docker_error
    return result


def select_candidate(candidates: list[dict[str, Any]], auto: bool = False) -> dict[str, Any]:
    if not candidates:
        raise RuntimeError("No MCP candidates were discovered.")

    ready = [candidate for candidate in candidates if candidate.get("scan_ready", True)]
    if not ready:
        raise RuntimeError("Candidates were discovered, but none are directly scannable from this host.")

    if auto:
        auto_ready = [candidate for candidate in ready if candidate.get("auto_selectable")]
        if not auto_ready:
            raise RuntimeError(
                "No strong MCP candidates were discovered for automatic selection. "
                "Use 'mcp-guard discover' or specify --path/--config/--endpoint."
            )
        return auto_ready[0]
    if not os.isatty(0):
        if len(ready) == 1:
            return ready[0]
        raise RuntimeError("Multiple candidates discovered in non-interactive mode. Re-run with --auto.")

    _print_candidates(ready)
    while True:
        choice = input(f"Select a target [1-{len(ready)}]: ").strip()
        if not choice:
            return ready[0]
        if choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(ready):
                return ready[index]
        print("Invalid selection.")


def format_discovery_text(discovery_result: dict[str, Any]) -> str:
    lines = [
        f"Platform: {discovery_result['platform']}",
        f"Docker available: {discovery_result.get('docker_available', False)}",
        f"Candidates: {discovery_result['candidate_count']}",
        "",
    ]

    candidates = discovery_result.get("candidates", [])
    if not candidates:
        lines.append("No likely MCP targets discovered.")
        return "\n".join(lines)

    for index, candidate in enumerate(candidates, start=1):
        lines.append(
            f"{index}. [{candidate['kind']}] {candidate['target']} "
            f"(score={candidate['score']}, source={candidate['source']})"
        )
        if candidate.get("auto_selectable"):
            lines.append("   auto: eligible")
        if candidate.get("host_path"):
            lines.append(f"   host path: {candidate['host_path']}")
        if candidate.get("container_name"):
            lines.append(
                f"   container: {candidate['container_name']}"
                + (f" service={candidate['service_name']}" if candidate.get("service_name") else "")
            )
        if candidate.get("public_urls"):
            lines.append(f"   public: {', '.join(candidate['public_urls'])}")
        if candidate.get("probe_summary"):
            probe = candidate["probe_summary"]
            lines.append(
                "   probe: "
                f"reachable={probe.get('reachable')} "
                f"mcp={probe.get('mcp_detected')} "
                f"tools={probe.get('tool_count', 0)}"
            )
        if candidate.get("evidence"):
            lines.append(f"   evidence: {', '.join(candidate['evidence'][:4])}")
    return "\n".join(lines)


def parse_lsof_output(output: str) -> list[dict[str, Any]]:
    listeners = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("COMMAND"):
            continue
        parts = line.split()
        if len(parts) < 10 or parts[-1] != "(LISTEN)":
            continue
        address = parts[-2]
        host, port = _split_address(address)
        if port is None:
            continue
        listeners.append(
            {
                "command": parts[0],
                "pid": int(parts[1]),
                "user": parts[2],
                "host": host,
                "port": port,
            }
        )
    return listeners


def parse_ps_output(output: str) -> dict[int, dict[str, Any]]:
    processes = {}
    for raw_line in output.splitlines():
        if raw_line.strip().startswith("PID"):
            continue
        match = re.match(r"\s*(\d+)\s+(\d+)\s+(.*)$", raw_line)
        if not match:
            continue
        pid = int(match.group(1))
        processes[pid] = {
            "pid": pid,
            "ppid": int(match.group(2)),
            "command": match.group(3).strip(),
        }
    return processes


def parse_docker_ps_output(output: str) -> list[dict[str, Any]]:
    entries = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def parse_docker_inspect_output(output: str) -> list[dict[str, Any]]:
    if not output.strip():
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def _discover_host_candidates(
    process_map: dict[int, dict[str, Any]],
    base_dir: Path,
    enable_probe: bool,
) -> list[Candidate]:
    listeners_output = _run_command(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    listeners = parse_lsof_output(listeners_output)
    candidates: list[Candidate] = []
    seen_paths: set[str] = set()

    for listener in listeners:
        if CURRENT_USER and listener["user"] != CURRENT_USER:
            continue

        pid = listener["pid"]
        process = process_map.get(pid, {"command": listener["command"], "pid": pid, "ppid": None})
        process.update(_inspect_process_files(pid))

        endpoint = _build_local_endpoint(listener["host"], listener["port"])
        candidate = Candidate(
            kind="endpoint",
            display_name=f"{process['command']} on {endpoint}",
            target=endpoint,
            source="host",
            pid=pid,
            command=process["command"],
            port=listener["port"],
            target_host=listener["host"],
            evidence=[],
        )
        candidate.evidence.extend(_describe_process(process["command"]))
        if process.get("cwd"):
            cwd_path = Path(process["cwd"])
            if _looks_like_user_path(cwd_path):
                candidate.host_path = str(cwd_path)
                candidate.evidence.extend(_analyze_path(cwd_path)[:3])

        if enable_probe:
            try:
                candidate.probe_summary = probe_endpoint(endpoint)
            except Exception as exc:
                candidate.probe_summary = {"reachable": False, "error": str(exc), "tool_count": 0}

        if _should_include_endpoint_candidate(candidate, base_dir):
            candidates.append(candidate)

        for path in _extract_candidate_paths(process, base_dir):
            path_key = str(path.resolve())
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            path_candidate = Candidate(
                kind="path",
                display_name=f"{path.name} source path",
                target=path_key,
                source="host",
                pid=pid,
                command=process["command"],
                host_path=path_key,
                evidence=_analyze_path(path),
            )
            candidates.append(path_candidate)

    return candidates


def _discover_docker_candidates(base_dir: Path, enable_probe: bool) -> list[Candidate] | None:
    if not shutil.which("docker"):
        return None

    ps_output = _run_command(["docker", "ps", "--format", "{{json .}}"])
    ps_entries = parse_docker_ps_output(ps_output)
    if not ps_entries:
        return []

    container_names = [entry["Names"] for entry in ps_entries if entry.get("Names")]
    inspect_output = _run_command(["docker", "inspect", *container_names])
    inspections = parse_docker_inspect_output(inspect_output)

    candidates: list[Candidate] = []
    compose_cache: dict[tuple[str, str], dict[str, Any]] = {}

    for item in inspections:
        name = (item.get("Name") or "").lstrip("/")
        config = item.get("Config") or {}
        labels = config.get("Labels") or {}
        service_name = labels.get("com.docker.compose.service")
        image = config.get("Image")
        process_command = " ".join(config.get("Cmd") or [])
        compose_service = _load_compose_service(labels, compose_cache)

        host_paths = []
        host_paths.extend(_host_paths_from_mounts(item.get("Mounts") or []))
        host_paths.extend(_host_paths_from_compose_service(compose_service))

        unique_host_paths = []
        seen = set()
        for path in host_paths:
            resolved = str(path.resolve())
            if resolved not in seen:
                seen.add(resolved)
                unique_host_paths.append(path)

        for path in unique_host_paths:
            evidence = _analyze_path(path)
            if not evidence and not _looks_like_user_path(path):
                continue
            candidates.append(
                Candidate(
                    kind="path",
                    display_name=f"{service_name or name} source path",
                    target=str(path.resolve()),
                    source="docker",
                    container_name=name,
                    service_name=service_name,
                    image=image,
                    host_path=str(path.resolve()),
                    command=process_command,
                    evidence=evidence + ["docker_source_path"],
                )
            )

        port_mappings = (item.get("NetworkSettings") or {}).get("Ports") or {}
        published = False
        for port_proto, bindings in port_mappings.items():
            if not bindings:
                continue
            container_port = int(port_proto.split("/")[0])
            for binding in bindings:
                host_port = binding.get("HostPort")
                if not host_port:
                    continue
                published = True
                host_ip = binding.get("HostIp") or "127.0.0.1"
                endpoint = _build_local_endpoint(host_ip, int(host_port))
                candidate = Candidate(
                    kind="endpoint",
                    display_name=f"{service_name or name} on {endpoint}",
                    target=endpoint,
                    source="docker",
                    container_name=name,
                    service_name=service_name,
                    image=image,
                    port=int(host_port),
                    target_host=host_ip,
                    command=process_command,
                    host_path=str(unique_host_paths[0].resolve()) if unique_host_paths else None,
                    evidence=["docker_published_port", f"container_port:{container_port}"],
                )
                if enable_probe:
                    try:
                        candidate.probe_summary = probe_endpoint(endpoint)
                    except Exception as exc:
                        candidate.probe_summary = {
                            "reachable": False,
                            "error": str(exc),
                            "tool_count": 0,
                        }
                candidates.append(candidate)

        if not published and not unique_host_paths:
            candidates.append(
                Candidate(
                    kind="endpoint",
                    display_name=f"{service_name or name} (docker internal only)",
                    target=f"docker://{name}",
                    source="docker",
                    container_name=name,
                    service_name=service_name,
                    image=image,
                    command=process_command,
                    evidence=["docker_internal_only"],
                    scan_ready=False,
                )
            )

    return candidates


def _discover_tunnel_links(process_map: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    links = []
    links.extend(_discover_ngrok_links(process_map))
    links.extend(_discover_cloudflared_links(process_map))
    return links


def _discover_ngrok_links(process_map: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    links = []
    for process in process_map.values():
        command = process.get("command", "")
        if "ngrok" not in command:
            continue

        web_addr = _extract_option(command, "--web-addr") or "127.0.0.1:4040"
        if web_addr in ("false", "off", "none"):
            continue
        base_url = f"http://{web_addr}/api"

        payload = _http_json(f"{base_url}/endpoints")
        if payload and isinstance(payload.get("endpoints"), list):
            for endpoint in payload["endpoints"]:
                links.append(
                    {
                        "provider": "ngrok",
                        "public_url": endpoint.get("url"),
                        "upstream": endpoint.get("upstream", {}).get("url"),
                    }
                )
            continue

        payload = _http_json(f"{base_url}/tunnels")
        if payload and isinstance(payload.get("tunnels"), list):
            for tunnel in payload["tunnels"]:
                config = tunnel.get("config") or {}
                links.append(
                    {
                        "provider": "ngrok",
                        "public_url": tunnel.get("public_url"),
                        "upstream": config.get("addr"),
                    }
                )
    return [link for link in links if link.get("public_url") and link.get("upstream")]


def _discover_cloudflared_links(process_map: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    links = []
    for process in process_map.values():
        command = process.get("command", "")
        if "cloudflared" not in command:
            continue

        upstream = _extract_option(command, "--url")
        public_url = _extract_option(command, "--hostname")
        if public_url and not public_url.startswith("http"):
            public_url = f"https://{public_url}"

        if not public_url:
            for fd in ("stdout", "stderr"):
                path = process.get(fd)
                if not path:
                    continue
                public_url = _extract_trycloudflare_url(Path(path))
                if public_url:
                    break

        if public_url and upstream:
            links.append(
                {
                    "provider": "cloudflared",
                    "public_url": public_url,
                    "upstream": upstream,
                }
            )
    return links


def _apply_tunnel_links(candidates: list[Candidate], links: list[dict[str, Any]]) -> None:
    for link in links:
        upstream = _normalize_upstream_url(link["upstream"])
        if not upstream:
            continue

        matched = False
        for candidate in candidates:
            if candidate.kind != "endpoint":
                continue
            if _normalize_upstream_url(candidate.target) == upstream:
                candidate.public_urls.append(link["public_url"])
                candidate.evidence.append(f"{link['provider']}_public_url")
                matched = True
        if not matched:
            candidates.append(
                Candidate(
                    kind="endpoint",
                    display_name=f"{link['provider']} tunnel to {upstream}",
                    target=upstream,
                    source="host",
                    public_urls=[link["public_url"]],
                    evidence=[f"{link['provider']}_public_url"],
                )
            )


def _merge_candidates(candidates: list[Candidate]) -> list[Candidate]:
    merged: dict[str, Candidate] = {}
    for candidate in candidates:
        key = candidate.fingerprint()
        if key not in merged:
            merged[key] = candidate
        else:
            merged[key].merge(candidate)
    return list(merged.values())


def _score_candidates(candidates: list[Candidate]) -> None:
    for candidate in candidates:
        score = 0
        if candidate.kind == "path":
            score += 45
        elif candidate.kind == "endpoint":
            score += 30
        else:
            score += 20

        if candidate.source == "docker":
            score += 10
        if candidate.host_path:
            score += 15
        if candidate.public_urls:
            score += 8
        if candidate.command:
            score += 2 * len(_describe_process(candidate.command))
        if candidate.service_name and "mcp" in candidate.service_name.lower():
            score += 10
        if candidate.container_name and "mcp" in candidate.container_name.lower():
            score += 6
        if candidate.port in {3000, 3001, 3002, 3003, 3101, 3102, 3103, 3104, 3105, 3201, 3202, 3203, 6274, 8000, 8080}:
            score += 6
        if candidate.probe_summary:
            if candidate.probe_summary.get("reachable"):
                score += 15
            if candidate.probe_summary.get("mcp_detected"):
                score += 25
            score += min(candidate.probe_summary.get("tool_count", 0) * 3, 15)
            if candidate.probe_summary.get("auth_required") is True:
                score -= 4
        if not candidate.scan_ready:
            score -= 100

        score += min(len(set(candidate.evidence)) * 2, 20)
        candidate.evidence = sorted(set(candidate.evidence))
        candidate.public_urls = sorted(set(candidate.public_urls))
        candidate.score = score
        candidate.auto_selectable = _candidate_has_strong_mcp_signal(candidate)


def _load_process_map() -> dict[int, dict[str, Any]]:
    ps_output = _run_command(["ps", "-axo", "pid,ppid,command"])
    return parse_ps_output(ps_output)


def _inspect_process_files(pid: int) -> dict[str, str]:
    output = _run_command(["lsof", "-a", "-p", str(pid), "-d", "cwd,txt,1,2"], check=False)
    details: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("COMMAND"):
            continue
        parts = line.split(maxsplit=8)
        if len(parts) < 9:
            continue
        fd = parts[3]
        name = parts[-1]
        if fd == "cwd":
            details["cwd"] = name
        elif fd == "txt":
            details["txt"] = name
        elif fd.startswith("1"):
            details["stdout"] = name
        elif fd.startswith("2"):
            details["stderr"] = name
    return details


def _extract_candidate_paths(process: dict[str, Any], base_dir: Path) -> list[Path]:
    paths: list[Path] = []
    cwd = process.get("cwd")
    if cwd:
        paths.append(Path(cwd))

    for token in _command_tokens(process.get("command", "")):
        if token.startswith("http://") or token.startswith("https://"):
            continue
        if token.startswith("/") or token.startswith("./") or token.startswith("../") or token.startswith("~/"):
            token_path = Path(token).expanduser()
            if not token_path.is_absolute() and cwd:
                token_path = (Path(cwd) / token_path).resolve()
            if token_path.exists():
                paths.append(token_path)

    resolved = []
    seen = set()
    for path in paths:
        normalized = _normalize_project_path(path, base_dir)
        if not normalized:
            continue
        key = str(normalized.resolve())
        if key not in seen:
            seen.add(key)
            resolved.append(normalized)
    return resolved


def _normalize_project_path(path: Path, base_dir: Path) -> Path | None:
    if not path.exists():
        return None

    candidate = path if path.is_dir() else path.parent
    if not _looks_like_user_path(candidate):
        return None

    for probe in [candidate, *candidate.parents[:4]]:
        if not _looks_like_user_path(probe):
            continue
        if any((probe / marker).exists() for marker in PROJECT_MARKERS):
            return probe
    if candidate.resolve().is_relative_to(base_dir):
        return candidate
    return None


def _analyze_path(path: Path) -> list[str]:
    evidence = []
    for marker in PROJECT_MARKERS:
        marker_path = path / marker
        if marker_path.exists():
            evidence.append(f"has_{marker}")

    for relative in ("server.py", "src/server.ts", "src/server.js", "package.json", "pyproject.toml"):
        file_path = path / relative
        if not file_path.exists() or not file_path.is_file():
            continue
        try:
            text = file_path.read_text(errors="ignore")[:4096].lower()
        except Exception:
            continue
        for token in MCP_TEXT_MARKERS:
            if token in text:
                evidence.append(f"marker:{token}")
    return sorted(set(evidence))


def _describe_process(command: str) -> list[str]:
    lower = command.lower()
    evidence = []
    patterns = {
        "mcp": r"(?<![a-z0-9])mcp(?![a-z0-9])",
        "fastmcp": r"fastmcp",
        "modelcontextprotocol": r"modelcontextprotocol",
        "cloudflared": r"cloudflared",
        "ngrok": r"ngrok",
        "windsurf": r"windsurf",
        "cursor": r"(?<![a-z0-9])cursor(?![a-z0-9])",
        "claude": r"(?<![a-z0-9])claude(?![a-z0-9])",
        "uvicorn": r"uvicorn",
        "node": r"(?<![a-z0-9])node(?![a-z0-9])",
        "python": r"(?<![a-z0-9])python[0-9.]*(?![a-z0-9])",
    }
    for token, pattern in patterns.items():
        if re.search(pattern, lower):
            evidence.append(f"cmd:{token}")
    return evidence


def _candidate_has_strong_mcp_signal(candidate: Candidate) -> bool:
    if candidate.kind == "config":
        return True
    if candidate.probe_summary and candidate.probe_summary.get("mcp_detected"):
        return True

    strong_evidence_prefixes = ("marker:",)
    strong_evidence_values = {
        "has_mcp.json",
        "has_mcp-config.json",
        "cmd:fastmcp",
        "cmd:modelcontextprotocol",
        "cmd:mcp",
    }
    for evidence in candidate.evidence:
        if evidence in strong_evidence_values:
            return True
        if evidence.startswith(strong_evidence_prefixes):
            return True

    for value in (candidate.service_name, candidate.container_name, candidate.image):
        if value and re.search(r"(?<![a-z0-9])mcp(?![a-z0-9])", value.lower()):
            return True

    target_name = Path(candidate.target).name.lower() if candidate.kind in {"path", "config"} else ""
    if target_name in {"mcp.json", "mcp-config.json"}:
        return True

    return False


def _should_include_endpoint_candidate(candidate: Candidate, base_dir: Path) -> bool:
    if candidate.public_urls:
        return True
    if candidate.source == "docker":
        return True
    if candidate.probe_summary and candidate.probe_summary.get("mcp_detected"):
        return True
    if candidate.evidence:
        return True
    if candidate.host_path:
        try:
            return Path(candidate.host_path).resolve().is_relative_to(base_dir)
        except Exception:
            return False
    return False


def _load_compose_service(
    labels: dict[str, str],
    cache: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any] | None:
    working_dir = labels.get("com.docker.compose.project.working_dir")
    config_files = labels.get("com.docker.compose.project.config_files")
    service_name = labels.get("com.docker.compose.service")
    if not working_dir or not config_files or not service_name:
        return None

    key = (working_dir, config_files)
    if key not in cache:
        merged_services: dict[str, Any] = {}
        for config_file in config_files.split(","):
            config_path = Path(config_file)
            if not config_path.is_absolute():
                config_path = Path(working_dir) / config_path
            if not config_path.exists():
                continue
            try:
                data = yaml.safe_load(config_path.read_text()) or {}
            except Exception:
                continue
            for name, service in (data.get("services") or {}).items():
                normalized = dict(service)
                normalized["__working_dir"] = working_dir
                merged_services[name] = normalized
        cache[key] = merged_services

    return cache[key].get(service_name)


def _host_paths_from_mounts(mounts: list[dict[str, Any]]) -> list[Path]:
    paths = []
    for mount in mounts:
        if mount.get("Type") != "bind":
            continue
        source = mount.get("Source")
        if source:
            path = Path(source).expanduser()
            if path.exists():
                paths.append(path)
    return paths


def _host_paths_from_compose_service(service: dict[str, Any] | None) -> list[Path]:
    if not service:
        return []

    paths = []
    working_dir = Path(service.get("__working_dir", ".")).expanduser()
    build = service.get("build")
    if isinstance(build, str):
        path = Path(build).expanduser()
        if not path.is_absolute():
            path = (working_dir / path).resolve()
        if path.exists():
            paths.append(path)
    elif isinstance(build, dict) and build.get("context"):
        path = Path(build["context"]).expanduser()
        if not path.is_absolute():
            path = (working_dir / path).resolve()
        if path.exists():
            paths.append(path)

    for volume in service.get("volumes") or []:
        if isinstance(volume, str):
            source = volume.split(":", 1)[0]
            if source.startswith("/") or source.startswith(".") or source.startswith("~"):
                path = Path(source).expanduser()
                if not path.is_absolute():
                    path = (working_dir / path).resolve()
                if path.exists():
                    paths.append(path)
        elif isinstance(volume, dict) and volume.get("type") == "bind" and volume.get("source"):
            path = Path(volume["source"]).expanduser()
            if not path.is_absolute():
                path = (working_dir / path).resolve()
            if path.exists():
                paths.append(path)

    return paths


def _extract_trycloudflare_url(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        data = path.read_text(errors="ignore")[-65536:]
    except Exception:
        return None
    match = re.search(r"https://[-a-zA-Z0-9.]+\.trycloudflare\.com", data)
    return match.group(0) if match else None


def _extract_option(command: str, option: str) -> str | None:
    tokens = _command_tokens(command)
    for index, token in enumerate(tokens):
        if token == option and index + 1 < len(tokens):
            return tokens[index + 1]
        if token.startswith(f"{option}="):
            return token.split("=", 1)[1]
    return None


def _normalize_upstream_url(value: str) -> str | None:
    if not value:
        return None
    value = value.strip()
    if re.fullmatch(r"\d+", value):
        value = f"http://127.0.0.1:{value}"
    elif re.fullmatch(r"localhost:\d+", value):
        value = f"http://{value}"
    elif re.fullmatch(r"127\.0\.0\.1:\d+", value):
        value = f"http://{value}"
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port
    if not port:
        return value
    if host == "localhost":
        host = "127.0.0.1"
    return f"{parsed.scheme}://{host}:{port}"


def _http_json(url: str) -> dict[str, Any] | None:
    try:
        request = Request(url, headers={"Accept": "application/json"})
        with urlopen(request, timeout=2) as response:
            return json.loads(response.read().decode("utf-8", errors="ignore"))
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None


def _print_candidates(candidates: list[dict[str, Any]]) -> None:
    print(format_discovery_text({"platform": platform.system(), "docker_available": True, "candidate_count": len(candidates), "candidates": candidates}))


def _build_local_endpoint(host: str, port: int) -> str:
    if host in ("*", "0.0.0.0", "::", "::1"):
        host = "127.0.0.1"
    elif host == "localhost":
        host = "127.0.0.1"
    return f"http://{host}:{port}"


def _split_address(address: str) -> tuple[str, int | None]:
    match = re.search(r"(.+):(\d+)$", address)
    if not match:
        return address, None
    return match.group(1), int(match.group(2))


def _looks_like_user_path(path: Path) -> bool:
    resolved = str(path.resolve())
    if resolved == "/":
        return False
    blocked_prefixes = ("/System", "/usr", "/bin", "/sbin", "/private/var", "/Library/Apple")
    return not resolved.startswith(blocked_prefixes)


def _command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _run_command(cmd: list[str], check: bool = True) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
    if check and result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(stderr or f"Command failed: {' '.join(cmd)}")
    return result.stdout
