"""Target identification helpers.

The scan result alone tells you *what* is wrong, but not *where* the target
actually lives. These collectors enrich the result with: which process is
listening on a port (and the Docker container behind it if any), what the
filesystem path resolves to, and what mcpServers a config defines. Used by
the CLI to render a "Target details" section in both text and JSON output.

Every collector is best-effort: missing tools (lsof, docker, git) silently
yield empty metadata so scans never fail because of identification.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import socket
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_logger = logging.getLogger("mcp_guard.target_info")


def collect(target_kind: str, target_value: str | None) -> dict[str, Any]:
    if not target_value:
        return {}
    try:
        if target_kind == "endpoint":
            return _endpoint_metadata(target_value)
        if target_kind == "path":
            return _path_metadata(target_value)
        if target_kind == "config":
            return _config_metadata(target_value)
    except Exception as exc:  # never break the scan over identification
        _logger.debug("target metadata collection failed: %s", exc)
    return {}


# ---------------------------------------------------------------------------
# endpoint
# ---------------------------------------------------------------------------


def _endpoint_metadata(url: str) -> dict[str, Any]:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or ""
    port = parsed.port
    if not port:
        port = 443 if parsed.scheme == "https" else 80

    info: dict[str, Any] = {
        "url": url,
        "host": host,
        "port": port,
        "scope": _classify_host(host),
    }

    listener = _resolve_listener(port)
    if listener:
        info["listener"] = listener

    docker_info = _resolve_docker_container(port)
    if docker_info:
        info["docker"] = docker_info

    return info


def _classify_host(host: str) -> str:
    if not host:
        return "unknown"
    if host in {"localhost"}:
        return "loopback"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "hostname"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "public"


def _resolve_listener(port: int) -> dict[str, Any] | None:
    if not shutil.which("lsof"):
        return None
    try:
        proc = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fpcun"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    if proc.returncode != 0:
        return None

    pid = command = user = None
    for line in proc.stdout.splitlines():
        if not line:
            continue
        tag, _, value = line[0], line[0], line[1:]
        if tag == "p":
            pid = value
        elif tag == "c":
            command = value
        elif tag == "u":
            user = value
    if not pid:
        return None
    out: dict[str, Any] = {"pid": int(pid)}
    if command:
        out["command"] = command
    if user:
        out["user"] = user
    return out


def _resolve_docker_container(host_port: int) -> dict[str, Any] | None:
    if not shutil.which("docker"):
        return None
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    if proc.returncode != 0:
        return None

    needle = f":{host_port}->"
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        ports = row.get("Ports", "") or ""
        if needle not in ports:
            continue
        # Confirm the host_port → container_port mapping for this row.
        container_port = _extract_container_port(ports, host_port)
        info: dict[str, Any] = {
            "container": row.get("Names") or "",
            "image": row.get("Image") or "",
            "command": (row.get("Command") or "").strip('"'),
            "status": row.get("Status") or "",
        }
        if container_port:
            info["internal_port"] = container_port
        labels = _docker_labels(info["container"]) if info["container"] else {}
        if labels:
            for label_key, info_key in (
                ("com.docker.compose.project", "compose_project"),
                ("com.docker.compose.service", "compose_service"),
                ("com.docker.compose.project.working_dir", "compose_working_dir"),
                ("com.docker.compose.project.config_files", "compose_config_files"),
            ):
                if labels.get(label_key):
                    info[info_key] = labels[label_key]
        return info
    return None


def _extract_container_port(ports_field: str, host_port: int) -> int | None:
    # Examples: "0.0.0.0:3103->8000/tcp, [::]:3103->8000/tcp"
    needle = f":{host_port}->"
    idx = ports_field.find(needle)
    if idx == -1:
        return None
    rest = ports_field[idx + len(needle):]
    container = rest.split("/", 1)[0]
    try:
        return int(container)
    except ValueError:
        return None


def _docker_labels(container: str) -> dict[str, str]:
    if not shutil.which("docker") or not container:
        return {}
    try:
        proc = subprocess.run(
            ["docker", "inspect", "--format", "{{json .Config.Labels}}", container],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return {}
    if proc.returncode != 0 or not proc.stdout.strip():
        return {}
    try:
        labels = json.loads(proc.stdout.strip())
    except json.JSONDecodeError:
        return {}
    if not isinstance(labels, dict):
        return {}
    return {str(k): str(v) for k, v in labels.items()}


# ---------------------------------------------------------------------------
# path
# ---------------------------------------------------------------------------


def _path_metadata(path: str) -> dict[str, Any]:
    target = Path(path).expanduser()
    info: dict[str, Any] = {"abs_path": str(target.resolve()) if target.exists() else str(target)}

    if not target.exists():
        info["kind"] = "missing"
        return info

    if target.is_file():
        info["kind"] = "file"
        info["total_bytes"] = target.stat().st_size
        info["files_by_ext"] = {target.suffix or "(none)": 1}
        return info

    info["kind"] = "directory"
    ext_counter: Counter[str] = Counter()
    total_bytes = 0
    file_count = 0
    for f in target.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix in (".py", ".ts", ".js", ".json", ".yaml", ".yml", ".toml"):
            file_count += 1
            ext_counter[f.suffix] += 1
            try:
                total_bytes += f.stat().st_size
            except OSError:
                pass
    info["files_scanned"] = file_count
    info["files_by_ext"] = dict(ext_counter.most_common())
    info["total_bytes"] = total_bytes

    git_info = _git_info(target)
    if git_info:
        info["git"] = git_info
    return info


def _git_info(path: Path) -> dict[str, Any] | None:
    if not shutil.which("git"):
        return None
    try:
        rev = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    if rev.returncode != 0:
        return None
    info: dict[str, Any] = {"commit": rev.stdout.strip()}
    try:
        remote = subprocess.run(
            ["git", "-C", str(path), "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if remote.returncode == 0 and remote.stdout.strip():
            info["remote"] = remote.stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if status.returncode == 0:
            info["dirty"] = bool(status.stdout.strip())
    except subprocess.SubprocessError:
        pass
    return info


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def _config_metadata(config: str) -> dict[str, Any]:
    info: dict[str, Any] = {}
    payload_text = config
    config_path: Path | None = None
    if not config.lstrip().startswith(("{", "[")):
        candidate = Path(config).expanduser()
        if candidate.exists():
            config_path = candidate
            try:
                payload_text = candidate.read_text()
                info["source"] = "file"
                info["path"] = str(candidate.resolve())
                info["bytes"] = candidate.stat().st_size
            except OSError as exc:
                info["read_error"] = str(exc)
                return info
    if "source" not in info:
        info["source"] = "inline_json"

    try:
        parsed = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        info["parse_error"] = str(exc)
        return info

    if isinstance(parsed, dict) and isinstance(parsed.get("mcpServers"), dict):
        servers = parsed["mcpServers"]
        info["server_count"] = len(servers)
        info["servers"] = [
            {
                "name": name,
                "command": (entry or {}).get("command") if isinstance(entry, dict) else None,
                "transport": (entry or {}).get("transport") if isinstance(entry, dict) else None,
            }
            for name, entry in servers.items()
        ]
    return info


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render_text(metadata: dict[str, Any], indent: str = "  ") -> list[str]:
    """Format target metadata as bullet lines for the text CLI output."""
    if not metadata:
        return []
    lines: list[str] = []
    for key, value in metadata.items():
        if value in (None, "", {}, []):
            continue
        if isinstance(value, dict):
            lines.append(f"{indent}{key}:")
            for sub_key, sub_value in value.items():
                if sub_value in (None, "", {}, []):
                    continue
                lines.append(f"{indent}  {sub_key}: {sub_value}")
        elif isinstance(value, list):
            lines.append(f"{indent}{key}:")
            for item in value:
                if isinstance(item, dict):
                    summary = ", ".join(f"{k}={v}" for k, v in item.items() if v is not None)
                    lines.append(f"{indent}  - {summary}")
                else:
                    lines.append(f"{indent}  - {item}")
        else:
            lines.append(f"{indent}{key}: {value}")
    return lines
