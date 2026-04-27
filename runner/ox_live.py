"""OX product live-validation runner."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_PRODUCTS_DIR = Path("integrations/ox/products")
DEFAULT_FIXTURE_FILE = Path("guard/tests/fixtures/ox_research_cases.json")
DEFAULT_RESULTS_DIR = Path("results")
REPO_ROOT = Path(__file__).resolve().parents[1]
_DOCKER_CHECK: tuple[bool, str] | None = None


class LaunchError(RuntimeError):
    """Raised when a product launch step fails."""


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def load_product_manifests(products_dir: Path) -> list[dict[str, Any]]:
    manifests = []
    for manifest_file in sorted(products_dir.glob("*.json")):
        with open(manifest_file) as f:
            manifest = json.load(f)
        manifest["manifest_path"] = str(manifest_file)
        manifests.append(manifest)
    return manifests


def load_fixture_cases(fixture_file: Path) -> dict[str, dict[str, Any]]:
    with open(fixture_file) as f:
        cases = json.load(f)
    return {case["name"]: case for case in cases}


def classify_failure_reason(text: str) -> str:
    lowered = (text or "").lower()
    if "docker_unavailable" in lowered:
        return "docker_unavailable"
    if "manual_blocked" in lowered:
        return "manual_blocked"
    if "no space left on device" in lowered:
        return "no_space_left"
    if "manifest unknown" in lowered or "pull access denied" in lowered or "repository does not exist" in lowered:
        return "image_not_found"
    if "authentication required" in lowered or "requested access to the resource is denied" in lowered:
        return "image_auth_required"
    if "port is already allocated" in lowered or "bind for 0.0.0.0" in lowered:
        return "port_conflict"
    if "docker compose" in lowered and "not found" in lowered:
        return "missing_docker_compose"
    if "docker-compose" in lowered and "not found" in lowered:
        return "missing_docker_compose"
    if "timed out" in lowered or "deadline exceeded" in lowered:
        return "timeout"
    if "no such host" in lowered or "name or service not known" in lowered:
        return "dns_resolution_failed"
    if "connection refused" in lowered:
        return "connection_refused"
    if "permission denied" in lowered:
        return "permission_denied"
    if "no configuration file provided" in lowered:
        return "compose_file_missing"
    if "requires gpu" in lowered or "could not select device driver" in lowered:
        return "requires_gpu"
    return "command_failed"


def build_docker_run_command(manifest: dict[str, Any], container_name: str) -> list[str]:
    launch = manifest["launch"]
    command = ["docker", "run", "-d", "--name", container_name, "--label", "mcpscan.ox-live=true"]

    for env_name, env_value in (launch.get("env") or {}).items():
        command.extend(["-e", f"{env_name}={resolve_env_value(env_value)}"])

    for port in launch.get("ports") or []:
        command.extend(["-p", f"{port['host']}:{port['container']}"])

    for volume in launch.get("volumes") or []:
        host = volume["host"]
        container = volume["container"]
        mode = volume.get("mode", "rw")
        command.extend(["-v", f"{host}:{container}:{mode}"])

    command.append(launch["image"])
    command.extend(launch.get("args") or [])
    return command


def build_compose_override(manifest: dict[str, Any]) -> dict[str, Any] | None:
    overrides = manifest.get("launch", {}).get("compose_overrides")
    if not overrides:
        return None

    services: dict[str, Any] = {}
    for service_name, service_override in overrides.get("services", {}).items():
        services[service_name] = service_override
    return {"services": services}


def render_compose_override(override_payload: dict[str, Any]) -> str:
    lines: list[str] = []

    def emit_mapping(mapping: dict[str, Any], indent: int) -> None:
        prefix = " " * indent
        for key, value in mapping.items():
            if isinstance(value, dict):
                if value:
                    lines.append(f"{prefix}{key}:")
                    emit_mapping(value, indent + 2)
                else:
                    lines.append(f"{prefix}{key}: {{}}")
                continue

            if isinstance(value, list):
                override_tag = " !override" if key == "ports" else ""
                if value:
                    lines.append(f"{prefix}{key}:{override_tag}")
                    for item in value:
                        lines.append(f"{prefix}  - {json.dumps(item)}")
                else:
                    lines.append(f"{prefix}{key}:{override_tag} []")
                continue

            lines.append(f"{prefix}{key}: {json.dumps(value)}")

    emit_mapping(override_payload, 0)
    return "\n".join(lines) + "\n"


def resolve_env_value(value: Any) -> str:
    if isinstance(value, dict) and "from_env" in value:
        env_name = value["from_env"]
        default = value.get("default", "")
        return os.environ.get(env_name, default)
    if value is None:
        return ""
    return str(value)


def build_guard_scan_env() -> dict[str, str]:
    env = os.environ.copy()
    existing_paths = [entry for entry in env.get("PYTHONPATH", "").split(os.pathsep) if entry]
    required_paths = [str(REPO_ROOT), str(REPO_ROOT / "guard")]
    ordered_paths: list[str] = []

    for entry in [*required_paths, *existing_paths]:
        if entry not in ordered_paths:
            ordered_paths.append(entry)

    env["PYTHONPATH"] = os.pathsep.join(ordered_paths)
    return env


def safe_write_text(path: Path, content: str) -> str | None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return None
    except OSError as exc:
        return str(exc)


def run_command(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
    check: bool = True,
) -> CommandResult:
    process = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    result = CommandResult(process.returncode, process.stdout, process.stderr)
    if check and process.returncode != 0:
        raise LaunchError(process.stderr.strip() or process.stdout.strip() or "command failed")
    return result


def _compose_command() -> list[str]:
    ok, error = docker_available()
    if not ok:
        raise LaunchError(f"docker_unavailable: {error}")

    docker_bin = shutil.which("docker")
    if docker_bin:
        try:
            result = subprocess.run(
                [docker_bin, "compose", "version"],
                text=True,
                capture_output=True,
                timeout=15,
            )
            if result.returncode == 0:
                return [docker_bin, "compose"]
        except subprocess.SubprocessError:
            pass

    docker_compose_bin = shutil.which("docker-compose")
    if docker_compose_bin:
        return [docker_compose_bin]

    raise LaunchError("docker compose not found")


def docker_available() -> tuple[bool, str]:
    global _DOCKER_CHECK
    if _DOCKER_CHECK is not None:
        return _DOCKER_CHECK

    docker_bin = shutil.which("docker")
    if not docker_bin:
        _DOCKER_CHECK = (False, "docker binary not found")
        return _DOCKER_CHECK

    try:
        result = subprocess.run(
            [docker_bin, "version", "--format", "{{.Client.Version}} / {{.Server.Version}}"],
            text=True,
            capture_output=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        _DOCKER_CHECK = (False, "docker version timed out")
        return _DOCKER_CHECK
    except OSError as exc:
        _DOCKER_CHECK = (False, str(exc))
        return _DOCKER_CHECK

    if result.returncode != 0:
        _DOCKER_CHECK = (False, result.stderr.strip() or result.stdout.strip() or "docker version failed")
        return _DOCKER_CHECK

    _DOCKER_CHECK = (True, "")
    return _DOCKER_CHECK


def write_support_files(base_dir: Path, manifest: dict[str, Any]) -> None:
    for relative_path, content in (manifest.get("launch", {}).get("write_files") or {}).items():
        target = base_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)


def http_probe(url: str, timeout: int = 5) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "mcpscan-ox-live/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {
                "reachable": True,
                "status": response.status,
                "headers": dict(response.headers),
            }
    except urllib.error.HTTPError as exc:
        return {
            "reachable": True,
            "status": exc.code,
            "headers": dict(exc.headers),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "reachable": False,
            "status": None,
            "error": str(exc),
        }


def wait_for_health(healthcheck: dict[str, Any]) -> dict[str, Any]:
    url = healthcheck["url"]
    timeout = int(healthcheck.get("startup_timeout_sec", 180))
    acceptable = set(healthcheck.get("acceptable_statuses", [200, 301, 302, 307, 308, 401, 403, 404]))
    deadline = time.time() + timeout
    last_probe: dict[str, Any] = {"reachable": False, "status": None, "error": "startup pending"}

    while time.time() < deadline:
        probe = http_probe(url)
        last_probe = probe
        if probe.get("reachable") and probe.get("status") in acceptable:
            return {
                "status": "reachable",
                "url": url,
                "http_status": probe.get("status"),
                "probe": probe,
            }
        time.sleep(3)

    return {
        "status": "unreachable",
        "url": url,
        "http_status": last_probe.get("status"),
        "probe": last_probe,
    }


def capture_docker_logs(container_name: str) -> str:
    result = run_command(["docker", "logs", container_name], check=False, timeout=60)
    combined = "\n".join(part for part in [result.stdout, result.stderr] if part)
    return combined.strip()


def capture_compose_logs(repo_dir: Path, compose_files: list[Path], project_name: str) -> str:
    command = _compose_command()
    for compose_file in compose_files:
        command.extend(["-f", str(compose_file)])
    command.extend(["-p", project_name, "logs", "--no-color"])
    result = run_command(command, cwd=repo_dir, check=False, timeout=180)
    combined = "\n".join(part for part in [result.stdout, result.stderr] if part)
    return combined.strip()


def launch_docker_image(manifest: dict[str, Any]) -> dict[str, Any]:
    launch = manifest["launch"]
    container_name = launch.get("container_name", f"mcpscan-ox-{manifest['id']}")
    ok, error = docker_available()
    if not ok:
        raise LaunchError(f"docker_unavailable: {error}")

    run_command(["docker", "rm", "-f", container_name], check=False, timeout=60)
    if launch.get("pull", True):
        run_command(["docker", "pull", launch["image"]], timeout=launch.get("pull_timeout_sec", 900))

    command = build_docker_run_command(manifest, container_name)
    result = run_command(command, timeout=launch.get("startup_command_timeout_sec", 180))
    return {
        "kind": "docker_image",
        "container_name": container_name,
        "container_id": result.stdout.strip(),
        "image": launch["image"],
        "command": command,
    }


def reclaim_docker_space() -> None:
    run_command(["docker", "image", "prune", "-af"], check=False, timeout=600)
    run_command(["docker", "builder", "prune", "-af"], check=False, timeout=600)


def cleanup_docker_image(context: dict[str, Any]) -> None:
    container_name = context.get("container_name")
    if container_name:
        run_command(["docker", "rm", "-f", container_name], check=False, timeout=60)
    image_name = context.get("image")
    if image_name:
        run_command(["docker", "image", "rm", "-f", image_name], check=False, timeout=300)
    reclaim_docker_space()


def prepare_repo_compose(manifest: dict[str, Any], workdir_root: Path) -> dict[str, Any]:
    launch = manifest["launch"]
    repo_dir = (workdir_root / manifest["id"]).resolve()
    if repo_dir.exists():
        shutil.rmtree(repo_dir)

    ref = launch.get("ref")
    if ref and re.fullmatch(r"[0-9a-f]{40}", ref):
        # A direct commit SHA is unlikely to exist in a shallow default-branch clone.
        run_command(["git", "clone", "--filter=blob:none", launch["repo_url"], str(repo_dir)], timeout=launch.get("clone_timeout_sec", 900))
        run_command(["git", "checkout", ref], cwd=repo_dir, timeout=120)
    elif ref:
        run_command(
            ["git", "clone", "--depth", "1", "--branch", ref, launch["repo_url"], str(repo_dir)],
            timeout=launch.get("clone_timeout_sec", 900),
        )
    else:
        run_command(["git", "clone", "--depth", "1", launch["repo_url"], str(repo_dir)], timeout=launch.get("clone_timeout_sec", 900))

    write_support_files(repo_dir, manifest)

    compose_file = repo_dir / launch["compose_file"]
    compose_files = [compose_file]
    override_payload = build_compose_override(manifest)
    override_file = None
    if override_payload:
        override_file = repo_dir / ".mcpscan-compose.override.yaml"
        override_error = safe_write_text(override_file, render_compose_override(override_payload))
        if override_error:
            raise LaunchError(override_error)
        compose_files.append(override_file)

    command = _compose_command()
    for compose_path in compose_files:
        command.extend(["-f", str(compose_path)])
    command.extend(["-p", launch.get("project_name", f"mcpscan-ox-{manifest['id']}"), "up", "-d", "--remove-orphans"])

    return {
        "kind": "repo_compose",
        "repo_dir": str(repo_dir),
        "compose_files": [str(path) for path in compose_files],
        "project_name": launch.get("project_name", f"mcpscan-ox-{manifest['id']}"),
        "command": command,
        "startup_command_timeout_sec": launch.get("startup_command_timeout_sec", 1800),
    }


def launch_repo_compose(context: dict[str, Any]) -> None:
    run_command(
        context["command"],
        cwd=Path(context["repo_dir"]),
        timeout=context.get("startup_command_timeout_sec", 1800),
    )


def cleanup_repo_compose(context: dict[str, Any], keep_workdir: bool = False) -> None:
    repo_dir = Path(context["repo_dir"])
    command = _compose_command()
    for compose_file in context.get("compose_files", []):
        command.extend(["-f", compose_file])
    command.extend(["-p", context["project_name"], "down", "--volumes", "--remove-orphans"])
    run_command(command, cwd=repo_dir, check=False, timeout=600)
    if not keep_workdir and repo_dir.exists():
        shutil.rmtree(repo_dir)
    reclaim_docker_space()


def run_guard_scan(scan_mode: str, manifest: dict[str, Any], fixture_cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    validation = manifest.get("validation", {})
    base_command = [sys.executable, "-m", "mcp_guard", "scan"]
    env = build_guard_scan_env()
    if scan_mode == "config_fixture":
        fixture_name = validation["fixture_name"]
        payload = fixture_cases[fixture_name]["payload"]
        command = [*base_command, "--config", json.dumps(payload), "--output", "json"]
    elif scan_mode == "endpoint":
        target = validation.get("endpoint_url") or manifest["healthcheck"]["url"]
        command = [*base_command, "--endpoint", target, "--output", "json"]
    else:
        return {
            "status": "skipped",
            "mode": scan_mode,
            "error": f"unsupported scan mode: {scan_mode}",
        }

    result = run_command(command, env=env, check=False, timeout=validation.get("scan_timeout_sec", 180))
    if result.returncode not in (0, 1):
        return {
            "status": "failed",
            "mode": scan_mode,
            "error": result.stderr.strip() or result.stdout.strip() or "scan failed",
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "status": "failed",
            "mode": scan_mode,
            "error": "invalid JSON from mcp-guard",
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    return {
        "status": "success",
        "mode": scan_mode,
        "command": command,
        "result": parsed,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def run_product(
    manifest: dict[str, Any],
    *,
    fixture_cases: dict[str, dict[str, Any]],
    results_dir: Path,
    keep_workdir: bool = False,
) -> dict[str, Any]:
    product_id = manifest["id"]
    evidence_dir = results_dir / "raw" / "ox-live" / "evidence" / product_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    workdir_root = (results_dir / "workdir" / "ox-live").resolve()
    workdir_root.mkdir(parents=True, exist_ok=True)

    raw_result: dict[str, Any] = {
        "target_type": "ox_live",
        "product_id": product_id,
        "product_name": manifest["name"],
        "source_url": manifest["source_url"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "launch_kind": manifest["launch"]["kind"],
        "launch_status": "skipped",
        "health_status": "skipped",
        "scan_status": "skipped",
        "failure_reason": None,
        "notes": [],
        "evidence": {},
    }

    launch_context: dict[str, Any] | None = None
    launch_logs = ""

    try:
        kind = manifest["launch"]["kind"]
        if kind == "manual_blocked":
            raise LaunchError(manifest["launch"].get("reason", "manual_blocked"))
        if kind == "docker_image":
            launch_context = launch_docker_image(manifest)
            raw_result["evidence"]["launch_command"] = launch_context.get("command")
        elif kind == "repo_compose":
            launch_context = prepare_repo_compose(manifest, workdir_root)
            raw_result["evidence"]["launch_command"] = launch_context.get("command")
            launch_repo_compose(launch_context)
        else:
            raise LaunchError(f"manual_blocked: unsupported launch kind {kind}")
        raw_result["launch_status"] = "success"

        health = wait_for_health(manifest["healthcheck"])
        raw_result["health_status"] = health["status"]
        raw_result["healthcheck"] = health
        health_file = evidence_dir / "health.json"
        health_error = safe_write_text(health_file, json.dumps(health, indent=2))
        if health_error:
            raw_result["notes"].append(f"health evidence write failed: {health_error}")
        else:
            raw_result["evidence"]["health"] = str(health_file)

        if health["status"] != "reachable":
            raw_result["failure_reason"] = "startup_timeout"
            raw_result["notes"].append(f"Health check failed for {manifest['healthcheck']['url']}")
    except (LaunchError, subprocess.SubprocessError) as exc:
        raw_result["launch_status"] = "failed"
        raw_result["health_status"] = "unreachable"
        raw_result["failure_reason"] = classify_failure_reason(str(exc))
        raw_result["notes"].append(str(exc))
    finally:
        if launch_context:
            if launch_context["kind"] == "docker_image":
                launch_logs = capture_docker_logs(launch_context["container_name"])
            elif launch_context["kind"] == "repo_compose":
                launch_logs = capture_compose_logs(
                    Path(launch_context["repo_dir"]),
                    [Path(path) for path in launch_context["compose_files"]],
                    launch_context["project_name"],
                )

            logs_file = evidence_dir / "launch.log"
            log_error = safe_write_text(logs_file, launch_logs)
            if log_error:
                raw_result["notes"].append(f"launch log write failed: {log_error}")
            else:
                raw_result["evidence"]["launch_logs"] = str(logs_file)

            if launch_context["kind"] == "docker_image":
                cleanup_docker_image(launch_context)
            elif launch_context["kind"] == "repo_compose":
                cleanup_repo_compose(launch_context, keep_workdir=keep_workdir)

    scan = run_guard_scan(manifest["validation"]["scan_mode"], manifest, fixture_cases)
    raw_result["scan_status"] = scan["status"]
    raw_result["scan_mode"] = scan["mode"]
    if scan["status"] == "success":
        raw_result["scan_result"] = scan["result"]
    else:
        raw_result["failure_reason"] = raw_result["failure_reason"] or classify_failure_reason(scan.get("error", "scan failed"))
        raw_result["notes"].append(scan.get("error", "scan failed"))

    scan_stdout_file = evidence_dir / "scan.stdout"
    scan_stderr_file = evidence_dir / "scan.stderr"
    stdout_error = safe_write_text(scan_stdout_file, scan.get("stdout", ""))
    stderr_error = safe_write_text(scan_stderr_file, scan.get("stderr", ""))
    if stdout_error:
        raw_result["notes"].append(f"scan stdout write failed: {stdout_error}")
    else:
        raw_result["evidence"]["scan_stdout"] = str(scan_stdout_file)
    if stderr_error:
        raw_result["notes"].append(f"scan stderr write failed: {stderr_error}")
    else:
        raw_result["evidence"]["scan_stderr"] = str(scan_stderr_file)

    raw_file = results_dir / "raw" / "ox-live" / f"{product_id}.json"
    raw_file.parent.mkdir(parents=True, exist_ok=True)
    raw_error = safe_write_text(raw_file, json.dumps(raw_result, indent=2))
    if raw_error:
        raw_result["notes"].append(f"raw result write failed: {raw_error}")
    return raw_result


def filter_manifests(manifests: list[dict[str, Any]], selected: set[str] | None) -> list[dict[str, Any]]:
    if not selected:
        return manifests
    return [manifest for manifest in manifests if manifest["id"] in selected]
