"""Tests for target_info — best-effort enrichment helpers.

Each collector is supposed to silently degrade when system tools (lsof,
docker, git) are missing or fail. Tests cover the parsing logic with
mocked subprocess output and end-to-end on real lab paths.
"""
from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_guard import target_info


class EndpointMetadataTests(unittest.TestCase):
    def test_classify_host_buckets(self):
        self.assertEqual(target_info._classify_host("127.0.0.1"), "loopback")
        self.assertEqual(target_info._classify_host("localhost"), "loopback")
        self.assertEqual(target_info._classify_host("10.0.0.1"), "private")
        self.assertEqual(target_info._classify_host("192.168.1.1"), "private")
        self.assertEqual(target_info._classify_host("8.8.8.8"), "public")
        self.assertEqual(target_info._classify_host("example.com"), "hostname")
        self.assertEqual(target_info._classify_host(""), "unknown")

    def test_extract_container_port(self):
        ports = "0.0.0.0:3103->8000/tcp, [::]:3103->8000/tcp"
        self.assertEqual(target_info._extract_container_port(ports, 3103), 8000)
        self.assertIsNone(target_info._extract_container_port(ports, 9999))

    def test_resolve_listener_parses_lsof_F_output(self):
        fake_proc = subprocess.CompletedProcess(
            args=["lsof"],
            returncode=0,
            stdout="p12345\nccom.docker.backend\nu1004276\n",
            stderr="",
        )
        with patch("mcp_guard.target_info.shutil.which", return_value="/usr/bin/lsof"), patch(
            "mcp_guard.target_info.subprocess.run", return_value=fake_proc
        ):
            info = target_info._resolve_listener(3103)
        self.assertEqual(info["pid"], 12345)
        self.assertEqual(info["command"], "com.docker.backend")
        self.assertEqual(info["user"], "1004276")

    def test_resolve_docker_container_finds_match(self):
        ps_line = json.dumps(
            {
                "Names": "mcp-lab-vuln-filesystem-1",
                "Image": "mcp-lab-vuln-filesystem",
                "Command": '"python server.py"',
                "Status": "Up 2 hours",
                "Ports": "0.0.0.0:3103->8000/tcp, [::]:3103->8000/tcp",
            }
        )
        labels_blob = json.dumps(
            {
                "com.docker.compose.project": "mcp-lab",
                "com.docker.compose.service": "vuln-filesystem",
                "com.docker.compose.project.working_dir": "/Users/x/mcpscan",
                "com.docker.compose.project.config_files": "/Users/x/mcpscan/docker-compose.yml",
            }
        )

        def fake_run(cmd, **kwargs):
            if cmd[:2] == ["docker", "ps"]:
                return subprocess.CompletedProcess(cmd, 0, ps_line + "\n", "")
            if cmd[:2] == ["docker", "inspect"]:
                return subprocess.CompletedProcess(cmd, 0, labels_blob + "\n", "")
            return subprocess.CompletedProcess(cmd, 1, "", "")

        with patch("mcp_guard.target_info.shutil.which", return_value="/usr/local/bin/docker"), patch(
            "mcp_guard.target_info.subprocess.run", side_effect=fake_run
        ):
            info = target_info._resolve_docker_container(3103)

        self.assertEqual(info["container"], "mcp-lab-vuln-filesystem-1")
        self.assertEqual(info["image"], "mcp-lab-vuln-filesystem")
        self.assertEqual(info["compose_project"], "mcp-lab")
        self.assertEqual(info["compose_service"], "vuln-filesystem")
        self.assertEqual(info["compose_working_dir"], "/Users/x/mcpscan")
        self.assertEqual(info["internal_port"], 8000)

    def test_resolve_docker_container_returns_none_without_match(self):
        ps_line = json.dumps(
            {
                "Names": "other",
                "Image": "x",
                "Command": "x",
                "Status": "Up",
                "Ports": "0.0.0.0:5000->5000/tcp",
            }
        )
        with patch("mcp_guard.target_info.shutil.which", return_value="/usr/local/bin/docker"), patch(
            "mcp_guard.target_info.subprocess.run",
            return_value=subprocess.CompletedProcess(["docker"], 0, ps_line, ""),
        ):
            self.assertIsNone(target_info._resolve_docker_container(3103))

    def test_collect_endpoint_basic_url_parsing(self):
        with patch("mcp_guard.target_info._resolve_listener", return_value=None), patch(
            "mcp_guard.target_info._resolve_docker_container", return_value=None
        ):
            info = target_info.collect("endpoint", "http://10.0.0.5:8080/sse")
        self.assertEqual(info["host"], "10.0.0.5")
        self.assertEqual(info["port"], 8080)
        self.assertEqual(info["scope"], "private")


class PathMetadataTests(unittest.TestCase):
    def test_directory_summary_counts_extensions(self):
        # Use repo's own server dir
        repo_root = Path(__file__).resolve().parents[2]
        target = repo_root / "servers" / "vuln-filesystem"
        if not target.exists():
            self.skipTest("lab vuln-filesystem source not present")
        info = target_info.collect("path", str(target))
        self.assertEqual(info["kind"], "directory")
        self.assertGreaterEqual(info["files_scanned"], 1)
        self.assertIn(".py", info["files_by_ext"])

    def test_missing_path(self):
        info = target_info.collect("path", "/nonexistent/path/zz9")
        self.assertEqual(info["kind"], "missing")


class ConfigMetadataTests(unittest.TestCase):
    def test_inline_json_extracts_servers(self):
        info = target_info.collect(
            "config",
            '{"mcpServers":{"x":{"command":"sh","transport":"stdio"}}}',
        )
        self.assertEqual(info["source"], "inline_json")
        self.assertEqual(info["server_count"], 1)
        self.assertEqual(info["servers"][0]["name"], "x")
        self.assertEqual(info["servers"][0]["command"], "sh")

    def test_invalid_json_records_parse_error(self):
        info = target_info.collect("config", "{not-json")
        self.assertIn("parse_error", info)


class RenderTextTests(unittest.TestCase):
    def test_render_text_handles_nested_dict_and_list(self):
        metadata = {
            "url": "http://x:1",
            "listener": {"pid": 1, "command": "c", "user": "u"},
            "servers": [{"name": "s1", "command": "sh"}],
            "empty": "",
        }
        lines = target_info.render_text(metadata)
        joined = "\n".join(lines)
        self.assertIn("url: http://x:1", joined)
        self.assertIn("listener:", joined)
        self.assertIn("pid: 1", joined)
        self.assertIn("- name=s1, command=sh", joined)
        self.assertNotIn("empty", joined)


if __name__ == "__main__":
    unittest.main()
