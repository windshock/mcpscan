import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_guard.discovery import (
    Candidate,
    _apply_tunnel_links,
    _discover_bore_links,
    _discover_cloudflared_links,
    _discover_docker_tunnel_links,
    _discover_localtunnel_links,
    _discover_ngrok_links,
    _extract_tunnel_upstream,
    _host_paths_from_compose_service,
    _rewrite_upstream_to_host,
    parse_lsof_output,
    parse_ps_output,
    select_candidate,
)


class DiscoveryParsingTests(unittest.TestCase):
    def test_parse_lsof_output(self):
        sample = """
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
python3  4242 alice   10u  IPv4 0x01      0t0  TCP 127.0.0.1:8000 (LISTEN)
node     5252 alice   11u  IPv6 0x02      0t0  TCP *:3201 (LISTEN)
"""
        listeners = parse_lsof_output(sample)
        self.assertEqual(
            listeners,
            [
                {"command": "python3", "pid": 4242, "user": "alice", "host": "127.0.0.1", "port": 8000},
                {"command": "node", "pid": 5252, "user": "alice", "host": "*", "port": 3201},
            ],
        )

    def test_parse_ps_output(self):
        sample = """
  PID  PPID COMMAND
 4242  1111 python3 /tmp/server.py
 5252  1111 cloudflared tunnel --url http://localhost:8000
"""
        processes = parse_ps_output(sample)
        self.assertEqual(processes[4242]["command"], "python3 /tmp/server.py")
        self.assertEqual(processes[5252]["ppid"], 1111)

    def test_select_candidate_requires_auto_in_noninteractive_mode(self):
        candidates = [
            {"kind": "endpoint", "target": "http://127.0.0.1:8000", "scan_ready": True, "auto_selectable": True},
            {"kind": "path", "target": "/tmp/project", "scan_ready": True},
        ]
        with patch("mcp_guard.discovery.os.isatty", return_value=False):
            with self.assertRaises(RuntimeError):
                select_candidate(candidates, auto=False)

        with patch("mcp_guard.discovery.os.isatty", return_value=False):
            selected = select_candidate(candidates, auto=True)
        self.assertEqual(selected["target"], "http://127.0.0.1:8000")

    def test_select_candidate_auto_requires_strong_signal(self):
        candidates = [
            {"kind": "endpoint", "target": "http://127.0.0.1:3000", "scan_ready": True, "auto_selectable": False},
            {"kind": "path", "target": "/tmp/project", "scan_ready": True, "auto_selectable": False},
        ]

        with self.assertRaises(RuntimeError):
            select_candidate(candidates, auto=True)


class DiscoveryDockerAndTunnelTests(unittest.TestCase):
    def test_compose_relative_paths_resolve(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            service_dir = root / "servers" / "demo"
            service_dir.mkdir(parents=True)
            (service_dir / "package.json").write_text('{"name":"demo"}')
            service = {
                "__working_dir": str(root),
                "build": {"context": "./servers/demo"},
                "volumes": ["./servers/demo:/app"],
            }

            paths = _host_paths_from_compose_service(service)
            self.assertIn(service_dir.resolve(), [path.resolve() for path in paths])

    def test_ngrok_links_are_loaded_from_local_api(self):
        process_map = {
            999: {"command": "ngrok http 8000"},
        }
        with patch("mcp_guard.discovery._http_json") as mock_http_json:
            mock_http_json.side_effect = [
                {
                    "endpoints": [
                        {
                            "url": "https://demo.ngrok.app",
                            "upstream": {"url": "http://localhost:8000"},
                        }
                    ]
                }
            ]
            links = _discover_ngrok_links(process_map)

        self.assertEqual(
            links,
            [
                {
                    "provider": "ngrok",
                    "public_url": "https://demo.ngrok.app",
                    "upstream": "http://localhost:8000",
                }
            ],
        )

    def test_cloudflared_links_read_trycloudflare_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "cloudflared.log"
            log_path.write_text("Started tunnel at https://happy-demo.trycloudflare.com\n")
            process_map = {
                123: {
                    "command": "cloudflared tunnel --url http://localhost:8000",
                    "stdout": str(log_path),
                }
            }

            links = _discover_cloudflared_links(process_map)

        self.assertEqual(
            links,
            [
                {
                    "provider": "cloudflared",
                    "public_url": "https://happy-demo.trycloudflare.com",
                    "upstream": "http://localhost:8000",
                }
            ],
        )

    def test_tunnel_public_urls_attach_to_existing_candidate(self):
        candidate = Candidate(
            kind="endpoint",
            display_name="local endpoint",
            target="http://127.0.0.1:8000",
        )

        _apply_tunnel_links(
            [candidate],
            [
                {
                    "provider": "ngrok",
                    "public_url": "https://demo.ngrok.app",
                    "upstream": "http://localhost:8000",
                }
            ],
        )

        self.assertEqual(candidate.public_urls, ["https://demo.ngrok.app"])
        self.assertIn("ngrok_public_url", candidate.evidence)


class LocaltunnelAndBoreTests(unittest.TestCase):
    """Host-side parsers for the no-signup tunnel CLIs."""

    def test_localtunnel_link_parsed_from_stdout_log(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as f:
            f.write("your url is: https://yellow-points-shake.loca.lt\n")
            log_path = f.name
        process_map = {
            999: {
                "command": "node /usr/local/bin/lt --port 3000 --local-host 127.0.0.1",
                "pid": 999,
                "stdout": log_path,
            }
        }
        links = _discover_localtunnel_links(process_map)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["provider"], "localtunnel")
        self.assertEqual(links[0]["public_url"], "https://yellow-points-shake.loca.lt")
        self.assertEqual(links[0]["upstream"], "http://127.0.0.1:3000")

    def test_bore_link_parsed_from_stderr_log(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as f:
            f.write("INFO bore_cli::client: listening at bore.pub:3061\n")
            log_path = f.name
        process_map = {
            777: {
                "command": "bore local 8000 --local-host 127.0.0.1 --to bore.pub",
                "pid": 777,
                "stderr": log_path,
            }
        }
        links = _discover_bore_links(process_map)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["provider"], "bore")
        self.assertEqual(links[0]["public_url"], "tcp://bore.pub:3061")
        self.assertEqual(links[0]["upstream"], "http://127.0.0.1:8000")


class DockerTunnelDiscoveryTests(unittest.TestCase):
    """Discovery of tunnel containers via docker ps + docker logs."""

    def test_extract_tunnel_upstream_handles_sh_wrapped_command(self):
        # Docker compose with `command: sh -c "..."` produces this Cmd shape.
        cmd = [
            "sh",
            "-c",
            "npx --yes localtunnel --port 3000 --local-host vuln-network --print-requests",
        ]
        upstream = _extract_tunnel_upstream("localtunnel", cmd, " ".join(cmd))
        self.assertEqual(upstream, "http://vuln-network:3000")

    def test_extract_tunnel_upstream_bore(self):
        cmd = ["local", "8000", "--local-host", "vuln-config-exec", "--to", "bore.pub"]
        upstream = _extract_tunnel_upstream("bore", cmd, " ".join(cmd))
        self.assertEqual(upstream, "http://vuln-config-exec:8000")

    def test_rewrite_upstream_to_host_uses_published_port(self):
        rewritten = _rewrite_upstream_to_host(
            "http://vuln-authless:8000",
            {"vuln-authless:8000": "127.0.0.1:3102"},
        )
        self.assertEqual(rewritten, "http://127.0.0.1:3102")

    def test_rewrite_upstream_to_host_returns_none_when_unmapped(self):
        self.assertIsNone(
            _rewrite_upstream_to_host("http://nowhere:9999", {"x:1": "127.0.0.1:1"})
        )


if __name__ == "__main__":
    unittest.main()
