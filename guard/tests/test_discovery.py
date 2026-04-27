import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_guard.discovery import (
    Candidate,
    _apply_tunnel_links,
    _discover_cloudflared_links,
    _discover_ngrok_links,
    _host_paths_from_compose_service,
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


if __name__ == "__main__":
    unittest.main()
