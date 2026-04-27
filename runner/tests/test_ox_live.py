import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runner.ox_live import (
    build_guard_scan_env,
    build_compose_override,
    build_docker_run_command,
    classify_failure_reason,
    load_fixture_cases,
    prepare_repo_compose,
    render_compose_override,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class OxLiveHelpersTest(unittest.TestCase):
    def test_classify_failure_reason(self):
        self.assertEqual(classify_failure_reason("manifest unknown"), "image_not_found")
        self.assertEqual(classify_failure_reason("requested access to the resource is denied"), "image_auth_required")
        self.assertEqual(classify_failure_reason("port is already allocated"), "port_conflict")
        self.assertEqual(classify_failure_reason("write /var/lib/docker/tmp/blob: no space left on device"), "no_space_left")

    def test_build_docker_run_command(self):
        manifest = {
            "id": "langflow",
            "launch": {
                "kind": "docker_image",
                "image": "langflowai/langflow:latest",
                "ports": [{"host": 37860, "container": 7860}],
                "env": {"LANGFLOW_AUTO_LOGIN": "false"},
            },
        }

        command = build_docker_run_command(manifest, "mcpscan-ox-langflow")

        self.assertEqual(command[:6], ["docker", "run", "-d", "--name", "mcpscan-ox-langflow", "--label"])
        self.assertIn("LANGFLOW_AUTO_LOGIN=false", command)
        self.assertIn("37860:7860", command)
        self.assertEqual(command[-1], "langflowai/langflow:latest")

    def test_build_compose_override(self):
        manifest = {
            "launch": {
                "compose_overrides": {
                    "services": {
                        "frontend": {"ports": ["35173:5173"]},
                        "postgres": {"ports": []},
                    }
                }
            }
        }

        override = build_compose_override(manifest)
        rendered = render_compose_override(override)

        self.assertEqual(
            override,
            {
                "services": {
                    "frontend": {"ports": ["35173:5173"]},
                    "postgres": {"ports": []},
                }
            },
        )
        self.assertIn('ports: !override\n      - "35173:5173"\n', rendered)
        self.assertIn("ports: !override []\n", rendered)

    def test_load_fixture_cases(self):
        fixtures = load_fixture_cases(REPO_ROOT / "guard" / "tests" / "fixtures" / "ox_research_cases.json")
        self.assertIn("LangFlow", fixtures)
        self.assertEqual(fixtures["PromptFoo"]["expected_findings"], ["config_to_execution", "allowlist_bypass"])

    def test_build_guard_scan_env_prepends_repo_paths(self):
        original = os.environ.get("PYTHONPATH")
        try:
            os.environ["PYTHONPATH"] = "/tmp/custom"
            env = build_guard_scan_env()
        finally:
            if original is None:
                os.environ.pop("PYTHONPATH", None)
            else:
                os.environ["PYTHONPATH"] = original

        pythonpath = env["PYTHONPATH"].split(os.pathsep)
        self.assertEqual(pythonpath[0], str(REPO_ROOT))
        self.assertEqual(pythonpath[1], str(REPO_ROOT / "guard"))
        self.assertIn("/tmp/custom", pythonpath)

    def test_prepare_repo_compose_preserves_context_before_up(self):
        manifest = {
            "id": "sample-app",
            "launch": {
                "kind": "repo_compose",
                "repo_url": "https://example.com/sample-app.git",
                "compose_file": "docker-compose.yml",
                "project_name": "mcpscan-ox-sample-app",
                "write_files": {
                    ".env": "TOKEN=\n",
                },
                "compose_overrides": {
                    "services": {
                        "app": {"ports": ["38000:8000"]},
                    }
                },
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            workdir_root = Path(tmpdir)

            def fake_run_command(args, **kwargs):
                if args[:3] == ["git", "clone", "--depth"]:
                    repo_dir = workdir_root / "sample-app"
                    repo_dir.mkdir(parents=True, exist_ok=True)
                    (repo_dir / "docker-compose.yml").write_text("services: {}\n")

            with patch("runner.ox_live.run_command", side_effect=fake_run_command), patch(
                "runner.ox_live._compose_command",
                return_value=["docker", "compose"],
            ):
                context = prepare_repo_compose(manifest, workdir_root)
                repo_dir = (workdir_root / "sample-app").resolve()
                self.assertEqual(context["project_name"], "mcpscan-ox-sample-app")
                self.assertEqual(context["command"][:2], ["docker", "compose"])
                self.assertIn(str(repo_dir / "docker-compose.yml"), context["command"])
                self.assertIn(str(repo_dir / ".mcpscan-compose.override.yaml"), context["command"])
                self.assertTrue((repo_dir / ".env").exists())


if __name__ == "__main__":
    unittest.main()
