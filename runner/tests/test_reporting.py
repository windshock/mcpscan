import json
import tempfile
import unittest
from pathlib import Path

from runner.reporting import generate_lab_outputs, generate_ox_live_outputs, generate_ox_live_report, normalize_ox_live


class ReportingTest(unittest.TestCase):
    def test_normalize_ox_live(self):
        raw = {
            "product_id": "langflow",
            "product_name": "LangFlow",
            "timestamp": "2026-04-21T00:00:00+00:00",
            "source_url": "https://github.com/langflow-ai/langflow",
            "launch_kind": "docker_image",
            "launch_status": "success",
            "health_status": "reachable",
            "scan_status": "success",
            "scan_result": {"findings": ["config_to_execution"]},
            "failure_reason": None,
            "notes": [],
            "evidence": {"launch_logs": "/tmp/langflow.log"},
        }
        expected = {
            "expected_launch_success": True,
            "expected_health_status": "reachable",
            "expected_scan_status": "success",
            "expected_findings": ["config_to_execution"],
            "optional_findings": ["allowlist_bypass"],
        }

        normalized = normalize_ox_live(raw, expected)

        self.assertEqual(normalized["true_positives"], ["config_to_execution"])
        self.assertEqual(normalized["false_positives"], [])
        self.assertTrue(normalized["launch_matches_expectation"])
        self.assertTrue(normalized["health_matches_expectation"])

    def test_generate_ox_live_report(self):
        normalized = [
            {
                "target": "langflow",
                "product_name": "LangFlow",
                "target_type": "ox_live",
                "scanner_name": "mcp-guard-live",
                "source_url": "https://github.com/langflow-ai/langflow",
                "launch_kind": "docker_image",
                "launch_status": "success",
                "health_status": "reachable",
                "scan_status": "success",
                "failure_reason": None,
                "expected_findings": ["config_to_execution"],
                "optional_findings": [],
                "detected_findings": ["config_to_execution"],
                "true_positives": ["config_to_execution"],
                "missed_findings": [],
                "false_positives": [],
                "notes": [],
                "evidence": {"launch_logs": "/tmp/langflow.log"},
            }
        ]

        report = generate_ox_live_report(normalized)

        self.assertIn("# OX Live Validation Report", report)
        self.assertIn("LangFlow (langflow)", report)
        self.assertIn("TP:1/FP:0/FN:0", report)

    def test_generate_lab_outputs_marks_invalid_and_skipped_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            raw_dir = results_dir / "raw"
            (raw_dir / "mcpscan").mkdir(parents=True)
            (raw_dir / "cisco-scanner").mkdir(parents=True)
            (raw_dir / "mcp-guard").mkdir(parents=True)

            (raw_dir / "mcpscan" / "demo.json").write_text("")
            (raw_dir / "cisco-scanner" / "demo.json").write_text(
                json.dumps(
                    {
                        "status": "skipped",
                        "reason": "path mode unsupported",
                        "target": "/servers/demo",
                    }
                )
            )
            (raw_dir / "mcp-guard" / "demo.json").write_text(
                json.dumps(
                    {
                        "status": "success",
                        "findings": ["command_exec"],
                        "policy_verdict": "BLOCK",
                    }
                )
            )

            expected_file = Path(tmpdir) / "expected-findings.json"
            expected_file.write_text(
                json.dumps(
                    {
                        "servers": {
                            "demo": {
                                "expected_findings": ["command_exec"],
                                "expected_false_positives": [],
                            }
                        }
                    }
                )
            )

            normalized = generate_lab_outputs(results_dir, expected_file)

            mcpscan_result = next(result for result in normalized if result["scanner_name"] == "mcpscan")
            cisco_result = next(result for result in normalized if result["scanner_name"] == "cisco-scanner")
            guard_result = next(result for result in normalized if result["scanner_name"] == "mcp-guard")

            self.assertEqual(mcpscan_result["status"], "failed")
            self.assertIn("empty raw result", mcpscan_result["error"])
            self.assertEqual(cisco_result["status"], "skipped")
            self.assertEqual(cisco_result["error"], "path mode unsupported")
            self.assertEqual(guard_result["status"], "success")
            self.assertEqual(guard_result["true_positives"], ["command_exec"])

            comparison_report = (results_dir / "report" / "comparison.md").read_text()
            self.assertIn("FAIL", comparison_report)
            self.assertIn("SKIP", comparison_report)

    def test_generate_lab_outputs_merges_endpoint_scanner(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            raw_dir = results_dir / "raw"
            (raw_dir / "mcpscan").mkdir(parents=True)
            (raw_dir / "cisco-scanner").mkdir(parents=True)
            (raw_dir / "mcp-guard").mkdir(parents=True)
            (raw_dir / "mcp-guard-endpoint").mkdir(parents=True)

            (raw_dir / "mcpscan" / "demo.json").write_text(json.dumps([]))
            (raw_dir / "cisco-scanner" / "demo.json").write_text(
                json.dumps({"status": "skipped", "reason": "n/a"})
            )
            (raw_dir / "mcp-guard" / "demo.json").write_text(
                json.dumps({"status": "success", "findings": ["unrestricted_file_read"]})
            )
            (raw_dir / "mcp-guard-endpoint" / "demo.json").write_text(
                json.dumps(
                    {
                        "status": "success",
                        "findings": ["authless_endpoint", "cors_misconfiguration"],
                    }
                )
            )

            expected_file = Path(tmpdir) / "expected-findings.json"
            expected_file.write_text(
                json.dumps(
                    {
                        "servers": {
                            "demo": {
                                "expected_findings": [
                                    "unrestricted_file_read",
                                    "authless_endpoint",
                                    "cors_misconfiguration",
                                ],
                                "expected_false_positives": [],
                            }
                        }
                    }
                )
            )

            normalized = generate_lab_outputs(results_dir, expected_file)

            endpoint_result = next(
                r for r in normalized if r["scanner_name"] == "mcp-guard-endpoint"
            )
            self.assertEqual(
                sorted(endpoint_result["true_positives"]),
                ["authless_endpoint", "cors_misconfiguration"],
            )

            comparison = (results_dir / "report" / "comparison.md").read_text()
            self.assertIn("mcp-guard-endpoint", comparison)
            self.assertIn("mcp-guard combined", comparison)
            # Combined view should report 100% recall when source ∪ endpoint covers expected.
            combined_section = comparison.split("## mcp-guard combined", 1)[1]
            self.assertIn("Recall**: 100.0%", combined_section)
            self.assertIn("OK **demo**: TP=3 FP=0 FN=0", combined_section)

    def test_ox_live_report_distinguishes_fixture_and_live_scans(self):
        normalized = [
            {
                "target": "langflow",
                "product_name": "LangFlow",
                "target_type": "ox_live",
                "scanner_name": "mcp-guard-live",
                "source_url": "https://github.com/langflow-ai/langflow",
                "launch_kind": "docker_image",
                "launch_status": "success",
                "health_status": "reachable",
                "scan_status": "success",
                "scan_mode": "config_fixture",
                "expected_manual_blocker": False,
                "failure_reason": None,
                "expected_findings": ["config_to_execution"],
                "optional_findings": [],
                "detected_findings": ["config_to_execution"],
                "true_positives": ["config_to_execution"],
                "missed_findings": [],
                "false_positives": [],
                "notes": [],
                "evidence": {},
            },
            {
                "target": "upsonic",
                "product_name": "Upsonic",
                "target_type": "ox_live",
                "scanner_name": "mcp-guard-live",
                "source_url": "https://github.com/Upsonic/Upsonic",
                "launch_kind": "manual_blocked",
                "launch_status": "failed",
                "health_status": "unreachable",
                "scan_status": "success",
                "scan_mode": "config_fixture",
                "expected_manual_blocker": True,
                "failure_reason": "manual_blocked",
                "expected_findings": ["config_to_execution", "allowlist_bypass"],
                "optional_findings": [],
                "detected_findings": ["config_to_execution", "allowlist_bypass"],
                "true_positives": ["allowlist_bypass", "config_to_execution"],
                "missed_findings": [],
                "false_positives": [],
                "notes": ["manual_blocked: ..."],
                "evidence": {},
            },
        ]

        report = generate_ox_live_report(normalized)
        # Manual blockers should be visible in the table
        self.assertIn("Expected Block", report)
        self.assertIn("| upsonic | failed | unreachable | success (config_fixture)", report)
        # Live launch + fixture scan should also show fixture mode
        self.assertIn("| langflow | success | reachable | success (config_fixture)", report)
        # Headline counts should split fixture vs live
        self.assertIn("Fixture-only scans (config_fixture)**: 2", report)
        self.assertIn("Live endpoint scans**: 0", report)
        self.assertIn("Expected manual blockers**: 1", report)
        self.assertIn("Launch-expected products**: 1", report)
        # Expected manual blocker appears in details
        self.assertIn("Expected Manual Blocker: yes", report)

    def test_normalize_cisco_maps_threat_names(self):
        from runner.reporting import normalize_cisco

        raw = {
            "scan_results": [
                {
                    "tool_name": "execute_command",
                    "is_safe": False,
                    "findings": {
                        "yara_analyzer": {
                            "severity": "HIGH",
                            "total_findings": 2,
                            "threat_names": ["CODE EXECUTION", "TOOL POISONING"],
                            "threat_summary": "shell exec",
                        },
                        "api_analyzer": {"severity": "SAFE", "total_findings": 0},
                    },
                },
                {
                    "tool_name": "list_environment",
                    "is_safe": False,
                    "findings": {
                        "yara_analyzer": {
                            "severity": "HIGH",
                            "total_findings": 1,
                            "threat_names": ["CREDENTIAL HARVESTING"],
                        }
                    },
                },
                {
                    "tool_name": "safe_tool",
                    "is_safe": True,
                    "findings": {},
                },
            ]
        }
        expected = {
            "expected_findings": ["command_exec", "tool_poisoning", "env_exposure"],
            "expected_false_positives": [],
        }

        normalized = normalize_cisco(raw, "vuln-authless", expected)
        self.assertEqual(
            sorted(normalized["true_positives"]),
            ["command_exec", "env_exposure", "tool_poisoning"],
        )
        self.assertEqual(normalized["false_positives"], [])

    def test_generate_lab_outputs_skips_optional_endpoint_when_dir_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            raw_dir = results_dir / "raw"
            (raw_dir / "mcpscan").mkdir(parents=True)
            (raw_dir / "cisco-scanner").mkdir(parents=True)
            (raw_dir / "mcp-guard").mkdir(parents=True)

            (raw_dir / "mcpscan" / "demo.json").write_text(json.dumps([]))
            (raw_dir / "cisco-scanner" / "demo.json").write_text(
                json.dumps({"status": "skipped", "reason": "n/a"})
            )
            (raw_dir / "mcp-guard" / "demo.json").write_text(
                json.dumps({"status": "success", "findings": []})
            )

            expected_file = Path(tmpdir) / "expected-findings.json"
            expected_file.write_text(
                json.dumps({"servers": {"demo": {"expected_findings": [], "expected_false_positives": []}}})
            )

            normalized = generate_lab_outputs(results_dir, expected_file)
            scanner_names = {result["scanner_name"] for result in normalized}
            self.assertNotIn("mcp-guard-endpoint", scanner_names)

    def test_generate_lab_outputs_accepts_mcpscan_list_payload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            raw_dir = results_dir / "raw"
            (raw_dir / "mcpscan").mkdir(parents=True)
            (raw_dir / "cisco-scanner").mkdir(parents=True)
            (raw_dir / "mcp-guard").mkdir(parents=True)

            (raw_dir / "mcpscan" / "demo.json").write_text(
                json.dumps([{"rule_id": "command_exec"}])
            )
            (raw_dir / "cisco-scanner" / "demo.json").write_text(
                json.dumps({"status": "skipped", "reason": "path mode unsupported"})
            )
            (raw_dir / "mcp-guard" / "demo.json").write_text(
                json.dumps({"status": "success", "findings": ["command_exec"]})
            )

            expected_file = Path(tmpdir) / "expected-findings.json"
            expected_file.write_text(
                json.dumps(
                    {
                        "servers": {
                            "demo": {
                                "expected_findings": ["command_exec"],
                                "expected_false_positives": [],
                            }
                        }
                    }
                )
            )

            normalized = generate_lab_outputs(results_dir, expected_file)
            mcpscan_result = next(result for result in normalized if result["scanner_name"] == "mcpscan")

            self.assertEqual(mcpscan_result["status"], "success")
            self.assertEqual(mcpscan_result["true_positives"], ["command_exec"])

    def test_generate_cisco_config_outputs_against_ox_corpus(self):
        from runner.reporting import generate_cisco_config_outputs

        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            raw_dir = results_dir / "raw" / "cisco-config"
            raw_dir.mkdir(parents=True)

            (raw_dir / "Flowise.json").write_text(
                json.dumps(
                    {
                        "scan_results": [
                            {
                                "tool_name": "flowise_attack",
                                "is_safe": False,
                                "findings": {
                                    "yara_analyzer": {
                                        "severity": "HIGH",
                                        "threat_names": ["CODE EXECUTION"],
                                    }
                                },
                            }
                        ]
                    }
                )
            )
            (raw_dir / "Upsonic.json").write_text(
                json.dumps({"scan_results": []})
            )

            fixture = Path(tmpdir) / "ox_research_cases.json"
            fixture.write_text(
                json.dumps(
                    [
                        {
                            "name": "Flowise",
                            "expected_findings": ["config_to_execution", "allowlist_bypass"],
                            "payload": {},
                        },
                        {
                            "name": "Upsonic",
                            "expected_findings": ["config_to_execution"],
                            "payload": {},
                        },
                    ]
                )
            )

            results = generate_cisco_config_outputs(results_dir, fixture)
            by_name = {r["target"]: r for r in results}
            self.assertEqual(by_name["Flowise"]["true_positives"], [])  # CODE EXECUTION → command_exec, not in expected
            self.assertEqual(by_name["Flowise"]["false_positives"], ["command_exec"])
            self.assertIn("config_to_execution", by_name["Flowise"]["missed_findings"])
            self.assertEqual(by_name["Upsonic"]["true_positives"], [])
            self.assertIn("config_to_execution", by_name["Upsonic"]["missed_findings"])

            report = (results_dir / "report" / "cisco-supply-chain.md").read_text()
            self.assertIn("Cisco Supply-Chain Coverage", report)
            self.assertIn("Flowise", report)
            self.assertIn("Upsonic", report)

    def test_generate_cisco_config_outputs_silently_skips_when_empty(self):
        from runner.reporting import generate_cisco_config_outputs

        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            (results_dir / "raw" / "cisco-config").mkdir(parents=True)
            fixture = Path(tmpdir) / "fix.json"
            fixture.write_text("[]")

            results = generate_cisco_config_outputs(results_dir, fixture)
            self.assertEqual(results, [])
            self.assertFalse((results_dir / "report" / "cisco-supply-chain.md").exists())

    def test_generate_ox_live_outputs_marks_missing_raw_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            expected_file = Path(tmpdir) / "ox-live-expected.json"
            expected_file.write_text(
                json.dumps(
                    {
                        "products": {
                            "langflow": {
                                "expected_launch_success": True,
                                "expected_health_status": "reachable",
                                "expected_scan_status": "success",
                                "expected_findings": ["config_to_execution"],
                            }
                        }
                    }
                )
            )

            normalized = generate_ox_live_outputs(results_dir, expected_file)

            self.assertEqual(len(normalized), 1)
            self.assertEqual(normalized[0]["target"], "langflow")
            self.assertEqual(normalized[0]["failure_reason"], "raw_result_unavailable")
            self.assertEqual(normalized[0]["scan_status"], "failed")


if __name__ == "__main__":
    unittest.main()
