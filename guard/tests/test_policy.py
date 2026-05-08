import unittest

from mcp_guard.policy import PolicyEngine


def _scan_result(pattern_ids, target="config_json"):
    """Build a minimal scan_result the PolicyEngine knows how to evaluate.

    PolicyEngine.evaluate iterates `scan_result["findings"]` expecting dicts
    with `pattern_id`, `severity`, `matched_indicator`, etc. — that's the
    shape produced by Scanner._scan_path / _scan_endpoint.
    """
    findings = [
        {
            "pattern_id": pattern,
            "pattern_name": pattern,
            "severity": "HIGH",
            "matched_indicator": f"synthetic indicator for {pattern}",
            "source": "mcp-guard",
            "confidence": "high",
        }
        for pattern in pattern_ids
    ]
    return {
        "target": target,
        "risk": "HIGH" if findings else "NONE",
        "findings": findings,
    }


class RuntimeVerificationHintTest(unittest.TestCase):
    def test_command_exec_finding_emits_runtime_verification_hint(self):
        engine = PolicyEngine()
        evaluation = engine.evaluate(_scan_result(["command_exec"]))
        hints = evaluation.get("runtime_verification") or []
        self.assertEqual(len(hints), 1, hints)
        hint = hints[0]
        self.assertIn("oh-my-secuaudit", hint["skill"])
        self.assertTrue(hint["url"].startswith("https://github.com/windshock/oh-my-secuaudit"))
        self.assertIn("PoC", hint["purpose"])

    def test_allowlist_bypass_finding_emits_runtime_verification_hint(self):
        engine = PolicyEngine()
        evaluation = engine.evaluate(_scan_result(["allowlist_bypass", "config_to_execution"]))
        self.assertEqual(len(evaluation["runtime_verification"]), 1)

    def test_no_findings_skips_runtime_verification_hint(self):
        engine = PolicyEngine()
        evaluation = engine.evaluate(_scan_result([]))
        self.assertEqual(evaluation["runtime_verification"], [])

    def test_unrelated_finding_skips_runtime_verification_hint(self):
        engine = PolicyEngine()
        # `cors_misconfiguration` is a real pattern but not in the runtime-
        # verifiable set; the scanner can confirm it at the endpoint without a
        # PoC project.
        evaluation = engine.evaluate(_scan_result(["cors_misconfiguration"]))
        self.assertEqual(evaluation["runtime_verification"], [])

    def test_format_output_renders_runtime_verification_block(self):
        engine = PolicyEngine()
        evaluation = engine.evaluate(_scan_result(["command_exec"]))
        text = engine.format_output(evaluation)
        self.assertIn("Runtime verification:", text)
        self.assertIn("oh-my-secuaudit", text)
        self.assertIn("lab/unknown/runtime/upsonic-cve-2026-30625/", text)


if __name__ == "__main__":
    unittest.main()
