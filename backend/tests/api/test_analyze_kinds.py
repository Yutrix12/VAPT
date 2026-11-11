"""Tests for POST /api/analyze with the other finding kinds."""

import unittest

from fastapi.testclient import TestClient

from app.fixes.secret_steps import SECRET_FIX_STEPS
from app.main import app
from tests.support.trivy_json import (
    dockerfile_result,
    misconf,
    report_with,
    secret,
    secrets_result,
)


class AnalyzeKindsTest(unittest.TestCase):
    """POST /api/analyze returns the three kinds; old fields keep their meaning."""

    def test_api_lists_each_kind(self) -> None:
        client = TestClient(app, base_url="http://localhost")
        content = report_with(dockerfile_result(misconf(), summary={"Successes": 3, "Failures": 1}),
                              secrets_result(secret()))
        body = client.post("/api/analyze", files={"file": ("k.json", content, "application/json")}).json()
        self.assertEqual(body["summary"]["by_kind"],
                         {"vulnerability": 0, "misconfiguration": 1, "secret": 1, "license": 0})
        self.assertEqual(body["summary"]["misconfig_passed"], 3)
        self.assertEqual(body["misconfigurations"][0]["check_id"], "DS-0002")
        self.assertEqual(set(body["secrets"][0]), {
            "fingerprint", "target", "rule_id", "category", "severity", "title", "start_line", "end_line"})
        self.assertEqual(body["secret_fix_steps"], list(SECRET_FIX_STEPS))
        self.assertEqual((body["report"]["misconfig_count"], body["report"]["secret_count"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
