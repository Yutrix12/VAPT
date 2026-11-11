"""Tests for POST /api/fix/other (misconfigurations, secrets, licenses), with a fake LLM."""

import json
import unittest

from fastapi.testclient import TestClient

from app.llm.client import LLMSettings
from app.main import app
from tests.support.fake_ollama import FakeOllama
from tests.support.llm_override import KEY, backend_llm, clean_llm_environment

SECRET = {
    "kind": "secret", "rule_id": "aws-access-key-id", "category": "AWS", "severity": "CRITICAL",
    "title": "AWS Access Key ID", "target": "deploy.sh", "start_line": 3, "end_line": 3,
}
MISCONFIG = {
    "kind": "misconfiguration", "check_id": "DS-0002", "title": "Image user should not be 'root'",
    "description": "Root is risky.", "resolution": "Add a USER line.", "severity": "HIGH",
    "misconf_type": "dockerfile", "target": "Dockerfile", "start_line": None, "end_line": None,
}
LICENSE = {
    "kind": "license", "name": "EPL-1.0", "category": "reciprocal", "license_class": "license",
    "package": "org.a:a", "severity": "MEDIUM",
}
ANSWER = {"summary": "Revoke it.", "solutions": ["Revoke the key at the provider."],
          "mitigations": ["Watch the access logs."], "risk_notes": "The key may already be used."}


class FixOtherEndpointTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app, base_url="http://localhost")
        self.enterContext(clean_llm_environment())

    def post(self, fake: FakeOllama, body: dict, key: str | None = None):
        settings = LLMSettings(fake.base_url, "qwen3:8b", api_key=key)
        with backend_llm(settings):
            return self.client.post("/api/fix/other", json=body)

    def test_each_kind_gets_its_checked_advice(self) -> None:
        for body in (SECRET, MISCONFIG, LICENSE):
            with self.subTest(kind=body["kind"]), FakeOllama(chat_answer=ANSWER) as fake:
                response = self.post(fake, body)
                self.assertEqual(response.status_code, 200)
                advice = response.json()
                self.assertEqual((advice["kind"], advice["status"]), (body["kind"], "solution_options"))
                self.assertEqual(advice["disclaimer"], "AI suggestion: verify before applying")

    def test_only_mitigations_gives_that_state(self) -> None:
        with FakeOllama(chat_answer={**ANSWER, "solutions": []}) as fake:
            self.assertEqual(self.post(fake, LICENSE).json()["status"], "mitigations_only")

    def test_the_model_gets_the_kind_prompt_and_only_the_fields_sent(self) -> None:
        with FakeOllama(chat_answer=ANSWER) as fake:
            self.post(fake, SECRET)
        sent = json.loads(fake.requests[0]["body"])
        system, user = sent["messages"][0]["content"], sent["messages"][-1]["content"]
        self.assertIn("a secret found in a file", system)
        self.assertIn("aws-access-key-id", user)
        self.assertEqual(sent["model"], "qwen3:8b")
        self.assertIn("properties", sent["format"])

    def test_a_secret_value_in_the_body_is_refused_and_never_reaches_the_model(self) -> None:
        with FakeOllama(chat_answer=ANSWER) as fake:
            response = self.post(fake, {**SECRET, "match": "AKIA-NOT-A-REAL-KEY"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(fake.requests, [])
        self.assertNotIn("AKIA-NOT-A-REAL-KEY", response.text)  # not echoed either

    def test_settings_in_the_body_are_refused(self) -> None:
        with FakeOllama(chat_answer=ANSWER) as fake:
            response = self.post(fake, {**LICENSE, "base_url": "http://evil.invalid"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(fake.requests, [])

    def test_a_broken_body_gives_one_clear_line(self) -> None:
        with FakeOllama(chat_answer=ANSWER) as fake:
            for body in ({}, {"kind": "vulnerability"}, {**SECRET, "severity": "SEVERE"}):
                with self.subTest(body=body):
                    response = self.post(fake, body)
                    self.assertEqual(response.status_code, 422)
                    self.assertIsInstance(response.json()["detail"], str)

    def test_failing_llm_gives_one_clear_502_without_key(self) -> None:
        with FakeOllama("http-500") as fake:
            response = self.post(fake, SECRET, key=KEY)
        self.assertEqual(response.status_code, 502)
        self.assertNotIn(KEY, response.text)

    def test_unusable_answer_gives_502(self) -> None:
        with FakeOllama(chat_answer={"summary": "x"}) as fake:
            response = self.post(fake, SECRET)
        self.assertEqual(response.status_code, 502)
        self.assertIn("did not match", response.json()["detail"])

    def test_misconfigured_backend_gives_503(self) -> None:
        with clean_llm_environment(LLM_MODE="cloud"):
            response = self.client.post("/api/fix/other", json=SECRET)
        self.assertEqual(response.status_code, 503)
        self.assertIn("LLM_MODE", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
