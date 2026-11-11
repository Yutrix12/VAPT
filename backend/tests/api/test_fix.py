"""Tests for POST /api/fix, with a fake LLM."""

import json
import unittest

from fastapi.testclient import TestClient

from app.llm.client import LLMSettings
from app.main import app
from tests.support.fake_ollama import FakeOllama
from tests.support.fix_samples import answer, make_group
from tests.support.llm_override import KEY, backend_llm, clean_llm_environment


class FixEndpointTest(unittest.TestCase):
    """POST /api/fix end to end: the body is the group only; the backend
    uses its own LLM (here a fake Ollama)."""

    def setUp(self) -> None:
        self.client = TestClient(app, base_url="http://localhost")
        self.enterContext(clean_llm_environment())

    def post(self, fake: FakeOllama, group: dict, key: str | None = None):
        settings = LLMSettings(fake.base_url, "qwen3:8b", api_key=key)
        with backend_llm(settings):
            return self.client.post("/api/fix", json=group)

    def test_verified_fix(self) -> None:
        with FakeOllama(chat_answer=answer()) as fake:
            response = self.post(fake, make_group().model_dump())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "verified")
        sent = json.loads(fake.requests[0]["body"])
        self.assertEqual(sent["model"], "qwen3:8b")
        self.assertIn("properties", sent["format"])  # the JSON schema

    def test_settings_in_the_body_are_ignored(self) -> None:
        body = {**make_group().model_dump(),
                "settings": {"base_url": "http://evil.invalid", "model": "x"},
                "base_url": "http://evil.invalid"}
        with FakeOllama(chat_answer=answer()) as fake:
            response = self.post(fake, body)
        self.assertEqual(response.json()["status"], "verified")
        self.assertEqual(len(fake.requests), 1)  # went to the backend's LLM

    def test_invented_version_comes_back_unverified(self) -> None:
        with FakeOllama(chat_answer=answer(target_version="9.9.9")) as fake:
            body = self.post(fake, make_group().model_dump()).json()
        self.assertEqual(body["status"], "unverified")
        self.assertIsNone(body["target_version"])

    def test_no_fix_available_yet(self) -> None:
        with FakeOllama(chat_answer=answer(target_version=None)) as fake:
            body = self.post(fake, make_group(fixed=[]).model_dump()).json()
        self.assertEqual(body["status"], "no_fix_available")
        self.assertTrue(body["mitigation_only"])

    def test_failing_llm_gives_one_clear_502_without_key(self) -> None:
        with FakeOllama("http-500") as fake:
            response = self.post(fake, make_group().model_dump(), key=KEY)
        self.assertEqual(response.status_code, 502)
        self.assertIsInstance(response.json()["detail"], str)
        self.assertNotIn(KEY, response.text)

    def test_unusable_answer_gives_502(self) -> None:
        with FakeOllama(chat_answer={"summary": "only this"}) as fake:
            response = self.post(fake, make_group().model_dump())
        self.assertEqual(response.status_code, 502)

    def test_misconfigured_backend_gives_503(self) -> None:
        with clean_llm_environment(LLM_MODE="cloud"):
            response = self.client.post("/api/fix",
                                        json=make_group().model_dump())
        self.assertEqual(response.status_code, 503)
        self.assertIn("LLM_MODE", response.json()["detail"])

    def test_broken_bodies_give_clear_lines(self) -> None:
        no_body = self.client.post(
            "/api/fix", content=b"",
            headers={"Content-Type": "application/json"})
        self.assertEqual(no_body.json()["detail"],
                         "request body: Field required")
        broken = self.client.post(
            "/api/fix", content=b"{bad",
            headers={"Content-Type": "application/json"})
        self.assertEqual(broken.json()["detail"],
                         "The request body is not valid JSON.")

    def test_large_real_groups_are_accepted(self) -> None:
        group = make_group(fixed=[f"1.{i}" for i in range(500)]).model_dump()
        group["pkg_name"] = "p" * 214  # npm allows names up to 214 chars
        with FakeOllama(chat_answer=answer(target_version="1.7")) as fake:
            response = self.post(fake, group)
        self.assertEqual(response.json()["status"], "verified")

    def test_very_long_fixed_version_is_refused(self) -> None:
        group = make_group().model_dump()
        group["fixed_versions"] = ["x" * 100_000]
        response = self.client.post("/api/fix", json=group)
        self.assertEqual(response.status_code, 422)

    def test_oversized_group_is_refused(self) -> None:
        group = make_group().model_dump()
        group["fixed_versions"] = ["1.0"] * 5000
        response = self.client.post("/api/fix", json=group)
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
