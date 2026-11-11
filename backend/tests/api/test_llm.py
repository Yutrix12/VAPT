"""Tests for POST /api/llm/check, against a fake Ollama."""

import unittest

from fastapi.testclient import TestClient

from app.llm.client import LLMSettings
from app.main import app
from tests.support.fake_ollama import FakeOllama
from tests.support.llm_override import KEY, backend_llm, clean_llm_environment


class LlmCheckEndpointTest(unittest.TestCase):
    """POST /api/llm/check: the backend's own LLM, or one clear error."""

    def setUp(self) -> None:
        self.client = TestClient(app, base_url="http://localhost")
        self.enterContext(clean_llm_environment())

    def status(self, fake: FakeOllama, model: str = "qwen3:8b",
               key: str | None = None):
        with backend_llm(LLMSettings(fake.base_url, model, api_key=key)):
            return self.client.post("/api/llm/check")

    def test_ready_with_the_model(self) -> None:
        with FakeOllama() as fake:
            response = self.status(fake)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "model": "qwen3:8b", "model_found": True,
            "leaves_this_computer": False})

    def test_model_without_tag_matches_latest(self) -> None:
        with FakeOllama() as fake:
            self.assertIs(self.status(fake, "llama3.2").json()["model_found"],
                          True)

    def test_model_not_found(self) -> None:
        with FakeOllama() as fake:
            self.assertIs(self.status(fake, "mistral").json()["model_found"],
                          False)

    def test_failing_llm_gives_502_without_the_key(self) -> None:
        for behaviour, message in {"http-500": "HTTP 500",
                                   "deep-json": "invalid JSON"}.items():
            with self.subTest(behaviour=behaviour), FakeOllama(behaviour) as f:
                response = self.status(f, key=KEY)
            self.assertEqual(response.status_code, 502)
            self.assertIn(message, response.json()["detail"])
            self.assertNotIn(KEY, response.text)

    def test_misconfigured_backend_gives_503(self) -> None:
        # No override: the real app.llm.config reads the environment.
        with clean_llm_environment(LLM_MODE="api"):
            response = self.client.post("/api/llm/check")
        self.assertEqual(response.status_code, 503)
        self.assertIn("OLLAMA_API_KEY", response.json()["detail"])

    def test_other_websites_cannot_trigger_a_check(self) -> None:
        # A check may send the API key to ollama.com, so it is a POST: a
        # browser always sends the Origin of a cross-site POST, and the
        # middleware refuses foreign origins. A plain GET is not allowed.
        with FakeOllama() as fake, backend_llm(LLMSettings(fake.base_url, "x")):
            foreign = self.client.post(
                "/api/llm/check", headers={"Origin": "https://evil.example"})
            as_get = self.client.get("/api/llm/check")
        self.assertEqual(foreign.status_code, 403)
        self.assertEqual(as_get.status_code, 405)
        self.assertEqual(fake.requests, [])

    def test_the_page_can_no_longer_send_settings(self) -> None:
        response = self.client.post("/api/llm/test", json={
            "base_url": "http://localhost:9", "model": "x"})
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
