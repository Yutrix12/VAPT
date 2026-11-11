"""Tests for llm_client.py and POST /api/llm/check, against a fake Ollama."""

import json
import unittest

from fastapi.testclient import TestClient

from app.main import app
from llm_client import (LLMError, LLMSettings, chat_json, list_models,
                        normalize_base_url)
from tests.fake_ollama import CHAT_ANSWER, FakeOllama
from tests.llm_override import backend_llm, clean_llm_environment

KEY = "sk-test-0123456789-do-not-leak"
SCHEMA = {"type": "object", "properties": {"summary": {"type": "string"}}}


class BaseUrlTest(unittest.TestCase):
    """Only http and https base URLs are accepted."""

    def test_valid_urls_are_normalized(self) -> None:
        self.assertEqual(normalize_base_url(" http://localhost:11434/ "),
                         "http://localhost:11434")
        self.assertEqual(normalize_base_url("https://ollama.com"),
                         "https://ollama.com")

    def test_bad_urls_are_refused(self) -> None:
        for url in ["ftp://localhost:11434", "file:///etc/passwd",
                    "localhost:11434", "http://", "http://user:pw@host",
                    "http://host/?x=1", "http://localhost:abc",
                    "http://local host", "http://[::1", "http://h\x00st"]:
            with self.subTest(url=url), self.assertRaises(LLMError):
                normalize_base_url(url)

    def test_settings_are_normalized_once(self) -> None:
        settings = LLMSettings(" http://localhost:11434/ ", " llama3.2 ")
        self.assertEqual(settings.base_url, "http://localhost:11434")
        self.assertEqual(settings.model, "llama3.2")


class ApiKeyTest(unittest.TestCase):
    """The key only travels safely, and never appears in an error."""

    def test_key_with_line_break_is_refused_without_echo(self) -> None:
        with self.assertRaises(LLMError) as caught:
            LLMSettings("https://ollama.com", "x", api_key=KEY + "\r\nX: y")
        self.assertNotIn(KEY, str(caught.exception))

    def test_key_over_plain_http_only_to_this_computer(self) -> None:
        LLMSettings("http://localhost:11434", "x", api_key=KEY)
        LLMSettings("http://127.0.0.1:11434", "x", api_key=KEY)
        LLMSettings("https://ollama.com", "x", api_key=KEY)
        with self.assertRaises(LLMError) as caught:
            LLMSettings("http://ollama.example.com", "x", api_key=KEY)
        self.assertIn("https", str(caught.exception))


class ListModelsTest(unittest.TestCase):

    def test_lists_model_names(self) -> None:
        with FakeOllama() as fake:
            names = list_models(LLMSettings(fake.base_url, "x"))
        self.assertEqual(names, ["llama3.2:latest", "qwen3:8b"])
        self.assertEqual(fake.requests[0]["path"], "/api/tags")

    def test_key_header_only_when_filled(self) -> None:
        with FakeOllama() as fake:
            list_models(LLMSettings(fake.base_url, "x"))
            list_models(LLMSettings(fake.base_url, "x", api_key=KEY))
        without, with_key = (r["headers"] for r in fake.requests)
        self.assertNotIn("Authorization", without)
        self.assertEqual(with_key["Authorization"], f"Bearer {KEY}")

    def test_key_is_hidden_in_repr(self) -> None:
        settings = LLMSettings("http://localhost:11434", "x", api_key=KEY)
        self.assertNotIn(KEY, repr(settings))
        self.assertNotIn(KEY, str(settings))

    def test_failures_give_one_clear_error_without_the_key(self) -> None:
        cases = {"http-500": "HTTP 500", "invalid-json": "invalid JSON",
                 "redirect": "redirect", "slow": "did not answer",
                 "drip": "did not answer"}
        for behaviour, message in cases.items():
            with self.subTest(behaviour=behaviour), FakeOllama(behaviour) as f:
                with self.assertRaises(LLMError) as caught:
                    list_models(LLMSettings(f.base_url, "x", api_key=KEY),
                                timeout=0.5)
                self.assertIn(message, str(caught.exception))
                self.assertNotIn(KEY, str(caught.exception))
                self.assertEqual(len(f.requests), 1)  # redirect not followed

    def test_ollama_error_text_is_shown_cleaned(self) -> None:
        with FakeOllama("http-404") as fake:
            with self.assertRaises(LLMError) as caught:
                list_models(LLMSettings(fake.base_url, "x"))
        message = str(caught.exception)
        self.assertIn("model 'x' not found", message)
        self.assertNotIn("\x1b", message)

    def test_unreachable_server(self) -> None:
        with FakeOllama() as fake:
            url = fake.base_url  # the port is closed after the with-block
        # Windows retries a refused local connection for about 2 seconds
        # before giving up, so the timeout must be longer than that.
        with self.assertRaises(LLMError) as caught:
            list_models(LLMSettings(url, "x"), timeout=5)
        self.assertIn("Cannot reach", str(caught.exception))


class ChatJsonTest(unittest.TestCase):

    def test_sends_schema_and_parses_the_answer(self) -> None:
        with FakeOllama() as fake:
            answer = chat_json(LLMSettings(fake.base_url, "llama3.2"),
                               [{"role": "user", "content": "hi"}], SCHEMA)
        self.assertEqual(answer, CHAT_ANSWER)
        sent = json.loads(fake.requests[0]["body"])
        self.assertEqual(fake.requests[0]["path"], "/api/chat")
        self.assertEqual(sent["model"], "llama3.2")
        self.assertIs(sent["stream"], False)
        self.assertEqual(sent["format"], SCHEMA)
        self.assertEqual(sent["options"]["temperature"], 0)  # docs suggest 0

    def test_answer_that_is_not_json_is_an_error(self) -> None:
        for behaviour in ["chat-not-json", "chat-no-content"]:
            with self.subTest(behaviour=behaviour), FakeOllama(behaviour) as f:
                with self.assertRaises(LLMError):
                    chat_json(LLMSettings(f.base_url, "x"), [], SCHEMA)


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
        # No override: the real llm_config reads the environment.
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
