"""Tests for llm_client.py and POST /api/llm/test, against a fake Ollama."""

import json
import unittest

from fastapi.testclient import TestClient

from llm_client import (LLMError, LLMSettings, chat_json, list_models,
                        normalize_base_url)
from main import app
from tests.fake_ollama import CHAT_ANSWER, FakeOllama

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


class LlmTestEndpointTest(unittest.TestCase):
    """POST /api/llm/test: ok + models, or one clear error."""

    def setUp(self) -> None:
        self.client = TestClient(app, base_url="http://localhost")

    def test_ok_with_model_found(self) -> None:
        with FakeOllama() as fake:
            response = self.client.post("/api/llm/test", json={
                "base_url": fake.base_url, "model": "llama3.2"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "ok": True, "models": ["llama3.2:latest", "qwen3:8b"],
            "model_found": True})

    def test_without_a_model_lists_the_models(self) -> None:
        with FakeOllama() as fake:
            response = self.client.post("/api/llm/test", json={
                "base_url": fake.base_url, "model": "   "})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["models"],
                         ["llama3.2:latest", "qwen3:8b"])
        self.assertIs(response.json()["model_found"], False)

    def test_deeply_nested_answer_gives_one_clear_error(self) -> None:
        with FakeOllama("deep-json") as fake:
            response = self.client.post("/api/llm/test", json={
                "base_url": fake.base_url, "model": "x"})
        self.assertEqual(response.status_code, 502)
        self.assertIn("invalid JSON", response.json()["detail"])

    def test_broken_request_bodies_give_clear_lines(self) -> None:
        no_body = self.client.post(
            "/api/llm/test", content=b"",
            headers={"Content-Type": "application/json"})
        self.assertEqual(no_body.json()["detail"],
                         "request body: Field required")
        empty = self.client.post("/api/llm/test", json={})
        self.assertEqual(empty.json()["detail"], "base_url: Field required")
        broken = self.client.post(
            "/api/llm/test", content=b"{bad",
            headers={"Content-Type": "application/json"})
        self.assertEqual(broken.json()["detail"],
                         "The request body is not valid JSON.")

    def test_model_not_found(self) -> None:
        with FakeOllama() as fake:
            response = self.client.post("/api/llm/test", json={
                "base_url": fake.base_url, "model": "mistral"})
        self.assertIs(response.json()["model_found"], False)

    def test_failing_llm_gives_502_without_the_key(self) -> None:
        with FakeOllama("http-500") as fake:
            response = self.client.post("/api/llm/test", json={
                "base_url": fake.base_url, "model": "x", "api_key": KEY})
        self.assertEqual(response.status_code, 502)
        self.assertIn("HTTP 500", response.json()["detail"])
        self.assertNotIn(KEY, response.text)

    def test_bad_base_url_gives_one_line_422(self) -> None:
        response = self.client.post("/api/llm/test", json={
            "base_url": "ftp://x", "model": "x", "api_key": KEY})
        self.assertEqual(response.status_code, 422)
        self.assertIn("base URL must start with http",
                      response.json()["detail"])
        self.assertNotIn(KEY, response.text)

    def test_bad_settings_give_422_without_the_key(self) -> None:
        cases = {
            # These settings are refused before any request is sent, so the
            # .invalid host names (never real) are not contacted.
            "key with line break": {"base_url": "https://ollama.invalid",
                                    "model": "x",
                                    "api_key": KEY + "\r\nX: y"},
            "key over http": {"base_url": "http://ollama.invalid",
                              "model": "x", "api_key": KEY},
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                response = self.client.post("/api/llm/test", json=body)
                self.assertEqual(response.status_code, 422)
                self.assertNotIn(KEY, response.text)


if __name__ == "__main__":
    unittest.main()
