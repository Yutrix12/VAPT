"""Tests for app/llm/config.py: which LLM the backend uses."""

import unittest

from app.llm.client import LLMError
from app.llm.config import current_settings

KEY = "sk-test-0123456789-do-not-leak"


class LlmConfigTest(unittest.TestCase):

    def test_local_llm_is_the_default(self) -> None:
        settings = current_settings({})
        self.assertEqual(
            (settings.base_url, settings.model, settings.api_key),
            ("http://localhost:11434", "qwen3:8b", None))

    def test_local_mode_never_sends_a_key(self) -> None:
        settings = current_settings({"LLM_MODE": "local",
                                     "OLLAMA_API_KEY": KEY})
        self.assertIsNone(settings.api_key)

    def test_api_mode_reads_key_and_model_from_the_environment(self) -> None:
        settings = current_settings({"LLM_MODE": " API ",
                                     "OLLAMA_API_KEY": KEY,
                                     "OLLAMA_API_MODEL": "gpt-oss:120b"})
        self.assertEqual(
            (settings.base_url, settings.model, settings.api_key),
            ("https://ollama.com", "gpt-oss:120b", KEY))
        default = current_settings({"LLM_MODE": "api", "OLLAMA_API_KEY": KEY})
        self.assertEqual(default.model, "qwen3:8b")

    def test_api_mode_without_key_is_one_clear_error(self) -> None:
        with self.assertRaises(LLMError) as caught:
            current_settings({"LLM_MODE": "api", "OLLAMA_API_KEY": "  "})
        self.assertIn("OLLAMA_API_KEY", str(caught.exception))

    def test_bad_key_is_refused_without_echo(self) -> None:
        with self.assertRaises(LLMError) as caught:
            current_settings({"LLM_MODE": "api",
                              "OLLAMA_API_KEY": KEY + "\r\nX: y"})
        self.assertNotIn(KEY, str(caught.exception))

    def test_unknown_mode_is_one_clear_error(self) -> None:
        with self.assertRaises(LLMError) as caught:
            current_settings({"LLM_MODE": "cloud"})
        self.assertIn('"local" or "api"', str(caught.exception))


if __name__ == "__main__":
    unittest.main()
