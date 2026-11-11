"""Point the backend's LLM at a test server, without touching the real setup."""

import os
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import patch

from app.api.dependencies import llm_settings
from app.llm.client import LLMSettings
from app.main import app


@contextmanager
def backend_llm(settings: LLMSettings) -> Iterator[None]:
    """Use `settings` instead of app.llm.config while the with-block runs.

    FastAPI's dependency_overrides replaces the llm_settings dependency.
    """
    app.dependency_overrides[llm_settings] = lambda: settings
    try:
        yield
    finally:
        app.dependency_overrides.pop(llm_settings, None)


# A fake API key; tests check it never shows up in an answer or a message.
KEY = "sk-test-0123456789-do-not-leak"
LLM_VARIABLES = ("LLM_MODE", "OLLAMA_API_KEY", "OLLAMA_API_MODEL")


@contextmanager
def clean_llm_environment(**variables: str) -> Iterator[None]:
    """Run with only `variables` of the LLM setup set, whatever the shell has.

    patch.dict puts the real environment back afterwards.
    """
    with patch.dict(os.environ):
        for name in LLM_VARIABLES:
            os.environ.pop(name, None)
        os.environ.update(variables)
        yield
