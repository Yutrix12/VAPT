"""Which LLM the backend uses. The page never chooses; only this file does.

Two setups, picked with the LLM_MODE environment variable:

- "local" (the default): Ollama on this computer, no key.
- "api": Ollama's hosted API at ollama.com, with a key.

To move to the API later: set LLM_MODE=api and OLLAMA_API_KEY in the
environment the backend starts in (nothing here reads .env files), check it
works, then delete the "Local LLM" part below and its branch in
current_settings().
"""

import os
from collections.abc import Mapping

from llm_client import LLMError, LLMSettings

MODEL = "qwen3:8b"  # the one model the app uses (owner's decision)


# --- Local LLM: Ollama on this computer (remove when moving to the API) ---

LOCAL_BASE_URL = "http://localhost:11434"


def local_settings() -> LLMSettings:
    """Ollama running on this computer; nothing leaves the machine."""
    return LLMSettings(LOCAL_BASE_URL, MODEL)


# --- Hosted API: Ollama at ollama.com, with a key ---

API_BASE_URL = "https://ollama.com"


def api_settings(environ: Mapping[str, str]) -> LLMSettings:
    """The hosted Ollama API; the key and model come from the environment.

    The key is never logged or sent to the page; LLMSettings hides it in
    repr and refuses keys with control characters.
    """
    key = environ.get("OLLAMA_API_KEY", "").strip()
    if not key:
        raise LLMError("LLM_MODE is \"api\", but OLLAMA_API_KEY is not set "
                       "in the backend's environment.")
    model = environ.get("OLLAMA_API_MODEL", "").strip() or MODEL
    return LLMSettings(API_BASE_URL, model, api_key=key)


def current_settings(environ: Mapping[str, str] = os.environ) -> LLMSettings:
    """The settings for LLM_MODE ("local" when it is not set).

    Read on every call, so a test or a restart with new variables takes
    effect without changing code.
    """
    mode = environ.get("LLM_MODE", "").strip().lower() or "local"
    if mode == "local":
        return local_settings()
    if mode == "api":
        return api_settings(environ)
    raise LLMError('LLM_MODE must be "local" or "api".')
