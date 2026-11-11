"""Shared FastAPI dependencies."""

from typing import Annotated

from fastapi import Depends, HTTPException

from app.llm.client import LLMError, LLMSettings
from app.llm.config import current_settings


def llm_settings() -> LLMSettings:
    """The LLM chosen in app/llm/config.py; a setup problem gives one 503 line.

    A FastAPI dependency, so tests can swap in a fake Ollama with
    app.dependency_overrides.
    """
    try:
        return current_settings()
    except LLMError as error:
        raise HTTPException(status_code=503, detail=str(error)) from None


BackendLLM = Annotated[LLMSettings, Depends(llm_settings)]
