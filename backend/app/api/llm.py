"""POST /api/llm/check."""

from fastapi import APIRouter, HTTPException

from app.api.dependencies import BackendLLM
from app.api.schemas import LLMStatus
from app.llm.client import LLMError, is_this_computer, list_models

router = APIRouter()


@router.post("/api/llm/check")
def llm_check(settings: BackendLLM) -> LLMStatus:
    """Check that the backend's LLM answers and has its model.

    A POST, not a GET: in api mode this sends the key to ollama.com, and a
    browser always sends the Origin of a cross-site POST, so the middleware
    can refuse other websites (a GET from an <img> carries no Origin).
    Uses Ollama's GET /api/tags, which is cheap: nothing is generated. A
    model name without a tag (e.g. "llama3.2") means its ":latest" tag.
    """
    try:
        models = list_models(settings)
    except LLMError as error:
        raise HTTPException(status_code=502, detail=str(error)) from None
    model = settings.model
    return LLMStatus(
        model=model,
        model_found=model in models or f"{model}:latest" in models,
        leaves_this_computer=not is_this_computer(settings.base_url),
    )
