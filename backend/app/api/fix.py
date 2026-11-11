"""POST /api/fix."""

from fastapi import APIRouter, HTTPException

from app.api.dependencies import BackendLLM
from app.llm.client import LLMError, chat_json
from fixes import FIX_SCHEMA, FixAdvice, FixError, FixGroup, build_messages, validate_answer

router = APIRouter()


@router.post("/api/fix")
def fix(group: FixGroup, settings: BackendLLM) -> FixAdvice:
    """Ask the backend's LLM to explain the fix for one group, then check it.

    The body is the group only: the page cannot choose where it is sent.
    The page always shows Trivy's own fixed versions; this only adds the
    explanation. A version counts as a fix only if Trivy lists it.
    """
    try:
        answer = chat_json(settings, build_messages(group), FIX_SCHEMA)
        return validate_answer(answer, group)
    except (LLMError, FixError) as error:
        raise HTTPException(status_code=502, detail=str(error)) from None
