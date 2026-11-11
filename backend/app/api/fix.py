"""POST /api/fix (vulnerable packages) and POST /api/fix/other (misconfigurations, secrets, licenses)."""

from fastapi import APIRouter, HTTPException

from app.api.dependencies import BackendLLM
from app.fixes.other import OtherAdvice, OtherFixRequest, build_other_messages, validate_other_answer
from app.fixes.other.schemas import OTHER_FIX_SCHEMA
from app.fixes.prompts import build_messages
from app.fixes.schemas import FIX_SCHEMA, FixAdvice, FixGroup
from app.fixes.validation import FixError, validate_answer
from app.llm.client import LLMError, chat_json

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


@router.post("/api/fix/other")
def fix_other(request: OtherFixRequest, settings: BackendLLM) -> OtherAdvice:
    """Ask the backend's LLM to explain one misconfiguration, secret or license, then check it.

    The body has the finding's own fields and nothing else (extra fields are
    refused), so a secret's value or a misconfiguration's message can never be
    sent on. Trivy's own fix and the fixed steps stay on the page; this only
    adds the explanation.
    """
    try:
        answer = chat_json(settings, build_other_messages(request), OTHER_FIX_SCHEMA)
        return validate_other_answer(answer, request.kind)
    except (LLMError, FixError) as error:
        raise HTTPException(status_code=502, detail=str(error)) from None

