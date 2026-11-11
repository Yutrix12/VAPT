"""AI explanation of the findings that are not a vulnerable package (U4.3):
misconfigurations, secrets and licenses. One prompt per kind, one answer shape."""

from app.fixes.other.prompts import build_other_messages
from app.fixes.other.schemas import OTHER_FIX_SCHEMA, OtherAdvice, OtherAnswer, OtherFixRequest
from app.fixes.other.validation import validate_other_answer

__all__ = [
    "OTHER_FIX_SCHEMA",
    "OtherAdvice",
    "OtherAnswer",
    "OtherFixRequest",
    "build_other_messages",
    "validate_other_answer",
]
