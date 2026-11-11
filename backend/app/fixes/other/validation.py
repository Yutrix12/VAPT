"""Check the model's answer for a misconfiguration, secret or license."""

from typing import Any

from pydantic import ValidationError

from app.fixes.other.schemas import OtherAdvice, OtherAnswer
from app.fixes.validation import FixError, clean_lines, clean_text


def validate_other_answer(answer: dict[str, Any], kind: str) -> OtherAdvice:
    """Check the answer; the state (solution options or mitigations only) is decided in code."""
    try:
        parsed = OtherAnswer.model_validate(answer)
    except ValidationError as error:
        first = error.errors()[0]
        field = ".".join(str(part) for part in first["loc"]) or "answer"
        # The message names the field and the problem, not the model's text.
        raise FixError(f"The model's answer did not match the expected format ({field}: {first['type']}).") from None
    summary = clean_text(parsed.summary)
    if not summary:
        raise FixError("The model's answer has an empty summary.")
    solutions = clean_lines(parsed.solutions)
    return OtherAdvice(
        kind=kind,  # type: ignore[arg-type]
        status="solution_options" if solutions else "mitigations_only",
        summary=summary,
        solutions=solutions,
        mitigations=clean_lines(parsed.mitigations),
        risk_notes=clean_text(parsed.risk_notes),
    )
