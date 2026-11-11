"""Check the model's answer. The code, not the model, decides what is a fix."""

from typing import Any

from pydantic import ValidationError

from app.fixes.commands import is_unsafe_command
from app.fixes.prompts import cves_without_fix
from app.fixes.schemas import FixAdvice, FixAnswer, FixGroup, FixStatus
from app.llm.client import strip_control_chars


class FixError(Exception):
    """The model's answer cannot be used."""


def clean_text(text: str) -> str:
    """Model text without control characters (line breaks and tabs stay)."""
    return strip_control_chars(text, keep="\n\t").strip()


def clean_lines(texts: list[str]) -> list[str]:
    """Each text cleaned; empty ones dropped."""
    return [text for text in map(clean_text, texts) if text]


def trivy_versions(fixed_versions: list[str]) -> set[str]:
    """Every version Trivy lists, also each part of a "1.2, 2.0" list."""
    versions = set(fixed_versions)
    for text in fixed_versions:
        versions.update(part.strip() for part in text.split(","))
    return versions - {""}


def decide_status(version: str | None, group: FixGroup) -> FixStatus:
    """The code, not the model, decides whether a version is a fix."""
    if not group.fixed_versions:
        return "no_fix_available"
    if not version:
        return "no_version_suggested"
    if version in trivy_versions(group.fixed_versions):
        return "verified"
    return "unverified"


def validate_answer(answer: dict[str, Any], group: FixGroup) -> FixAdvice:
    """Check the model's answer and decide, in code, what counts as a fix."""
    try:
        parsed = FixAnswer.model_validate(answer)
    except ValidationError as error:
        first = error.errors()[0]
        field = ".".join(str(part) for part in first["loc"]) or "answer"
        # The message names the field and the problem, not the model's text.
        raise FixError(f"The model's answer did not match the expected "
                       f"format ({field}: {first['type']}).") from None

    summary = clean_text(parsed.summary)
    if not summary:
        raise FixError("The model's answer has an empty summary.")
    version = clean_text(parsed.target_version or "") or None
    status = decide_status(version, group)
    commands = clean_lines(parsed.commands)
    # A command with a flag that skips a safety check is never shown as recommended.
    safe_commands = [command for command in commands if not is_unsafe_command(command)]
    return FixAdvice(
        status=status,
        target_version=version if status == "verified" else None,
        # With no fix at all, a version from the model is not shown.
        unverified_version=version if status == "unverified" else None,
        trivy_fixed_versions=group.fixed_versions,
        mitigation_only=not group.fixed_versions,
        cves_without_fix=cves_without_fix(group),
        summary=summary,
        solutions=clean_lines(parsed.solutions),
        mitigations=clean_lines(parsed.mitigations),
        commands=safe_commands,
        unsafe_commands_removed=len(commands) - len(safe_commands),
        risk_notes=clean_text(parsed.risk_notes),
    )
