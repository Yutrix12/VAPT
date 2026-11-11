"""The shapes of the fix request, the model's answer and the checked advice."""

from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator

from app.parsers.common import SEVERITIES

MAX_COMMANDS = 5
MAX_STEPS = 5  # solutions and mitigations, each
DISCLAIMER = "AI suggestion: verify before applying"
FixStatus = Literal["verified", "unverified", "no_version_suggested",
                    "no_fix_available"]


class CveIn(BaseModel):
    """One vulnerability of the group, as the page sends it."""

    vuln_id: str = Field(max_length=100)
    severity: str
    # Long enough for real titles; the prompt cuts them to 120 anyway.
    title: str | None = Field(default=None, max_length=10_000)
    fixed_version: str | None = Field(default=None, max_length=500)

    @field_validator("severity")
    @classmethod
    def known_severity(cls, value: str) -> str:
        """Only the parser's severities (CRITICAL ... UNKNOWN)."""
        if value not in SEVERITIES:
            raise ValueError(f"must be one of {', '.join(SEVERITIES)}")
        return value


class FixGroup(BaseModel):
    """One package group, as the page got it from /api/analyze."""

    target: str = Field(max_length=2000)  # not sent to the LLM
    pkg_name: str | None = Field(default=None, max_length=500)
    installed_version: str | None = Field(default=None, max_length=200)
    ecosystem: str | None = Field(default=None, max_length=100)
    os: str | None = Field(default=None, max_length=100)
    # A Go stdlib group can have hundreds of fixed versions; each one is
    # short, so long strings are refused.
    fixed_versions: list[Annotated[str, Field(max_length=500)]] = Field(
        max_length=1000)
    cves: list[CveIn] = Field(max_length=5000)


class FixAnswer(BaseModel):
    """Fix advice for one vulnerable package."""

    # Pydantic puts the docstring above into the JSON schema that is sent
    # to the model, so it describes the answer, not the code.

    summary: str = Field(max_length=2000)
    solutions: list[Annotated[str, Field(max_length=1000)]] = Field(
        max_length=MAX_STEPS, description="Concrete options that remove the problem.")
    mitigations: list[Annotated[str, Field(max_length=1000)]] = Field(
        max_length=MAX_STEPS, description="Steps that reduce the risk until a fix exists.")
    target_version: str | None = Field(max_length=200)
    commands: list[str] = Field(max_length=MAX_COMMANDS)
    risk_notes: str = Field(max_length=2000)


class FixAdvice(BaseModel):
    """The checked advice the page shows."""

    status: FixStatus
    target_version: str | None  # set only when verified
    unverified_version: str | None  # a version Trivy does not list
    trivy_fixed_versions: list[str]
    mitigation_only: bool
    cves_without_fix: int  # still open after any upgrade
    summary: str
    solutions: list[str]  # options that remove the problem
    mitigations: list[str]  # steps that reduce the risk until a fix exists
    commands: list[str]  # the AI's own: the page labels them "AI-suggested, verify before running"
    unsafe_commands_removed: int = 0  # AI commands dropped for a flag that skips a safety check
    risk_notes: str
    disclaimer: str = DISCLAIMER


FIX_SCHEMA = FixAnswer.model_json_schema()
