"""The shapes for the AI explanation of misconfigurations, secrets and licenses.

Every request model forbids extra fields, so a secret's value, a
misconfiguration's message or its code lines can never travel to the model,
even if a page sent them (the secrets rule).
"""

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.fixes.schemas import DISCLAIMER, MAX_STEPS
from app.parsers.common import SEVERITIES


def check_severity(value: str) -> str:
    """Only the parser's severities (CRITICAL ... UNKNOWN)."""
    if value not in SEVERITIES:
        raise ValueError(f"must be one of {', '.join(SEVERITIES)}")
    return value


Severity = Annotated[str, AfterValidator(check_severity)]
Text = Annotated[str, Field(max_length=1000)]


class MisconfigurationIn(BaseModel):
    """A failed check: what is wrong and Trivy's own fix text. No message, no code lines."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["misconfiguration"]
    check_id: str | None = Field(default=None, max_length=100)
    title: Text | None = None
    description: str | None = Field(default=None, max_length=5000)
    resolution: str | None = Field(default=None, max_length=5000)
    severity: Severity
    misconf_type: str | None = Field(default=None, max_length=100)
    target: str = Field(max_length=2000)
    start_line: int | None = Field(default=None, ge=0, le=10_000_000)
    end_line: int | None = Field(default=None, ge=0, le=10_000_000)


class SecretIn(BaseModel):
    """Where a secret is. There is no field for its value."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["secret"]
    rule_id: str | None = Field(default=None, max_length=200)
    category: str | None = Field(default=None, max_length=200)
    severity: Severity
    title: Text | None = None
    target: str = Field(max_length=2000)
    start_line: int | None = Field(default=None, ge=0, le=10_000_000)
    end_line: int | None = Field(default=None, ge=0, le=10_000_000)


class LicenseIn(BaseModel):
    """One license of a package or found in a file."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["license"]
    name: str | None = Field(default=None, max_length=500)
    category: str | None = Field(default=None, max_length=100)
    license_class: str | None = Field(default=None, max_length=100)
    package: str | None = Field(default=None, max_length=500)  # the package, or the file
    severity: Severity


OtherFixRequest = Annotated[MisconfigurationIn | SecretIn | LicenseIn, Field(discriminator="kind")]


class OtherAnswer(BaseModel):
    """Advice for one finding that is not a vulnerable package."""

    # Pydantic puts the docstring above into the JSON schema that is sent to
    # the model, so it describes the answer, not the code.

    summary: str = Field(max_length=2000)
    solutions: list[Text] = Field(max_length=MAX_STEPS, description="Concrete options that remove the problem.")
    mitigations: list[Text] = Field(
        max_length=MAX_STEPS, description="Steps that reduce the risk until it is fixed.")
    risk_notes: str = Field(max_length=2000)


class OtherAdvice(BaseModel):
    """The checked advice the page shows for a finding that is not a vulnerable package."""

    kind: Literal["misconfiguration", "secret", "license"]
    status: Literal["solution_options", "mitigations_only"]  # decided by code from the answer
    summary: str
    solutions: list[str]
    mitigations: list[str]
    risk_notes: str
    disclaimer: str = DISCLAIMER


OTHER_FIX_SCHEMA = OtherAnswer.model_json_schema()
