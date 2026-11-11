"""The shapes of the API answers (what the page receives)."""

from pydantic import BaseModel, ConfigDict

from app.parsers.models import Finding


class ReportDetails(BaseModel):
    """What was scanned. Git author, committer and message are never here."""

    model_config = ConfigDict(from_attributes=True)

    file_name: str
    file_sha256: str
    report_format: str
    not_in_format: list[str]
    schema_version: int | None
    trivy_version: str | None
    created_at: str | None
    artifact_name: str | None
    artifact_type: str | None
    os_family: str | None
    os_name: str | None
    repo_url: str | None
    branch: str | None
    commit: str | None
    misconfig_count: int
    secret_count: int


class Summary(BaseModel):
    """The counts from app.analysis.summary.summarize()."""

    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    unique_vuln_ids: int
    unique_packages: int
    without_fixed_version: int
    distinct_fingerprints: int
    by_kind: dict[str, int]
    misconfig_passed: int
    misconfig_exceptions: int


class MisconfigurationOut(BaseModel):
    """One failed configuration check. No Message or code lines (they can quote a credential)."""

    model_config = ConfigDict(from_attributes=True)

    fingerprint: str
    target: str
    misconf_type: str | None
    check_type: str | None
    check_id: str | None
    title: str | None
    description: str | None
    resolution: str | None
    severity: str
    status: str
    primary_url: str | None
    references: list[str]
    resource: str | None
    start_line: int | None
    end_line: int | None


class SecretOut(BaseModel):
    """Where a secret is. This model has no field for its value (rule n)."""

    model_config = ConfigDict(from_attributes=True)

    fingerprint: str
    target: str
    rule_id: str | None
    category: str | None
    severity: str
    title: str | None
    start_line: int | None
    end_line: int | None


class LicenseOut(BaseModel):
    """One license of a package or found in a file."""

    model_config = ConfigDict(from_attributes=True)

    fingerprint: str
    target: str
    license_class: str | None
    pkg_name: str | None
    file_path: str | None
    name: str | None
    category: str | None
    severity: str
    confidence: float | None
    link: str | None


class FixCommandOut(BaseModel):
    """One block of built commands: the lines, and the fixed version they are for (if several)."""

    label: str | None
    lines: list[str]


class PackageGroupOut(BaseModel):
    """One package group with the findings that belong to it."""

    model_config = ConfigDict(from_attributes=True)

    target: str
    pkg_name: str | None
    installed_version: str | None
    finding_count: int
    worst_severity: str
    fixed_versions: list[str]
    has_unfixed: bool
    findings: list[Finding]
    fix_commands: list[FixCommandOut]  # built by code from Trivy's fixed versions
    fix_commands_note: str | None  # why there is no command, or what to know about them


class AnalyzeResponse(BaseModel):
    """Everything the results page shows for one report."""

    report: ReportDetails
    summary: Summary
    package_groups: list[PackageGroupOut]
    misconfigurations: list[MisconfigurationOut]
    secrets: list[SecretOut]
    licenses: list[LicenseOut]
    secret_fix_steps: list[str]  # the same fixed steps for every secret


class LLMStatus(BaseModel):
    """Answer of "Check connection": the backend's own LLM, never its key."""

    model: str
    model_found: bool
    leaves_this_computer: bool  # the page then warns which data is sent
