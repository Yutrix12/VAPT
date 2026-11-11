"""The objects a parsed Trivy report is made of (same for every format)."""

from dataclasses import dataclass


class ReportError(Exception):
    """A file cannot be used as a Trivy JSON report (bad input, not a bug)."""


@dataclass(frozen=True)
class Finding:
    """One vulnerability row: one vulnerability ID in one package."""

    fingerprint: str
    target: str
    vuln_class: str | None
    vuln_type: str | None
    vuln_id: str | None
    pkg_name: str | None
    installed_version: str | None
    fixed_version: str | None
    status: str
    severity: str
    title: str | None
    cvss_score: float | None
    primary_url: str | None
    published_date: str | None


@dataclass(frozen=True)
class Misconfiguration:
    """One failed configuration check (Status FAIL) in one file.

    Its Message and code lines are never kept: they can quote a credential.
    """

    fingerprint: str
    target: str
    misconf_type: str | None  # the result's Type, e.g. "dockerfile"
    check_type: str | None  # e.g. "Dockerfile Security Check"
    check_id: str | None  # ID, or the older AVDID when ID is missing
    title: str | None
    description: str | None
    resolution: str | None  # Trivy's own fix text; None if not in the report
    severity: str
    status: str
    primary_url: str | None
    references: tuple[str, ...]
    resource: str | None
    start_line: int | None  # optional (rule o)
    end_line: int | None


@dataclass(frozen=True)
class Secret:
    """Where a secret was found. The secret value itself is never kept."""

    fingerprint: str
    target: str
    rule_id: str | None
    category: str | None
    severity: str
    title: str | None
    start_line: int | None
    end_line: int | None


@dataclass(frozen=True)
class License:
    """One license of a package (PkgName) or found in a file (FilePath)."""

    fingerprint: str
    target: str
    license_class: str | None  # "license" or "license-file"
    pkg_name: str | None
    file_path: str | None
    name: str | None
    category: str | None
    severity: str
    confidence: float | None  # 0.0 to 1.0
    link: str | None


@dataclass(frozen=True)
class Report:
    """One parsed report. Git author, committer and message are never kept,
    and neither are secret values or misconfiguration code lines."""

    file_name: str
    file_sha256: str
    report_format: str  # e.g. "Trivy JSON", detected from the content (U3)
    not_in_format: tuple[str, ...]  # fields this format does not carry
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
    findings: tuple[Finding, ...]  # the vulnerabilities
    misconfigurations: tuple[Misconfiguration, ...]  # Status FAIL only
    secrets: tuple[Secret, ...]
    licenses: tuple[License, ...]
    misconfig_passed: int  # checks that passed (rule m): counted, not listed
    misconfig_exceptions: int  # checks with Status EXCEPTION: counted only

    @property
    def misconfig_count(self) -> int:
        """Listed (failed) misconfigurations; the page shows it until U5."""
        return len(self.misconfigurations)

    @property
    def secret_count(self) -> int:
        """Secrets found; the page shows it until U5."""
        return len(self.secrets)


@dataclass(frozen=True)
class PackageGroup:
    """All findings for one installed package version in one target."""

    target: str
    pkg_name: str | None
    installed_version: str | None
    finding_count: int
    worst_severity: str
    fixed_versions: tuple[str, ...]
    has_unfixed: bool
