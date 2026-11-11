"""Group the vulnerabilities of a report by package, most severe first."""

from app.parsers.common import severity_sort_key
from app.parsers.models import Finding, PackageGroup, Report

# What makes one package group: (target, package name, installed version).
GroupKey = tuple[str, str | None, str | None]


def group_key(item: Finding | PackageGroup) -> GroupKey:
    """The package group of a finding (or the key of a group itself)."""
    return (item.target, item.pkg_name, item.installed_version)


def make_group(findings: list[Finding]) -> PackageGroup:
    """Build one PackageGroup from findings that share target and package."""
    first = findings[0]
    # Plain text sort of distinct values: versions are never compared as
    # versions (rule k), so "6.10" sorts before "6.9".
    fixed_versions = sorted(
        {f.fixed_version for f in findings if f.fixed_version is not None}
    )
    return PackageGroup(
        target=first.target,
        pkg_name=first.pkg_name,
        installed_version=first.installed_version,
        finding_count=len(findings),
        worst_severity=min((f.severity for f in findings),
                           key=severity_sort_key),
        fixed_versions=tuple(fixed_versions),
        has_unfixed=any(f.fixed_version is None for f in findings),
    )


def group_sort_key(
    group: PackageGroup,
) -> tuple[tuple[int, int], int, str, str, str]:
    """Sort key: worst severity, then most findings, then names for ties."""
    return (
        severity_sort_key(group.worst_severity),
        -group.finding_count,
        group.target,
        group.pkg_name or "",
        group.installed_version or "",
    )


def findings_by_group(report: Report) -> dict[GroupKey, list[Finding]]:
    """The findings of each package group, in report order."""
    grouped: dict[GroupKey, list[Finding]] = {}
    for finding in report.findings:
        grouped.setdefault(group_key(finding), []).append(finding)
    return grouped


def group_by_package(report: Report) -> list[PackageGroup]:
    """Group findings by (target, package name, installed version).

    Sorted worst severity first, then by most findings. Ties are sorted by
    target, name and version so the order is always the same.
    """
    grouped = findings_by_group(report).values()
    groups = [make_group(findings) for findings in grouped]
    return sorted(groups, key=group_sort_key)
