"""Count the findings of a report."""

from collections import Counter
from typing import Any

from app.analysis.grouping import GroupKey, group_key
from app.parsers.common import SEVERITIES
from app.parsers.models import Report


def summarize(report: Report) -> dict[str, Any]:
    """Count the findings of one report in a single pass.

    "unique_vuln_ids" counts every distinct vulnerability ID: CVE- and also
    GHSA-, DSA- or TEMP- IDs. A package is one (target, name, installed
    version), the same key the package groups use.
    """
    severity_counts = dict.fromkeys(SEVERITIES, 0)
    status_counts: Counter[str] = Counter()
    vuln_ids: set[str] = set()
    packages: set[GroupKey] = set()
    fingerprints: set[str] = set()
    without_fixed_version = 0
    for finding in report.findings:
        severity_counts[finding.severity] += 1
        status_counts[finding.status] += 1
        if finding.vuln_id is not None:
            vuln_ids.add(finding.vuln_id)
        if finding.pkg_name is not None:
            packages.add(group_key(finding))
        fingerprints.add(finding.fingerprint)
        if finding.fixed_version is None:
            without_fixed_version += 1
    return {
        "total": len(report.findings),
        "by_severity": severity_counts,
        "by_status": dict(status_counts.most_common()),
        "unique_vuln_ids": len(vuln_ids),
        "unique_packages": len(packages),
        "without_fixed_version": without_fixed_version,
        "distinct_fingerprints": len(fingerprints),
        # The other finding kinds (U2). The keys above count vulnerabilities
        # only, so their expected numbers never change.
        "by_kind": {
            "vulnerability": len(report.findings),
            "misconfiguration": len(report.misconfigurations),
            "secret": len(report.secrets),
            "license": len(report.licenses),
        },
        "misconfig_passed": report.misconfig_passed,
        "misconfig_exceptions": report.misconfig_exceptions,
    }
