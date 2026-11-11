"""Tests for app/analysis/grouping.py: package groups are ranked by severity."""

import unittest

from app.analysis.grouping import group_by_package
from app.parsers.json.parser import parse_report_bytes
from tests.support.trivy_json import as_bytes, small_report


class GroupRankingTest(unittest.TestCase):
    """A package group is ranked by its highest severity; UNKNOWN comes last."""

    def test_groups_rank_rated_findings_before_unknown_ones(self) -> None:
        report = small_report()
        vulns = report["Results"][0]["Vulnerabilities"]
        template = vulns[0]
        vulns[:] = [
            # "demo": one LOW and one UNKNOWN finding -> its worst is LOW.
            {**template, "VulnerabilityID": "CVE-1", "Severity": "LOW"},
            {**template, "VulnerabilityID": "CVE-2", "Severity": "UNKNOWN"},
            # "other": three UNKNOWN findings -> listed after "demo",
            # although it has more findings.
            *({**template, "PkgName": "other", "VulnerabilityID": f"CVE-{i}",
               "Severity": "UNKNOWN"} for i in (3, 4, 5)),
        ]
        groups = group_by_package(parse_report_bytes("r.json",
                                                     as_bytes(report)))
        self.assertEqual([(g.pkg_name, g.worst_severity) for g in groups],
                         [("demo", "LOW"), ("other", "UNKNOWN")])


if __name__ == "__main__":
    unittest.main()
