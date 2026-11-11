"""Tests for app/analysis/: summary and package groups of the real reports.

Needs image.json and fs.json (see tests/support/reports.py); skipped with a
reason when they are missing. Expected numbers: trivy-report-format skill.
"""

import unittest

from app.analysis.grouping import group_by_package
from app.analysis.summary import summarize
from app.parsers.common import severity_sort_key
from app.parsers.json.parser import parse_report
from tests.support.reports import FS_JSON, IMAGE_JSON, REAL_REPORTS_FOUND, SKIP_REASON


@unittest.skipUnless(REAL_REPORTS_FOUND, SKIP_REASON)
class RealReportsAnalysisTest(unittest.TestCase):
    """Every expected number for image.json and fs.json."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.image = parse_report(IMAGE_JSON)
        cls.fs = parse_report(FS_JSON)

    def test_image_summary(self) -> None:
        self.assertEqual(summarize(self.image), {
            "total": 492,
            "by_severity": {"CRITICAL": 6, "HIGH": 126, "MEDIUM": 193,
                            "LOW": 158, "UNKNOWN": 9},
            "by_status": {"fixed": 306, "affected": 184, "fix_deferred": 2},
            "unique_vuln_ids": 208,
            "unique_packages": 54,
            "without_fixed_version": 186,
            "distinct_fingerprints": 491,
            "by_kind": {"vulnerability": 492, "misconfiguration": 0,
                        "secret": 0, "license": 0},
            "misconfig_passed": 0,
            "misconfig_exceptions": 0,
        })

    def test_image_groups(self) -> None:
        groups = group_by_package(self.image)
        self.assertEqual(len(groups), 54)
        counts = {g.pkg_name: g.finding_count for g in groups}
        # Each name is one group here, so the lookup below is unambiguous.
        self.assertEqual(len(counts), 54)
        expected = [("libssl3t64", 57), ("openssl", 57),
                    ("openssl-provider-legacy", 57), ("libc-bin", 30),
                    ("libc6", 30), ("perl-base", 18)]
        for pkg, want in expected:
            with self.subTest(package=pkg):
                self.assertEqual(counts[pkg], want)

    def test_image_groups_worst_first_then_most_findings(self) -> None:
        groups = group_by_package(self.image)
        order = [(severity_sort_key(g.worst_severity), -g.finding_count)
                 for g in groups]
        self.assertEqual(order, sorted(order))
        self.assertEqual((groups[0].worst_severity, groups[0].finding_count),
                         ("CRITICAL", 57))

    def test_fs_single_group(self) -> None:
        groups = group_by_package(self.fs)
        self.assertEqual(len(groups), 1)
        g = groups[0]
        self.assertEqual(
            (g.pkg_name, g.installed_version, g.finding_count),
            ("pypdf", "6.19.0", 18))
        self.assertEqual(
            g.fixed_versions,
            ("6.20.0", "6.20.1", "6.21.0", "6.21.1", "6.21.2", "6.21.3",
             "6.21.4"))
        self.assertFalse(g.has_unfixed)


if __name__ == "__main__":
    unittest.main()
