"""Tests for app/parsers/json/parser.py: the rules and the real reports.

The real-report tests need image.json and fs.json (see tests/support/reports.py)
and are skipped with a reason when they are missing. Expected numbers are
fixed in the tests.
"""

import unittest

from app.analysis.summary import summarize
from app.parsers.json.loader import decode_report_json
from app.parsers.json.parser import parse_report, parse_report_bytes
from tests.support.reports import FS_JSON, IMAGE_JSON, REAL_REPORTS_FOUND, SKIP_REASON
from tests.support.trivy_json import as_bytes, small_report


DEBIAN_TARGET = "python:3.9-slim (debian 13.1)"


class RulesTest(unittest.TestCase):
    """Rules a-d, g and l."""

    def first_finding(self, report: dict):
        return parse_report_bytes("r.json", as_bytes(report)).findings[0]

    def test_missing_fields_get_defaults(self) -> None:
        report = small_report()
        vuln = report["Results"][0]["Vulnerabilities"][0]
        del vuln["Status"], vuln["FixedVersion"]
        vuln["Severity"] = "weird"
        finding = self.first_finding(report)
        self.assertEqual(finding.status, "unknown")
        self.assertIsNone(finding.fixed_version)
        self.assertEqual(finding.severity, "UNKNOWN")

    def test_null_vulnerabilities_is_empty(self) -> None:
        report = small_report()
        report["Results"][0]["Vulnerabilities"] = None
        parsed = parse_report_bytes("r.json", as_bytes(report))
        self.assertEqual(parsed.findings, ())

    def test_cvss_prefers_highest_v3_then_v2(self) -> None:
        report = small_report()
        report["Results"][0]["Vulnerabilities"][0]["CVSS"] = {
            "nvd": {"V2Score": 9.0, "V3Score": 5.5},
            "redhat": {"V3Score": 7.5},
        }
        self.assertEqual(self.first_finding(report).cvss_score, 7.5)

    def test_git_personal_data_is_dropped_at_load(self) -> None:
        person = "Some Person <person@example.invalid>"
        raw = as_bytes(small_report(
            RepoURL="https://example.invalid/repo.git", Branch="main",
            Commit="abc123", CommitMsg="secret message",
            Author=person, Committer=person,
        ))
        metadata = decode_report_json(raw)["Metadata"]
        for key in ("CommitMsg", "Author", "Committer"):
            with self.subTest(field=key):
                self.assertNotIn(key, metadata)
        report = parse_report_bytes("r.json", raw)
        self.assertEqual(
            (report.repo_url, report.branch, report.commit),
            ("https://example.invalid/repo.git", "main", "abc123"))


@unittest.skipUnless(REAL_REPORTS_FOUND, SKIP_REASON)
class RealReportsTest(unittest.TestCase):
    """Every expected number for image.json and fs.json."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.image = parse_report(IMAGE_JSON)
        cls.fs = parse_report(FS_JSON)

    def test_image_report_details(self) -> None:
        r = self.image
        self.assertEqual(
            (r.artifact_name, r.artifact_type, r.trivy_version),
            ("python:3.9-slim", "container_image", "0.76.2"))
        self.assertEqual((r.os_family, r.os_name), ("debian", "13.1"))
        self.assertEqual((r.repo_url, r.branch, r.commit), (None, None, None))

    def test_image_findings_per_target(self) -> None:
        targets = [f.target for f in self.image.findings]
        self.assertEqual(len(targets), 492)
        self.assertEqual(targets.count(DEBIAN_TARGET), 480)
        self.assertEqual(targets.count("Python"), 12)

    def test_image_duplicate_row_is_kept(self) -> None:
        duplicate = ("Python", "wheel", "0.45.1", "CVE-2026-24049")
        rows = [f for f in self.image.findings
                if (f.target, f.pkg_name, f.installed_version, f.vuln_id)
                == duplicate]
        self.assertEqual(len(rows), 2)

    def test_fs_report(self) -> None:
        r = self.fs
        self.assertEqual(r.artifact_type, "repository")
        self.assertEqual((r.os_family, r.os_name), (None, None))
        self.assertEqual(
            (r.repo_url, r.branch, r.commit),
            ("https://github.com/Yutrix12/AI-Mock-interviewer.git", "main",
             "b8105d37a9be7d95d1d2e71f9ff4302264ef69a7"))
        targets = {f.target for f in r.findings}
        self.assertEqual(targets, {"backend/requirements.txt"})
        summary = summarize(r)
        self.assertEqual(summary["total"], 18)
        self.assertEqual(summary["by_severity"],
                         {"CRITICAL": 0, "HIGH": 10, "MEDIUM": 7, "LOW": 1,
                          "UNKNOWN": 0})
        self.assertEqual(summary["by_status"], {"fixed": 18})
        self.assertEqual(summary["unique_packages"], 1)
        self.assertEqual(summary["distinct_fingerprints"], 18)


if __name__ == "__main__":
    unittest.main()
