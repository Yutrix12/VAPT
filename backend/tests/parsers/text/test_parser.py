"""Tests for app/parsers/text/: Trivy's text (table) output (upgrade step U3b).

Small tables are drawn by tests/support/trivy_tables.py. The tests against
real Trivy output need the sample tables (see tests/support/reports.py) and
are skipped with a reason when they are missing. Facts: trivy-formats skill.
"""

import codecs
import json
import unittest
from dataclasses import asdict

from app.parsers import SUPPORTED_FORMATS, parse_report_file
from app.parsers.models import ReportError
from app.parsers.text.parser import parse_report_text
from tests.support.trivy_tables import (
    LICENSE_HEADER,
    VULN_HEADER,
    box,
    misconfig_block,
    secret_block,
    section,
    summary,
    totals,
)

URL = "https://avd.aquasec.com/nvd/"


def vulnerabilities(*rows: list, heading: str = "Python (python-pkg)", **counts: int) -> str:
    """A text report with one vulnerability section."""
    return section(heading, totals(**counts), box(VULN_HEADER, rows))


def parse(text: str, name: str = "report.txt"):
    return parse_report_text(name, text.encode("utf-8"), text)


MERGED = vulnerabilities(
    ["curl", "CVE-1", "HIGH", "fixed", "7.0", "7.1", ["curl: a bug", URL + "cve-1"]],
    [None, "CVE-2", None, None, None, None, ["curl: another bug", URL + "cve-2"]],
    ["wheel (METADATA)", "CVE-3", "LOW", "", "0.45", "", ["wheel: a bug", URL + "cve-3"]],
    high=2, low=1,
)


class VulnerabilityTableTest(unittest.TestCase):
    """Merged cells are followed; every row gets its own values."""

    def test_merged_cells_carry_their_value_down(self) -> None:
        report = parse(MERGED)
        rows = [(f.pkg_name, f.vuln_id, f.severity, f.status, f.installed_version, f.fixed_version)
                for f in report.findings]
        self.assertEqual(rows, [
            ("curl", "CVE-1", "HIGH", "fixed", "7.0", "7.1"),
            ("curl", "CVE-2", "HIGH", "fixed", "7.0", "7.1"),
            ("wheel", "CVE-3", "LOW", "unknown", "0.45", None),
        ])

    def test_title_and_url_are_split_and_the_target_is_the_heading(self) -> None:
        first = parse(MERGED).findings[0]
        self.assertEqual((first.title, first.primary_url), ("curl: a bug", URL + "cve-1"))
        self.assertEqual(first.target, "Python")

    def test_same_id_in_two_libraries_is_two_findings(self) -> None:
        text = vulnerabilities(
            ["curl", "CVE-9", "LOW", "affected", "7.0", "", "same CVE"],
            ["libcurl4", None, None, None, None, None, "same CVE again"],
            low=2,
        )
        self.assertEqual([(f.pkg_name, f.vuln_id, f.severity) for f in parse(text).findings],
                         [("curl", "CVE-9", "LOW"), ("libcurl4", "CVE-9", "LOW")])

    def test_wrapped_cells_are_joined(self) -> None:
        text = vulnerabilities(
            ["libxml2", "CVE-5", "HIGH", "fixed", "2.9",
             ["2.9.1+deb12u2,", "2.9.1+deb12u3"],
             ["a long title that Trivy", "cut ...", "https://security-tracker.example/", "tracker/CVE-5"]],
            high=1,
        )
        finding = parse(text).findings[0]
        self.assertEqual(finding.fixed_version, "2.9.1+deb12u2, 2.9.1+deb12u3")
        self.assertEqual(finding.title, "a long title that Trivy cut ...")
        self.assertEqual(finding.primary_url, "https://security-tracker.example/tracker/CVE-5")

    def test_os_heading_is_the_whole_target(self) -> None:
        text = vulnerabilities(["apt", "CVE-1", "HIGH", "fixed", "1", "2", "t"],
                               heading="python:3.9-slim (debian 13.1)", high=1)
        self.assertEqual(parse(text).findings[0].target, "python:3.9-slim (debian 13.1)")

    def test_summary_gives_the_exact_target_and_type(self) -> None:
        rows = [["Python", "python-pkg", "1", "-", "-", "-"],
                ["python:3.9-slim (debian 13.1)", "debian", "1", "-", "-", "-"]]
        text = summary(rows) + vulnerabilities(["a", "CVE-1", "HIGH", "fixed", "1", "2", "t"], high=1)
        text += vulnerabilities(["b", "CVE-2", "LOW", "fixed", "1", "2", "t"],
                                heading="python:3.9-slim (debian 13.1)", low=1)
        findings = parse(text).findings
        self.assertEqual([(f.target, f.vuln_type) for f in findings],
                         [("Python", "python-pkg"), ("python:3.9-slim (debian 13.1)", "debian")])

    def test_total_that_does_not_match_the_rows_is_refused(self) -> None:
        wrong = MERGED.replace("Total: 3 (UNKNOWN: 0, LOW: 1, MEDIUM: 0, HIGH: 2", "Total: 3 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 2")
        with self.assertRaises(ReportError) as caught:
            parse(wrong)
        self.assertIn("do not match", str(caught.exception))

    def test_fewer_rows_than_the_total_is_accepted_but_not_more(self) -> None:
        """Trivy draws an identical row as blank lines but still counts it."""
        fewer = MERGED.replace("HIGH: 2", "HIGH: 3").replace("Total: 3", "Total: 4")
        self.assertEqual(len(parse(fewer).findings), 3)
        more = MERGED.replace("HIGH: 2", "HIGH: 1").replace("Total: 3", "Total: 2")
        with self.assertRaises(ReportError):
            parse(more)

    def test_unknown_columns_are_refused(self) -> None:
        text = section("X (pip)", totals(low=1), box(["Foo", "Bar"], [["a", "b"]]))
        with self.assertRaises(ReportError):
            parse(text)


class ReportFieldsTest(unittest.TestCase):
    """What the table does not carry is named, never guessed."""

    def test_format_and_missing_fields(self) -> None:
        report = parse(MERGED)
        self.assertEqual(report.report_format, "Trivy text (table)")
        for field in ("trivy_version", "created_at", "artifact_name", "artifact_type", "os", "git",
                      "cvss_score", "published_date", "full_titles", "misconfiguration_title"):
            self.assertIn(field, report.not_in_format)
        self.assertIsNone(report.created_at)
        self.assertIsNone(report.artifact_name)
        self.assertIsNone(report.findings[0].cvss_score)
        self.assertEqual(report.findings[0].fingerprint, "")  # class is missing: "not in this format"

    def test_hash_and_name_come_from_the_file(self) -> None:
        report = parse_report_text("r.txt", b"abc", MERGED)
        self.assertEqual(report.file_name, "r.txt")
        self.assertEqual(report.file_sha256,
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


class OtherKindsTest(unittest.TestCase):
    CODE = ["   3 [ TOKEN=NOT-A-REAL-SECRET-VALUE-1234", "   4   echo done"]

    def test_misconfigurations_passed_count_and_ignored_code(self) -> None:
        block = misconfig_block("DS-0002", "HIGH", "Specify a USER, not ENV TOKEN=NOT-A-REAL-TOKEN-1234",
                                "Running as root is risky.", "https://avd.aquasec.com/misconfig/ds-0002",
                                code=["   3 [ ENV PASSWORD=NOT-A-REAL-PASSWORD-1234"])
        text = section("Dockerfile (dockerfile)",
                       "Tests: 27 (SUCCESSES: 26, FAILURES: 1)\nFailures: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)\n",
                       block)
        report = parse(text)
        self.assertEqual(report.misconfig_passed, 26)
        (item,) = report.misconfigurations
        self.assertEqual((item.check_id, item.severity, item.target, item.status),
                         ("DS-0002", "HIGH", "Dockerfile", "FAIL"))
        self.assertIsNone(item.title)  # the text after the colon is a Message: never kept
        self.assertEqual(item.description, "Running as root is risky.")
        self.assertEqual(item.primary_url, "https://avd.aquasec.com/misconfig/ds-0002")
        self.assertIsNone(item.resolution)
        self.assertNotIn("NOT-A-REAL-PASSWORD", json.dumps(asdict(report)))
        self.assertNotIn("NOT-A-REAL-TOKEN", json.dumps(asdict(report)))

    def test_empty_description_is_none(self) -> None:
        block = misconfig_block("DS-0026", "LOW", "", "", "https://avd.aquasec.com/misconfig/ds-0026")
        text = section("Dockerfile (dockerfile)", "Tests: 1 (SUCCESSES: 0, FAILURES: 1)\n", block)
        (item,) = parse(text).misconfigurations
        self.assertEqual((item.title, item.description), (None, None))
        self.assertEqual(item.primary_url, "https://avd.aquasec.com/misconfig/ds-0026")

    def test_failure_count_must_match(self) -> None:
        text = section("Dockerfile (dockerfile)", "Tests: 2 (SUCCESSES: 0, FAILURES: 2)\n",
                       misconfig_block("DS-0002", "HIGH", "t", "d", "https://x.example/"))
        with self.assertRaises(ReportError):
            parse(text)

    def test_secret_value_never_leaves_the_parser(self) -> None:
        block = secret_block("CRITICAL", "AWS", "aws-access-key-id", "AWS Access Key ID",
                             "deploy.sh:3 (offset: 36 bytes)", self.CODE)
        text = section("deploy.sh (secrets)", totals(critical=1), block)
        report = parse(text)
        (item,) = report.secrets
        self.assertEqual((item.rule_id, item.category, item.severity, item.title, item.target),
                         ("aws-access-key-id", "AWS", "CRITICAL", "AWS Access Key ID", "deploy.sh"))
        self.assertEqual((item.start_line, item.end_line), (3, 3))
        self.assertNotIn("NOT-A-REAL-SECRET", json.dumps(asdict(report)))

    def test_secret_without_a_location_has_no_lines(self) -> None:
        text = section("app/settings.py (secrets)", totals(critical=1),
                       secret_block("CRITICAL", "Synthetic", "synthetic-key", "Synthetic secret"))
        (item,) = parse(text).secrets
        self.assertEqual((item.start_line, item.end_line), (None, None))

    def test_two_secrets_and_a_line_range(self) -> None:
        text = section("a.sh (secrets)", totals(high=2),
                       secret_block("HIGH", "Custom", "one", "One", "a.sh:7-9 (offset: 1 bytes)", self.CODE)
                       + secret_block("HIGH", "Custom", "two", "Two", "a.sh:20", self.CODE))
        self.assertEqual([(s.rule_id, s.start_line, s.end_line) for s in parse(text).secrets],
                         [("one", 7, 9), ("two", 20, 20)])

    def test_licenses_follow_merged_classification(self) -> None:
        rows = [["org.a:a", "EPL-1.0", "reciprocal", "MEDIUM"],
                ["org.b:b", "BSD-3-Clause", "notice", "LOW"],
                ["org.c:c", "MIT License", None, None]]
        text = section("Java (license)", totals(medium=1, low=2), box(LICENSE_HEADER, rows))
        report = parse(text)
        self.assertEqual([(x.pkg_name, x.name, x.category, x.severity, x.license_class)
                          for x in report.licenses],
                         [("org.a:a", "EPL-1.0", "reciprocal", "MEDIUM", "license"),
                          ("org.b:b", "BSD-3-Clause", "notice", "LOW", "license"),
                          ("org.c:c", "MIT License", "notice", "LOW", "license")])
        self.assertEqual(report.licenses[0].target, "Java")


class DetectionTest(unittest.TestCase):
    """parse_report_file finds a text report from its content."""

    def test_text_is_detected_whatever_the_name(self) -> None:
        report = parse_report_file("scan.json", MERGED.encode("utf-8"))
        self.assertEqual((report.report_format, len(report.findings)), ("Trivy text (table)", 3))

    def test_powershell_utf16_is_read(self) -> None:
        for raw in (codecs.BOM_UTF16_LE + MERGED.encode("utf-16-le"),
                    codecs.BOM_UTF8 + MERGED.encode("utf-8"),
                    MERGED.replace("\n", "\r\n").encode("utf-8")):
            self.assertEqual(len(parse_report_file("x", raw).findings), 3)

    def test_report_summary_alone_is_an_empty_report(self) -> None:
        text = summary([["Python", "python-pkg", "0", "-", "-", "-"]])
        report = parse_report_file("x.txt", text.encode("utf-8"))
        self.assertEqual((len(report.findings), report.report_format), (0, "Trivy text (table)"))

    def test_old_ascii_tables_and_other_text_are_not_supported(self) -> None:
        ascii_table = "Python (python-pkg)\n===================\nTotal: 1 (LOW: 1)\n\n+---+---+\n| a | b |\n+---+---+\n"
        for raw in (ascii_table.encode(), b"hello world", b"", "text\x00bad".encode()):
            with self.subTest(raw=raw[:20]), self.assertRaises(ReportError) as caught:
                parse_report_file("x.txt", raw)
            self.assertIn("not a supported Trivy report", str(caught.exception))
            self.assertIn("Trivy text (table)", str(caught.exception))

    def test_supported_formats_list_the_text_format(self) -> None:
        self.assertEqual(SUPPORTED_FORMATS, ("Trivy JSON", "Trivy text (table)"))


if __name__ == "__main__":
    unittest.main()
