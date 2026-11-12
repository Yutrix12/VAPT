"""Tests for app/parsers/text/: Trivy's text (table) output (upgrade step U3b).

Small tables are drawn by tests/support/trivy_tables.py. The tests against
real Trivy output need the sample tables (see tests/support/reports.py) and
are skipped with a reason when they are missing.
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
    SUMMARY_HEADER_NO_LICENSES,
    VULN_HEADER,
    box,
    misconfig_block,
    plain_misconfig_block,
    plain_secret_block,
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


def shorten_wide(text: str) -> str:
    """Draw wide (CJK) characters the way Trivy does: it pads by display width,
    so a line with N wide characters has N fewer padding spaces."""
    out = []
    for line in text.split("\n"):
        wide = sum(1 for char in line if "　" <= char <= "鿿")
        if wide and line.endswith(" │"):
            line = line[:-1 - wide] + "│"
        out.append(line)
    return "\n".join(out)


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

    def test_wide_characters_do_not_shift_the_columns(self) -> None:
        """Trivy pads by display width: a CJK character is 2 wide but 1 character."""
        text = vulnerabilities(
            ["curl", "CVE-1", "HIGH", "fixed", "7.0", "7.1", "漢字漢字 title"],
            ["zlib", "CVE-2", "LOW", "fixed", "1.0", "1.1", "a considerably longer title than the first one"],
            high=1, low=1,
        )
        shortened = shorten_wide(text)
        self.assertNotEqual(shortened, text)  # the test really draws a shorter line
        self.assertEqual([(f.pkg_name, f.title) for f in parse(shortened).findings],
                         [("curl", "漢字漢字 title"), ("zlib", "a considerably longer title than the first one")])

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

    def test_a_line_of_equals_signs_inside_a_description_is_not_a_heading(self) -> None:
        block = misconfig_block("DS-0002", "HIGH", "m", "Notes\n=========\nMore", "https://x.example/")
        text = section("Dockerfile (dockerfile)", "Tests: 1 (SUCCESSES: 0, FAILURES: 1)\n", block)
        (item,) = parse(text).misconfigurations
        self.assertEqual(item.description, "Notes ========= More")

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

    def test_a_block_without_a_rule_line_does_not_swallow_the_next_one(self) -> None:
        rule = "═" * 40
        body = (f"HIGH: Custom (one)\n{rule}\nOne\n\n"
                f"HIGH: Custom (two)\n{rule}\nTwo\n{'─' * 40}\n a.sh:3\n{'─' * 40}\n"
                "   3 [ SECRET-NOT-A-REAL-VALUE-1234\n" + "─" * 40 + "\n")
        report = parse(section("a.sh (secrets)", totals(high=2), body))
        self.assertEqual([(s.rule_id, s.title, s.start_line) for s in report.secrets],
                         [("one", "One", None), ("two", "Two", 3)])
        self.assertNotIn("SECRET-NOT-A-REAL", json.dumps(asdict(report)))

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


class SecondLayoutTest(unittest.TestCase):
    """The second layout of Trivy's table output (a file given by the owner)."""

    TOKEN = "TOKEN-NOT-A-REAL-SECRET-VALUE-1234"

    def test_summary_without_a_licenses_column_is_read(self) -> None:
        rows = [["Python", "python-pkg", "1", "-", "-"], ["deploy.sh", "secret", "-", "-", "1"]]
        text = summary(rows, SUMMARY_HEADER_NO_LICENSES) + vulnerabilities(
            ["a", "CVE-1", "HIGH", "fixed", "1", "2", "t"], high=1)
        text += section("deploy.sh", totals(high=1), plain_secret_block("HIGH", "Custom", "My Secret", "deploy.sh:7"))
        report = parse(text)
        self.assertEqual((len(report.findings), len(report.secrets)), (1, 1))
        self.assertEqual(report.findings[0].vuln_type, "python-pkg")  # the exact type, from the summary

    def test_a_blank_library_cell_means_the_package_above(self) -> None:
        text = vulnerabilities(
            ["openssl-libs", "CVE-1", "MEDIUM", "fixed", "1:1.0", "1:2.0", ["t", "-->avd.aquasec.com/nvd/cve-1"]],
            ["", "CVE-2", "LOW", "fixed", "1:1.0", "1:2.0", ["t", "-->avd.aquasec.com/nvd/cve-2"]],
            ["bash", "CVE-3", "LOW", "affected", "5.0", "", "t"], medium=1, low=2)
        self.assertEqual([(f.pkg_name, f.vuln_id) for f in parse(text).findings],
                         [("openssl-libs", "CVE-1"), ("openssl-libs", "CVE-2"), ("bash", "CVE-3")])

    def test_a_status_wrapped_inside_a_word_is_put_back_together(self) -> None:
        text = vulnerabilities(["bash", "CVE-1", "LOW", ["will_not", "_fix"], "4.2", "", "t"], low=1)
        self.assertEqual(parse(text).findings[0].status, "will_not_fix")

    def test_the_avd_link_without_a_scheme_gets_https_and_other_hosts_stay_empty(self) -> None:
        text = vulnerabilities(
            ["a", "CVE-1", "LOW", "fixed", "1", "2", ["title", "-->avd.aquasec.com/nvd/cve-1"]],
            ["b", "CVE-2", "LOW", "fixed", "1", "2", ["title", "-->evil.example/x"]],
            ["c", "CVE-3", "LOW", "fixed", "1", "2", ["title", "-->avd.aquasec.com.evil.example/x"]], low=3)
        urls = [(f.title, f.primary_url) for f in parse(text).findings]
        self.assertEqual(urls, [("title", "https://avd.aquasec.com/nvd/cve-1"), ("title", None), ("title", None)])

    def test_misconfiguration_without_an_id_is_read_and_its_message_is_dropped(self) -> None:
        block = plain_misconfig_block("HIGH", f"Specify a USER, not ENV TOKEN={self.TOKEN}", "Root is risky.",
                                      "https://avd.aquasec.com/misconfig/ds-0002")
        text = section("Dockerfile (dockerfile)", "Tests: 27 (SUCCESSES: 26, FAILURES: 1)\n", block)
        report = parse(text)
        (item,) = report.misconfigurations
        self.assertEqual((item.severity, item.check_id, item.title, item.description), ("HIGH", None, None, "Root is risky."))
        self.assertEqual(item.primary_url, "https://avd.aquasec.com/misconfig/ds-0002")
        self.assertEqual(report.misconfig_passed, 26)
        self.assertNotIn(self.TOKEN, json.dumps(asdict(report)))
        self.assertIn("check_id", report.not_in_format)

    def test_secret_with_the_category_in_brackets_has_no_rule_id_and_no_value(self) -> None:
        code = [f"   3 export KEY={self.TOKEN}", "   4"]
        block = plain_secret_block("CRITICAL", "AWS", "AWS Access Key ID", "deploy.sh:3", code)
        block += plain_secret_block("HIGH", "Custom", "My Secret", "deploy.sh:7", [f"   7 echo {self.TOKEN}"])
        report = parse(section("deploy.sh", totals(high=1, critical=1), block))
        self.assertEqual([(s.severity, s.category, s.title, s.rule_id, s.start_line) for s in report.secrets],
                         [("CRITICAL", "AWS", "AWS Access Key ID", None, 3), ("HIGH", "Custom", "My Secret", None, 7)])
        self.assertNotIn(self.TOKEN, json.dumps(asdict(report)))
        self.assertIn("rule_id", report.not_in_format)

    def test_the_first_layout_still_has_its_ids(self) -> None:
        report = parse(section("Dockerfile (dockerfile)", "Tests: 1 (SUCCESSES: 0, FAILURES: 1)\n",
                               misconfig_block("DS-0002", "HIGH", "m", "d", "https://x.example/")))
        self.assertNotIn("check_id", report.not_in_format)
        self.assertEqual(report.misconfigurations[0].check_id, "DS-0002")

    def test_the_count_check_still_refuses_a_missing_block(self) -> None:
        text = section("Dockerfile (dockerfile)", "Tests: 2 (SUCCESSES: 0, FAILURES: 2)\n",
                       plain_misconfig_block("HIGH", "m", "d", "https://x.example/"))
        with self.assertRaises(ReportError):
            parse(text)

    def test_detection_finds_a_file_that_starts_with_the_five_column_summary(self) -> None:
        text = summary([["Python", "python-pkg", "1", "-", "-"]], SUMMARY_HEADER_NO_LICENSES) + vulnerabilities(
            ["a", "CVE-1", "HIGH", "fixed", "1", "2", "t"], high=1)
        self.assertEqual(len(parse_report_file("x.txt", text.encode()).findings), 1)


class SecondLayoutReviewTest(unittest.TestCase):
    """Cases found by the code review of the second layout."""

    def test_a_bracket_header_without_a_title_uses_the_lines_below_it(self) -> None:
        block = "\n".join(["CRITICAL (AWS):", "═" * 70, "AWS Access Key ID", "─" * 70, "deploy.sh:3", "─" * 70]) + "\n\n"
        (item,) = parse(section("deploy.sh", totals(critical=1), block)).secrets
        self.assertEqual((item.category, item.title, item.start_line), ("AWS", "AWS Access Key ID", 3))

    def test_a_summary_without_a_licenses_column_does_not_judge_the_licenses(self) -> None:
        """No Licenses column: the licenses were not counted there, so a license section is fine."""
        rows = [["Java", "-", "-", "-", "-"]]
        text = summary(rows, SUMMARY_HEADER_NO_LICENSES) + section(
            "Java (license)", totals(low=1), box(LICENSE_HEADER, [["org.a:a", "MIT License", "notice", "LOW"]]))
        self.assertEqual(len(parse(text).licenses), 1)

    def test_a_summary_with_a_licenses_column_still_checks_the_licenses(self) -> None:
        rows = [["Java", "-", "-", "-", "-", "0"]]
        text = summary(rows) + section(
            "Java (license)", totals(low=1), box(LICENSE_HEADER, [["org.a:a", "MIT License", "notice", "LOW"]]))
        with self.assertRaises(ReportError):
            parse(text)


if __name__ == "__main__":
    unittest.main()
