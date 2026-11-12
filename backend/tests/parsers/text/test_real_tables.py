"""The text parser against real Trivy output, with the JSON report as the oracle.

Each table in samples/tables was made by `trivy convert` from the JSON report
of the same name, so both must give the same findings.
Skipped with a reason when the sample tables are missing.
"""

import unittest
from collections import Counter

from app.analysis.summary import summarize
from app.parsers import parse_report_file
from app.parsers.json.parser import parse_report
from app.parsers.models import Report
from tests.support.reports import (
    FS_JSON,
    IMAGE_JSON,
    SAMPLES_DIR,
    TABLES_DIR,
    TABLES_FOUND,
    TABLES_SKIP_REASON,
)

PAIRS = {
    "image": IMAGE_JSON,
    "fs": FS_JSON,
    **{name: SAMPLES_DIR / f"{name}.json" for name in (
        "alpine-310", "centos-7", "dockerfile", "gomod", "license-cyclonedx", "npm", "pip",
        "secrets", "synthetic-test-report", "ubuntu-1804", "yarn")},
}


def load_table(name: str, suffix: str = ".txt") -> Report:
    raw = (TABLES_DIR / f"{name}{suffix}").read_bytes()
    return parse_report_file(f"{name}{suffix}", raw)


def vuln_rows(report: Report, with_target: bool = True) -> Counter:
    return Counter(
        ((f.target,) if with_target else ()) + (f.pkg_name, f.vuln_id, f.severity, f.status,
                                                f.installed_version, f.fixed_version)
        for f in report.findings)


@unittest.skipUnless(TABLES_FOUND, TABLES_SKIP_REASON)
class RealTablesTest(unittest.TestCase):
    def assert_same_vulnerabilities(self, table: Counter, oracle: Counter) -> None:
        """The same rows. Trivy draws an identical row as blank lines, so the
        table can lack that copy (image.json has one: 491 rows, not 492)."""
        self.assertEqual(set(table), set(oracle))
        self.assertLessEqual(sum(table.values()), sum(oracle.values()))
        self.assertGreaterEqual(sum(table.values()), len(oracle))

    def test_every_table_has_the_findings_of_its_json_report(self) -> None:
        for name, json_path in PAIRS.items():
            with self.subTest(name=name):
                table, oracle = load_table(name), parse_report(json_path)
                self.assert_same_vulnerabilities(vuln_rows(table), vuln_rows(oracle))
                self.assertEqual(
                    Counter((m.target, m.check_id, m.severity) for m in table.misconfigurations),
                    Counter((m.target, m.check_id, m.severity) for m in oracle.misconfigurations))
                self.assertEqual(
                    Counter((s.target, s.rule_id, s.category, s.severity, s.title) for s in table.secrets),
                    Counter((s.target, s.rule_id, s.category, s.severity, s.title) for s in oracle.secrets))
                # The table shows a line only when it prints source lines (never read).
                lines = {(s.target, s.rule_id): s.start_line for s in oracle.secrets}
                for secret in table.secrets:
                    if secret.start_line is not None:
                        self.assertEqual(secret.start_line, lines[(secret.target, secret.rule_id)])
                self.assertEqual(
                    Counter((x.target, x.pkg_name, x.name, x.category, x.severity) for x in table.licenses),
                    Counter((x.target, x.pkg_name, x.name, x.category, x.severity) for x in oracle.licenses))

    def test_tables_without_a_summary_have_the_same_findings(self) -> None:
        for name in ("image", "fs", "synthetic-test-report"):
            with self.subTest(name=name):
                self.assert_same_vulnerabilities(vuln_rows(load_table(name, ".noscan.txt"), with_target=False),
                                                 vuln_rows(parse_report(PAIRS[name]), with_target=False))

    def test_image_numbers(self) -> None:
        summary = summarize(load_table("image"))
        # 492 in the JSON report: its exact duplicate row is not drawn in the table.
        self.assertEqual(summary["total"], 491)
        self.assertEqual(list(summary["by_severity"].values()), [6, 125, 193, 158, 9])
        self.assertEqual(summary["unique_packages"], 54)

    def test_fs_numbers(self) -> None:
        summary = summarize(load_table("fs"))
        self.assertEqual((summary["total"], summary["unique_packages"]), (18, 1))

    def test_other_kinds_in_the_samples(self) -> None:
        self.assertEqual(len(load_table("dockerfile").misconfigurations), 1)
        self.assertEqual(len(load_table("secrets").secrets), 2)
        self.assertEqual(len(load_table("license-cyclonedx").licenses), 4)

    def test_secret_values_of_the_sample_never_appear(self) -> None:
        report = load_table("secrets")
        text = repr(report)
        for value in ("ghp_0123456789", "AKIA"):
            self.assertNotIn(value, text)


SECOND_LAYOUT = TABLES_DIR / "second-layout.txt"


@unittest.skipUnless(SECOND_LAYOUT.exists(), f"{SECOND_LAYOUT} not found")
class SecondLayoutRealTest(unittest.TestCase):
    """The owner's file: a second layout of Trivy's table output."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = parse_report_file("trivy-sample-report.txt", SECOND_LAYOUT.read_bytes())

    def test_numbers(self) -> None:
        report = self.report
        self.assertEqual((len(report.findings), len(report.misconfigurations), len(report.secrets)), (13, 1, 2))
        self.assertEqual(report.misconfig_passed, 26)
        summary = summarize(report)
        self.assertEqual(list(summary["by_severity"].values()), [1, 1, 7, 4, 0])
        self.assertEqual(summary["unique_packages"], 11)

    def test_findings(self) -> None:
        rows = [(f.target, f.pkg_name, f.vuln_id, f.severity, f.status, f.installed_version, f.fixed_version)
                for f in self.report.findings]
        self.assertIn(("testdata/fixtures/images/centos-7.tar.gz (centos 7.6.1810)", "bash", "CVE-2019-18276", "LOW",
                       "will_not_fix", "4.2.46-31.el7", None), rows)
        self.assertIn(("testdata/fixtures/images/centos-7.tar.gz (centos 7.6.1810)", "openssl-libs", "CVE-2018-0734",
                       "LOW", "fixed", "1:1.0.2k-16.el7", "1:1.0.2k-19.el7"), rows)  # a blank library cell
        self.assertIn(("requirements.txt", "Werkzeug", "CVE-2020-28724", "MEDIUM", "fixed", "0.11", "0.11.6"), rows)
        self.assertEqual({f.vuln_type for f in self.report.findings}, {"ubuntu", "centos", "debian", "npm", "pip"})

    def test_links_and_other_kinds(self) -> None:
        self.assertEqual(self.report.findings[0].primary_url, "https://avd.aquasec.com/nvd/cve-2019-18276")
        self.assertEqual([(s.severity, s.category, s.title, s.start_line) for s in self.report.secrets],
                         [("CRITICAL", "AWS", "AWS Access Key ID", 3), ("HIGH", "Custom", "My Secret", 7)])
        self.assertEqual(self.report.misconfigurations[0].severity, "HIGH")

    def test_the_secret_text_in_the_source_lines_never_appears(self) -> None:
        self.assertNotIn("ghp_0123456789", repr(self.report))


if __name__ == "__main__":
    unittest.main()
