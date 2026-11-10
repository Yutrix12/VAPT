"""Tests for trivy_parser: loading, parsing, summarize and group_by_package.

The real-report tests need image.json and fs.json (see tests/reports.py)
and are skipped with a reason when they are missing. Expected numbers come
from the trivy-report-format skill.
"""

import codecs
import json
import unittest

from tests.reports import FS_JSON, IMAGE_JSON, REAL_REPORTS_FOUND, SKIP_REASON
from trivy_parser import (
    ReportError,
    decode_report_json,
    group_by_package,
    parse_report,
    parse_report_bytes,
    severity_level,
    severity_sort_key,
    summarize,
)

DEBIAN_TARGET = "python:3.9-slim (debian 13.1)"


def small_report(**metadata: object) -> dict:
    """A tiny valid schema-v2 report with one vulnerability."""
    return {
        "SchemaVersion": 2,
        "ArtifactType": "repository",
        "Metadata": dict(metadata),
        "Results": [{
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-0001",
                "PkgName": "demo",
                "InstalledVersion": "1.0",
                "FixedVersion": "1.1",
                "Status": "fixed",
                "Severity": "high",
            }],
        }],
    }


def as_bytes(report: object) -> bytes:
    """Encode a report the way Trivy writes it (UTF-8 JSON)."""
    return json.dumps(report).encode("utf-8")


class SeverityLevelTest(unittest.TestCase):
    """A higher level is more severe; UNKNOWN is not rated at all."""

    def test_higher_number_is_more_severe(self) -> None:
        self.assertEqual(
            [severity_level(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")],
            [4, 3, 2, 1])

    def test_unknown_has_no_level(self) -> None:
        self.assertIsNone(severity_level("UNKNOWN"))

    def test_unknown_comes_after_every_rated_severity(self) -> None:
        mixed = ["UNKNOWN", "LOW", "CRITICAL", "MEDIUM", "HIGH"]
        self.assertEqual(sorted(mixed, key=severity_sort_key),
                         ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])

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


class EncodingTest(unittest.TestCase):
    """Rule h: UTF-8, UTF-8 with BOM and UTF-16 (PowerShell's >)."""

    def test_all_encodings_give_the_same_report(self) -> None:
        text = json.dumps(small_report())
        variants = {
            "utf-8": text.encode("utf-8"),
            "utf-8 BOM": codecs.BOM_UTF8 + text.encode("utf-8"),
            "utf-16 LE": codecs.BOM_UTF16_LE + text.encode("utf-16-le"),
            "utf-16 BE": codecs.BOM_UTF16_BE + text.encode("utf-16-be"),
        }
        expected = parse_report_bytes("r.json", variants["utf-8"]).findings
        for name, raw in variants.items():
            with self.subTest(encoding=name):
                report = parse_report_bytes("r.json", raw)
                self.assertEqual(report.findings, expected)


class BadInputTest(unittest.TestCase):
    """Bad input gives one clear ReportError, never a crash."""

    def assert_rejected(self, name: str, raw: bytes, message: str) -> None:
        with self.assertRaises(ReportError) as caught:
            parse_report_bytes(name, raw)
        self.assertIn(message, str(caught.exception))

    def test_bad_inputs(self) -> None:
        cases = [
            ("report.html", b"<html></html>",
             "only Trivy JSON reports are supported"),
            ("broken.json", b'{"SchemaVersion": 2, "Results": [',
             "not valid JSON"),
            ("other.json", b'{"name": "my-app"}', "not a Trivy JSON report"),
            ("v3.json", b'{"SchemaVersion": 3}',
             "unsupported SchemaVersion 3"),
            ("empty.json", b"[]", "not a Trivy JSON report"),
            ("nan.json", b'{"SchemaVersion": 2, "X": NaN}',
             "NaN is not allowed"),
            ("dup.json", b'{"SchemaVersion": 2, "Results": [], "Results": []}',
             "duplicate key"),
            ("deep.json", b"[" * 100_000, "nested too deeply"),
            ("binary.json", b"\x80\x81\xfe\x00",
             "not UTF-8, UTF-16 or UTF-32"),
        ]
        for name, raw, message in cases:
            with self.subTest(file=name):
                self.assert_rejected(name, raw, message)

    def test_wrong_field_types(self) -> None:
        report = small_report()
        report["Results"][0]["Vulnerabilities"] = "oops"
        self.assert_rejected("r.json", as_bytes(report),
                             "Vulnerabilities is not a list")


class RulesTest(unittest.TestCase):
    """Rules a-d, g and l from the trivy-report-format skill."""

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
