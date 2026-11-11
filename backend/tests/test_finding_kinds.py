"""Tests for misconfigurations, secrets and licenses (upgrade step U2).

The expected numbers come from the real sample reports (trivy-report-format
skill). Secret values are compared, never printed: unittest's assertIn and
assertNotIn print both strings when they fail, so the secret checks use
assertFalse(value in text, ...) instead.
"""

import contextlib
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from fastapi.testclient import TestClient

from app.analysis.summary import summarize
from app.fixes.secret_steps import SECRET_FIX_STEPS
from app.main import app
from app.parsers.json.parser import parse_report, parse_report_bytes
from app.parsers.models import ReportError
from cli import main as cli_main
from tests.support.reports import SAMPLES_DIR, SAMPLES_FOUND, SAMPLES_SKIP_REASON


def report_with(*results: dict) -> bytes:
    """A small schema-v2 report with the given Results, as file bytes."""
    data = {"SchemaVersion": 2, "ArtifactType": "repository", "Results": list(results)}
    return json.dumps(data).encode("utf-8")


def dockerfile_result(*misconfigs: dict, summary: dict | None = None) -> dict:
    result = {"Target": "Dockerfile", "Class": "config", "Type": "dockerfile",
              "Misconfigurations": list(misconfigs)}
    if summary is not None:
        result["MisconfSummary"] = summary
    return result


def misconf(status: str = "FAIL", **fields: object) -> dict:
    return {"ID": "DS-0002", "Title": "Image user should not be 'root'", "Severity": "HIGH",
            "Status": status, **fields}


def secret(rule: str = "aws-access-key-id", line: int = 3) -> dict:
    return {"RuleID": rule, "Category": "AWS", "Severity": "CRITICAL", "Title": "AWS Access Key ID",
            "StartLine": line, "EndLine": line, "Match": "AKIA-NOT-A-REAL-KEY-0000",
            "Code": {"Lines": [{"Number": line, "Content": "AKIA-NOT-A-REAL-KEY-0000"}]}, "Offset": 10}


def secrets_result(*items: dict, target: str = "deploy.sh") -> dict:
    return {"Target": target, "Class": "secret", "Secrets": list(items)}


def parse(*results: dict):
    return parse_report_bytes("test.json", report_with(*results))


@unittest.skipUnless(SAMPLES_FOUND, SAMPLES_SKIP_REASON)
class RealSamplesTest(unittest.TestCase):
    """The counts measured in the real samples (U2)."""

    def load(self, name: str):
        return parse_report(SAMPLES_DIR / name)

    def test_vulnerability_samples_have_no_other_kinds(self) -> None:
        expected = {"alpine-310.json": 4, "centos-7.json": 3, "gomod.json": 5, "npm.json": 1,
                    "pip.json": 2, "ubuntu-1804.json": 5, "yarn.json": 1}
        for name, vulnerabilities in expected.items():
            with self.subTest(name=name):
                report = self.load(name)
                self.assertEqual(len(report.findings), vulnerabilities)
                self.assertEqual((len(report.misconfigurations), len(report.secrets), len(report.licenses)),
                                 (0, 0, 0))

    def test_dockerfile_misconfiguration(self) -> None:
        report = self.load("dockerfile.json")
        self.assertEqual((report.misconfig_passed, report.misconfig_exceptions), (26, 0))
        [item] = report.misconfigurations
        self.assertEqual((item.check_id, item.severity, item.status, item.target), ("DS-0002", "HIGH", "FAIL", "Dockerfile"))
        self.assertEqual(item.resolution, "Add 'USER <non root user name>' line to the Dockerfile")
        self.assertEqual(item.primary_url, "https://avd.aquasec.com/misconfig/ds-0002")
        self.assertEqual((item.start_line, item.end_line), (None, None))  # rule o: no lines in this file

    def test_secrets(self) -> None:
        report = self.load("secrets.json")
        found = [(s.target, s.rule_id, s.category, s.severity, s.title, s.start_line, s.end_line)
                 for s in report.secrets]
        self.assertEqual(found, [
            ("deploy.sh", "aws-access-key-id", "AWS", "CRITICAL", "AWS Access Key ID", 3, 3),
            ("deploy.sh", "mysecret", "Custom", "HIGH", "My Secret", 7, 7),
        ])

    def test_synthetic_report(self) -> None:
        report = self.load("synthetic-test-report.json")
        self.assertEqual((len(report.findings), len(report.misconfigurations), len(report.secrets)), (14, 2, 1))
        self.assertEqual(report.misconfig_passed, 20)
        self.assertEqual([(m.check_id, m.severity, m.resolution) for m in report.misconfigurations],
                         [("DS-0002", "HIGH", None), ("DS-0026", "LOW", None)])  # no Resolution in this file

    def test_licenses(self) -> None:
        report = self.load("license-cyclonedx.json")
        found = [(lic.severity, lic.category, lic.pkg_name, lic.file_path, lic.name, lic.link)
                 for lic in report.licenses]
        self.assertEqual(found, [
            ("UNKNOWN", "unknown", "javax.servlet:javax.servlet-api", None,
             "CDDL + GPLv2 with classpath exception", None),
            ("MEDIUM", "reciprocal", "org.eclipse.sisu:org.eclipse.sisu.plexus", None, "EPL-1.0", None),
            ("LOW", "notice", "org.ow2.asm:asm", None, "BSD-3-Clause", None),
            ("LOW", "notice", "org.slf4j:slf4j-api", None, "MIT License", None),
        ])

    def test_summary_counts_each_kind(self) -> None:
        summary = summarize(self.load("synthetic-test-report.json"))
        self.assertEqual(summary["by_kind"],
                         {"vulnerability": 14, "misconfiguration": 2, "secret": 1, "license": 0})
        self.assertEqual((summary["misconfig_passed"], summary["misconfig_exceptions"]), (20, 0))


@unittest.skipUnless(SAMPLES_FOUND, SAMPLES_SKIP_REASON)
class SecretsRuleRealTest(unittest.TestCase):
    """The secret values in secrets.json never leave the parser (rule n)."""

    @classmethod
    def setUpClass(cls) -> None:
        raw = json.loads((SAMPLES_DIR / "secrets.json").read_text(encoding="utf-8"))
        values = set()
        for result in raw["Results"]:
            for item in result.get("Secrets") or []:
                values.add(item["Match"])
                values.update(line["Content"] for line in item["Code"]["Lines"] if line.get("IsCause"))
        cls.values = {v.strip() for v in values if v.strip()}

    def assert_no_secret(self, text: str) -> None:
        self.assertTrue(self.values)  # the test really has values to look for
        for value in self.values:
            self.assertFalse(value in text, "a secret value leaked")  # never print it

    def test_not_in_the_parsed_report(self) -> None:
        self.assert_no_secret(json.dumps(asdict(parse_report(SAMPLES_DIR / "secrets.json"))))

    def test_not_in_the_api_answer(self) -> None:
        client = TestClient(app, base_url="http://localhost")
        content = (SAMPLES_DIR / "secrets.json").read_bytes()
        response = client.post("/api/analyze", files={"file": ("secrets.json", content, "application/json")})
        self.assertEqual(response.status_code, 200)
        self.assert_no_secret(response.text)

    def test_not_in_the_command_line_json(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / "out.json"
            with open(Path(folder) / "stdout.txt", "w", encoding="utf-8") as sink:
                with contextlib.redirect_stdout(sink):
                    cli_main([str(SAMPLES_DIR / "secrets.json"), "--json", str(out)])
            self.assert_no_secret(out.read_text(encoding="utf-8"))
            self.assert_no_secret((Path(folder) / "stdout.txt").read_text(encoding="utf-8"))


class MisconfigurationRulesTest(unittest.TestCase):

    def test_pass_and_exception_are_counted_not_listed(self) -> None:
        # With --include-non-failures Trivy lists PASS and EXCEPTION too; the
        # listed PASS items are already inside MisconfSummary.Successes.
        report = parse(dockerfile_result(misconf("FAIL"), misconf("PASS"), misconf("EXCEPTION"),
                                         summary={"Successes": 5, "Failures": 1}))
        self.assertEqual([m.status for m in report.misconfigurations], ["FAIL"])
        self.assertEqual((report.misconfig_passed, report.misconfig_exceptions), (5, 1))

    def test_older_trivy_exceptions_count_is_read(self) -> None:
        # Trivy up to at least v0.50 wrote MisconfSummary.Exceptions.
        report = parse(dockerfile_result(misconf("FAIL"), summary={"Successes": 4, "Failures": 1, "Exceptions": 3}))
        self.assertEqual((report.misconfig_passed, report.misconfig_exceptions), (4, 3))

    def test_only_fail_is_a_finding_other_statuses_are_refused(self) -> None:
        for item in (misconf("SKIP"), {"ID": "DS-0002", "Title": "no status"}):
            with self.subTest(item=item), self.assertRaises(ReportError) as caught:
                parse(dockerfile_result(item))
            self.assertIn("Status", str(caught.exception))

    def test_counted_items_are_not_parsed_further(self) -> None:
        # A broken field in a PASS or EXCEPTION item is never used, so it
        # must not make the whole upload fail.
        broken = {"CauseMetadata": {"StartLine": "four"}, "References": "x"}
        report = parse(dockerfile_result(misconf("FAIL"), misconf("PASS", **broken), misconf("EXCEPTION", **broken)))
        self.assertEqual((len(report.misconfigurations), report.misconfig_passed, report.misconfig_exceptions), (1, 1, 1))

    def test_without_a_summary_the_listed_passes_are_counted(self) -> None:
        report = parse(dockerfile_result(misconf("PASS"), misconf("PASS"), misconf("FAIL")))
        self.assertEqual((len(report.misconfigurations), report.misconfig_passed), (1, 2))

    def test_missing_parts_stay_empty(self) -> None:
        [item] = parse(dockerfile_result({"ID": "DS-0026", "Status": "FAIL"})).misconfigurations
        self.assertEqual((item.title, item.resolution, item.start_line, item.severity), (None, None, None, "UNKNOWN"))

    def test_avdid_is_used_when_id_is_missing(self) -> None:
        [item] = parse(dockerfile_result({"AVDID": "AVD-DS-0002", "Status": "FAIL"})).misconfigurations
        self.assertEqual(item.check_id, "AVD-DS-0002")

    def test_lines_resource_and_references(self) -> None:
        [item] = parse(dockerfile_result(misconf(
            CauseMetadata={"Resource": "aws_s3_bucket.logs", "StartLine": 4, "EndLine": 6,
                           "Code": {"Lines": [{"Number": 4, "Content": "ENV PASSWORD=hunter2"}]}},
            References=["https://example.invalid/a"]))).misconfigurations
        self.assertEqual((item.resource, item.start_line, item.end_line, item.references),
                         ("aws_s3_bucket.logs", 4, 6, ("https://example.invalid/a",)))
        # Code lines can hold a credential: never kept (owner's decision 2026-11-11).
        self.assertFalse("hunter2" in json.dumps(asdict(item)), "misconfiguration code leaked")

    def test_message_is_never_kept(self) -> None:
        # Trivy's checks quote the file in Message (e.g. DS-0013 quotes the
        # whole RUN command), so it is dropped like the code lines (owner's
        # decision 2026-11-11): only the problem and its place are used.
        item = misconf(Message="RUN should not be used to change directory: 'cd /app && curl -u admin:hunter2 x'")
        report = parse(dockerfile_result(item))
        self.assertFalse("hunter2" in json.dumps(asdict(report)), "misconfiguration message leaked")
        self.assertFalse(hasattr(report.misconfigurations[0], "message"))

    def test_bad_values_give_one_clear_error(self) -> None:
        cases = {"StartLine is not a whole number": misconf(CauseMetadata={"StartLine": "four"}),
                 "References is not a list": misconf(References="x")}
        for message, item in cases.items():
            with self.subTest(message=message), self.assertRaises(ReportError) as caught:
                parse(dockerfile_result(item))
            self.assertIn(message, str(caught.exception))


class SecretRulesTest(unittest.TestCase):

    def test_value_code_and_offset_are_never_kept(self) -> None:
        report = parse(secrets_result(secret()))
        self.assertFalse("AKIA-NOT-A-REAL-KEY-0000" in json.dumps(asdict(report)), "a secret value leaked")

    def test_fix_steps_are_fixed_text(self) -> None:
        self.assertIn("Revoke", SECRET_FIX_STEPS[0])
        self.assertTrue(any("git-filter-repo" in step for step in SECRET_FIX_STEPS))


class FingerprintTest(unittest.TestCase):
    """New kinds: stable when lines move (owner's OK, 2026-11-11)."""

    def test_misconfiguration_ignores_line_numbers(self) -> None:
        def fingerprint(line: int) -> str:
            item = misconf(CauseMetadata={"StartLine": line, "EndLine": line})
            return parse(dockerfile_result(item)).misconfigurations[0].fingerprint
        self.assertEqual(fingerprint(3), fingerprint(30))

    def test_repeated_misconfigurations_get_their_own_fingerprint(self) -> None:
        # Owner's OK, 2026-11-11: an occurrence number n, as for secrets.
        def fingerprints(*lines: int) -> list[str]:
            items = [misconf(CauseMetadata={"StartLine": line}) for line in lines]
            return [m.fingerprint for m in parse(dockerfile_result(*items)).misconfigurations]
        first = fingerprints(3, 9)
        self.assertNotEqual(first[0], first[1])
        self.assertEqual(first, fingerprints(13, 19))  # still no line numbers inside

    def test_secret_uses_the_occurrence_not_the_line_or_value(self) -> None:
        first = parse(secrets_result(secret(line=3), secret(line=9))).secrets
        moved = parse(secrets_result(secret(line=13), secret(line=19))).secrets
        self.assertEqual([s.fingerprint for s in first], [s.fingerprint for s in moved])
        self.assertNotEqual(first[0].fingerprint, first[1].fingerprint)

    def test_kinds_never_share_a_fingerprint(self) -> None:
        report = parse(dockerfile_result(misconf()), secrets_result(secret()),
                       {"Target": "Java", "Class": "license",
                        "Licenses": [{"Name": "MIT", "PkgName": "a", "Severity": "LOW"}]})
        prints = [report.misconfigurations[0].fingerprint, report.secrets[0].fingerprint,
                  report.licenses[0].fingerprint]
        self.assertEqual(len(set(prints)), 3)


class LicenseRulesTest(unittest.TestCase):

    def test_license_in_a_file_and_confidence(self) -> None:
        [lic] = parse({"Target": "LICENSE", "Class": "license-file", "Licenses": [
            {"Name": "GPL-3.0", "FilePath": "LICENSE", "Category": "restricted", "Severity": "HIGH",
             "Confidence": 0.9, "Link": "https://spdx.org/licenses/GPL-3.0.html", "Text": "long text"}]}).licenses
        self.assertEqual((lic.pkg_name, lic.file_path, lic.confidence, lic.link),
                         (None, "LICENSE", 0.9, "https://spdx.org/licenses/GPL-3.0.html"))
        self.assertFalse("long text" in json.dumps(asdict(lic)), "license text kept")

    def test_confidence_out_of_range_is_refused(self) -> None:
        with self.assertRaises(ReportError):
            parse({"Target": "Java", "Class": "license", "Licenses": [{"Name": "MIT", "Confidence": 2}]})


class AnalyzeKindsTest(unittest.TestCase):
    """POST /api/analyze returns the three kinds; old fields keep their meaning."""

    def test_api_lists_each_kind(self) -> None:
        client = TestClient(app, base_url="http://localhost")
        content = report_with(dockerfile_result(misconf(), summary={"Successes": 3, "Failures": 1}),
                              secrets_result(secret()))
        body = client.post("/api/analyze", files={"file": ("k.json", content, "application/json")}).json()
        self.assertEqual(body["summary"]["by_kind"],
                         {"vulnerability": 0, "misconfiguration": 1, "secret": 1, "license": 0})
        self.assertEqual(body["summary"]["misconfig_passed"], 3)
        self.assertEqual(body["misconfigurations"][0]["check_id"], "DS-0002")
        self.assertEqual(set(body["secrets"][0]), {
            "fingerprint", "target", "rule_id", "category", "severity", "title", "start_line", "end_line"})
        self.assertEqual(body["secret_fix_steps"], list(SECRET_FIX_STEPS))
        self.assertEqual((body["report"]["misconfig_count"], body["report"]["secret_count"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
