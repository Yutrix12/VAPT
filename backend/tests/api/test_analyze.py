"""Tests for POST /api/analyze (upload one Trivy JSON report)."""

import dataclasses
import json
import unittest

import httpx2
from fastapi.testclient import TestClient

from app.api.schemas import PackageGroupOut, ReportDetails
from app.main import app
from app.middleware import MAX_REQUEST_BYTES, MAX_UPLOAD_BYTES
from app.parsers.models import PackageGroup, Report
from tests.support.reports import FS_JSON, IMAGE_JSON, REAL_REPORTS_FOUND, SKIP_REASON


def upload(client: TestClient, name: str, content: bytes) -> httpx2.Response:
    """POST one file the way the browser form will send it."""
    return client.post("/api/analyze",
                       files={"file": (name, content, "application/json")})


def tiny_report(**metadata: object) -> bytes:
    """A tiny valid report with one vulnerability, as UTF-8 JSON bytes."""
    return json.dumps({
        "SchemaVersion": 2,
        "ArtifactType": "repository",
        "Metadata": metadata,
        "Results": [{"Target": "requirements.txt", "Class": "lang-pkgs",
                     "Type": "pip", "Vulnerabilities": [
                         {"VulnerabilityID": "CVE-2026-0001",
                          "PkgName": "demo", "InstalledVersion": "1.0",
                          "FixedVersion": "1.1", "Severity": "HIGH"}]}],
    }).encode("utf-8")


class AnalyzeErrorsTest(unittest.TestCase):
    """Bad uploads get one clear 4xx JSON error and no crash."""

    def setUp(self) -> None:
        self.client = TestClient(app, base_url="http://localhost")

    def test_unsupported_file_lists_the_formats(self) -> None:
        # U3: the content decides, and the message names what is supported.
        response = upload(self.client, "report.html", b"<html></html>")
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json(), {"detail": (
            "Skipped report.html: not a supported Trivy report. "
            "Supported formats: Trivy JSON, Trivy text (table)")})

    def test_broken_json_is_skipped(self) -> None:
        response = upload(self.client, "broken.json", b'{"Results": [')
        self.assertEqual(response.status_code, 422)
        self.assertTrue(response.json()["detail"].startswith(
            "Skipped broken.json: not valid JSON"))

    def test_path_in_file_name_is_cut_to_the_name(self) -> None:
        response = upload(self.client, "../../secret/x.html", b"x")
        self.assertIn("Skipped x.html:", response.json()["detail"])

    def test_file_over_50_mb_is_refused(self) -> None:
        response = upload(self.client, "big.json",
                          b" " * (MAX_UPLOAD_BYTES + 1))
        self.assertEqual(response.status_code, 413)
        self.assertIn("50 MB", response.json()["detail"])

    def test_request_over_limit_is_refused_before_reading(self) -> None:
        response = self.client.post(
            "/api/analyze", content=b" " * (MAX_REQUEST_BYTES + 1),
            headers={"Content-Type": "application/octet-stream"})
        self.assertEqual(response.status_code, 413)

    def test_request_without_size_is_refused(self) -> None:
        # A generator body is sent in chunks, without Content-Length.
        response = self.client.post("/api/analyze",
                                    content=(part for part in [b"{}"]))
        self.assertEqual(response.status_code, 411)

    def test_missing_file_field_gives_one_line(self) -> None:
        response = self.client.post("/api/analyze", data={"other": "x"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json(), {"detail": "file: Field required"})


class ResponseModelTest(unittest.TestCase):
    """The API models list exactly the parser's fields (an allowlist)."""

    def test_report_details_match_report_fields(self) -> None:
        parser_fields = {f.name for f in dataclasses.fields(Report)}
        # The finding lists and the misconfiguration counts travel in their
        # own response fields; the two counts the page still shows (until
        # U5) are properties of Report.
        elsewhere = {"findings", "misconfigurations", "secrets", "licenses",
                     "misconfig_passed", "misconfig_exceptions"}
        self.assertEqual(set(ReportDetails.model_fields),
                         parser_fields - elsewhere | {"misconfig_count", "secret_count"})

    def test_group_model_matches_group_fields(self) -> None:
        parser_fields = {f.name for f in dataclasses.fields(PackageGroup)}
        self.assertEqual(set(PackageGroupOut.model_fields),
                         parser_fields | {"findings", "fix_commands", "fix_commands_note"})


class AnalyzeContentTest(unittest.TestCase):
    """The response shape and the personal-data rule (rule l)."""

    def setUp(self) -> None:
        self.client = TestClient(app, base_url="http://localhost")

    def test_groups_carry_their_findings(self) -> None:
        body = upload(self.client, "r.json", tiny_report()).json()
        self.assertEqual(set(body), {"report", "summary", "package_groups", "misconfigurations",
                                     "secrets", "licenses", "secret_fix_steps"})
        group = body["package_groups"][0]
        self.assertEqual(group["pkg_name"], "demo")
        self.assertEqual(len(group["findings"]), group["finding_count"])
        self.assertEqual(group["findings"][0]["vuln_id"], "CVE-2026-0001")

    def test_each_group_carries_its_built_fix_commands(self) -> None:
        group = upload(self.client, "r.json", tiny_report()).json()["package_groups"][0]
        self.assertEqual(group["fix_commands"], [{"label": None, "version": "1.1", "lines": ["python -m pip install 'demo==1.1'"]}])
        self.assertIsNone(group["fix_commands_note"])

    def test_a_group_without_a_verified_command_says_why(self) -> None:
        report = json.loads(tiny_report())
        report["Results"][0]["Type"] = "alpine"
        group = upload(self.client, "r.json", json.dumps(report).encode()).json()["package_groups"][0]
        self.assertEqual(group["fix_commands"], [])
        self.assertIn("not verified", group["fix_commands_note"])

    def test_no_git_personal_data_in_response(self) -> None:
        person = "Some Person <person@example.invalid>"
        response = upload(self.client, "r.json", tiny_report(
            RepoURL="https://example.invalid/repo.git", Branch="main",
            Commit="abc123", CommitMsg="secret message",
            Author=person, Committer=person))
        self.assertEqual(response.status_code, 200)
        for text in ("Some Person", "secret message", "CommitMsg",
                     "Author", "Committer"):
            with self.subTest(text=text):
                self.assertNotIn(text, response.text)
        self.assertEqual(response.json()["report"]["commit"], "abc123")


@unittest.skipUnless(REAL_REPORTS_FOUND, SKIP_REASON)
class AnalyzeRealReportsTest(unittest.TestCase):
    """The API gives the same numbers as the parser for the real files."""

    @classmethod
    def setUpClass(cls) -> None:
        client = TestClient(app, base_url="http://localhost")
        cls.image = upload(client, "image.json", IMAGE_JSON.read_bytes())
        cls.fs = upload(client, "fs.json", FS_JSON.read_bytes())

    def test_image_json(self) -> None:
        self.assertEqual(self.image.status_code, 200)
        body = self.image.json()
        self.assertEqual(body["summary"]["total"], 492)
        self.assertEqual(len(body["package_groups"]), 54)
        findings = sum(len(g["findings"]) for g in body["package_groups"])
        self.assertEqual(findings, 492)
        self.assertEqual(body["report"]["os_name"], "13.1")

    def test_fs_json(self) -> None:
        self.assertEqual(self.fs.status_code, 200)
        body = self.fs.json()
        self.assertEqual(body["summary"]["total"], 18)
        self.assertEqual(len(body["package_groups"]), 1)
        self.assertEqual(body["package_groups"][0]["pkg_name"], "pypdf")
        self.assertEqual(body["report"]["branch"], "main")
        for key in ("CommitMsg", "Author", "Committer"):
            with self.subTest(field=key):
                self.assertNotIn(key, self.fs.text)


if __name__ == "__main__":
    unittest.main()
