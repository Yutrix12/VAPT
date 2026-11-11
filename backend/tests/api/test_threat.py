"""KEV and EPSS in POST /api/analyze: local files only, never guessed, never sent to the AI."""

import json
import socket
import unittest
import urllib.request
from unittest import mock

from fastapi.testclient import TestClient

from app.fixes.prompts import build_messages, prompt_data
from app.fixes.schemas import FixGroup
from app.main import app
from tests.api.test_analyze import upload
from tests.support.threat_files import ThreatDataDirCase, epss_gz, kev_json


def two_cve_report() -> bytes:
    """One package with two CVEs, and a second package with one."""
    def vuln(cve: str, pkg: str) -> dict:
        return {"VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": "1.0",
                "FixedVersion": "1.1", "Severity": "HIGH"}
    return json.dumps({"SchemaVersion": 2, "ArtifactType": "repository", "Results": [
        {"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip", "Vulnerabilities": [
            vuln("CVE-2026-0001", "demo"), vuln("CVE-2026-0002", "demo"), vuln("GHSA-aaaa-bbbb-cccc", "other")]}]}).encode()


class AnalyzeWithoutDataTest(ThreatDataDirCase):
    """No data files: the answer is exactly as it was before this feature."""

    def test_the_answer_has_no_threat_fields_at_all(self) -> None:
        body = upload(TestClient(app, base_url="http://localhost"), "r.json", two_cve_report()).json()
        self.assertNotIn("threat_data", body)
        for group in body["package_groups"]:
            for finding in group["findings"]:
                self.assertNotIn("threat", finding)


class AnalyzeWithDataTest(ThreatDataDirCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_kev(kev_json(["CVE-2026-0001"]))
        self.write_epss(epss_gz({"CVE-2026-0001": "0.97", "CVE-2026-0002": "0.002"}))
        self.client = TestClient(app, base_url="http://localhost")

    def analyze(self) -> dict:
        # (socket.connect itself cannot be patched: the test client's event loop needs it)
        refuse = AssertionError("network used during analysis")
        with mock.patch.object(socket, "getaddrinfo", side_effect=refuse),                 mock.patch.object(socket, "create_connection", side_effect=refuse),                 mock.patch.object(urllib.request, "urlopen", side_effect=refuse):
            response = upload(self.client, "r.json", two_cve_report())
        self.assertEqual(response.status_code, 200)
        return response.json()

    def findings(self, body: dict) -> dict[str, dict]:
        return {f["vuln_id"]: f for g in body["package_groups"] for f in g["findings"]}

    def test_a_package_with_two_cves_only_one_of_them_in_kev(self) -> None:
        found = self.findings(self.analyze())
        self.assertEqual(found["CVE-2026-0001"]["threat"], {"kev": "listed", "epss_state": "listed", "epss": 0.97})
        self.assertEqual(found["CVE-2026-0002"]["threat"], {"kev": "not_listed", "epss_state": "listed", "epss": 0.002})

    def test_an_id_that_is_not_a_cve_is_not_called_not_listed(self) -> None:
        threat = self.findings(self.analyze())["GHSA-aaaa-bbbb-cccc"]["threat"]
        self.assertEqual(threat, {"kev": "not_cve", "epss_state": "not_cve", "epss": None})

    def test_the_status_of_both_files_is_in_the_answer(self) -> None:
        status = self.analyze()["threat_data"]
        self.assertEqual(status["kev"]["status"], "loaded")
        self.assertEqual(status["kev"]["as_of"], "2026-11-10")
        self.assertEqual(status["epss"]["as_of"], "2026-11-11")
        self.assertIn("age_days", status["epss"])
        self.assertIsNone(status["kev"]["error"])

    def test_a_broken_file_is_a_message_and_the_analysis_still_works(self) -> None:
        self.write_epss(b"not a gzip file")
        body = self.analyze()
        self.assertEqual(body["threat_data"]["epss"]["status"], "error")
        self.assertIn("EPSS", body["threat_data"]["epss"]["error"])
        threat = self.findings(body)["CVE-2026-0001"]["threat"]
        self.assertEqual(threat, {"kev": "listed", "epss_state": "no_data", "epss": None})
        self.assertEqual(body["summary"]["total"], 3)

    def test_both_files_broken_gives_two_errors_and_no_values(self) -> None:
        self.write_kev(b"{")
        self.write_epss(b"x")
        body = self.analyze()
        self.assertEqual([body["threat_data"][k]["status"] for k in ("kev", "epss")], ["error", "error"])
        self.assertNotIn("threat", self.findings(body)["CVE-2026-0001"])


class TheModelNeverSeesItTest(unittest.TestCase):
    def test_the_fix_request_has_no_field_for_it_and_the_prompt_never_mentions_it(self) -> None:
        group = FixGroup.model_validate({
            "target": "requirements.txt", "pkg_name": "demo", "installed_version": "1.0", "ecosystem": "pip",
            "fixed_versions": ["1.1"],
            "cves": [{"vuln_id": "CVE-2026-0001", "severity": "HIGH", "fixed_version": "1.1",
                      "threat": {"kev": "listed", "epss_state": "listed", "epss": 0.97}, "kev": True, "epss": 0.97}]})
        text = json.dumps(build_messages(group)).lower()
        for word in ("kev", "epss", "known exploited", "exploit prob", "0.97", "threat"):
            self.assertNotIn(word, text)
        self.assertEqual(set(prompt_data(group)["vulnerabilities"][0]), {"id", "severity", "title", "fixed_in"})


if __name__ == "__main__":
    unittest.main()
