"""Tests for format detection (upgrade step U3).

Supported formats (owner's decision 2026-11-11): Trivy JSON, Trivy's text
(table) output and Trivy HTML (html.tpl); the last two are added in the
next sub-steps. Everything else gets one clear message.
"""

import json
import unittest

from app.parsers import SUPPORTED_FORMATS, parse_report_file
from app.parsers.models import ReportError


class DetectionTest(unittest.TestCase):
    """The format comes from the content, never from the file name."""

    def test_trivy_json_parses_whatever_the_name(self) -> None:
        raw = json.dumps({"SchemaVersion": 2, "Results": []}).encode()
        for name in ("report.json", "report.txt", "report"):
            with self.subTest(name=name):
                self.assertEqual(parse_report_file(name, raw).report_format, "Trivy JSON")

    def test_unsupported_content_lists_the_formats(self) -> None:
        sarif = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy"}}}]}).encode()
        for raw in (b"just text", json.dumps({"name": "my-app"}).encode(), sarif):
            with self.subTest(raw=raw[:30]), self.assertRaises(ReportError) as caught:
                parse_report_file("r.txt", raw)
            self.assertEqual(str(caught.exception),
                             "not a supported Trivy report. Supported formats: " + ", ".join(SUPPORTED_FORMATS))

    def test_broken_json_keeps_the_json_error(self) -> None:
        with self.assertRaises(ReportError) as caught:
            parse_report_file("b.json", b'{"Results": [')
        self.assertIn("not valid JSON", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
