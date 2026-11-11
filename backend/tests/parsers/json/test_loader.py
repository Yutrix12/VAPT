"""Tests for app/parsers/json/loader.py: encodings and bad input."""

import codecs
import json
import unittest

from app.parsers.json.parser import parse_report_bytes
from app.parsers.models import ReportError
from tests.support.trivy_json import as_bytes, small_report


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


if __name__ == "__main__":
    unittest.main()
