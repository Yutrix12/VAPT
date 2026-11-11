"""The secrets rule across the parser, the API and the command line."""

import contextlib
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.parsers.json.parser import parse_report
from cli import main as cli_main
from tests.support.reports import SAMPLES_DIR, SAMPLES_FOUND, SAMPLES_SKIP_REASON


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


if __name__ == "__main__":
    unittest.main()
