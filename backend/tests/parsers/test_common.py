"""Tests for app/parsers/common.py: severity levels and their order."""

import unittest

from app.parsers.common import severity_level, severity_sort_key


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


if __name__ == "__main__":
    unittest.main()
