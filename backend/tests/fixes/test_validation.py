"""Tests for app/fixes/validation.py: what counts as a fix."""

import unittest

from app.fixes.schemas import DISCLAIMER, FixGroup
from app.fixes.validation import FixError, validate_answer
from tests.support.fix_samples import FIXED, answer, make_group


class ValidateAnswerTest(unittest.TestCase):
    """The code, not the model, decides what counts as a fix."""

    def test_exact_trivy_version_is_verified(self) -> None:
        advice = validate_answer(answer(), make_group())
        self.assertEqual(advice.status, "verified")
        self.assertEqual(advice.target_version, FIXED[0])
        self.assertEqual(advice.disclaimer, DISCLAIMER)

    def test_invented_version_is_unverified(self) -> None:
        advice = validate_answer(answer(target_version="9.9.9"), make_group())
        self.assertEqual(advice.status, "unverified")
        self.assertIsNone(advice.target_version)
        self.assertEqual(advice.unverified_version, "9.9.9")

    def test_near_miss_is_not_verified(self) -> None:
        advice = validate_answer(answer(target_version=" 3.5.4 "),
                                 make_group())
        self.assertEqual(advice.status, "unverified")

    def test_no_version_suggested(self) -> None:
        for version in [None, "", "   "]:
            with self.subTest(version=version):
                advice = validate_answer(answer(target_version=version),
                                         make_group())
                self.assertEqual(advice.status, "no_version_suggested")
                self.assertIsNone(advice.unverified_version)

    def test_one_part_of_a_comma_list_is_verified(self) -> None:
        advice = validate_answer(answer(target_version="2.0.1"),
                                 make_group(fixed=["2.0.1, 1.9.5"]))
        self.assertEqual(advice.status, "verified")
        self.assertEqual(advice.target_version, "2.0.1")

    def test_group_without_fix_is_mitigation_only(self) -> None:
        advice = validate_answer(answer(target_version="1.0"),
                                 make_group(fixed=[]))
        self.assertEqual(advice.status, "no_fix_available")
        self.assertIsNone(advice.target_version)
        self.assertIsNone(advice.unverified_version)  # no invented version
        self.assertTrue(advice.mitigation_only)
        self.assertEqual(advice.trivy_fixed_versions, [])

    def test_open_cves_after_the_upgrade_are_counted(self) -> None:
        group = make_group()
        group.cves[2].fixed_version = None
        advice = validate_answer(answer(), group)
        self.assertEqual(advice.status, "verified")
        self.assertEqual(advice.cves_without_fix, 1)

    def test_bad_answers_give_one_clear_error(self) -> None:
        bad = [answer(commands="rm -rf /"), answer(summary=None),
               {"summary": "only this"}, answer(summary="x" * 50_000),
               answer(summary="\x00\x07"),
               answer(commands=[f"cmd {i}" for i in range(6)])]
        for broken in bad:
            with self.subTest(answer=str(broken)[:60]):
                with self.assertRaises(FixError):
                    validate_answer(broken, make_group())

    def test_control_characters_are_removed(self) -> None:
        advice = validate_answer(
            answer(summary="Upgrade\x1b[31m now\nplease",
                   commands=["\x1b\x07", "apt-get install openssl"]),
            make_group())
        self.assertEqual(advice.summary, "Upgrade[31m now\nplease")
        self.assertEqual(advice.commands, ["apt-get install openssl"])

    def test_unknown_severity_is_refused(self) -> None:
        group = make_group().model_dump()
        group["cves"][0]["severity"] = "SEVERE"
        with self.assertRaises(ValueError):
            FixGroup.model_validate(group)


if __name__ == "__main__":
    unittest.main()
