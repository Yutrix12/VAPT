"""Tests for the AI explanation of misconfigurations, secrets and licenses (U4.3).

The request carries only what the project's rules allow (never a secret's value
or a misconfiguration's message or code); the answer has solutions and
mitigations apart; licenses get options only, never a legal verdict.
"""

import json
import unittest

from pydantic import TypeAdapter, ValidationError

from app.fixes.other import (
    OTHER_FIX_SCHEMA,
    OtherAnswer,
    OtherFixRequest,
    build_other_messages,
    validate_other_answer,
)
from app.fixes.validation import FixError
from tests.support.fix_samples import INJECTION

REQUEST = TypeAdapter(OtherFixRequest)

MISCONFIG = {
    "kind": "misconfiguration", "check_id": "DS-0002", "title": "Image user should not be 'root'",
    "description": "Running containers as root can lead to a container escape.",
    "resolution": "Add 'USER <non root user name>' line to the Dockerfile", "severity": "HIGH",
    "misconf_type": "dockerfile", "target": "Dockerfile", "start_line": None, "end_line": None,
}
SECRET = {
    "kind": "secret", "rule_id": "aws-access-key-id", "category": "AWS", "severity": "CRITICAL",
    "title": "AWS Access Key ID", "target": "deploy.sh", "start_line": 3, "end_line": 3,
}
LICENSE = {
    "kind": "license", "name": "EPL-1.0", "category": "reciprocal", "license_class": "license",
    "package": "org.eclipse.sisu:org.eclipse.sisu.plexus", "severity": "MEDIUM",
}


def answer(**changes: object) -> dict:
    base = {"summary": "Run the container as a non-root user.", "solutions": ["Add a USER line."],
            "mitigations": ["Drop capabilities."], "risk_notes": "The image may need file permission changes."}
    return {**base, **changes}


def data_block(messages: list[dict[str, str]]) -> dict:
    lines = messages[-1]["content"].splitlines()
    return json.loads("\n".join(lines[1:-1]))


class RequestTest(unittest.TestCase):
    def test_each_kind_is_accepted(self) -> None:
        for body in (MISCONFIG, SECRET, LICENSE):
            with self.subTest(kind=body["kind"]):
                self.assertEqual(REQUEST.validate_python(body).kind, body["kind"])

    def test_any_extra_field_is_refused_so_a_secret_value_can_never_arrive(self) -> None:
        for body in (MISCONFIG, SECRET, LICENSE):
            for extra in ("match", "code", "Message", "value", "secret"):
                with self.subTest(kind=body["kind"], extra=extra), self.assertRaises(ValidationError):
                    REQUEST.validate_python({**body, extra: "AKIA-NOT-A-REAL-KEY"})

    def test_unknown_kind_and_bad_severity_are_refused(self) -> None:
        for body in ({**SECRET, "kind": "vulnerability"}, {**SECRET, "severity": "SEVERE"}, {"severity": "HIGH"}):
            with self.subTest(body=body), self.assertRaises(ValidationError):
                REQUEST.validate_python(body)

    def test_texts_have_a_length_limit(self) -> None:
        with self.assertRaises(ValidationError):
            REQUEST.validate_python({**MISCONFIG, "description": "x" * 20_000})


class PromptTest(unittest.TestCase):
    def test_the_data_block_holds_only_the_fields_of_the_request(self) -> None:
        data = data_block(build_other_messages(REQUEST.validate_python(SECRET)))
        self.assertEqual(set(data), set(SECRET))
        self.assertEqual(data["rule_id"], "aws-access-key-id")

    def test_secret_prompt_never_asks_for_or_guesses_the_value(self) -> None:
        system = build_other_messages(REQUEST.validate_python(SECRET))[0]["content"]
        self.assertIn("value of the secret is not given", system)
        self.assertIn("never ask for it", system)

    def test_secret_prompt_says_the_fixed_steps_are_already_shown_and_must_not_be_repeated(self) -> None:
        from app.fixes.secret_steps import SECRET_FIX_STEPS

        system = build_other_messages(REQUEST.validate_python(SECRET))[0]["content"]
        for step in SECRET_FIX_STEPS:
            self.assertIn(step, system)
        self.assertIn("already shown", system)
        self.assertIn("do not repeat", system.lower())

    def test_license_prompt_gives_options_only_and_no_legal_verdict(self) -> None:
        system = build_other_messages(REQUEST.validate_python(LICENSE))[0]["content"]
        self.assertIn("legal or compliance team", system)
        self.assertIn("must never say that a license is allowed", system)

    def test_misconfiguration_prompt_starts_from_trivys_own_fix_text(self) -> None:
        system = build_other_messages(REQUEST.validate_python(MISCONFIG))[0]["content"]
        self.assertIn("resolution", system)

    def test_every_prompt_guards_untrusted_data_and_unknown_severity(self) -> None:
        for body in (MISCONFIG, SECRET, LICENSE):
            with self.subTest(kind=body["kind"]):
                system = build_other_messages(REQUEST.validate_python(body))[0]["content"]
                self.assertIn("untrusted", system)
                self.assertIn("UNKNOWN", system)
                self.assertIn("not rated", system)
                self.assertIn("solutions", system)
                self.assertIn("mitigations", system)

    def test_the_schema_is_in_the_prompt(self) -> None:
        system = build_other_messages(REQUEST.validate_python(SECRET))[0]["content"]
        self.assertIn(json.dumps(OTHER_FIX_SCHEMA), system)

    def test_injection_in_a_field_stays_inside_the_data_block(self) -> None:
        body = {**MISCONFIG, "description": INJECTION}
        messages = build_other_messages(REQUEST.validate_python(body))
        self.assertNotIn(INJECTION, messages[0]["content"])
        user = messages[-1]["content"]
        self.assertTrue(user.startswith("REPORT DATA ") and user.rstrip().endswith("END"))
        self.assertEqual(data_block(messages)["description"], INJECTION)

    def test_markers_differ_between_requests(self) -> None:
        request = REQUEST.validate_python(SECRET)
        first = build_other_messages(request)[-1]["content"].splitlines()[0]
        again = build_other_messages(request)[-1]["content"].splitlines()[0]
        self.assertNotEqual(first, again)


class ValidationTest(unittest.TestCase):
    def test_solutions_make_it_solution_options(self) -> None:
        advice = validate_other_answer(answer(), "misconfiguration")
        self.assertEqual((advice.kind, advice.status), ("misconfiguration", "solution_options"))
        self.assertEqual(advice.solutions, ["Add a USER line."])
        self.assertEqual(advice.mitigations, ["Drop capabilities."])
        self.assertEqual(advice.disclaimer, "AI suggestion: verify before applying")

    def test_only_mitigations_make_it_mitigations_only(self) -> None:
        advice = validate_other_answer(answer(solutions=[]), "secret")
        self.assertEqual(advice.status, "mitigations_only")

    def test_texts_are_cleaned_and_empty_ones_dropped(self) -> None:
        advice = validate_other_answer(answer(solutions=["  fix\x07 ", "", "  "], summary=" ok\x1b "), "license")
        self.assertEqual((advice.solutions, advice.summary), (["fix"], "ok"))

    def test_bad_answers_give_one_clear_error(self) -> None:
        bad = [{}, answer(summary=None), answer(solutions="x"), answer(mitigations=[1]),
               answer(solutions=[f"s{i}" for i in range(7)]), answer(summary="   ")]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(FixError):
                validate_other_answer(item, "secret")

    def test_the_answer_has_no_version_and_no_commands(self) -> None:
        self.assertEqual(set(OtherAnswer.model_fields), {"summary", "solutions", "mitigations", "risk_notes"})


class PromptTextTest(unittest.TestCase):
    def test_braces_in_a_rule_text_or_in_the_schema_do_not_break_the_prompt(self) -> None:
        from app.fixes.other import prompts

        original = dict(prompts.KIND_RULES)
        try:
            prompts.KIND_RULES["secret"] = "Use {curly} braces {0} {} carefully."
            system = build_other_messages(REQUEST.validate_python(SECRET))[0]["content"]
        finally:
            prompts.KIND_RULES.update(original)
        self.assertIn("Use {curly} braces {0} {} carefully.", system)
        self.assertIn(json.dumps(OTHER_FIX_SCHEMA), system)


if __name__ == "__main__":
    unittest.main()
