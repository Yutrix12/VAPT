"""Tests for app/fixes/commands.py: upgrade commands built by code (U4).

The syntax of every command is in the fix-commands skill, with its source.
"""

import unittest

from app.fixes.commands import UNSAFE_FLAGS, build_fix_commands, is_unsafe_command


def lines(built) -> list[tuple[str | None, tuple[str, ...]]]:
    return [(command.label, command.lines) for command in built.commands]


class BuiltCommandsTest(unittest.TestCase):
    def test_debian_and_ubuntu_refresh_then_upgrade_one_package(self) -> None:
        for package_type in ("debian", "ubuntu"):
            built = build_fix_commands("openssl", package_type, ["3.0.13-1~deb12u1"])
            self.assertEqual(lines(built), [(None, ("apt-get update", "apt-get install --only-upgrade openssl=3.0.13-1~deb12u1"))])
            self.assertIsNone(built.note)

    def test_epoch_in_a_version_is_allowed(self) -> None:
        built = build_fix_commands("bsdutils", "debian", ["1:2.41.5-0+deb13u1"])
        self.assertEqual(built.commands[0].lines[1], "apt-get install --only-upgrade bsdutils=1:2.41.5-0+deb13u1")

    def test_each_supported_type_has_its_documented_form(self) -> None:
        expected = {
            ("fedora", "curl", "8.0.1-1.fc39"): "dnf install curl-8.0.1-1.fc39",
            ("rocky", "curl", "8.0.1-1.el9"): "dnf install curl-8.0.1-1.el9",
            ("alma", "curl", "8.0.1-1.el9"): "dnf install curl-8.0.1-1.el9",
            ("pip", "pypdf", "6.20.0"): "python -m pip install 'pypdf==6.20.0'",
            ("python-pkg", "wheel", "0.46.2"): "python -m pip install 'wheel==0.46.2'",
            ("npm", "lodash", "4.17.21"): "npm install lodash@4.17.21",
            ("node-pkg", "@scope/pkg", "1.2.3"): "npm install @scope/pkg@1.2.3",
            ("gomod", "golang.org/x/text", "0.3.8"): "go get golang.org/x/text@v0.3.8",
            ("gobinary", "golang.org/x/text", "v0.3.8"): "go get golang.org/x/text@v0.3.8",
            ("cargo", "regex", "1.5.5"): "cargo update regex --precise 1.5.5",
        }
        for (package_type, name, version), command in expected.items():
            with self.subTest(package_type=package_type):
                built = build_fix_commands(name, package_type, [version])
                self.assertEqual([c.lines for c in built.commands], [(command,)])

    def test_several_fixed_versions_give_one_labelled_command_each(self) -> None:
        built = build_fix_commands("pip", "pip", ["23.3", "25.3, 26.0"])
        self.assertEqual(lines(built), [
            ("Fixed version 23.3", ("python -m pip install 'pip==23.3'",)),
            ("Fixed version 25.3", ("python -m pip install 'pip==25.3'",)),
            ("Fixed version 26.0", ("python -m pip install 'pip==26.0'",)),
        ])
        self.assertIn("several fixed versions", built.note or "")

    def test_a_long_version_list_is_cut_and_says_so(self) -> None:
        versions = [f"1.{number}" for number in range(12)]
        built = build_fix_commands("lodash", "npm", versions)
        self.assertEqual(len(built.commands), 8)
        self.assertIn("12", built.note or "")


class NoCommandTest(unittest.TestCase):
    def assertNoCommand(self, built, words: str) -> None:
        self.assertEqual(built.commands, ())
        self.assertIn(words, built.note or "")

    def test_no_fixed_version_means_no_command(self) -> None:
        self.assertNoCommand(build_fix_commands("zlib1g", "debian", []), "no fixed version")

    def test_unknown_or_missing_type_means_no_command(self) -> None:
        self.assertNoCommand(build_fix_commands("p", None, ["1"]), "does not say")

    def test_types_whose_syntax_is_not_verified_get_no_command(self) -> None:
        for package_type in ("alpine", "centos", "redhat", "oracle", "amazon", "yarn", "pnpm", "jar", "nuget",
                             "bundler", "composer", "gradle", "something-new"):
            with self.subTest(package_type=package_type):
                self.assertNoCommand(build_fix_commands("p", package_type, ["1.0"]), "not verified")

    def test_words_that_could_run_something_else_in_a_shell_get_no_command(self) -> None:
        bad_names = ["x; rm -rf /", "$(whoami)", "a b", "`id`", "--force", "a\nb", "a‮b", "a'b", "a|b", "", "a&b"]
        for name in bad_names:
            with self.subTest(name=name):
                self.assertNoCommand(build_fix_commands(name, "pip", ["1.0"]), "unusual characters")
        bad_versions = ["1.0; reboot", "1.0 && id", "$(id)", "-1", "1.0'", "1.0\n2", "1.0‮", "1|2"]
        for version in bad_versions:
            with self.subTest(version=version):
                self.assertNoCommand(build_fix_commands("pkg", "npm", [version]), "unusual characters")


class NeverRecommendedFlagsTest(unittest.TestCase):
    def test_no_built_command_contains_a_flag_that_skips_a_safety_check(self) -> None:
        for package_type in ("debian", "ubuntu", "fedora", "rocky", "alma", "pip", "python-pkg", "npm", "node-pkg",
                             "gomod", "gobinary", "cargo"):
            built = build_fix_commands("pkg", package_type, ["1.2.3"])
            for command in built.commands:
                for line in command.lines:
                    self.assertFalse(is_unsafe_command(line), line)

    def test_documented_unsafe_flags_are_recognised_in_any_command(self) -> None:
        for flag in UNSAFE_FLAGS:
            with self.subTest(flag=flag):
                self.assertTrue(is_unsafe_command(f"apt-get install {flag} openssl"))
        self.assertTrue(is_unsafe_command("dnf install --nogpgcheck x"))
        self.assertTrue(is_unsafe_command("GOSUMDB=off go get a@v1"))
        self.assertFalse(is_unsafe_command("apt-get install --only-upgrade openssl"))
        self.assertFalse(is_unsafe_command("pip install 'a==1'"))


if __name__ == "__main__":
    unittest.main()
